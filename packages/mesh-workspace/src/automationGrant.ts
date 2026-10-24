import { canonicalizeJson, verifyEnvelope, type LocalProfile } from "@meta-uber/mesh-identity"
import type { WorkspaceGrant } from "./index"
import { signWorkspaceRecord, type WorkspaceRecordSigner } from "./signing"

export type AutomationGrantScope = NonNullable<WorkspaceGrant["payload"]["automation"]>
export type AutomationWorkspaceGrantIntent = {
  workspaceId: string
  personId: string
  scope: AutomationGrantScope
  accessEpoch?: number
  /** Retain this ID with the approval intent to retry the same grant. */
  grantId?: string
}

/** Validate the protocol shape; the application chooses the actual board, fields and lifetime. */
export function parseAutomationGrantScope(value: unknown, now = Date.now()): AutomationGrantScope {
  const scope = structuredClone(value) as AutomationGrantScope
  if (!exactKeys(scope, ["version", "boardId", "columns", "fieldIds", "expiresAt"]) ||
      ![1, 2].includes(scope.version) || typeof scope.boardId !== "string" || !scope.boardId.trim() ||
      !validColumns(scope.columns) || !uniqueIds(scope.fieldIds, 128) ||
      !Number.isSafeInteger(scope.expiresAt) || scope.expiresAt <= now) {
    throw new TypeError("Invalid automation grant scope")
  }
  return scope
}

/** Issue one exact scoped grant, with optional application-owned live signing authorization. */
export async function createAutomationWorkspaceGrant(profile: LocalProfile, intent: AutomationWorkspaceGrantIntent,
  signer?: WorkspaceRecordSigner): Promise<WorkspaceGrant> {
  const owner = { ...profile, identity: structuredClone(profile.identity), device: structuredClone(profile.device),
    certificate: structuredClone(profile.certificate), privateKeys: { ...profile.privateKeys } }
  const captured = structuredClone(intent)
  const automation = parseAutomationGrantScope(captured.scope)
  const accessEpoch = captured.accessEpoch ?? 1
  const grantId = captured.grantId ?? crypto.randomUUID()
  if (typeof captured.workspaceId !== "string" || !captured.workspaceId.trim() ||
      typeof captured.personId !== "string" || !captured.personId.trim() || !Number.isSafeInteger(accessEpoch) || accessEpoch < 1 ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(grantId)) {
    throw new TypeError("Invalid automation workspace grant intent")
  }
  const payload: WorkspaceGrant["payload"] = { kind: "workspace-grant", version: 1, grantId,
    workspaceId: captured.workspaceId, personId: captured.personId, role: "automation", accessEpoch, automation }
  const authorization = await signWorkspaceRecord(owner, payload, signer)
  if (authorization.signerKeyId !== owner.device.deviceId ||
      canonicalizeJson(authorization.payload) !== canonicalizeJson(payload) ||
      !await verifyEnvelope(authorization, owner.device.publicKey)) {
    throw new Error("Invalid automation grant authorization")
  }
  return authorization
}

function exactKeys(value: unknown, fields: string[]): boolean {
  return Boolean(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field)))
}

function uniqueIds(value: unknown, limit: number): value is string[] {
  return Array.isArray(value) && value.length <= limit && value.every(id => typeof id === "string" && Boolean(id)) &&
    new Set(value).size === value.length
}

function validColumns(value: AutomationGrantScope["columns"]): boolean {
  if (!exactKeys(value, ["lead", "interview", "rejected", ...(value?.applied === undefined ? [] : ["applied"])])) return false
  return uniqueIds([value.lead, value.interview, value.rejected, ...(value.applied === undefined ? [] : [value.applied])], 4)
}
