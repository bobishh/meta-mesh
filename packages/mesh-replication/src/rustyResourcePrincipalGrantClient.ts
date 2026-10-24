import {
  authorizeIdentityDataDevice,
  canonicalizeJson,
  publicKeyId,
  sha256Base64Url,
  verifyEnvelope,
  verifyIdentityAuthorityView,
  type IdentityAuthorityView,
  type PublicIdentity,
  type SignedEnvelope,
} from "@meta-uber/mesh-identity"
import { rustyOrigin, decodeBlindBytes } from "./rustyReplica"
import type { RustyFetch } from "./rustyDiscovery"
import {
  readRustyScopeAuthorityStatus,
  type ScopeAuthorityValidation,
} from "./rustyScopeAuthorityClient"
import { meshRustRuntime } from "./runtime"

const encoder = new TextEncoder()
const idPattern = /^[A-Za-z0-9_-]{1,128}$/u

export type RustyWorkspaceMembershipGrant = SignedEnvelope<{
  kind: "workspace-grant"
  version: 1
  grantId: string
  workspaceId: string
  personId: string
  role: "owner" | "editor" | "visitor" | "automation"
  accessEpoch?: number
  automation?: unknown
}>

export type RustyResourcePrincipalGrant = SignedEnvelope<{
  kind: "rusty-resource-principal-grant"
  version: 1
  serviceId: string
  origin: string
  workspaceId: string
  resourceKind: "scope"
  resourceId: string
  scopeId: string
  ownerPersonId: string
  subjectPersonId: string
  subjectPublicKey: string
  grantId: string
  policyEpoch: number
  readTokenHash: string
  writeTokenHash?: string
  actions: Array<"read" | "write">
  workspaceGrant: RustyWorkspaceMembershipGrant
  scopeAuthority: unknown
}>

export type RegisterRustyResourcePrincipalGrantOptions = {
  origin: string
  servicePublicKey: string
  storageScopeId: string
  workspaceId: string
  expectedScopeAuthoritySnapshot: unknown
  identity: PublicIdentity
  authorityView: IdentityAuthorityView
  deviceId: string
  devicePublicKey: string
  subjectIdentity: PublicIdentity
  workspaceGrant: RustyWorkspaceMembershipGrant
  readToken: string
  writeToken?: string
  fetcher?: RustyFetch
  ensureCurrent?: () => void | Promise<void>
  validateSnapshot: (snapshot: unknown) => ScopeAuthorityValidation
  signAuthorization: (payload: RustyResourcePrincipalGrant["payload"]) => Promise<RustyResourcePrincipalGrant>
  now?: () => number
}

export type RegisteredRustyResourcePrincipalGrant = {
  principalGrant: RustyResourcePrincipalGrant
  scopeAuthority: ScopeAuthorityValidation
}

/** Validate one current workspace member and register its scoped Rusty data grant. */
export async function registerRustyResourcePrincipalGrant(
  options: RegisterRustyResourcePrincipalGrantOptions,
): Promise<RegisteredRustyResourcePrincipalGrant> {
  const now = options.now ?? Date.now
  const origin = rustyOrigin(options.origin)
  const { storageScopeId, workspaceId } = options
  if (![storageScopeId, workspaceId].every((value) => idPattern.test(value))) {
    throw new Error("Invalid Rusty resource principal binding")
  }
  const grant = options.workspaceGrant
  if (!grant || typeof grant !== "object" || !grant.payload || typeof grant.payload !== "object" ||
      !["owner", "editor", "visitor", "automation"].includes(grant.payload.role)) {
    throw new Error("Invalid workspace membership grant for Rusty resource access")
  }
  const readToken = validateToken(options.readToken, "read")
  const readOnly = grant.payload.role === "visitor"
  const writeToken = options.writeToken === undefined ? undefined : validateToken(options.writeToken, "write")
  if (readOnly && writeToken !== undefined) {
    throw new Error("Read-only Rusty resource principal must not include a write token")
  }
  if (!readOnly && writeToken === undefined) {
    throw new Error("Writable Rusty resource principal requires a write token")
  }

  const serviceId = await publicKeyId(options.servicePublicKey)
  const identity = structuredClone(options.identity)
  const subjectIdentity = structuredClone(options.subjectIdentity)
  if (await publicKeyId(identity.publicKey) !== identity.personId ||
      await publicKeyId(subjectIdentity.publicKey) !== subjectIdentity.personId) {
    throw new Error("Invalid Rusty resource principal Identity")
  }
  const view = await verifyIdentityAuthorityView(options.authorityView)
  if (view.personId !== identity.personId || view.identityPublicKey !== identity.publicKey) {
    throw new Error("Rusty resource principal Identity authority mismatch")
  }
  const activeKey = await authorizeIdentityDataDevice(view, options.deviceId)
  if (activeKey !== options.devicePublicKey || await publicKeyId(activeKey) !== options.deviceId) {
    throw new Error("Rusty resource principal signer is not an active Identity device")
  }

  await options.ensureCurrent?.()
  const accepted = await readRustyScopeAuthorityStatus({
    origin,
    servicePublicKey: options.servicePublicKey,
    scopeId: storageScopeId,
    fetcher: options.fetcher,
    validateSnapshot: options.validateSnapshot,
    now,
  })
  const authority = accepted.authority
  if (!authority || authority.workspaceId !== workspaceId ||
      authority.controllerPersonId !== identity.personId || authority.controllerPublicKey !== identity.publicKey) {
    throw new Error("Rusty resource principal requires the current workspace controller")
  }

  const state = meshRustRuntime().state
  const expected = normalizeScopeSnapshot(options.expectedScopeAuthoritySnapshot, options.validateSnapshot, now())
  const current = normalizeScopeSnapshot(authority.snapshot, options.validateSnapshot, now())
  if (expected.workspaceId !== workspaceId || expected.controllerPersonId !== authority.controllerPersonId ||
      expected.controllerPublicKey !== authority.controllerPublicKey || expected.controlEpoch !== authority.controlEpoch ||
      canonicalizeJson(expected.snapshot) !== canonicalizeJson(current.snapshot)) {
    throw new Error("Rusty resource principal scope authority is stale")
  }

  const membershipGrant = structuredClone(grant)
  const member = membershipGrant.payload
  if (!idPattern.test(member.grantId) || member.workspaceId !== workspaceId ||
      member.personId !== subjectIdentity.personId || member.personId === identity.personId ||
      !Number.isSafeInteger(member.accessEpoch ?? 1) || (member.accessEpoch ?? 1) < 1) {
    throw new Error("Workspace membership grant does not match the Rusty principal subject")
  }
  const role = verifyGrantInAcceptedControllerHistory(state, membershipGrant, authority.snapshot, workspaceId, subjectIdentity.personId)
  if (role === "automation") throw new Error("Automation grants cannot access Rusty resource storage")
  const actions: Array<"read" | "write"> = role === "visitor" ? ["read"] : ["read", "write"]
  await options.ensureCurrent?.()

  const payload: RustyResourcePrincipalGrant["payload"] = {
    kind: "rusty-resource-principal-grant",
    version: 1,
    serviceId,
    origin,
    workspaceId,
    resourceKind: "scope",
    resourceId: storageScopeId,
    scopeId: storageScopeId,
    ownerPersonId: identity.personId,
    subjectPersonId: subjectIdentity.personId,
    subjectPublicKey: subjectIdentity.publicKey,
    grantId: member.grantId,
    policyEpoch: member.accessEpoch ?? 1,
    readTokenHash: await sha256Base64Url(encoder.encode(readToken)),
    ...(writeToken === undefined ? {} : { writeTokenHash: await sha256Base64Url(encoder.encode(writeToken)) }),
    actions,
    workspaceGrant: membershipGrant,
    scopeAuthority: structuredClone(authority.snapshot),
  }
  const principalGrant = await options.signAuthorization(payload)
  if (!hasExactKeys(principalGrant, ["payload", "signerKeyId", "signature"]) ||
      principalGrant.signerKeyId !== options.deviceId ||
      canonicalizeJson(principalGrant.payload) !== canonicalizeJson(payload) ||
      !await verifyEnvelope(principalGrant, activeKey, "MATCH/1")) {
    throw new Error("Invalid Rusty resource principal grant authorization")
  }
  await options.ensureCurrent?.()

  const response = await (options.fetcher ?? fetch)(
    `${origin}/v2/scopes/${encodeURIComponent(storageScopeId)}/principals/${encodeURIComponent(member.grantId)}`,
    {
      method: "PUT",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ version: 1, grant: principalGrant }),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    },
  )
  if (response.status !== 204) {
    await response.body?.cancel()
    throw new Error(`Rusty resource principal registration failed with HTTP ${response.status}`)
  }
  await options.ensureCurrent?.()
  return { principalGrant, scopeAuthority: current }
}

function normalizeScopeSnapshot(
  snapshot: unknown,
  validateSnapshot: RegisterRustyResourcePrincipalGrantOptions["validateSnapshot"],
  nowMs: number,
): ScopeAuthorityValidation {
  const validated = validateSnapshot(snapshot)
  const normalized = meshRustRuntime().state.mergeScopeAuthoritySnapshots(snapshot, snapshot, nowMs)
  const result = validateSnapshot(normalized)
  if (validated.workspaceId !== result.workspaceId || validated.controllerPersonId !== result.controllerPersonId ||
      validated.controllerPublicKey !== result.controllerPublicKey || validated.controlEpoch !== result.controlEpoch) {
    throw new Error("Rusty resource principal scope snapshot changed while normalizing")
  }
  return result
}

function verifyGrantInAcceptedControllerHistory(
  state: ReturnType<typeof meshRustRuntime>["state"],
  grant: RustyWorkspaceMembershipGrant,
  snapshot: unknown,
  workspaceId: string,
  subjectPersonId: string,
): RustyWorkspaceMembershipGrant["payload"]["role"] {
  const controllers = scopeControllers(snapshot)
  const matches = new Map<string, RustyWorkspaceMembershipGrant["payload"]["role"]>()
  for (const controller of controllers) {
    try {
      const role = state.verifyWorkspaceGrant(grant, workspaceId, subjectPersonId, controller) as RustyWorkspaceMembershipGrant["payload"]["role"]
      matches.set(`${controller.personId}\u0000${controller.publicKey}`, role)
    } catch {
      // A scope snapshot can contain several authenticated controllers; only one must validate this grant.
    }
  }
  if (matches.size !== 1) throw new Error("Workspace membership grant is not uniquely bound to accepted scope history")
  return [...matches.values()][0]!
}

function scopeControllers(snapshot: unknown): Array<{ personId: string; publicKey: string; certificates: unknown[] }> {
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
    throw new Error("Invalid accepted Rusty workspace scope snapshot")
  }
  const value = snapshot as {
    genesis?: { payload?: { creator?: unknown } }
    controlTransfers?: Array<{ payload?: { toController?: unknown } }>
    successionTransfers?: Array<{ claim?: { payload?: unknown } }>
  }
  const candidates: Array<{ personId: string; publicKey: string; certificates: unknown[] }> = []
  const add = (raw: unknown) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return
    const candidate = raw as Record<string, unknown>
    if (typeof candidate.personId !== "string" || typeof candidate.publicKey !== "string" ||
        !Array.isArray(candidate.certificates)) return
    candidates.push({ personId: candidate.personId, publicKey: candidate.publicKey, certificates: candidate.certificates })
  }
  add(value.genesis?.payload?.creator)
  for (const transfer of value.controlTransfers ?? []) add(transfer.payload?.toController)
  for (const transfer of value.successionTransfers ?? []) {
    const claim = transfer.claim?.payload
    if (claim && typeof claim === "object" && !Array.isArray(claim)) {
      const payload = claim as Record<string, unknown>
      add({ personId: payload.toOwnerPersonId, publicKey: payload.toOwnerPublicKey,
        certificates: payload.toOwnerCertificates })
    }
  }
  if (candidates.length === 0) throw new Error("Accepted Rusty scope snapshot has no controller history")
  return candidates
}

function validateToken(value: string, label: string): string {
  if (typeof value !== "string" || decodeBlindBytes(value).byteLength !== 32) {
    throw new Error(`Invalid Rusty resource principal ${label} token`)
  }
  return value
}

function hasExactKeys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key))
}
