import { canonicalizeJson, sha256Base64Url, verifyDeviceCertificateChain, verifyEnvelope,
  type DeviceCertificate, type PublicIdentity, type SignedEnvelope } from "@meta-uber/mesh-identity"
import { verifyRustyManagementCapability, verifyRustyManagementEvidence,
  type RustyManagementCapability } from "./rustyManagementCapability"
import type { RustyFetch } from "./rustyDiscovery"
import { decodeBlindBytes, rustyOrigin } from "./rustyReplica"

export type RustyManagementMutationBinding = {
  origin: string
  servicePublicKey: string
  resourceKind: "person" | "scope" | "board"
  resourceId: string
}

export type RustyManagementUpdateAuthorization = {
  kind: "rusty-management-policy-update"
  version: 1
  serviceId: string
  origin: string
  personId: string
  deviceId: string
  resourceKind: RustyManagementMutationBinding["resourceKind"]
  resourceId: string
  expectedRevision: number
  operations: string[]
  revokedDeviceIds: string[]
  requestId: string
  issuedAt: number
  expiresAt: number
  personManagementRevision?: number
  restoredDeviceIds?: string[]
}

export type RustyManagementUpdateRequest = {
  version: 1
  identity: PublicIdentity
  deviceId: string
  certificates: DeviceCertificate[]
  managementCapability?: SignedEnvelope<RustyManagementCapability>
  personManagementCapability?: SignedEnvelope<RustyManagementCapability>
  authorization: SignedEnvelope<RustyManagementUpdateAuthorization>
}

export type RustyManagementUpdatePolicy = {
  operations: string[]
  revokedDeviceIds: string[]
  restoredDeviceIds?: string[]
}

export type RustyManagementMutationJournal = {
  read(binding: RustyManagementMutationBinding): Promise<{ body: string } | undefined>
  prepare(binding: RustyManagementMutationBinding, request: RustyManagementUpdateRequest,
    ensureCurrent: () => Promise<void>): Promise<void>
  complete(binding: RustyManagementMutationBinding, request: RustyManagementUpdateRequest,
    capability: SignedEnvelope<RustyManagementCapability>, ensureCurrent: () => Promise<void>): Promise<void>
}

export type RustyManagementMutationClientOptions = {
  binding: RustyManagementMutationBinding
  identity: PublicIdentity
  deviceId: string
  devicePublicKey: string
  certificates: readonly DeviceCertificate[]
  fetcher?: RustyFetch
  ensureCurrent: () => void | Promise<void>
  getCapability: () => Promise<SignedEnvelope<RustyManagementCapability> | undefined>
  getParentCapability: () => Promise<SignedEnvelope<RustyManagementCapability> | undefined>
  allowUnparentedScopeCreation?: boolean
  ensureAuthorityCurrent: (input: { binding: RustyManagementMutationBinding
    capability?: SignedEnvelope<RustyManagementCapability>; parentCapability?: SignedEnvelope<RustyManagementCapability> }) => void | Promise<void>
  signAuthorization: (payload: RustyManagementUpdateAuthorization) => Promise<SignedEnvelope<RustyManagementUpdateAuthorization>>
  journal: RustyManagementMutationJournal
  now?: () => number
}

const allowedOperations = {
  person: ["management.update", "resource.create"],
  scope: ["management.update", "scope.policy", "snapshot.checkpoint"],
  board: ["management.update", "publication.status", "publication.publish", "publication.update", "publication.unpublish", "publication.stage-file"],
} satisfies Record<RustyManagementMutationBinding["resourceKind"], string[]>

/** Shared signed management mutation protocol; identity state and key custody remain with the caller. */
export function createRustyManagementMutationClient(options: RustyManagementMutationClientOptions) {
  const fetcher = options.fetcher ?? fetch
  const now = options.now ?? Date.now
  const binding = structuredClone(options.binding)
  binding.origin = rustyOrigin(binding.origin)
  const identity = structuredClone(options.identity)
  const certificates = structuredClone(options.certificates) as DeviceCertificate[]
  if (!validId(identity.personId) || !identity.publicKey || !validId(options.deviceId) || !options.devicePublicKey ||
    !validId(binding.resourceId) || !validResourceKind(binding.resourceKind) || !decodeKey(binding.servicePublicKey) ||
    !certificates.length || certificates.length > 32 || (binding.resourceKind === "person" && binding.resourceId !== identity.personId)) {
    throw new Error("Invalid Rusty management mutation input")
  }

  async function currentAuthority() {
    await options.ensureCurrent()
    const capability = await options.getCapability()
    const parentCapability = binding.resourceKind === "person" ? undefined : await options.getParentCapability()
    await options.ensureAuthorityCurrent({ binding, capability, parentCapability })
    await options.ensureCurrent()
    const access = { origin: binding.origin, servicePublicKey: binding.servicePublicKey }
    if (capability) await verifyRustyManagementCapability(capability, access, { personId: identity.personId,
      deviceId: options.deviceId, resourceKind: binding.resourceKind, resourceId: binding.resourceId,
      operation: "management.update", minimumRevision: capability.payload.revision })
    if (parentCapability) await verifyRustyManagementCapability(parentCapability,
      access,
      { personId: identity.personId, deviceId: options.deviceId, resourceKind: "person", resourceId: identity.personId,
        operation: "resource.create", minimumRevision: parentCapability.payload.revision })
    return { capability, parentCapability }
  }

  async function update(policyValue: RustyManagementUpdatePolicy): Promise<SignedEnvelope<RustyManagementCapability>> {
    const policy = snapshotPolicy(policyValue, binding.resourceKind)
    const pending = await options.journal.read(binding)
    if (pending) throw new Error("A Rusty management request is pending; retry or review it first")
    const { capability, parentCapability } = await currentAuthority()
    if (!capability && binding.resourceKind !== "person" && !parentCapability && !options.allowUnparentedScopeCreation) {
      throw new Error("Person resource.create capability is required before creating a Rusty scope policy")
    }
    const issuedAt = now()
    const authorizationPayload: RustyManagementUpdateAuthorization = {
      kind: "rusty-management-policy-update", version: 1,
      serviceId: await sha256Base64Url(decodeBlindBytes(binding.servicePublicKey)), origin: binding.origin,
      personId: identity.personId, deviceId: options.deviceId, resourceKind: binding.resourceKind,
      resourceId: binding.resourceId, expectedRevision: capability?.payload.revision ?? 0,
      ...policy, requestId: crypto.randomUUID(), issuedAt, expiresAt: issuedAt + 120_000,
      ...(parentCapability ? { personManagementRevision: parentCapability.payload.revision } : {}),
    }
    await ensureCurrent(capability, parentCapability)
    const authorization = await options.signAuthorization(authorizationPayload)
    await ensureCurrent(capability, parentCapability)
    const request: RustyManagementUpdateRequest = {
      version: 1, identity, deviceId: options.deviceId, certificates,
      ...(capability ? { managementCapability: capability } : {}),
      ...(parentCapability ? { personManagementCapability: parentCapability } : {}), authorization,
    }
    const body = canonicalizeJson(request)
    await verifyRequest(request, body, { binding, identity, deviceId: options.deviceId, devicePublicKey: options.devicePublicKey,
      certificates, capability, parentCapability, allowUnparentedScopeCreation: options.allowUnparentedScopeCreation,
      now, allowExpired: false })
    await ensureCurrent(capability, parentCapability)
    await options.journal.prepare(binding, structuredClone(request), () => ensureCurrent(capability, parentCapability))
    return send(binding, request, body, capability, parentCapability)
  }

  async function retry(): Promise<SignedEnvelope<RustyManagementCapability>> {
    const pending = await options.journal.read(binding)
    if (!pending) throw new Error("No Rusty management request is pending")
    if (new TextEncoder().encode(pending.body).byteLength > 1_048_576) throw new Error("Pending Rusty management request is too large")
    let request: RustyManagementUpdateRequest
    try { request = JSON.parse(pending.body) as RustyManagementUpdateRequest }
    catch { throw new Error("Pending Rusty management request is malformed") }
    const { capability, parentCapability } = await currentAuthority()
    await verifyRequest(request, pending.body, { binding, identity, deviceId: options.deviceId, devicePublicKey: options.devicePublicKey,
      certificates, capability, parentCapability, allowUnparentedScopeCreation: options.allowUnparentedScopeCreation,
      now, allowExpired: true })
    await ensureCurrent(capability, parentCapability)
    return send(binding, request, pending.body, capability, parentCapability)
  }

  async function ensureCurrent(capability?: SignedEnvelope<RustyManagementCapability>, parentCapability?: SignedEnvelope<RustyManagementCapability>) {
    await options.ensureCurrent()
    await options.ensureAuthorityCurrent({ binding, capability, parentCapability })
  }

  async function send(bodyBinding: RustyManagementMutationBinding, request: RustyManagementUpdateRequest, body: string,
    capability?: SignedEnvelope<RustyManagementCapability>, parentCapability?: SignedEnvelope<RustyManagementCapability>) {
    await ensureCurrent(capability, parentCapability)
    const response = await fetcher(`${bodyBinding.origin}/v2/management/${bodyBinding.resourceKind}/${bodyBinding.resourceId}`, {
      method: "PUT", signal: AbortSignal.timeout(30_000), headers: { "Content-Type": "application/json" }, body,
    })
    await ensureCurrent(capability, parentCapability)
    const parsed = await readJson<{ capability: SignedEnvelope<RustyManagementCapability> }>(response)
    if (!parsed || Object.keys(parsed).length !== 1 || !parsed.capability) throw new Error("Invalid Rusty management update response")
    const expectedRevision = request.authorization.payload.expectedRevision
    const confirmed = await verifyRustyManagementEvidence(parsed.capability, bodyBinding, {
      personId: identity.personId, resourceKind: bodyBinding.resourceKind, resourceId: bodyBinding.resourceId,
      minimumRevision: expectedRevision + 1,
    })
    await verifyConfirmation(confirmed, request)
    await ensureCurrent(capability, parentCapability)
    await options.journal.complete(bodyBinding, structuredClone(request), structuredClone(parsed.capability),
      () => ensureCurrent(capability, parentCapability))
    return structuredClone(parsed.capability)
  }

  return { update, retry }
}

export async function verifyRustyManagementUpdateRequest(value: unknown, binding: RustyManagementMutationBinding,
  identity: PublicIdentity, deviceId: string, devicePublicKey: string, certificates: readonly DeviceCertificate[],
  capability?: SignedEnvelope<RustyManagementCapability>, parentCapability?: SignedEnvelope<RustyManagementCapability>): Promise<RustyManagementUpdateRequest> {
  const request = structuredClone(value) as RustyManagementUpdateRequest
  const body = JSON.stringify(request)
  await verifyRequest(request, body, { binding, identity, deviceId, devicePublicKey, certificates: [...certificates], capability,
    parentCapability, now: Date.now, allowExpired: true })
  return request
}

async function verifyRequest(request: RustyManagementUpdateRequest, body: string, expected: {
  binding: RustyManagementMutationBinding; identity: PublicIdentity; deviceId: string; devicePublicKey: string;
  certificates: DeviceCertificate[]; capability?: SignedEnvelope<RustyManagementCapability>;
  parentCapability?: SignedEnvelope<RustyManagementCapability>; allowUnparentedScopeCreation?: boolean;
  now: () => number; allowExpired: boolean
}): Promise<void> {
  exactKeys(request, ["version", "identity", "deviceId", "certificates", "authorization"], ["managementCapability", "personManagementCapability"])
  exactKeys(request.identity, ["personId", "publicKey", "displayName"])
  exactKeys(request.authorization, ["payload", "signerKeyId", "signature"])
  if (request.version !== 1 || canonicalizeJson(request.identity) !== canonicalizeJson(expected.identity) ||
    request.deviceId !== expected.deviceId || canonicalizeJson(request.certificates) !== canonicalizeJson(expected.certificates) ||
    canonicalizeJson(request.managementCapability ?? null) !== canonicalizeJson(expected.capability ?? null) ||
    canonicalizeJson(request.personManagementCapability ?? null) !== canonicalizeJson(expected.parentCapability ?? null) ||
    new TextEncoder().encode(body).byteLength > 1_048_576) throw new Error("Rusty management request authority changed")
  const authorization = request.authorization.payload
  exactKeys(authorization, ["kind", "version", "serviceId", "origin", "personId", "deviceId", "resourceKind", "resourceId",
    "expectedRevision", "operations", "revokedDeviceIds", "requestId", "issuedAt", "expiresAt"], ["personManagementRevision", "restoredDeviceIds"])
  const expectedRevision = expected.capability?.payload.revision ?? 0
  const expectedPayload = authorization as RustyManagementUpdateAuthorization
  if (expectedPayload.kind !== "rusty-management-policy-update" || expectedPayload.version !== 1 ||
    expectedPayload.serviceId !== await sha256Base64Url(decodeBlindBytes(expected.binding.servicePublicKey)) ||
    expectedPayload.origin !== expected.binding.origin || expectedPayload.personId !== expected.identity.personId ||
    expectedPayload.deviceId !== expected.deviceId || expectedPayload.resourceKind !== expected.binding.resourceKind ||
    expectedPayload.resourceId !== expected.binding.resourceId || expectedPayload.expectedRevision !== expectedRevision ||
    expectedPayload.personManagementRevision !== expected.parentCapability?.payload.revision ||
    !validId(expectedPayload.requestId) || !Number.isSafeInteger(expectedPayload.issuedAt) ||
    !Number.isSafeInteger(expectedPayload.expiresAt) || expectedPayload.expiresAt - expectedPayload.issuedAt !== 120_000 ||
    expectedPayload.issuedAt > expected.now() + 30_000 || (!expected.allowExpired && expectedPayload.expiresAt <= expected.now())) {
    throw new Error("Invalid Rusty management request binding or lifetime")
  }
  if (request.authorization.signerKeyId !== expected.deviceId ||
    !await verifyEnvelope(request.authorization, expected.devicePublicKey)) throw new Error("Rusty management request signature invalid")
  const publicKey = await verifyDeviceCertificateChain(request.identity, request.deviceId, request.certificates, "MATCH/1")
  if (publicKey !== expected.devicePublicKey) throw new Error("Rusty management request device certificate mismatch")
  validatePolicy(expectedPayload)
  if (expected.binding.resourceKind === "person") {
    if (expected.parentCapability || expectedPayload.personManagementRevision !== undefined) throw new Error("Person management policy cannot use a parent capability")
  } else if (!expected.capability) {
    if (!expected.parentCapability && expected.allowUnparentedScopeCreation) return
    if (!expected.parentCapability || expectedPayload.personManagementRevision !== expected.parentCapability.payload.revision ||
      !expected.parentCapability.payload.operations.includes("resource.create")) {
      throw new Error("Person resource.create capability is required before creating a Rusty scope policy")
    }
    await verifyRustyManagementCapability(expected.parentCapability, {
      origin: expected.binding.origin, servicePublicKey: expected.binding.servicePublicKey,
    }, { personId: expected.identity.personId, deviceId: expected.deviceId, resourceKind: "person",
      resourceId: expected.identity.personId, operation: "resource.create", minimumRevision: expected.parentCapability.payload.revision })
  }
}

async function verifyConfirmation(capability: RustyManagementCapability, request: RustyManagementUpdateRequest): Promise<void> {
  const authorization = request.authorization.payload
  if (capability.revision !== authorization.expectedRevision + 1 || capability.requestId !== authorization.requestId ||
    capability.authorizationHash !== await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(request.authorization))) ||
    canonicalizeJson(capability.operations) !== canonicalizeJson(authorization.operations) ||
    canonicalizeJson(capability.revokedDeviceIds) !== canonicalizeJson(authorization.revokedDeviceIds) ||
    canonicalizeJson(capability.restoredDeviceIds ?? []) !== canonicalizeJson(authorization.restoredDeviceIds ?? [])) {
    throw new Error("Rusty management response does not cover pending request intent")
  }
}

function snapshotPolicy(value: RustyManagementUpdatePolicy, resourceKind: RustyManagementMutationBinding["resourceKind"]): RustyManagementUpdatePolicy {
  const policy = structuredClone(value)
  if (!policy || !Array.isArray(policy.operations) || !Array.isArray(policy.revokedDeviceIds) ||
    (policy.restoredDeviceIds !== undefined && !Array.isArray(policy.restoredDeviceIds))) throw new Error("Invalid Rusty management policy")
  policy.operations.sort()
  policy.revokedDeviceIds.sort()
  policy.restoredDeviceIds?.sort()
  const allowed = allowedOperations[resourceKind]
  if (!policy.operations.length || !policy.operations.includes("management.update") ||
    policy.operations.some((operation, index) => !allowed.includes(operation) || (index > 0 && policy.operations[index - 1]! >= operation)) ||
    policy.revokedDeviceIds.some((id, index) => !validId(id) || (index > 0 && policy.revokedDeviceIds[index - 1]! >= id)) ||
    (policy.restoredDeviceIds?.some((id, index) => !validId(id) || (index > 0 && policy.restoredDeviceIds![index - 1]! >= id)) ?? false) ||
    policy.revokedDeviceIds.length > 4096 || (policy.restoredDeviceIds?.length ?? 0) > 4096) {
    throw new Error("Invalid Rusty management policy rights")
  }
  if (policy.restoredDeviceIds?.length) throw new Error("Device restoration requires an application-specific restoration flow")
  return policy
}

function validatePolicy(value: RustyManagementUpdateAuthorization): void {
  const allowed = allowedOperations[value.resourceKind]
  const ordered = (values: unknown[], maximum: number) => values.length <= maximum && values.every((entry, index) =>
    typeof entry === "string" && (index === 0 || (values[index - 1] as string) < entry))
  if (!ordered(value.operations, allowed.length) || !value.operations.includes("management.update") ||
    value.operations.some(operation => !allowed.includes(operation)) || !ordered(value.revokedDeviceIds, 4096) ||
    value.revokedDeviceIds.some(id => !validId(id)) ||
    (value.restoredDeviceIds !== undefined && (!ordered(value.restoredDeviceIds, 4096) || value.restoredDeviceIds.some(id => !validId(id))))) {
    throw new Error("Invalid Rusty management policy rights")
  }
}

async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    await response.body?.cancel()
    throw new RustyManagementMutationHttpError(response.status, `Rusty management request failed with HTTP ${response.status}`)
  }
  const maximumBytes = 1_048_576
  const size = response.headers.get("content-length")
  if (size !== null && (!/^\d+$/.test(size) || Number(size) > maximumBytes)) {
    await response.body?.cancel()
    throw new Error("Rusty management response is too large")
  }
  const reader = response.body?.getReader()
  if (!reader) throw new Error("Rusty management response is empty")
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > maximumBytes) { await reader.cancel(); throw new Error("Rusty management response is too large") }
      chunks.push(value)
    }
  } finally { reader.releaseLock() }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as T }
  catch { throw new Error("Invalid Rusty management response") }
}

export class RustyManagementMutationHttpError extends Error {
  constructor(readonly status: number, message: string) { super(message); this.name = "RustyManagementMutationHttpError" }
}

function exactKeys(value: unknown, required: string[], optional: string[] = []): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || required.some(key => !Object.hasOwn(value, key)) ||
    Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) throw new Error("Invalid Rusty management request fields")
}

function decodeKey(value: string): boolean {
  try { return decodeBlindBytes(value).byteLength === 32 } catch { return false }
}

function validId(value: unknown): value is string { return typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value) }
function validResourceKind(value: unknown): value is RustyManagementMutationBinding["resourceKind"] {
  return value === "person" || value === "scope" || value === "board"
}
