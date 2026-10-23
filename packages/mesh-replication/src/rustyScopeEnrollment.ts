import { canonicalizeJson, sha256Base64Url, verifyDeviceCertificateChain, verifyEnvelope,
  type DeviceCertificate, type PublicIdentity, type SignedEnvelope } from "@meta-uber/mesh-identity"
import { verifyRustyManagementCapability, type RustyManagementCapability } from "./rustyManagementCapability"
import { discoverRustyService, type RustyFetch, type RustyServicePin } from "./rustyDiscovery"
import { decodeBlindBytes, rustyOrigin } from "./rustyReplica"

export type RustyScopeEnrollmentAccess = {
  origin: string
  scopeId: string
  servicePublicKey: string
  readToken: string
  writeToken: string
}

export type RustyScopeEnrollmentChallenge = {
  kind: "rusty-enrollment-challenge"
  version: 1
  challengeId: string
  nonce: string
  serviceId: string
  publicOrigin: string
  scopeId: string
  personId: string
  deviceId: string
  deviceKeyId: string
  expectedRevision: number
  issuedAt: number
  expiresAt: number
}

export type RustyScopeEnrollmentAuthorization = {
  kind: "rusty-scope-enrollment"
  version: 1
  challengeId: string
  nonce: string
  serviceId: string
  publicOrigin: string
  scopeId: string
  personId: string
  deviceId: string
  deviceKeyId: string
  expectedRevision: number
  readTokenHash: string
  writeTokenHash: string
  revoked: boolean
  expiresAt: number
  minimumWriterVersion?: 2
  managementRevision?: number
}

export type RustyScopePolicyReceiptPayload = {
  kind: "rusty-scope-policy-receipt"
  version: 1
  serviceId: string
  scopeId: string
  personId: string
  revision: number
  revoked: boolean
  challengeId: string
  authorizationHash: string
  minimumWriterVersion?: 2
}

export type RustyScopePolicyReceipt = SignedEnvelope<RustyScopePolicyReceiptPayload>
export type RustyScopeEnrollmentRequest = {
  challenge: SignedEnvelope<RustyScopeEnrollmentChallenge>
  identity: PublicIdentity
  deviceId: string
  certificates: DeviceCertificate[]
  managementCapability?: SignedEnvelope<RustyManagementCapability>
  readToken: string
  writeToken: string
  revoked: boolean
  authorization: SignedEnvelope<RustyScopeEnrollmentAuthorization>
}

export type RustyScopeEnrollmentBinding = {
  origin: string
  scopeId: string
  servicePublicKey: string
  personId: string
  deviceId: string
  readTokenHash: string
  writeTokenHash: string
  revoked: boolean
  minimumWriterVersion?: 2
}

export type RustyScopeEnrollmentJournal = {
  read(binding: RustyScopeEnrollmentBinding): Promise<{ body: string } | undefined>
  prepare(binding: RustyScopeEnrollmentBinding, body: string, ensureCurrent: () => Promise<void>): Promise<void>
  replace(binding: RustyScopeEnrollmentBinding, previousBody: string, nextBody: string,
    ensureCurrent: () => Promise<void>): Promise<void>
  complete(binding: RustyScopeEnrollmentBinding, body: string, ensureCurrent: () => Promise<void>): Promise<void>
}

export type RustyScopeEnrollmentClientOptions = {
  access: RustyScopeEnrollmentAccess
  identity: PublicIdentity
  deviceId: string
  devicePublicKey: string
  certificates: readonly DeviceCertificate[]
  fetcher?: RustyFetch
  ensureCurrent: () => void | Promise<void>
  getManagementCapability: (service: RustyServicePin) => Promise<SignedEnvelope<RustyManagementCapability> | undefined>
  ensureManagementCurrent: (capability: SignedEnvelope<RustyManagementCapability> | undefined) => void | Promise<void>
  signAuthorization: (payload: RustyScopeEnrollmentAuthorization,
    challenge: SignedEnvelope<RustyScopeEnrollmentChallenge>) => Promise<SignedEnvelope<RustyScopeEnrollmentAuthorization>>
  journal: RustyScopeEnrollmentJournal
  now?: () => number
}

export type RustyScopeEnrollmentOptions = {
  revoked?: boolean
  minimumWriterVersion?: 2
  requireExactRetry?: boolean
  expectedPolicyRevision?: number
  confirmed?: (receipt: RustyScopePolicyReceipt) => void | Promise<void>
}

export type RustyScopeEnrollmentResult = { policyRevision: number; receipt: RustyScopePolicyReceipt }

/** Protocol-only HTTP, signature, retry, and receipt handling for an Identity-owned Rusty scope. */
export function createRustyScopeEnrollmentClient(options: RustyScopeEnrollmentClientOptions) {
  const fetcher = options.fetcher ?? fetch
  const now = options.now ?? Date.now
  const access = Object.freeze({ ...options.access, origin: rustyOrigin(options.access.origin) })
  const identity = structuredClone(options.identity)
  const certificates = structuredClone(options.certificates) as DeviceCertificate[]
  if (!identity.personId || !identity.publicKey || !options.deviceId || !options.devicePublicKey || !certificates.length || certificates.length > 32 ||
    !access.scopeId || !access.servicePublicKey || !access.readToken || !access.writeToken) {
    throw new Error("Invalid Rusty scope enrollment input")
  }

  const ensureCurrent = async (capability?: SignedEnvelope<RustyManagementCapability>) => {
    await options.ensureCurrent()
    await options.ensureManagementCurrent(capability)
  }

  async function discoverAndPin(): Promise<RustyServicePin> {
    await ensureCurrent()
    const service = await discoverRustyService(access.origin, fetcher)
    await ensureCurrent()
    if (service.servicePublicKey !== access.servicePublicKey) throw new Error("Rusty management service pin changed")
    return service
  }

  async function enroll(enrollmentOptions: RustyScopeEnrollmentOptions = {}): Promise<RustyScopeEnrollmentResult> {
    const revoked = enrollmentOptions.revoked ?? false
    const minimumWriterVersion = enrollmentOptions.minimumWriterVersion
    const expectedPolicyRevision = enrollmentOptions.expectedPolicyRevision
    if (minimumWriterVersion !== undefined && minimumWriterVersion !== 2) throw new Error("Unsupported Rusty writer version")
    if (expectedPolicyRevision !== undefined && (!Number.isSafeInteger(expectedPolicyRevision) || expectedPolicyRevision < 0)) {
      throw new Error("Invalid expected scope policy revision")
    }

    await ensureCurrent()
    const service = await discoverAndPin()
    if (minimumWriterVersion === 2 && featureObject(service, "writerPolicy")?.maximumWriterVersion !== 2) {
      throw new Error("Rusty service does not advertise the requested writer policy")
    }
    const managementCapability = await options.getManagementCapability(service)
    await ensureCurrent(managementCapability)
    if (featureFlag(service, "scopeManagement") === 1 && !managementCapability) {
      throw new Error("Current Rusty scope management authority is required")
    }
    if (managementCapability) {
      await verifyRustyManagementCapability(managementCapability, access, {
        personId: identity.personId, deviceId: options.deviceId, resourceKind: "scope", resourceId: access.scopeId,
        operation: "scope.policy", minimumRevision: 1,
      })
      await ensureCurrent(managementCapability)
    }

    const binding: RustyScopeEnrollmentBinding = {
      origin: access.origin, scopeId: access.scopeId, servicePublicKey: access.servicePublicKey,
      personId: identity.personId, deviceId: options.deviceId,
      readTokenHash: await sha256Base64Url(new TextEncoder().encode(access.readToken)),
      writeTokenHash: await sha256Base64Url(new TextEncoder().encode(access.writeToken)), revoked,
      ...(minimumWriterVersion === undefined ? {} : { minimumWriterVersion }),
    }
    const pending = await options.journal.read(binding)
    const supportsRetry = featureFlag(service, "scopeEnrollmentRetry") === 1
    if ((pending || enrollmentOptions.requireExactRetry) && !supportsRetry) {
      throw new Error("Rusty upgrade required for recoverable scope enrollment")
    }

    const initialBody = pending?.body ?? await createRequest({ access, identity, deviceId: options.deviceId, certificates,
      binding, service, managementCapability, signAuthorization: options.signAuthorization, fetcher, now,
      ensureCurrent: () => ensureCurrent(managementCapability) })
    const initialRequest = await verifyRequest(initialBody, { access, identity, deviceId: options.deviceId,
      devicePublicKey: options.devicePublicKey, certificates,
      binding, service, managementCapability, allowExpired: Boolean(pending), now })
    if (expectedPolicyRevision !== undefined && initialRequest.authorization.payload.expectedRevision !== expectedPolicyRevision) {
      throw new Error("Concurrent Rusty scope policy revision changed; original credentials retained for review")
    }
    await ensureCurrent(managementCapability)
    if (supportsRetry) await options.journal.prepare(binding, initialBody, () => ensureCurrent(managementCapability))
    await ensureCurrent(managementCapability)

    let body = initialBody
    let request = initialRequest
    let receipt: RustyScopePolicyReceipt
    try {
      receipt = await submitRequest(access, body, fetcher, () => ensureCurrent(managementCapability))
    } catch (error) {
      if (!pending || !(error instanceof RustyScopeEnrollmentHttpError) || error.status !== 410) throw error
      await ensureCurrent(managementCapability)
      const freshBody = await createRequest({ access, identity, deviceId: options.deviceId, certificates, binding, service,
        managementCapability, signAuthorization: options.signAuthorization, fetcher, now,
        ensureCurrent: () => ensureCurrent(managementCapability) })
      const freshRequest = await verifyRequest(freshBody, { access, identity, deviceId: options.deviceId,
        devicePublicKey: options.devicePublicKey, certificates,
        binding, service, managementCapability, allowExpired: false, now })
      if (freshRequest.challenge.payload.expectedRevision !== request.challenge.payload.expectedRevision ||
        freshRequest.challenge.payload.issuedAt < request.challenge.payload.expiresAt) {
        throw new Error("Rusty enrollment outcome is unresolved; original request retained for recovery", { cause: error })
      }
      await ensureCurrent(managementCapability)
      await options.journal.replace(binding, body, freshBody, () => ensureCurrent(managementCapability))
      await ensureCurrent(managementCapability)
      body = freshBody
      request = freshRequest
      receipt = await submitRequest(access, body, fetcher, () => ensureCurrent(managementCapability))
    }

    await verifyServiceEnvelope(receipt, access, service.serviceId)
    await ensureCurrent(managementCapability)
    const authorizationHash = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(request.authorization)))
    if (!receiptCoversEnrollment(receipt.payload, { serviceId: service.serviceId, scopeId: access.scopeId,
      personId: identity.personId, revision: request.authorization.payload.expectedRevision, revoked,
      challengeId: request.authorization.payload.challengeId, authorizationHash, minimumWriterVersion })) {
      throw new Error("Rusty receipt does not cover this connection")
    }
    await ensureCurrent(managementCapability)
    await enrollmentOptions.confirmed?.(structuredClone(receipt))
    await ensureCurrent(managementCapability)
    if (supportsRetry) await options.journal.complete(binding, body, () => ensureCurrent(managementCapability))
    return { policyRevision: receipt.payload.revision, receipt: structuredClone(receipt) }
  }

  return { enroll }
}

export class RustyScopeEnrollmentHttpError extends Error {
  constructor(readonly status: number, message: string) { super(message); this.name = "RustyScopeEnrollmentHttpError" }
}

async function createRequest(input: {
  access: RustyScopeEnrollmentAccess
  identity: PublicIdentity
  deviceId: string
  certificates: DeviceCertificate[]
  binding: RustyScopeEnrollmentBinding
  service: RustyServicePin
  managementCapability?: SignedEnvelope<RustyManagementCapability>
  signAuthorization: RustyScopeEnrollmentClientOptions["signAuthorization"]
  fetcher: RustyFetch
  now: () => number
  ensureCurrent: () => Promise<void>
}): Promise<string> {
  const { access, identity, deviceId, certificates, binding, service, managementCapability, fetcher } = input
  const optionalManagement = managementCapability ? { managementCapability } : {}
  await input.ensureCurrent()
  const response = await fetcher(`${access.origin}/v2/enrollment/challenge`, {
    method: "POST", signal: AbortSignal.timeout(15_000), headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ version: 1, scopeId: access.scopeId, identity, deviceId, certificates, ...optionalManagement }),
  })
  await input.ensureCurrent()
  const { challenge } = await readJson<{ challenge: SignedEnvelope<RustyScopeEnrollmentChallenge> }>(response, 65_536)
  await verifyServiceEnvelope(challenge, access, service.serviceId)
  validateChallenge(challenge.payload, access, identity, deviceId, service.serviceId, input.now())
  const payload: RustyScopeEnrollmentAuthorization = {
    kind: "rusty-scope-enrollment", version: 1, challengeId: challenge.payload.challengeId,
    nonce: challenge.payload.nonce, serviceId: service.serviceId, publicOrigin: binding.origin,
    scopeId: binding.scopeId, personId: binding.personId, deviceId, deviceKeyId: deviceId,
    expectedRevision: challenge.payload.expectedRevision, readTokenHash: binding.readTokenHash,
    writeTokenHash: binding.writeTokenHash, revoked: binding.revoked, expiresAt: challenge.payload.expiresAt,
    ...(binding.minimumWriterVersion === undefined ? {} : { minimumWriterVersion: binding.minimumWriterVersion }),
    ...(managementCapability ? { managementRevision: managementCapability.payload.revision } : {}),
  }
  await input.ensureCurrent()
  const authorization = await input.signAuthorization(payload, challenge)
  await input.ensureCurrent()
  const body: RustyScopeEnrollmentRequest = { challenge, identity, deviceId, certificates, ...optionalManagement,
    readToken: access.readToken, writeToken: access.writeToken, revoked: binding.revoked, authorization }
  return JSON.stringify(body)
}

async function verifyRequest(body: string, expected: {
  access: RustyScopeEnrollmentAccess
  identity: PublicIdentity
  deviceId: string
  devicePublicKey: string
  certificates: DeviceCertificate[]
  binding: RustyScopeEnrollmentBinding
  service: RustyServicePin
  managementCapability?: SignedEnvelope<RustyManagementCapability>
  allowExpired: boolean
  now: () => number
}): Promise<RustyScopeEnrollmentRequest> {
  if (new TextEncoder().encode(body).byteLength > 65_536) throw new Error("Saved Rusty enrollment request is too large")
  const request = JSON.parse(body) as RustyScopeEnrollmentRequest
  exactKeys(request, ["challenge", "identity", "deviceId", "certificates", "readToken", "writeToken", "revoked", "authorization"], ["managementCapability"])
  exactKeys(request.authorization, ["payload", "signerKeyId", "signature"])
  exactKeys(request.challenge, ["payload", "signerKeyId", "signature"])
  if (request.identity.personId !== expected.identity.personId || request.identity.publicKey !== expected.identity.publicKey ||
    request.identity.displayName !== expected.identity.displayName || request.deviceId !== expected.deviceId ||
    canonicalizeJson(request.certificates) !== canonicalizeJson(expected.certificates) ||
    request.readToken !== expected.access.readToken || request.writeToken !== expected.access.writeToken ||
    request.revoked !== expected.binding.revoked ||
    canonicalizeJson(request.managementCapability ?? null) !== canonicalizeJson(expected.managementCapability ?? null)) {
    throw new Error("Saved Rusty enrollment request no longer matches this connection or authority")
  }
  await verifyServiceEnvelope(request.challenge, expected.access, expected.service.serviceId)
  validateChallenge(request.challenge.payload, expected.access, expected.identity, expected.deviceId,
    expected.service.serviceId, expected.now(), expected.allowExpired)
  const authorization = request.authorization.payload
  exactKeys(authorization, ["kind", "version", "challengeId", "nonce", "serviceId", "publicOrigin", "scopeId", "personId", "deviceId",
    "deviceKeyId", "expectedRevision", "readTokenHash", "writeTokenHash", "revoked", "expiresAt"], ["minimumWriterVersion", "managementRevision"])
  const challenge = request.challenge.payload
  const expectedAuthorization: RustyScopeEnrollmentAuthorization = {
    kind: "rusty-scope-enrollment", version: 1, challengeId: challenge.challengeId, nonce: challenge.nonce,
    serviceId: expected.service.serviceId, publicOrigin: expected.binding.origin, scopeId: expected.binding.scopeId,
    personId: expected.binding.personId, deviceId: expected.binding.deviceId, deviceKeyId: expected.binding.deviceId,
    expectedRevision: challenge.expectedRevision, readTokenHash: expected.binding.readTokenHash,
    writeTokenHash: expected.binding.writeTokenHash, revoked: expected.binding.revoked, expiresAt: challenge.expiresAt,
    ...(expected.binding.minimumWriterVersion === undefined ? {} : { minimumWriterVersion: expected.binding.minimumWriterVersion }),
    ...(expected.managementCapability ? { managementRevision: expected.managementCapability.payload.revision } : {}),
  }
  if (request.authorization.signerKeyId !== expected.deviceId ||
    canonicalizeJson(authorization) !== canonicalizeJson(expectedAuthorization)) {
    throw new Error("Saved Rusty enrollment authorization binding invalid")
  }
  const publicKey = await verifyDeviceCertificateChain(request.identity, request.deviceId, request.certificates, "MATCH/1")
  if (publicKey !== expected.devicePublicKey || !await verifyEnvelope(request.authorization, publicKey)) {
    throw new Error("Saved Rusty enrollment authorization signature invalid")
  }
  return request
}

function validateChallenge(payload: RustyScopeEnrollmentChallenge, access: RustyScopeEnrollmentAccess,
  identity: PublicIdentity, deviceId: string, serviceId: string, now: number, allowExpired = false): void {
  const validTiming = Number.isSafeInteger(payload.expectedRevision) && payload.expectedRevision >= 0 &&
    payload.expectedRevision < Number.MAX_SAFE_INTEGER && Number.isSafeInteger(payload.issuedAt) &&
    Number.isSafeInteger(payload.expiresAt) && payload.issuedAt >= 0 && payload.issuedAt <= now + 5_000 &&
    (allowExpired || payload.expiresAt > now) && payload.expiresAt - payload.issuedAt <= 120_000 && payload.expiresAt > payload.issuedAt
  if (payload.kind !== "rusty-enrollment-challenge" || payload.version !== 1 || payload.serviceId !== serviceId ||
    payload.publicOrigin !== access.origin || payload.scopeId !== access.scopeId || payload.personId !== identity.personId ||
    payload.deviceId !== deviceId || payload.deviceKeyId !== deviceId || !payload.challengeId || !payload.nonce || !validTiming) {
    throw new Error("Rusty challenge does not cover this connection")
  }
}

async function verifyServiceEnvelope<T extends { kind: string }>(value: SignedEnvelope<T>, access: RustyScopeEnrollmentAccess, serviceId: string): Promise<void> {
  const key = decodeBlindBytes(access.servicePublicKey)
  if (key.byteLength !== 32 || value?.signerKeyId !== serviceId || serviceId !== await sha256Base64Url(key) ||
    !await verifyEnvelope(value, access.servicePublicKey, "RUSTY/2")) throw new Error("Rusty signature invalid")
}

async function submitRequest(access: RustyScopeEnrollmentAccess, body: string, fetcher: RustyFetch,
  ensureCurrent: () => Promise<void>): Promise<RustyScopePolicyReceipt> {
  await ensureCurrent()
  const response = await fetcher(`${access.origin}/v2/scopes/${access.scopeId}`, {
    method: "PUT", signal: AbortSignal.timeout(15_000), headers: { "Content-Type": "application/json" }, body,
  })
  await ensureCurrent()
  const { receipt } = await readJson<{ receipt: RustyScopePolicyReceipt }>(response, 65_536)
  await ensureCurrent()
  return receipt
}

async function readJson<T>(response: Response, maximumBytes: number): Promise<T> {
  if (!response.ok) {
    await response.body?.cancel()
    throw new RustyScopeEnrollmentHttpError(response.status, `Rusty request failed with HTTP ${response.status}`)
  }
  const contentLength = response.headers.get("content-length")
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) > maximumBytes)) {
    await response.body?.cancel()
    throw new Error("Rusty response is too large")
  }
  const text = await readBoundedText(response, maximumBytes)
  try { return JSON.parse(text) as T } catch { throw new Error("Invalid Rusty response") }
}

async function readBoundedText(response: Response, maximumBytes: number): Promise<string> {
  if (!response.body) return ""
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > maximumBytes) { await reader.cancel(); throw new Error("Rusty response is too large") }
      chunks.push(value)
    }
  } finally { reader.releaseLock() }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes) }
  catch { throw new Error("Invalid Rusty response") }
}

function receiptCoversEnrollment(receipt: RustyScopePolicyReceiptPayload, expected: {
  serviceId: string; scopeId: string; personId: string; revision: number; revoked: boolean; challengeId: string;
  authorizationHash: string; minimumWriterVersion?: 2
}): boolean {
  const revisionMatches = receipt.revision === expected.revision + 1 ||
    (expected.minimumWriterVersion === 2 && receipt.revision === expected.revision)
  const writerVersionMatches = expected.minimumWriterVersion === 2
    ? receipt.minimumWriterVersion === 2
    : !Object.hasOwn(receipt, "minimumWriterVersion") || receipt.minimumWriterVersion === 2
  return receipt.kind === "rusty-scope-policy-receipt" && receipt.version === 1 && receipt.serviceId === expected.serviceId &&
    receipt.scopeId === expected.scopeId && receipt.personId === expected.personId && revisionMatches &&
    receipt.revoked === expected.revoked && receipt.challengeId === expected.challengeId &&
    receipt.authorizationHash === expected.authorizationHash && writerVersionMatches
}

function exactKeys(value: unknown, required: string[], optional: string[] = []): asserts value is Record<string, any> {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
    required.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) {
    throw new Error("Invalid saved Rusty enrollment request fields")
  }
}

function featureObject(service: RustyServicePin, name: string): Record<string, unknown> | undefined {
  const value = service.capabilities[name]
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined
}

function featureFlag(service: RustyServicePin, name: string): number | undefined {
  const value = service.capabilities[name]
  if (value === 1) return 1
  if (value && typeof value === "object" && !Array.isArray(value) &&
    (value as Record<string, unknown>).version === 1 && Object.keys(value).length === 1) return 1
  return undefined
}
