import { authorizeIdentityDataDevice, authorizeIdentityDevice, canonicalizeJson, fromBase64Url,
  identityProfileRustyServicePins, normalizeIdentityRustyServicePins, publicKeyId, readIdentityProfileStateWithRevocations,
  sealIdentityCatalogAccessForManager, sha256Base64Url, signEnvelope,
  verifyEnvelope, verifyIdentityAuthorityView, verifyIdentityDeviceAuthority,
  verifyRetainedDeviceAuthorizationApproval,
  type DeviceAuthorizationApproval, type DeviceAuthorizationRequest, type IdentityAuthorityView,
  type IdentityProfileState, type LocalProfile, type SignedEnvelope,
  type VerifiedIdentityCatalogAccessGrant, type RustyIdentityCatalogAccessPublicationPayload } from "@meta-uber/mesh-identity"
import { verifyAndOpenRustyIdentityCatalogAccessPublication } from "@meta-uber/mesh-identity"
import { discoverRustyService, type RustyFetch } from "./rustyDiscovery"
import { rustyOrigin } from "./rustyReplica"

const encoder = new TextEncoder()
const maxEntries = 8
const maxResponseBytes = 384 * 1024
const maxCiphertextBytes = 48 * 1024
const maxPublishedCiphertextBytes = 16 * 1024
const maxPublishedCiphertextTotal = 64 * 1024
const publishDomain = "MESH-IDENTITY-CATALOG-ACCESS-PUBLISH/1"
const requestDomain = "MESH-IDENTITY-CATALOG-ACCESS-REQUEST/1"

export type RustyIdentityCatalogAccessPublication = SignedEnvelope<RustyIdentityCatalogAccessPublicationPayload>

export type RustyIdentityCatalogAccessPublishReceipt = SignedEnvelope<{
  kind: "rusty-identity-catalog-access-publish-receipt"
  version: 1
  serviceId: string
  origin: string
  publisherDeviceId: string
  personId: string
  applicationOrigin: string
  catalogId: string
  sourceRevision: number
  recipientDeviceId: string
  recipientPublicKeyId: string
  envelopeHash: string
  issuedAt: number
}>

export type RustyIdentityCatalogAccessRequestPayload = {
  kind: "mesh-identity-catalog-access-list-request"
  version: 1
  serviceId: string
  personId: string
  applicationOrigin: string
  recipientDeviceId: string
  recipientPublicKeyId: string
  recipientPublicKey: string
  challenge: string
  issuedAt: number
  expiresAt: number
}

export type RustyIdentityCatalogAccessRequest = SignedEnvelope<RustyIdentityCatalogAccessRequestPayload>

export type RustyIdentityCatalogAccessListReceipt = SignedEnvelope<{
  kind: "rusty-identity-catalog-access-list-receipt"
  version: 1
  serviceId: string
  origin: string
  requestHash: string
  personId: string
  applicationOrigin: string
  recipientDeviceId: string
  recipientPublicKeyId: string
  challenge: string
  envelopeCount: number
  envelopeListHash: string
  issuedAt: number
  expiresAt: number
}>

export type IdentityCatalogAccessPublicationJournalKey = {
  serviceId: string
  personId: string
  applicationOrigin: string
  catalogId: string
  recipientDeviceId: string
  recipientPublicKeyId: string
}

export type IdentityCatalogAccessPublicationJournalEntry = {
  version: number
  sourceRevision: number
  contentHash: string
  state: "pending" | "published"
  envelope?: RustyIdentityCatalogAccessPublication
  receipt?: RustyIdentityCatalogAccessPublishReceipt
}

/** Caller persists these opaque records atomically; SDK owns all state transitions and retry ordering. */
export type IdentityCatalogAccessPublicationJournal = {
  read(key: string): Promise<IdentityCatalogAccessPublicationJournalEntry | null>
  compareAndSet(
    key: string,
    expectedVersion: number | null,
    next: IdentityCatalogAccessPublicationJournalEntry,
  ): Promise<boolean>
}

export type PublishRustyIdentityCatalogAccessOptions = {
  origin: string
  servicePublicKey: string
  publisher: LocalProfile
  currentAuthorityView: IdentityAuthorityView
  retainedAuthorization: DeviceAuthorizationApproval
  applicationOrigin: string
  catalogId: string
  access: Uint8Array
  journal: IdentityCatalogAccessPublicationJournal
  ensureCurrent?: () => void | Promise<void>
  fetcher?: RustyFetch
  now?: () => number
}

export type RequestRustyIdentityCatalogAccessOptions = {
  manager: LocalProfile
  currentAuthorityView: IdentityAuthorityView
  profileState: IdentityProfileState
  applicationOrigin: string
  fetcher?: RustyFetch
  now?: () => number
  ensureCurrent?: () => void | Promise<void>
}

/** Publish current opaque access to each active Identity manager, reusing exact journaled envelopes after interruption. */
export async function publishRustyIdentityCatalogAccess(
  options: PublishRustyIdentityCatalogAccessOptions,
): Promise<RustyIdentityCatalogAccessPublishReceipt[]> {
  const fetcher = options.fetcher ?? fetch
  const now = options.now ?? Date.now
  const origin = rustyOrigin(options.origin)
  const discovery = await discoverRustyService(origin, fetcher)
  assertCatalogAccessCapability(discovery.capabilities)
  const serviceId = await publicKeyId(options.servicePublicKey)
  if (discovery.serviceId !== serviceId || discovery.servicePublicKey !== options.servicePublicKey) {
    throw new Error("Rusty Identity catalog access service does not match its pin")
  }
  const authorityView = await verifyIdentityAuthorityView(options.currentAuthorityView)
  if (authorityView.personId !== options.publisher.identity.personId ||
      authorityView.identityPublicKey !== options.publisher.identity.publicKey) {
    throw new Error("Identity catalog publisher authority belongs to another Identity")
  }
  const publisherKey = await authorizeIdentityDataDevice(authorityView, options.publisher.device.deviceId)
  if (publisherKey !== options.publisher.device.publicKey) throw new Error("Identity catalog publisher device is not active")
  const publicationAuthorization = await validatePublisherAuthorization(options, origin, serviceId, now)
  const access = new Uint8Array(options.access)
  if (access.byteLength < 1 || access.byteLength > 8 * 1024) throw new Error("Identity catalog access exceeds its size limit")
  const contentHash = await sha256Base64Url(access)
  const authority = await verifyIdentityDeviceAuthority(options.publisher.identity, {
    certificates: authorityView.certificates,
    revocations: authorityView.revocations,
  })
  const recipients = await Promise.all(authorityView.certificates.filter(value => value.payload.canEnrollDevices &&
    !authority.blockedDeviceIds.includes(value.payload.deviceId))
    .map(async certificate => ({
      deviceId: certificate.payload.deviceId,
      publicKey: await authorizeIdentityDevice(authority, certificate.payload.deviceId),
    })))
  if (recipients.length < 1 || recipients.length > 32) throw new Error("Identity manager catalog is invalid")
  const unique = new Set<string>()
  const receipts: RustyIdentityCatalogAccessPublishReceipt[] = []
  for (const recipient of recipients) {
    const recipientPublicKeyId = await publicKeyId(recipient.publicKey)
    if (recipient.deviceId !== recipientPublicKeyId || unique.has(recipient.deviceId)) {
      throw new Error("Identity manager catalog contains a duplicate or mismatched key")
    }
    unique.add(recipient.deviceId)
    const keyFields: IdentityCatalogAccessPublicationJournalKey = {
      serviceId, personId: options.publisher.identity.personId, applicationOrigin: options.applicationOrigin,
      catalogId: options.catalogId, recipientDeviceId: recipient.deviceId, recipientPublicKeyId,
    }
    const journalKey = publicationJournalKey(keyFields)
    receipts.push(await publishOneRecipient({ ...options, origin, serviceId, recipient, recipientPublicKeyId,
      journalKey, contentHash, access, publicationAuthorization, fetcher, now }))
  }
  return receipts
}

/** Fetch the catalogs published for this signed Identity profile, opening only manager-recipient envelopes. */
export async function requestRustyIdentityCatalogAccess(
  options: RequestRustyIdentityCatalogAccessOptions,
): Promise<VerifiedIdentityCatalogAccessGrant[]> {
  const now = options.now ?? Date.now
  const pins = await readIdentityProfileStateWithRevocations(options.profileState, options.manager.identity,
    options.currentAuthorityView.certificates, options.currentAuthorityView.revocations)
  const servicePins = await normalizeIdentityRustyServicePins(identityProfileRustyServicePins(pins))
  const authorityView = await verifyIdentityAuthorityView(options.currentAuthorityView)
  if (authorityView.personId !== options.manager.identity.personId ||
      authorityView.identityPublicKey !== options.manager.identity.publicKey) {
    throw new Error("Identity catalog recipient authority belongs to another person")
  }
  const managerKey = await authorizeIdentityDataDevice(authorityView, options.manager.device.deviceId)
  if (managerKey !== options.manager.device.publicKey) throw new Error("Identity catalog recipient device is not active")
  const currentAuthority = await verifyIdentityDeviceAuthority(options.manager.identity, {
    certificates: authorityView.certificates,
    revocations: authorityView.revocations,
  })
  await authorizeIdentityDevice(currentAuthority, options.manager.device.deviceId)

  const grants: VerifiedIdentityCatalogAccessGrant[] = []
  const fetcher = options.fetcher ?? fetch
  for (const servicePin of servicePins) {
    if (grants.length >= maxEntries) break
    await options.ensureCurrent?.()
    const service = await discoverRustyService(servicePin.origin, fetcher)
    assertCatalogAccessCapability(service.capabilities)
    if (service.serviceId !== servicePin.serviceId || service.servicePublicKey !== servicePin.servicePublicKey) {
      throw new Error("Identity catalog access service pin does not match discovery")
    }
    const issuedAt = now()
    if (!Number.isSafeInteger(issuedAt)) throw new Error("Invalid Identity catalog access request time")
    const requestPayload: RustyIdentityCatalogAccessRequestPayload = {
      kind: "mesh-identity-catalog-access-list-request", version: 1,
      serviceId: servicePin.serviceId, personId: options.manager.identity.personId,
      applicationOrigin: options.applicationOrigin, recipientDeviceId: options.manager.device.deviceId,
      recipientPublicKeyId: options.manager.device.deviceId, recipientPublicKey: options.manager.device.publicKey,
      challenge: randomNonce(), issuedAt, expiresAt: issuedAt + 120_000,
    }
    const request = await signEnvelope(options.manager.privateKeys.devicePrivateKey, requestPayload,
      options.manager.device.deviceId, requestDomain)
    if (!await verifyEnvelope(request, options.manager.device.publicKey, requestDomain)) {
      throw new Error("Identity catalog access request signature is invalid")
    }
    await options.ensureCurrent?.()
    const response = await fetcher(`${service.origin}/v2/identity/catalog-access/request`, {
      method: "POST", headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(request), cache: "no-store", redirect: "error", signal: AbortSignal.timeout(10_000),
    })
    if (!response.ok) {
      await response.body?.cancel()
      throw new Error(`Rusty Identity catalog access request failed with HTTP ${response.status}`)
    }
    const body = await readBoundedJson(response, maxResponseBytes, "Rusty Identity catalog access list")
    if (!isRecord(body) || !hasExactKeys(body, ["envelopes", "receipt"]) || !Array.isArray(body.envelopes) ||
        body.envelopes.length > maxEntries) throw new Error("Invalid Rusty Identity catalog access list response")
    const envelopes = body.envelopes as unknown[]
    const receipt = await verifyCatalogListReceipt({ response: body.receipt, request, envelopes,
      servicePublicKey: service.servicePublicKey, serviceId: service.serviceId, origin: service.origin,
      personId: options.manager.identity.personId, applicationOrigin: options.applicationOrigin,
      recipientDeviceId: options.manager.device.deviceId, recipientPublicKeyId: options.manager.device.deviceId,
      now,
    })
    void receipt
    let totalCiphertextBytes = 0
    let previousCatalogId = ""
    for (const envelope of envelopes) {
      const publication = asCatalogPublication(envelope)
      const payload = publication.payload
      if (payload.applicationOrigin !== options.applicationOrigin ||
          payload.recipientDeviceId !== options.manager.device.deviceId ||
          payload.recipientPublicKeyId !== options.manager.device.deviceId ||
          payload.personId !== options.manager.identity.personId ||
          payload.serviceId !== service.serviceId ||
          (previousCatalogId && compareOrdinal(previousCatalogId, payload.catalogId) >= 0)) {
        throw new Error("Rusty Identity catalog access list binding does not match")
      }
      previousCatalogId = payload.catalogId
      const ciphertextBytes = fromBase64Url(payload.ciphertext).byteLength
      if (ciphertextBytes > maxPublishedCiphertextBytes) throw new Error("Rusty Identity catalog entry exceeds its size limit")
      totalCiphertextBytes += ciphertextBytes
      if (totalCiphertextBytes > maxPublishedCiphertextTotal) throw new Error("Rusty Identity catalog list exceeds its size limit")
      grants.push(await verifyAndOpenRustyIdentityCatalogAccessPublication(publication, {
        servicePin, applicationOrigin: options.applicationOrigin, recipient: options.manager,
        currentAuthorityView: options.currentAuthorityView,
      }))
    }
    if (grants.length > maxEntries) throw new Error("Too many Identity catalog access grants")
  }
  return grants
}

async function publishOneRecipient(options: PublishRustyIdentityCatalogAccessOptions & {
  origin: string
  serviceId: string
  recipient: { deviceId: string; publicKey: string }
  recipientPublicKeyId: string
  journalKey: string
  contentHash: string
  access: Uint8Array
  publicationAuthorization: RustyIdentityCatalogAccessPublicationPayload["publisherAuthorization"]
  fetcher: RustyFetch
  now: () => number
}): Promise<RustyIdentityCatalogAccessPublishReceipt> {
  let current = await options.journal.read(options.journalKey)
  while (current?.state === "pending") {
    const receipt = await sendPublication(options, current.envelope)
    await options.ensureCurrent?.()
    const published: IdentityCatalogAccessPublicationJournalEntry = {
      version: current.version + 1, sourceRevision: current.sourceRevision,
      contentHash: current.contentHash, state: "published", receipt,
    }
    if (await options.journal.compareAndSet(options.journalKey, current.version, published)) {
      current = published
    } else {
      current = await options.journal.read(options.journalKey)
    }
  }
  if (current?.state === "published" && current.contentHash === options.contentHash) {
    if (!current.receipt) throw new Error("Identity catalog publication journal is missing its receipt")
    return verifyPublishReceipt({ receipt: current.receipt, envelope: undefined, servicePublicKey: options.servicePublicKey,
      serviceId: options.serviceId, origin: options.origin, publisherDeviceId: options.publisher.device.deviceId,
      personId: options.publisher.identity.personId, applicationOrigin: options.applicationOrigin,
      catalogId: options.catalogId, sourceRevision: current.sourceRevision,
      recipientDeviceId: options.recipient.deviceId, recipientPublicKeyId: options.recipientPublicKeyId,
      now: options.now, allowHistoricalReceipt: true,
    })
  }
  const sourceRevision = (current?.sourceRevision ?? 0) + 1
  if (!Number.isSafeInteger(sourceRevision)) throw new Error("Identity catalog source revision exhausted")
  const binding = {
    serviceId: options.serviceId, personId: options.publisher.identity.personId,
    applicationOrigin: options.applicationOrigin, catalogId: options.catalogId, sourceRevision,
    recipientDeviceId: options.recipient.deviceId, recipientPublicKeyId: options.recipientPublicKeyId,
  }
  const ciphertext = await sealIdentityCatalogAccessForManager(options.access, binding, options.recipient.publicKey)
  const ciphertextBytes = fromBase64Url(ciphertext).byteLength
  if (ciphertextBytes > maxPublishedCiphertextBytes) throw new Error("Identity catalog access ciphertext exceeds its size limit")
  const payload: RustyIdentityCatalogAccessPublicationPayload = {
    kind: "mesh-identity-catalog-access-publication", version: 1,
    ...binding, recipientPublicKey: options.recipient.publicKey, ciphertext, issuedAt: options.now(),
    publisherAuthorization: options.publicationAuthorization,
  }
  if (!Number.isSafeInteger(payload.issuedAt)) throw new Error("Invalid Identity catalog publication time")
  const envelope = await signEnvelope(options.publisher.privateKeys.devicePrivateKey, payload,
    options.publisher.device.deviceId, publishDomain)
  const entry: IdentityCatalogAccessPublicationJournalEntry = {
    version: (current?.version ?? 0) + 1, sourceRevision, contentHash: options.contentHash,
    state: "pending", envelope,
  }
  await options.ensureCurrent?.()
  if (!await options.journal.compareAndSet(options.journalKey, current?.version ?? null, entry)) {
    return publishOneRecipient(options)
  }
  const receipt = await sendPublication(options, envelope)
  await options.ensureCurrent?.()
  const published: IdentityCatalogAccessPublicationJournalEntry = {
    version: entry.version + 1, sourceRevision, contentHash: options.contentHash, state: "published", receipt,
  }
  if (!await options.journal.compareAndSet(options.journalKey, entry.version, published)) {
    const latest = await options.journal.read(options.journalKey)
    if (latest?.state !== "published" || latest.sourceRevision !== sourceRevision || !latest.receipt) {
      throw new Error("Identity catalog publication journal changed before receipt commit")
    }
    return verifyPublishReceipt({ receipt: latest.receipt, envelope: undefined, servicePublicKey: options.servicePublicKey,
      serviceId: options.serviceId, origin: options.origin, publisherDeviceId: options.publisher.device.deviceId,
      personId: options.publisher.identity.personId, applicationOrigin: options.applicationOrigin,
      catalogId: options.catalogId, sourceRevision, recipientDeviceId: options.recipient.deviceId,
      recipientPublicKeyId: options.recipientPublicKeyId, now: options.now, allowHistoricalReceipt: true,
    })
  }
  return receipt
}

async function sendPublication(
  options: Parameters<typeof publishOneRecipient>[0],
  envelope: RustyIdentityCatalogAccessPublication | undefined,
): Promise<RustyIdentityCatalogAccessPublishReceipt> {
  if (!envelope) throw new Error("Identity catalog publication journal is missing its pending envelope")
  await options.ensureCurrent?.()
  const response = await options.fetcher(`${options.origin}/v2/identity/catalog-access`, {
    method: "PUT", headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(envelope), cache: "no-store", redirect: "error", signal: AbortSignal.timeout(10_000),
  })
  if (!response.ok) {
    await response.body?.cancel()
    throw new Error(`Rusty Identity catalog access publication failed with HTTP ${response.status}`)
  }
  const body = await readBoundedJson(response, 16 * 1024, "Rusty Identity catalog access receipt")
  if (!isRecord(body) || !hasExactKeys(body, ["receipt"])) throw new Error("Invalid Rusty Identity catalog access publication response")
  const receipt = await verifyPublishReceipt({
    receipt: body.receipt, envelope, servicePublicKey: options.servicePublicKey,
    serviceId: options.serviceId, origin: options.origin, publisherDeviceId: options.publisher.device.deviceId,
    personId: options.publisher.identity.personId, applicationOrigin: options.applicationOrigin,
    catalogId: options.catalogId, sourceRevision: envelope.payload.sourceRevision,
    recipientDeviceId: options.recipient.deviceId, recipientPublicKeyId: options.recipientPublicKeyId,
    now: options.now,
  })
  await options.ensureCurrent?.()
  return receipt
}

async function validatePublisherAuthorization(
  options: PublishRustyIdentityCatalogAccessOptions,
  rustyServerOrigin: string,
  serviceId: string,
  now: () => number,
): Promise<RustyIdentityCatalogAccessPublicationPayload["publisherAuthorization"]> {
  const proof = options.retainedAuthorization.proof
  if (!proof?.payload || !("request" in proof.payload)) throw new Error("Identity catalog publisher lacks retained app authorization")
  const request = proof.payload.request as DeviceAuthorizationRequest
  if (request.payload.version !== 3 || request.payload.includeIdentityCatalogAccess !== true ||
      request.payload.applicationOrigin !== options.applicationOrigin ||
      (request.payload.personId !== null && request.payload.personId !== options.publisher.identity.personId) ||
      request.payload.deviceId !== options.publisher.device.deviceId ||
      request.payload.devicePublicKey !== options.publisher.device.publicKey ||
      options.retainedAuthorization.certificate.payload.deviceId !== options.publisher.device.deviceId ||
      canonicalizeJson(options.retainedAuthorization.certificate) !== canonicalizeJson(options.publisher.certificate)) {
    throw new Error("Identity catalog publisher authorization does not match this app device")
  }
  const verified = await verifyRetainedDeviceAuthorizationApproval(options.retainedAuthorization, request, {
    now,
    expectedExistingProfile: {
      identity: options.publisher.identity,
      device: options.publisher.device,
      certificate: options.publisher.certificate,
    },
  })
  if (verified.proof.payload.version !== 5) {
    throw new Error("Identity catalog publisher authorization must bind a committed Rusty service pin")
  }
  const matchingPin = (verified.rustyServicePins ?? []).some(pin => pin.origin === rustyServerOrigin &&
    pin.serviceId === serviceId && pin.servicePublicKey === options.servicePublicKey)
  if (!matchingPin) throw new Error("Identity catalog publisher authorization does not pin this Rusty service")
  return { request: verified.proof.payload.request, proof: verified.proof, certificate: verified.certificate,
    rustyServicePins: verified.rustyServicePins ?? [] }
}

async function verifyPublishReceipt(options: {
  receipt: unknown
  envelope: RustyIdentityCatalogAccessPublication | undefined
  servicePublicKey: string
  serviceId: string
  origin: string
  publisherDeviceId: string
  personId: string
  applicationOrigin: string
  catalogId: string
  sourceRevision: number
  recipientDeviceId: string
  recipientPublicKeyId: string
  now: () => number
  allowHistoricalReceipt?: boolean
}): Promise<RustyIdentityCatalogAccessPublishReceipt> {
  const receipt = snapshotSignedEnvelope(options.receipt)
  if (!hasExactKeys(receipt.payload, ["kind", "version", "serviceId", "origin", "publisherDeviceId", "personId",
    "applicationOrigin", "catalogId", "sourceRevision", "recipientDeviceId", "recipientPublicKeyId", "envelopeHash",
    "issuedAt"])) throw new Error("Invalid Rusty Identity catalog access receipt")
  const payload = receipt.payload as unknown as RustyIdentityCatalogAccessPublishReceipt["payload"]
  const current = options.now()
  const envelopeHash = options.envelope
    ? await digest(options.envelope)
    : payload.envelopeHash
  if (receipt.signerKeyId !== options.serviceId || !await verifyEnvelope(receipt as SignedEnvelope<{ kind: string }>, options.servicePublicKey, "RUSTY/2") ||
      payload.kind !== "rusty-identity-catalog-access-publish-receipt" || payload.version !== 1 ||
      payload.serviceId !== options.serviceId || payload.origin !== options.origin ||
      payload.publisherDeviceId !== options.publisherDeviceId || payload.personId !== options.personId ||
      payload.applicationOrigin !== options.applicationOrigin || payload.catalogId !== options.catalogId ||
      payload.sourceRevision !== options.sourceRevision || payload.recipientDeviceId !== options.recipientDeviceId ||
      payload.recipientPublicKeyId !== options.recipientPublicKeyId || payload.envelopeHash !== envelopeHash ||
      !Number.isSafeInteger(payload.issuedAt) || (!options.allowHistoricalReceipt && Math.abs(current - payload.issuedAt) > 120_000)) {
    throw new Error("Rusty Identity catalog access receipt does not match its publication")
  }
  return receipt as RustyIdentityCatalogAccessPublishReceipt
}

async function verifyCatalogListReceipt(options: {
  response: unknown
  request: RustyIdentityCatalogAccessRequest
  envelopes: unknown[]
  servicePublicKey: string
  serviceId: string
  origin: string
  personId: string
  applicationOrigin: string
  recipientDeviceId: string
  recipientPublicKeyId: string
  now: () => number
}): Promise<RustyIdentityCatalogAccessListReceipt> {
  const receipt = snapshotSignedEnvelope(options.response)
  if (!hasExactKeys(receipt.payload, ["kind", "version", "serviceId", "origin", "requestHash", "personId",
    "applicationOrigin", "recipientDeviceId", "recipientPublicKeyId", "challenge", "envelopeCount",
    "envelopeListHash", "issuedAt", "expiresAt"])) throw new Error("Invalid Rusty Identity catalog access list receipt")
  const payload = receipt.payload as unknown as RustyIdentityCatalogAccessListReceipt["payload"]
  const requestHash = await digest(options.request)
  const envelopeListHash = await digest(options.envelopes)
  const current = options.now()
  if (receipt.signerKeyId !== options.serviceId || !await verifyEnvelope(receipt as SignedEnvelope<{ kind: string }>, options.servicePublicKey, "RUSTY/2") ||
      payload.kind !== "rusty-identity-catalog-access-list-receipt" || payload.version !== 1 ||
      payload.serviceId !== options.serviceId || payload.origin !== options.origin ||
      payload.requestHash !== requestHash || payload.personId !== options.personId ||
      payload.applicationOrigin !== options.applicationOrigin || payload.recipientDeviceId !== options.recipientDeviceId ||
      payload.recipientPublicKeyId !== options.recipientPublicKeyId ||
      payload.challenge !== options.request.payload.challenge || payload.envelopeCount !== options.envelopes.length ||
      payload.envelopeListHash !== envelopeListHash || payload.expiresAt !== options.request.payload.expiresAt ||
      !Number.isSafeInteger(payload.issuedAt) || Math.abs(current - payload.issuedAt) > 120_000 ||
      payload.issuedAt < options.request.payload.issuedAt - 30_000 || payload.issuedAt > options.request.payload.expiresAt) {
    throw new Error("Rusty Identity catalog access list receipt does not match its request")
  }
  return receipt as RustyIdentityCatalogAccessListReceipt
}

function assertCatalogAccessCapability(capabilities: Record<string, unknown>): void {
  const value = capabilities.identityCatalogAccess
  if (!isRecord(value) || value.version !== 1 || value.maximumEntries !== maxEntries ||
      value.maximumResponseBytes !== maxResponseBytes || value.maximumCiphertextBytes !== maxCiphertextBytes) {
    throw new Error("Rusty service does not support Identity catalog access version 1")
  }
}

function asCatalogPublication(value: unknown): RustyIdentityCatalogAccessPublication {
  const envelope = snapshotSignedEnvelope(value)
  if (!isRecord(envelope.payload) || envelope.payload.kind !== "mesh-identity-catalog-access-publication" ||
      envelope.payload.version !== 1) throw new Error("Invalid Rusty Identity catalog access publication")
  return envelope as unknown as RustyIdentityCatalogAccessPublication
}

function snapshotSignedEnvelope(value: unknown): SignedEnvelope<Record<string, unknown>> {
  let result: unknown
  try { result = JSON.parse(JSON.stringify(value)) as unknown }
  catch { throw new Error("Invalid signed Rusty Identity catalog access envelope") }
  if (!isRecord(result) || !hasExactKeys(result, ["payload", "signerKeyId", "signature"]) ||
      !isRecord(result.payload) || typeof result.signerKeyId !== "string" || typeof result.signature !== "string") {
    throw new Error("Invalid signed Rusty Identity catalog access envelope")
  }
  return result as unknown as SignedEnvelope<Record<string, unknown>>
}

function publicationJournalKey(key: IdentityCatalogAccessPublicationJournalKey): string {
  const parts = [key.serviceId, key.personId, key.applicationOrigin, key.catalogId, key.recipientDeviceId, key.recipientPublicKeyId]
  if (parts.some(value => !value || value.includes("\u0000"))) throw new Error("Invalid Identity catalog publication journal key")
  return `identity-catalog-publisher.v1/${parts.map(value => encodeURIComponent(value)).join("/")}`
}

async function digest(value: unknown): Promise<string> {
  return sha256Base64Url(encoder.encode(canonicalizeJson(value)))
}

function randomNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "")
}

async function readBoundedJson(response: Response, maximumBytes: number, description: string): Promise<unknown> {
  const contentLength = response.headers.get("content-length")
  if (contentLength !== null && (!/^\d+$/u.test(contentLength) || Number(contentLength) > maximumBytes)) {
    await response.body?.cancel()
    throw new Error(`${description} exceeds its size limit`)
  }
  const reader = response.body?.getReader()
  if (!reader) throw new Error(`${description} is empty`)
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      length += value.byteLength
      if (length > maximumBytes) {
        await reader.cancel()
        throw new Error(`${description} exceeds its size limit`)
      }
      chunks.push(value)
    }
  } finally { reader.releaseLock() }
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown }
  catch { throw new Error(`Invalid ${description}`) }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}

function compareOrdinal(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}
