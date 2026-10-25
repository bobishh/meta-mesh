/// <reference path="./libsodium-wrappers-sumo.d.ts" />

import { authorizeIdentityDataDevice, authorizeIdentityDevice, canonicalizeJson, certificateHash,
  fromBase64Url, publicKeyId, sha256Base64Url, toBase64Url, verifyDeviceCertificateChain, verifyEnvelope,
  verifyIdentityAuthorityView, verifyIdentityDeviceAuthority, type DeviceCertificate, type IdentityAuthorityView, type LocalProfile,
  type SignedEnvelope } from "./index"
import { normalizeIdentityRustyServicePins, type IdentityRustyServicePin } from "./identityProfile"
import type { DeviceAuthorizationRequest } from "./deviceAuthorization"

export const maxIdentityCatalogAccessEntries = 8
export const maxIdentityCatalogAccessBytes = 8 * 1024
const maxOpaqueAccessBytes = maxIdentityCatalogAccessBytes
const maxCiphertextBytes = 16 * 1024
const ed25519Pkcs8Prefix = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
])

// Existing profiles carry only an Ed25519 device key. Libsodium's supported
// Ed25519-to-X25519 conversion seals the catalog without changing that profile;
// distinct signing and encryption keys remain preferable when provisioning supports them.

export type IdentityCatalogAccessManagerBinding = {
  serviceId: string
  personId: string
  applicationOrigin: string
  catalogId: string
  sourceRevision: number
  recipientDeviceId: string
  recipientPublicKeyId: string
}

export type IdentityCatalogAccessApplicationBinding = Omit<IdentityCatalogAccessManagerBinding,
  "recipientDeviceId" | "recipientPublicKeyId"> & {
  recipientDeviceId: string
  recipientPublicKeyId: string
  challenge: string
  expiresAt: number
}

export type IdentityCatalogAccessApprovalEntry = {
  serviceId: string
  catalogId: string
  sourceRevision: number
  recipientDeviceId: string
  recipientPublicKeyId: string
  expiresAt: number
  ciphertext: string
}

export type IdentityCatalogAccessStatus = "ready" | "empty" | "unavailable"

export type IdentityCatalogAccessApproval = {
  status: IdentityCatalogAccessStatus
  entries: IdentityCatalogAccessApprovalEntry[]
}

export type OpenedIdentityCatalogAccess = {
  serviceId: string
  catalogId: string
  sourceRevision: number
  access: Uint8Array
}

export type OpenedIdentityCatalogAccessResult = {
  status: IdentityCatalogAccessStatus
  entries: OpenedIdentityCatalogAccess[]
}

const verifiedGrantBrand: unique symbol = Symbol("verifiedIdentityCatalogAccessGrant")
export type VerifiedIdentityCatalogAccessGrant = { readonly [verifiedGrantBrand]: true }
const verifiedGrantValues = new WeakMap<object, {
  binding: IdentityCatalogAccessManagerBinding
  access: Uint8Array
  servicePin: IdentityRustyServicePin
}>()

export type RustyIdentityCatalogAccessPublicationPayload = {
  kind: "mesh-identity-catalog-access-publication"
  version: 1
  serviceId: string
  personId: string
  applicationOrigin: string
  catalogId: string
  sourceRevision: number
  recipientDeviceId: string
  recipientPublicKeyId: string
  recipientPublicKey: string
  ciphertext: string
  issuedAt: number
  publisherAuthorization: {
    request: DeviceAuthorizationRequest
    proof: SignedEnvelope<Record<string, unknown>>
    certificate: DeviceCertificate
    rustyServicePins: IdentityRustyServicePin[]
  }
}

export type RustyIdentityCatalogAccessPublication = SignedEnvelope<RustyIdentityCatalogAccessPublicationPayload>

/** Verify an opaque publication against its pinned service and current Identity authority, then open it for this manager. */
export async function verifyAndOpenRustyIdentityCatalogAccessPublication(
  publicationValue: unknown,
  options: {
    servicePin: IdentityRustyServicePin
    applicationOrigin: string
    recipient: LocalProfile
    currentAuthorityView: IdentityAuthorityView
  },
): Promise<VerifiedIdentityCatalogAccessGrant> {
  const publication = snapshotPublication(publicationValue)
  const value = publication.payload
  const servicePin = await normalizeIdentityRustyServicePins([options.servicePin]).then(pins => pins[0]!)
  if (value.serviceId !== servicePin.serviceId || value.applicationOrigin !== options.applicationOrigin ||
      !isOrigin(value.applicationOrigin) || value.personId !== options.recipient.identity.personId ||
      value.recipientDeviceId !== options.recipient.device.deviceId ||
      value.recipientPublicKeyId !== options.recipient.device.deviceId ||
      value.recipientPublicKey !== options.recipient.device.publicKey ||
      value.issuedAt > Date.now() + 30_000 || value.issuedAt < 0 ||
      !Number.isSafeInteger(value.issuedAt)) {
    throw new Error("Rusty Identity catalog access publication binding does not match")
  }
  const checkedView = await verifyIdentityAuthorityView(options.currentAuthorityView)
  if (checkedView.personId !== value.personId || checkedView.identityPublicKey !== options.recipient.identity.publicKey) {
    throw new Error("Rusty Identity catalog access belongs to another person")
  }
  const authority = await verifyIdentityDeviceAuthority(options.recipient.identity, {
    certificates: options.currentAuthorityView.certificates,
    revocations: options.currentAuthorityView.revocations,
  })
  const recipientKey = await authorizeIdentityDevice(authority, value.recipientDeviceId)
  if (recipientKey !== value.recipientPublicKey) throw new Error("Identity catalog recipient is not a current manager")
  const publisher = value.publisherAuthorization
  const request = publisher.request
  const appCertificate = publisher.certificate
  const requestPayload = request.payload
  if (requestPayload.version !== 3 || requestPayload.includeIdentityCatalogAccess !== true ||
      requestPayload.kind !== "mesh-device-authorization-request" ||
      requestPayload.applicationOrigin !== value.applicationOrigin ||
      (requestPayload.personId !== null && requestPayload.personId !== value.personId) ||
      requestPayload.deviceId !== publication.signerKeyId || requestPayload.devicePublicKey !== appCertificate.payload.devicePublicKey ||
      appCertificate.payload.deviceId !== publication.signerKeyId || appCertificate.payload.personId !== value.personId ||
      request.signerKeyId !== publication.signerKeyId ||
      !await verifyEnvelope(request, requestPayload.devicePublicKey, "MESH-DEVICE-AUTHORIZATION/1")) {
    throw new Error("Identity catalog publisher approval does not match the app device")
  }
  const approvedPins = await normalizeIdentityRustyServicePins(publisher.rustyServicePins)
  if (canonicalizeJson(approvedPins) !== canonicalizeJson(publisher.rustyServicePins)) {
    throw new Error("Identity catalog publisher pins are not canonically ordered")
  }
  const pinDigest = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(approvedPins)))
  const proof = publisher.proof
  if (!isApprovalProof(proof)) throw new Error("Invalid retained Identity app authorization proof")
  const proofPayload = proof.payload
  const requestedPins = "rustyServicePins" in requestPayload ? requestPayload.rustyServicePins ?? [] : []
  if (proofPayload.version !== 5 || proofPayload.rustyServicePinsDigest !== pinDigest ||
      !/^[A-Za-z0-9_-]{43}$/u.test(String(proofPayload.profileStateDigest)) ||
      !/^[A-Za-z0-9_-]{43}$/u.test(String(proofPayload.identityCatalogAccessDigest)) ||
      !requestedPins.every(pin => approvedPins.some(saved => canonicalizeJson(saved) === canonicalizeJson(pin))) ||
      !approvedPins.some(pin => canonicalizeJson(pin) === canonicalizeJson(servicePin))) {
    throw new Error("Identity catalog publisher approval does not pin this Rusty service")
  }
  if (canonicalizeJson(proofPayload.request) !== canonicalizeJson(request) ||
      proofPayload.certificateHash !== await certificateHash(appCertificate) ||
      proofPayload.expiresAt !== requestPayload.expiresAt || proofPayload.issuedAt >= proofPayload.expiresAt ||
      !Number.isSafeInteger(proofPayload.issuedAt) ||
      !await verifyEnvelope(proof, await verifyDeviceCertificateChain(authority.identity, proof.signerKeyId, authority.certificates),
        "MESH-APP-DEVICE-AUTHORIZATION/1")) {
    throw new Error("Invalid retained Identity app authorization proof")
  }
  const issuerCertificate = authority.certificates.find(certificate => certificate.payload.deviceId === proof.signerKeyId)
  if (!issuerCertificate?.payload.canEnrollDevices) throw new Error("Retained app authorization was not issued by an Identity manager")
  await authorizeIdentityDevice(authority, proof.signerKeyId)
  const publisherKey = await authorizeIdentityDataDevice(checkedView, publication.signerKeyId)
  if (publisherKey !== requestPayload.devicePublicKey || publication.signerKeyId !== requestPayload.deviceId ||
      !await verifyEnvelope(publication, publisherKey, "MESH-IDENTITY-CATALOG-ACCESS-PUBLISH/1") ||
      !authority.certificates.some(certificate => canonicalizeJson(certificate) === canonicalizeJson(appCertificate))) {
    throw new Error("Identity catalog publisher is not an active app device")
  }
  const expectedBinding: IdentityCatalogAccessManagerBinding = {
    serviceId: value.serviceId,
    personId: value.personId,
    applicationOrigin: value.applicationOrigin,
    catalogId: value.catalogId,
    sourceRevision: value.sourceRevision,
    recipientDeviceId: value.recipientDeviceId,
    recipientPublicKeyId: value.recipientPublicKeyId,
  }
  const access = await openIdentityCatalogAccessForManager(value.ciphertext, options.recipient, expectedBinding)
  const grant = Object.freeze({}) as VerifiedIdentityCatalogAccessGrant
  verifiedGrantValues.set(grant, { binding: expectedBinding, access, servicePin })
  return grant
}

/** Convert verified manager grants into approval entries bound to one app request. */
export async function createIdentityCatalogAccessApprovalEntries(
  grants: readonly VerifiedIdentityCatalogAccessGrant[],
  request: { applicationOrigin: string; challenge: string; expiresAt: number; personId: string | null;
    deviceId: string; devicePublicKey: string },
  approvedPersonId: string,
  approvedServicePins: readonly IdentityRustyServicePin[],
): Promise<IdentityCatalogAccessApprovalEntry[]> {
  if (grants.length > maxIdentityCatalogAccessEntries) throw new Error("Too many Identity catalog access grants")
  if (request.personId !== null && request.personId !== approvedPersonId) {
    throw new Error("Identity catalog access grant does not match this app request")
  }
  const entries: IdentityCatalogAccessApprovalEntry[] = []
  const unique = new Set<string>()
  for (const grant of grants) {
    const stored = verifiedGrantValues.get(grant as object)
    if (!stored || stored.binding.personId !== approvedPersonId ||
        stored.binding.applicationOrigin !== request.applicationOrigin) {
      throw new Error("Identity catalog access grant does not match this app request")
    }
    if (!approvedServicePins.some(pin => canonicalizeJson(pin) === canonicalizeJson(stored.servicePin))) {
      throw new Error("Identity catalog access grant service is not pinned in the current Identity profile")
    }
    const recipientPublicKeyId = await publicKeyId(request.devicePublicKey)
    const binding: IdentityCatalogAccessApplicationBinding = {
      ...stored.binding,
      personId: approvedPersonId,
      recipientDeviceId: request.deviceId,
      recipientPublicKeyId,
      challenge: request.challenge,
      expiresAt: request.expiresAt,
    }
    const ciphertext = await sealIdentityCatalogAccessForApplication(stored.access, binding, request.devicePublicKey)
    const entry: IdentityCatalogAccessApprovalEntry = {
      serviceId: binding.serviceId,
      catalogId: binding.catalogId,
      sourceRevision: binding.sourceRevision,
      recipientDeviceId: binding.recipientDeviceId,
      recipientPublicKeyId: binding.recipientPublicKeyId,
      expiresAt: binding.expiresAt,
      ciphertext,
    }
    const key = `${entry.serviceId}\n${entry.catalogId}`
    if (unique.has(key)) throw new Error("Duplicate Identity catalog access grant")
    unique.add(key)
    entries.push(entry)
  }
  entries.sort((left, right) => compareOrdinal(`${left.serviceId}\n${left.catalogId}`, `${right.serviceId}\n${right.catalogId}`))
  if (entries.reduce((sum, entry) => sum + fromBase64Url(entry.ciphertext).byteLength, 0) > 64 * 1024) {
    throw new Error("Identity catalog access grants exceed the approval size limit")
  }
  return entries
}

/** Open a verified approval's catalog entries after the approval signature and request have been checked. */
export async function openIdentityCatalogAccessApprovalEntries(
  approval: IdentityCatalogAccessApproval,
  request: { applicationOrigin: string; challenge: string; expiresAt: number; personId: string | null;
    deviceId: string; devicePublicKey: string },
  recipient: LocalProfile,
): Promise<OpenedIdentityCatalogAccessResult> {
  const checkedApproval = await verifyIdentityCatalogAccessApprovalEntries(approval, request, recipient.identity.personId)
  if (request.personId !== null && request.personId !== recipient.identity.personId ||
      request.deviceId !== recipient.device.deviceId || request.devicePublicKey !== recipient.device.publicKey) {
    throw new Error("Identity catalog access approval recipient does not match")
  }
  const result: OpenedIdentityCatalogAccess[] = []
  for (const entry of checkedApproval.entries) {
    const binding: IdentityCatalogAccessApplicationBinding = {
      serviceId: entry.serviceId,
      personId: recipient.identity.personId,
      applicationOrigin: request.applicationOrigin,
      catalogId: entry.catalogId,
      sourceRevision: entry.sourceRevision,
      recipientDeviceId: entry.recipientDeviceId,
      recipientPublicKeyId: entry.recipientPublicKeyId,
      challenge: request.challenge,
      expiresAt: entry.expiresAt,
    }
    if (entry.expiresAt !== request.expiresAt || entry.recipientDeviceId !== request.deviceId ||
        entry.recipientPublicKeyId !== await publicKeyId(request.devicePublicKey)) {
      throw new Error("Identity catalog access approval entry does not match this request")
    }
    result.push({ serviceId: entry.serviceId, catalogId: entry.catalogId, sourceRevision: entry.sourceRevision,
      access: await openIdentityCatalogAccessForApplication(entry.ciphertext, recipient, binding) })
  }
  return { status: checkedApproval.status, entries: result }
}

export async function verifyIdentityCatalogAccessApprovalEntries(
  approvalValue: unknown,
  request: { applicationOrigin: string; challenge: string; expiresAt: number; personId: string | null;
    deviceId: string; devicePublicKey: string },
  approvedPersonId: string,
): Promise<IdentityCatalogAccessApproval> {
  if (!isRecord(approvalValue) || !hasExactKeys(approvalValue, ["status", "entries"]) ||
      !["ready", "empty", "unavailable"].includes(String(approvalValue.status)) ||
      !Array.isArray(approvalValue.entries) || approvalValue.entries.length > maxIdentityCatalogAccessEntries ||
      (request.personId !== null && request.personId !== approvedPersonId)) {
    throw new Error("Invalid Identity catalog access approval list")
  }
  const entriesValue = approvalValue.entries
  const status = approvalValue.status as IdentityCatalogAccessStatus
  const entries = entriesValue as unknown[]
  const seen = new Set<string>()
  let totalCiphertextBytes = 0
  let previousKey = ""
  const verified: IdentityCatalogAccessApprovalEntry[] = []
  const expectedRecipientKeyId = await publicKeyId(request.devicePublicKey)
  for (const value of entries) {
    if (!isRecord(value) || !hasExactKeys(value, ["serviceId", "catalogId", "sourceRevision", "recipientDeviceId",
      "recipientPublicKeyId", "expiresAt", "ciphertext"]) ||
        typeof value.serviceId !== "string" || !/^[A-Za-z0-9_-]{32,128}$/u.test(value.serviceId) ||
        typeof value.catalogId !== "string" || value.catalogId.length < 1 || value.catalogId.length > 128 ||
        /[\u0000-\u001f\u007f]/u.test(value.catalogId) ||
        typeof value.sourceRevision !== "number" || !Number.isSafeInteger(value.sourceRevision) || value.sourceRevision < 1 ||
        value.recipientDeviceId !== request.deviceId || value.recipientPublicKeyId !== expectedRecipientKeyId ||
        value.expiresAt !== request.expiresAt || typeof value.ciphertext !== "string" ||
        !/^[A-Za-z0-9_-]+$/u.test(value.ciphertext)) {
      throw new Error("Invalid Identity catalog access approval entry")
    }
    const ciphertextLength = fromBase64Url(value.ciphertext).byteLength
    if (ciphertextLength < 48 || ciphertextLength > maxCiphertextBytes) {
      throw new Error("Invalid Identity catalog access approval ciphertext")
    }
    totalCiphertextBytes += ciphertextLength
    const key = `${value.serviceId}\n${value.catalogId}`
    if (seen.has(key) || (previousKey && compareOrdinal(previousKey, key) >= 0)) {
      throw new Error("Identity catalog access approval entries are duplicated or unsorted")
    }
    seen.add(key)
    previousKey = key
    verified.push(value as unknown as IdentityCatalogAccessApprovalEntry)
  }
  if (totalCiphertextBytes > 64 * 1024) throw new Error("Identity catalog access grants exceed the approval size limit")
  if ((status === "ready") !== (verified.length > 0) || (status !== "ready" && verified.length > 0)) {
    throw new Error("Identity catalog access status does not match its entries")
  }
  return { status, entries: verified }
}

type SealedCatalogAccess = {
  kind: "mesh-identity-catalog-access"
  version: 1
  purpose: "identity-manager" | "application-device"
  binding: IdentityCatalogAccessManagerBinding | IdentityCatalogAccessApplicationBinding
  access: string
}

type Sodium = {
  ready: Promise<void>
  crypto_box_seal(message: Uint8Array, publicKey: Uint8Array): Uint8Array
  crypto_box_seal_open(ciphertext: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array): Uint8Array
  crypto_sign_ed25519_pk_to_curve25519(publicKey: Uint8Array): Uint8Array
  crypto_sign_ed25519_sk_to_curve25519(privateKey: Uint8Array): Uint8Array
  crypto_sign_seed_keypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array }
  memcmp(left: Uint8Array, right: Uint8Array): boolean
  memzero(value: Uint8Array): void
}

/** Seal bounded opaque TCB access bytes for one exact active Identity manager device. */
export async function sealIdentityCatalogAccessForManager(
  access: Uint8Array,
  binding: IdentityCatalogAccessManagerBinding,
  recipientPublicKey: string,
): Promise<string> {
  return sealAccess(access, binding, recipientPublicKey, "identity-manager")
}

/** Open bytes only when profile, recipient key and all catalog bindings match exactly. */
export async function openIdentityCatalogAccessForManager(
  ciphertext: string,
  recipient: LocalProfile,
  expectedBinding: IdentityCatalogAccessManagerBinding,
): Promise<Uint8Array> {
  return openAccess(ciphertext, recipient, expectedBinding, "identity-manager")
}

/** Reseal manager-opened opaque bytes for the exact short-lived app authorization request. */
export async function sealIdentityCatalogAccessForApplication(
  access: Uint8Array,
  binding: IdentityCatalogAccessApplicationBinding,
  recipientPublicKey: string,
): Promise<string> {
  return sealAccess(access, binding, recipientPublicKey, "application-device")
}

/** Open app approval bytes only for the exact request's origin, device, challenge and expiry. */
export async function openIdentityCatalogAccessForApplication(
  ciphertext: string,
  recipient: LocalProfile,
  expectedBinding: IdentityCatalogAccessApplicationBinding,
): Promise<Uint8Array> {
  return openAccess(ciphertext, recipient, expectedBinding, "application-device")
}

async function sealAccess(
  access: Uint8Array,
  binding: IdentityCatalogAccessManagerBinding | IdentityCatalogAccessApplicationBinding,
  recipientPublicKey: string,
  purpose: SealedCatalogAccess["purpose"],
): Promise<string> {
  validateAccess(access)
  await validateRecipientBinding(binding, recipientPublicKey)
  const plaintext = new TextEncoder().encode(canonicalizeJson({
    kind: "mesh-identity-catalog-access",
    version: 1,
    purpose,
    binding,
    access: toBase64Url(access),
  } satisfies SealedCatalogAccess))
  const sodium = await getSodium()
  const recipientCurveKey = sodium.crypto_sign_ed25519_pk_to_curve25519(fromBase64Url(recipientPublicKey))
  const ciphertext = sodium.crypto_box_seal(plaintext, recipientCurveKey)
  if (ciphertext.byteLength > maxCiphertextBytes) throw new Error("Identity catalog access ciphertext exceeds its size limit")
  return toBase64Url(ciphertext)
}

async function openAccess(
  ciphertext: string,
  recipient: LocalProfile,
  expectedBinding: IdentityCatalogAccessManagerBinding | IdentityCatalogAccessApplicationBinding,
  purpose: SealedCatalogAccess["purpose"],
): Promise<Uint8Array> {
  if (!/^[A-Za-z0-9_-]+$/u.test(ciphertext)) throw new Error("Invalid Identity catalog access ciphertext")
  const ciphertextBytes = fromBase64Url(ciphertext)
  if (ciphertextBytes.byteLength < 48 || ciphertextBytes.byteLength > maxCiphertextBytes) {
    throw new Error("Invalid Identity catalog access ciphertext")
  }
  await validateRecipientBinding(expectedBinding, recipient.device.publicKey)
  if (recipient.identity.personId !== expectedBinding.personId ||
      recipient.device.deviceId !== expectedBinding.recipientDeviceId ||
      await publicKeyId(recipient.device.publicKey) !== expectedBinding.recipientPublicKeyId) {
    throw new Error("Identity catalog access recipient does not match its binding")
  }
  const sodium = await getSodium()
  const { seed, sodiumSecretKey } = await deviceKeyMaterial(sodium, recipient)
  const recipientCurvePublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(fromBase64Url(recipient.device.publicKey))
  const recipientCurvePrivateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(sodiumSecretKey)
  let plaintext: Uint8Array
  try {
    plaintext = sodium.crypto_box_seal_open(ciphertextBytes, recipientCurvePublicKey, recipientCurvePrivateKey)
  } catch {
    throw new Error("Identity catalog access cannot be opened by this device")
  } finally {
    sodium.memzero(seed)
    sodium.memzero(sodiumSecretKey)
    sodium.memzero(recipientCurvePrivateKey)
  }
  if (plaintext.byteLength > maxOpaqueAccessBytes * 2) throw new Error("Identity catalog access plaintext exceeds its size limit")
  let wrapper: unknown
  try {
    wrapper = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext)) as unknown
  } catch { throw new Error("Invalid Identity catalog access plaintext") }
  if (!isSealedCatalogAccess(wrapper) || wrapper.purpose !== purpose ||
      canonicalizeJson(wrapper) !== new TextDecoder().decode(plaintext) ||
      canonicalizeJson(wrapper.binding) !== canonicalizeJson(expectedBinding)) {
    throw new Error("Identity catalog access plaintext binding does not match")
  }
  const access = fromBase64Url(wrapper.access)
  validateAccess(access)
  return access
}

async function deviceKeyMaterial(sodium: Sodium, profile: LocalProfile): Promise<{ seed: Uint8Array; sodiumSecretKey: Uint8Array }> {
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", profile.privateKeys.devicePrivateKey))
  if (pkcs8.byteLength !== ed25519Pkcs8Prefix.byteLength + 32 ||
      !ed25519Pkcs8Prefix.every((byte, index) => pkcs8[index] === byte)) {
    throw new Error("Identity device key is not an exportable Ed25519 key")
  }
  const seed = pkcs8.slice(ed25519Pkcs8Prefix.byteLength)
  const keypair = sodium.crypto_sign_seed_keypair(seed)
  if (!sodium.memcmp(keypair.publicKey, fromBase64Url(profile.device.publicKey))) {
    sodium.memzero(seed)
    sodium.memzero(keypair.privateKey)
    throw new Error("Identity device private key does not match its public key")
  }
  return { seed, sodiumSecretKey: keypair.privateKey }
}

async function validateRecipientBinding(
  binding: IdentityCatalogAccessManagerBinding | IdentityCatalogAccessApplicationBinding,
  recipientPublicKey: string,
): Promise<void> {
  if (!binding || typeof binding !== "object" ||
      !/^[A-Za-z0-9_-]{32,128}$/u.test(binding.serviceId) ||
      !/^[A-Za-z0-9_-]{32,128}$/u.test(binding.personId) ||
      !isOrigin(binding.applicationOrigin) ||
      typeof binding.catalogId !== "string" || binding.catalogId.length < 1 || binding.catalogId.length > 128 ||
      /[\u0000-\u001f\u007f]/u.test(binding.catalogId) ||
      !Number.isSafeInteger(binding.sourceRevision) || binding.sourceRevision < 1 ||
      !/^[A-Za-z0-9_-]{32,128}$/u.test(binding.recipientDeviceId) ||
      !/^[A-Za-z0-9_-]{32,128}$/u.test(binding.recipientPublicKeyId) ||
      binding.recipientDeviceId !== binding.recipientPublicKeyId ||
      await publicKeyId(recipientPublicKey) !== binding.recipientPublicKeyId) {
    throw new Error("Invalid Identity catalog access binding")
  }
  if ("challenge" in binding && (!/^[a-f0-9]{64}$/u.test(binding.challenge) ||
      !Number.isSafeInteger(binding.expiresAt) || binding.expiresAt <= 0)) {
    throw new Error("Invalid Identity catalog access request binding")
  }
}

function validateAccess(access: Uint8Array): void {
  if (!(access instanceof Uint8Array) || access.byteLength < 1 || access.byteLength > maxOpaqueAccessBytes) {
    throw new Error("Identity catalog access exceeds its size limit")
  }
}

function isOrigin(value: string): boolean {
  try {
    const parsed = new URL(value)
    return (parsed.protocol === "https:" || parsed.protocol === "http:") && parsed.origin === value
  } catch { return false }
}

function isSealedCatalogAccess(value: unknown): value is SealedCatalogAccess {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false
  const record = value as Record<string, unknown>
  return Object.keys(record).sort().join(",") === "access,binding,kind,purpose,version" &&
    record.kind === "mesh-identity-catalog-access" && record.version === 1 &&
    (record.purpose === "identity-manager" || record.purpose === "application-device") &&
    typeof record.access === "string" && !!record.binding && typeof record.binding === "object" && !Array.isArray(record.binding)
}

function snapshotPublication(value: unknown): RustyIdentityCatalogAccessPublication {
  let publication: unknown
  try { publication = JSON.parse(JSON.stringify(value)) as unknown }
  catch { throw new Error("Invalid Rusty Identity catalog access publication") }
  if (!isRecord(publication) || !hasExactKeys(publication, ["payload", "signerKeyId", "signature"]) ||
      typeof publication.signerKeyId !== "string" || typeof publication.signature !== "string" ||
      !isRecord(publication.payload) || !hasExactKeys(publication.payload, ["kind", "version", "serviceId", "personId",
        "applicationOrigin", "catalogId", "sourceRevision", "recipientDeviceId", "recipientPublicKeyId",
        "recipientPublicKey", "ciphertext", "issuedAt", "publisherAuthorization"])) {
    throw new Error("Invalid Rusty Identity catalog access publication")
  }
  const payload = publication.payload
  if (payload.kind !== "mesh-identity-catalog-access-publication" || payload.version !== 1 ||
      typeof payload.serviceId !== "string" || typeof payload.personId !== "string" ||
      typeof payload.applicationOrigin !== "string" || typeof payload.catalogId !== "string" ||
      typeof payload.sourceRevision !== "number" || typeof payload.recipientDeviceId !== "string" ||
      typeof payload.recipientPublicKeyId !== "string" || typeof payload.recipientPublicKey !== "string" ||
      typeof payload.ciphertext !== "string" || typeof payload.issuedAt !== "number" ||
      !isRecord(payload.publisherAuthorization) ||
      !hasExactKeys(payload.publisherAuthorization, ["request", "proof", "certificate", "rustyServicePins"]) ||
      !Array.isArray(payload.publisherAuthorization.rustyServicePins) ||
      payload.publisherAuthorization.rustyServicePins.length > 32) {
    throw new Error("Invalid Rusty Identity catalog access publication")
  }
  const authorization = payload.publisherAuthorization
  if (!isSignedEnvelope(authorization.request) || !isSignedEnvelope(authorization.proof) ||
      !isDeviceCertificate(authorization.certificate)) {
    throw new Error("Invalid Identity catalog publisher authorization")
  }
  return publication as unknown as RustyIdentityCatalogAccessPublication
}

function isSignedEnvelope(value: unknown): value is SignedEnvelope<Record<string, unknown>> {
  return isRecord(value) && hasExactKeys(value, ["payload", "signerKeyId", "signature"]) &&
    isRecord(value.payload) && typeof value.signerKeyId === "string" && typeof value.signature === "string"
}

function isDeviceCertificate(value: unknown): value is DeviceCertificate {
  return isSignedEnvelope(value) && hasExactKeys(value.payload, ["kind", "version", "personId", "deviceId",
    "devicePublicKey", "issuerCertificateHash", "canEnrollDevices"]) && value.payload.kind === "device-certificate" &&
    value.payload.version === 1 && typeof value.payload.personId === "string" && typeof value.payload.deviceId === "string" &&
    typeof value.payload.devicePublicKey === "string" &&
    (value.payload.issuerCertificateHash === null || typeof value.payload.issuerCertificateHash === "string") &&
    typeof value.payload.canEnrollDevices === "boolean"
}

type RetainedApprovalPayload = Record<string, unknown> & {
  kind: string
  version: number
  request: SignedEnvelope<Record<string, unknown>>
  certificateHash: string
  issuedAt: number
  expiresAt: number
}

function isApprovalProof(value: unknown): value is SignedEnvelope<RetainedApprovalPayload> {
  if (!isSignedEnvelope(value) || !hasExactKeys(value.payload, ["kind", "version", "request", "certificateHash",
    "issuedAt", "expiresAt", "authorityViewDigest", "revocationHead", "rustyServicePinsDigest", "profileStateDigest",
    "identityCatalogAccessDigest"])) return false
  const payload = value.payload
  return payload.kind === "mesh-device-authorization-approval" && payload.version === 5 &&
    typeof payload.certificateHash === "string" && typeof payload.issuedAt === "number" &&
    typeof payload.expiresAt === "number" && isSignedEnvelope(payload.request)
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

let sodiumPromise: Promise<Sodium> | undefined
async function getSodium(): Promise<Sodium> {
  sodiumPromise ??= import("libsodium-wrappers-sumo").then(async module => {
    const sodium = module.default as unknown as Sodium
    await sodium.ready
    return sodium
  })
  return sodiumPromise
}
