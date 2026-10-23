import { getPublicKeyAsync } from "@noble/ed25519"
import { entropyToMnemonic, generateMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39"
import { wordlist } from "@scure/bip39/wordlists/english.js"
import { EFF_LONG_WORDS } from "./eff-long"
import { readIdentityProfileState, readIdentityProfileStateWithRevocations, type IdentityProfileState } from "./identityProfile"

export type PersonId = string
export type DeviceId = string
export type RecoveryStrengthBits = 128 | 192 | 256
export type IdentitySecurity = "legacy" | "better" | "insane"

export type IdentityRecoveryEnvelope = {
  kind: "mesh-identity-recovery"
  version: 3
  personId: PersonId
  security: IdentitySecurity
  kdf: {
    name: "PBKDF2"
    hash: "SHA-256"
    iterations: 600_000
    salt: string
  }
  cipher: {
    name: "AES-GCM"
    iv: string
  }
  ciphertext: string
}

export type RecoverableIdentity = {
  profile: LocalProfile
  recoveryKey: string
  recoveryEnvelope: IdentityRecoveryEnvelope
}

export type IdentityPassphraseEnvelope = {
  kind: "mesh-identity-passphrase"
  version: 1
  personId: PersonId
  kdf: IdentityRecoveryEnvelope["kdf"]
  cipher: IdentityRecoveryEnvelope["cipher"]
  ciphertext: string
}

export type PassphraseIdentity = {
  profile: LocalProfile
  passphraseEnvelope: IdentityPassphraseEnvelope
}

export type SignedEnvelope<T> = {
  payload: T
  signerKeyId: PersonId | DeviceId
  signature: string
}

export type PublicIdentity = {
  personId: PersonId
  publicKey: string
  displayName: string
}

export type DeviceCertificate = SignedEnvelope<{
  kind: "device-certificate"
  version: 1
  personId: PersonId
  deviceId: DeviceId
  devicePublicKey: string
  issuerCertificateHash: string | null
  canEnrollDevices: boolean
}>

export type IdentityDeviceRevocation = SignedEnvelope<{
  kind: "mesh-identity-device-revocation"
  version: 1
  personId: PersonId
  deviceId: DeviceId
  revision: number
  /** Per-device ordered signed-operation hashes observed before this revocation. */
  profileOperationHashes: Record<DeviceId, string[]>
}>

export type IdentityDeviceAuthorityEvidence = {
  certificates: DeviceCertificate[]
  revocations: IdentityDeviceRevocation[]
}

/** Portable, self-verifying authority projection. Profile history remains in the Identity document. */
export type IdentityAuthorityHead = { revision: number; recordHash: string }
export type IdentityAuthorityView = {
  kind: "mesh-identity-authority-view"
  version: 1
  personId: PersonId
  identityPublicKey: string
  certificates: DeviceCertificate[]
  revocations: IdentityDeviceRevocation[]
  /** Hash of the last signed revocation (or identity-bound genesis), independent of certificate enrollment. */
  revocationHead: IdentityAuthorityHead
  /** Digest of identity binding, full sorted certificate catalog and signed revocation history. */
  viewDigest: string
}

const verifiedDeviceAuthority: unique symbol = Symbol("verifiedIdentityDeviceAuthority")
const verifiedDeviceAuthorityState = new WeakMap<object, {
  identity: PublicIdentity
  certificates: DeviceCertificate[]
  revocations: IdentityDeviceRevocation[]
  revokedDeviceIds: Set<string>
  blockedDeviceIds: Set<string>
}>()
const verifiedIdentityAuthorityView = Symbol("verifiedIdentityAuthorityView")
const verifiedIdentityAuthorityViews = new WeakMap<object, IdentityAuthorityView>()
export type VerifiedIdentityAuthorityView = IdentityAuthorityView & {
  [verifiedIdentityAuthorityView]: true
}
export type VerifiedIdentityDeviceAuthority = IdentityDeviceAuthorityEvidence & {
  identity: PublicIdentity
  revokedDeviceIds: DeviceId[]
  blockedDeviceIds: DeviceId[]
  [verifiedDeviceAuthority]: true
}

export type LocalProfile = {
  identity: PublicIdentity
  device: {
    deviceId: DeviceId
    publicKey: string
    displayName: string
  }
  certificate: DeviceCertificate
  privateKeys: {
    identityPrivateKey?: CryptoKey
    devicePrivateKey: CryptoKey
  }
}

export { createDelegatedCertificate, createDeviceAuthorizationRequest, encodeDeviceAuthorizationRequest,
  parseDeviceAuthorizationRequest, createDeviceAuthorizationApproval, issueDeviceAuthorization,
  verifyDeviceAuthorizationApproval, verifyDeviceAuthorizationRequest } from "./deviceAuthorization"
export type { DeviceAuthorizationRequest, DeviceAuthorizationApproval, DeviceAuthorizationApprovalPayload } from "./deviceAuthorization"
export { createIdentityEnrollmentDevice, createIdentityDeviceEnrollmentRequest, issueIdentityDeviceEnrollment,
  verifyIdentityDeviceEnrollmentRequest, identityRequestAllowsRecoveryTransfer } from "./identityEnrollment"
export type { IdentityDeviceEnrollmentRequest, IdentityEnrollmentDevice } from "./identityEnrollment"
export { createServiceLoginRequest, encodeServiceLoginRequest, verifyServiceLoginApproval } from "./serviceLoginClient"

export {
  assertServiceLoginSession,
  createServiceLoginApproval,
  parseServiceLoginRequest,
  serviceLoginPayload,
  snapshotServiceLoginRequest,
} from "./serviceLogin"
export type {
  ServiceLoginApproval,
  ServiceLoginApprovalOptions,
  ServiceLoginPayload,
  ServiceLoginRequest,
} from "./serviceLogin"

export { createIdentityProfileRecovery, openIdentityProfileRecovery, parseIdentityProfileRecoveryFile,
  sealIdentityProfileRecovery } from "./identityProfileRecovery"
export type { IdentityProfileRecoveryFile, IdentityProfileRecoveryPayload } from "./identityProfileRecovery"

export { createIdentityProfileOperation, emptyIdentityProfileState, identityProfileRevision, identityProfileValue,
  createIdentityRustyServicePinOperation, identityProfileRustyServicePins, mergeIdentityProfileState,
  normalizeIdentityRustyServicePin, normalizeIdentityRustyServicePins, observeLegacyIdentityProfile, readIdentityProfileState,
  readIdentityProfileStateWithRevocations } from "./identityProfile"
export type { IdentityProfileField, IdentityProfileOperation, IdentityProfileState, IdentityProfileValue,
  IdentityRustyServicePin } from "./identityProfile"

export type IdentityStoreOptions = {
  storageKey: string
  signatureDomain?: string
  storage?: Pick<Storage, "getItem" | "setItem" | "removeItem">
  asyncStorage?: {
    getItem(key: string): Promise<string | null>
    setItem(key: string, value: string): Promise<void>
    removeItem(key: string): Promise<void>
  }
  requirePersistence?: boolean
}

export function generateRecoveryPhrase(strengthBits: RecoveryStrengthBits = 128): string {
  return generateMnemonic(wordlist, strengthBits)
}

export function identitySecurityWordCount(security: IdentitySecurity): 4 | 12 | 24 {
  if (security === "legacy") return 4
  return security === "insane" ? 24 : 12
}

export function generateIdentityRecovery(security: IdentitySecurity = "better"): string {
  if (security === "legacy") return generateChatKey()
  return generateRecoveryPhrase(security === "insane" ? 256 : 128)
}

export function generateChatKey(): string {
  const words: string[] = []
  const limit = Math.floor(65_536 / EFF_LONG_WORDS.length) * EFF_LONG_WORDS.length
  while (words.length < 4) {
    const sample = crypto.getRandomValues(new Uint16Array(1))[0]
    if (sample < limit) words.push(EFF_LONG_WORDS[sample % EFF_LONG_WORDS.length])
  }
  return words.join(" ")
}

export function normalizeRecoveryPhrase(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, " ")
}

export function recoveryPhraseIsValid(value: string): boolean {
  return validateMnemonic(normalizeRecoveryPhrase(value), wordlist)
}

export function chatKeyIsValid(value: string): boolean {
  const words = normalizeRecoveryPhrase(value).split(" ")
  return words.length === 4 && words.every(word => (EFF_LONG_WORDS as readonly string[]).includes(word))
}

export function identitySecurityForRecovery(value: string): IdentitySecurity | null {
  const normalized = normalizeRecoveryPhrase(value)
  if (chatKeyIsValid(normalized)) return "legacy"
  if (!recoveryPhraseIsValid(normalized)) return null
  const count = normalized.split(" ").length
  if (count === 12) return "better"
  if (count === 24) return "insane"
  return null
}

export function recoveryPhraseFromEntropy(entropy: Uint8Array): string {
  return entropyToMnemonic(entropy, wordlist)
}

export function recoveryPhraseToEntropy(value: string): Uint8Array {
  return mnemonicToEntropy(normalizeRecoveryPhrase(value), wordlist)
}

async function deriveSeed(entropy: Uint8Array, label: string): Promise<Uint8Array> {
  const material = await crypto.subtle.importKey("raw", entropy, "HKDF", false, ["deriveBits"])
  return new Uint8Array(await crypto.subtle.deriveBits({
    name: "HKDF",
    hash: "SHA-256",
    salt: new TextEncoder().encode("meta-mesh/identity/v1"),
    info: new TextEncoder().encode(label),
  }, material, 256))
}

async function importEd25519Private(seed: Uint8Array): Promise<CryptoKey> {
  const prefix = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])
  const pkcs8 = new Uint8Array(prefix.length + seed.length)
  pkcs8.set(prefix)
  pkcs8.set(seed, prefix.length)
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"])
}

const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
])

/**
 * Extract the seed only from the exact Ed25519 PKCS#8 representation this
 * package imports. Keeping this here prevents callers from treating arbitrary
 * PKCS#8 trailing bytes as an identity root.
 */
export async function identitySeedFromPrivateKey(privateKey: CryptoKey, expectedPersonId?: PersonId): Promise<Uint8Array> {
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey))
  if (pkcs8.byteLength !== ED25519_PKCS8_PREFIX.byteLength + 32 ||
    !ED25519_PKCS8_PREFIX.every((byte, index) => pkcs8[index] === byte)) {
    throw new Error("Identity private key is not an exportable Ed25519 root")
  }
  const seed = pkcs8.slice(ED25519_PKCS8_PREFIX.byteLength)
  if (expectedPersonId && await sha256Base64Url(await getPublicKeyAsync(seed)) !== expectedPersonId) {
    throw new Error("Identity private key does not match this identity")
  }
  return seed
}

const RECOVERY_KDF_ITERATIONS = 600_000 as const

function recoveryEnvelopeAad(envelope: Omit<IdentityRecoveryEnvelope, "ciphertext">): Uint8Array {
  return new TextEncoder().encode(canonicalizeJson(envelope))
}

async function recoveryWrappingKey(recoveryKey: string, salt: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(normalizeRecoveryPhrase(recoveryKey)),
    "PBKDF2",
    false,
    ["deriveKey"],
  )
  return crypto.subtle.deriveKey({
    name: "PBKDF2",
    hash: "SHA-256",
    salt,
    iterations: RECOVERY_KDF_ITERATIONS,
  }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"])
}

async function passphraseWrappingKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const normalized = normalizeRecoveryPhrase(passphrase)
  if (!normalized) throw new Error("Passphrase is empty")
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(normalized),
    "PBKDF2",
    false,
    ["deriveKey"],
  )
  return crypto.subtle.deriveKey({
    name: "PBKDF2",
    hash: "SHA-256",
    salt,
    iterations: RECOVERY_KDF_ITERATIONS,
  }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"])
}

export async function sealIdentitySeed(
  identitySeed: Uint8Array,
  personId: PersonId,
  recoveryKey: string,
  security: IdentitySecurity,
): Promise<IdentityRecoveryEnvelope> {
  if (identitySeed.byteLength !== 32) throw new Error("Identity root must contain 32 bytes")
  if (identitySecurityForRecovery(recoveryKey) !== security) throw new Error("Invalid identity recovery")
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const header: Omit<IdentityRecoveryEnvelope, "ciphertext"> = {
    kind: "mesh-identity-recovery",
    version: 3,
    personId,
    security,
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: RECOVERY_KDF_ITERATIONS,
      salt: toBase64Url(salt),
    },
    cipher: { name: "AES-GCM", iv: toBase64Url(iv) },
  }
  const key = await recoveryWrappingKey(recoveryKey, salt)
  const ciphertext = await crypto.subtle.encrypt({
    name: "AES-GCM",
    iv,
    additionalData: recoveryEnvelopeAad(header),
    tagLength: 128,
  }, key, identitySeed)
  return { ...header, ciphertext: toBase64Url(new Uint8Array(ciphertext)) }
}

function assertRecoveryEnvelope(value: IdentityRecoveryEnvelope): void {
  if (value?.kind !== "mesh-identity-recovery" || value.version !== 3 || !value.personId ||
    !["legacy", "better", "insane"].includes(value.security) ||
    value.kdf?.name !== "PBKDF2" || value.kdf.hash !== "SHA-256" ||
    value.kdf.iterations !== RECOVERY_KDF_ITERATIONS || value.cipher?.name !== "AES-GCM" ||
    fromBase64Url(value.kdf.salt).byteLength !== 16 || fromBase64Url(value.cipher.iv).byteLength !== 12 ||
    fromBase64Url(value.ciphertext).byteLength !== 48) throw new Error("Invalid identity recovery envelope")
}

async function sealIdentitySeedWithPassphrase(
  identitySeed: Uint8Array,
  personId: PersonId,
  passphrase: string,
): Promise<IdentityPassphraseEnvelope> {
  if (identitySeed.byteLength !== 32) throw new Error("Identity root must contain 32 bytes")
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const header: Omit<IdentityPassphraseEnvelope, "ciphertext"> = {
    kind: "mesh-identity-passphrase",
    version: 1,
    personId,
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: RECOVERY_KDF_ITERATIONS,
      salt: toBase64Url(salt),
    },
    cipher: { name: "AES-GCM", iv: toBase64Url(iv) },
  }
  const key = await passphraseWrappingKey(passphrase, salt)
  const ciphertext = await crypto.subtle.encrypt({
    name: "AES-GCM",
    iv,
    additionalData: new TextEncoder().encode(canonicalizeJson(header)),
    tagLength: 128,
  }, key, identitySeed)
  return { ...header, ciphertext: toBase64Url(new Uint8Array(ciphertext)) }
}

function assertPassphraseEnvelope(value: IdentityPassphraseEnvelope): void {
  if (value?.kind !== "mesh-identity-passphrase" || value.version !== 1 || !value.personId ||
    value.kdf?.name !== "PBKDF2" || value.kdf.hash !== "SHA-256" ||
    value.kdf.iterations !== RECOVERY_KDF_ITERATIONS || value.cipher?.name !== "AES-GCM" ||
    fromBase64Url(value.kdf.salt).byteLength !== 16 || fromBase64Url(value.cipher.iv).byteLength !== 12 ||
    fromBase64Url(value.ciphertext).byteLength !== 48) throw new Error("Invalid identity passphrase envelope")
}

async function openIdentitySeedWithPassphrase(
  envelope: IdentityPassphraseEnvelope,
  passphrase: string,
): Promise<Uint8Array> {
  try {
    assertPassphraseEnvelope(envelope)
    const { ciphertext: _ciphertext, ...header } = envelope
    const key = await passphraseWrappingKey(passphrase, fromBase64Url(envelope.kdf.salt))
    const plaintext = await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv: fromBase64Url(envelope.cipher.iv),
      additionalData: new TextEncoder().encode(canonicalizeJson(header)),
      tagLength: 128,
    }, key, fromBase64Url(envelope.ciphertext))
    const seed = new Uint8Array(plaintext)
    if (seed.byteLength !== 32 || await sha256Base64Url(await getPublicKeyAsync(seed)) !== envelope.personId) {
      throw new Error("identity mismatch")
    }
    return seed
  } catch {
    throw new Error("Passphrase does not open this identity")
  }
}

async function openIdentitySeed(
  envelope: IdentityRecoveryEnvelope,
  recoveryKey: string,
): Promise<Uint8Array> {
  try {
    assertRecoveryEnvelope(envelope)
    if (identitySecurityForRecovery(recoveryKey) !== envelope.security) throw new Error("wrong recovery")
    const { ciphertext: _ciphertext, ...header } = envelope
    const key = await recoveryWrappingKey(recoveryKey, fromBase64Url(envelope.kdf.salt))
    const plaintext = await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv: fromBase64Url(envelope.cipher.iv),
      additionalData: recoveryEnvelopeAad(header),
      tagLength: 128,
    }, key, fromBase64Url(envelope.ciphertext))
    const seed = new Uint8Array(plaintext)
    if (seed.byteLength !== 32 || await sha256Base64Url(await getPublicKeyAsync(seed)) !== envelope.personId) {
      throw new Error("identity mismatch")
    }
    return seed
  } catch {
    throw new Error("Recovery words do not open this identity")
  }
}

export async function profileFromIdentitySeedForDevice(
  identitySeed: Uint8Array,
  displayName = "Mesh user",
  deviceEntropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32)),
): Promise<LocalProfile> {
  if (identitySeed.byteLength !== 32) throw new Error("Identity root must contain 32 bytes")
  if (deviceEntropy.byteLength !== 32) throw new Error("Device entropy must contain 32 bytes")
  const deviceSeed = await deriveSeed(deviceEntropy, "device")
  const identityPublic = await getPublicKeyAsync(identitySeed)
  const devicePublic = await getPublicKeyAsync(deviceSeed)
  const identityPrivateKey = await importEd25519Private(identitySeed)
  const devicePrivateKey = await importEd25519Private(deviceSeed)
  const personId = await sha256Base64Url(identityPublic)
  const deviceId = await sha256Base64Url(devicePublic)
  const identity: PublicIdentity = { personId, publicKey: toBase64Url(identityPublic), displayName }
  const certificate = await signEnvelope(identityPrivateKey, {
    kind: "device-certificate" as const,
    version: 1 as const,
    personId,
    deviceId,
    devicePublicKey: toBase64Url(devicePublic),
    issuerCertificateHash: null,
    canEnrollDevices: true as const,
  }, personId)
  return {
    identity,
    device: { deviceId, publicKey: toBase64Url(devicePublic), displayName: `${displayName}'s device` },
    certificate,
    privateKeys: { identityPrivateKey, devicePrivateKey },
  }
}

export async function createRecoverableIdentity(
  security: IdentitySecurity = "better",
  displayName = "Mesh user",
  deviceEntropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32)),
): Promise<RecoverableIdentity> {
  const recoveryKey = generateIdentityRecovery(security)
  const identitySeed = crypto.getRandomValues(new Uint8Array(32))
  const profile = await profileFromIdentitySeedForDevice(identitySeed, displayName, deviceEntropy)
  const recoveryEnvelope = await sealIdentitySeed(identitySeed, profile.identity.personId, recoveryKey, security)
  return { profile, recoveryKey, recoveryEnvelope }
}

export async function openIdentityRecoveryEnvelope(
  envelope: IdentityRecoveryEnvelope,
  recoveryKey: string,
  displayName = "Mesh user",
  deviceEntropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32)),
): Promise<LocalProfile> {
  return profileFromIdentitySeedForDevice(await openIdentitySeed(envelope, recoveryKey), displayName, deviceEntropy)
}

export async function createPassphraseIdentity(
  passphrase: string,
  displayName = "Mesh user",
  deviceEntropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32)),
): Promise<PassphraseIdentity> {
  const identitySeed = crypto.getRandomValues(new Uint8Array(32))
  const profile = await profileFromIdentitySeedForDevice(identitySeed, displayName, deviceEntropy)
  const passphraseEnvelope = await sealIdentitySeedWithPassphrase(identitySeed, profile.identity.personId, passphrase)
  return { profile, passphraseEnvelope }
}

export async function openIdentityPassphraseEnvelope(
  envelope: IdentityPassphraseEnvelope,
  passphrase: string,
  displayName = "Mesh user",
  deviceEntropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32)),
): Promise<LocalProfile> {
  return profileFromIdentitySeedForDevice(
    await openIdentitySeedWithPassphrase(envelope, passphrase),
    displayName,
    deviceEntropy,
  )
}

export async function rewrapIdentityRecoveryEnvelope(
  envelope: IdentityRecoveryEnvelope,
  currentRecoveryKey: string,
  security: IdentitySecurity,
): Promise<Pick<RecoverableIdentity, "recoveryKey" | "recoveryEnvelope">> {
  const identitySeed = await openIdentitySeed(envelope, currentRecoveryKey)
  const recoveryKey = generateIdentityRecovery(security)
  return {
    recoveryKey,
    recoveryEnvelope: await sealIdentitySeed(
      identitySeed,
      envelope.personId,
      recoveryKey,
      security,
    ),
  }
}

type SerializedProfile = {
  identity: PublicIdentity
  device: LocalProfile["device"]
  certificate: DeviceCertificate
  privateKeys: {
    identityPrivateKeyPkcs8?: string
    devicePrivateKeyPkcs8: string
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}

export type IdentityAdoptionCommitPlan = {
  storageKey: string
  previousProfile: string | null
  candidateProfile: string
  publicProfile: Pick<LocalProfile, "identity" | "device" | "certificate">
  backup?: { key: string; value: string }
}

export type IdentityAdoptionCommit = (
  plan: IdentityAdoptionCommitPlan,
  ensureCurrent: () => void,
) => Promise<void>

function compareCanonicalKeys(left: string, right: string): number {
  let leftIndex = 0
  let rightIndex = 0
  while (leftIndex < left.length && rightIndex < right.length) {
    const leftPoint = left.codePointAt(leftIndex)!
    const rightPoint = right.codePointAt(rightIndex)!
    if (leftPoint !== rightPoint) return leftPoint - rightPoint
    leftIndex += leftPoint > 0xffff ? 2 : 1
    rightIndex += rightPoint > 0xffff ? 2 : 1
  }
  return (leftIndex < left.length ? 1 : 0) - (rightIndex < right.length ? 1 : 0)
}

function canonicalizeJsonWithOrder(value: unknown, compareKeys?: (left: string, right: string) => number): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error("Non-finite number cannot be canonicalized")
    }
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return "[" + value.map(item => canonicalizeJsonWithOrder(item, compareKeys)).join(",") + "]"
  const object = value as Record<string, unknown>
  return "{" + Object.keys(object).sort(compareKeys)
    .map(key => `${JSON.stringify(key)}:${canonicalizeJsonWithOrder(object[key], compareKeys)}`).join(",") + "}"
}

export function canonicalizeJson(value: unknown): string {
  return canonicalizeJsonWithOrder(value)
}

function canonicalizeSignatureJson(value: unknown): string {
  // Rust strings sort by Unicode scalar value, rather than JavaScript UTF-16 units.
  return canonicalizeJsonWithOrder(value, compareCanonicalKeys)
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function fromBase64Url(value: string): Uint8Array {
  let base64 = value.replace(/-/g, "+").replace(/_/g, "/")
  while (base64.length % 4 !== 0) base64 += "="
  const binary = atob(base64)
  return Uint8Array.from(binary, character => character.charCodeAt(0))
}

export async function sha256Base64Url(data: Uint8Array): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", data)))
}

export async function publicKeyId(publicKey: string): Promise<string> {
  const bytes = fromBase64Url(publicKey)
  if (bytes.byteLength !== 32) throw new Error("Invalid public key")
  return sha256Base64Url(bytes)
}

export async function certificateHash(certificate: DeviceCertificate): Promise<string> {
  return sha256Base64Url(new TextEncoder().encode(canonicalizeJson(certificate)))
}

export async function verifyDeviceCertificateChain(
  identity: PublicIdentity,
  deviceId: string,
  certificates: DeviceCertificate[],
  domain = "MATCH/1",
): Promise<string> {
  if (await publicKeyId(identity.publicKey) !== identity.personId) throw new Error("Identity does not match its key")
  if (!Array.isArray(certificates) || certificates.length < 1 || certificates.length > 32) {
    throw new Error("Invalid certificate chain")
  }
  const byHash = new Map<string, DeviceCertificate>()
  for (const certificate of certificates) byHash.set(await certificateHash(certificate), certificate)
  const leaf = certificates.find(certificate => certificate.payload.deviceId === deviceId)
  if (!leaf) throw new Error("Missing device certificate")
  let current: DeviceCertificate | undefined = leaf
  const seen = new Set<string>()
  while (current) {
    const payload = current.payload
    if (payload.kind !== "device-certificate" || payload.version !== 1 ||
      payload.personId !== identity.personId || await publicKeyId(payload.devicePublicKey) !== payload.deviceId ||
      seen.has(payload.deviceId)) throw new Error("Invalid device certificate")
    seen.add(payload.deviceId)
    if (payload.issuerCertificateHash === null) {
      if (current.signerKeyId !== identity.personId ||
        !await verifyEnvelope(current, identity.publicKey, domain)) throw new Error("Invalid root certificate")
      return leaf.payload.devicePublicKey
    }
    const issuer = byHash.get(payload.issuerCertificateHash)
    if (!issuer || !issuer.payload.canEnrollDevices || current.signerKeyId !== issuer.payload.deviceId ||
      !await verifyEnvelope(current, issuer.payload.devicePublicKey, domain)) throw new Error("Invalid certificate chain")
    current = issuer
  }
  throw new Error("Invalid certificate chain")
}

/** Verify an append-only, revision-ordered Identity device authority view. */
export async function verifyIdentityDeviceAuthority(
  identity: PublicIdentity,
  evidenceValue: IdentityDeviceAuthorityEvidence,
  domain = "MATCH/1",
): Promise<VerifiedIdentityDeviceAuthority> {
  const evidence = structuredClone(evidenceValue)
  if (!evidence || !Array.isArray(evidence.certificates) || evidence.certificates.length < 1 ||
      evidence.certificates.length > 256 || !Array.isArray(evidence.revocations) || evidence.revocations.length > 256) {
    throw new Error("Invalid Identity device authority evidence")
  }
  const byDevice = new Map<string, DeviceCertificate>()
  for (const certificate of evidence.certificates) {
    const deviceId = certificate?.payload?.deviceId
    if (typeof deviceId !== "string" || byDevice.has(deviceId)) throw new Error("Conflicting Identity device certificate")
    byDevice.set(deviceId, certificate)
  }
  for (const deviceId of byDevice.keys()) {
    await verifyDeviceCertificateChain(identity, deviceId, evidence.certificates, domain)
  }

  const ordered = [...evidence.revocations].sort((left, right) => left?.payload?.revision - right?.payload?.revision)
  const revoked = new Set<string>()
  const coveredSubtrees = new Set<string>()
  let totalProfileOperations = 0
  for (let index = 0; index < ordered.length; index += 1) {
    const record = ordered[index]!
    const payload = record?.payload
    const signerId = record?.signerKeyId
    if (!payload || payload.kind !== "mesh-identity-device-revocation" || payload.version !== 1 ||
        Object.keys(payload).sort().join(",") !== "deviceId,kind,personId,profileOperationHashes,revision,version" ||
        payload.personId !== identity.personId || !byDevice.has(payload.deviceId) ||
        !Number.isSafeInteger(payload.revision) || payload.revision !== index + 1 ||
        !payload.profileOperationHashes || typeof payload.profileOperationHashes !== "object" ||
        Array.isArray(payload.profileOperationHashes) || Object.keys(payload.profileOperationHashes).length > 256 ||
        typeof signerId !== "string" || signerId === payload.deviceId || revoked.has(payload.deviceId) ||
        await isChainRevoked(signerId, revoked, evidence.certificates) ||
        await isChainRevoked(payload.deviceId, revoked, evidence.certificates)) {
      throw new Error("Invalid or stale Identity device revocation")
    }
    const subtree = await identityDeviceDescendants(payload.deviceId, evidence.certificates)
    for (const deviceId of subtree) {
      if (coveredSubtrees.has(deviceId)) throw new Error("Overlapping Identity device revocation subtrees")
      coveredSubtrees.add(deviceId)
    }
    let observedOperationCount = 0
    for (const [deviceId, hashes] of Object.entries(payload.profileOperationHashes)) {
      if (!subtree.has(deviceId) || !Array.isArray(hashes) || hashes.length > 512 ||
          hashes.some(hash => typeof hash !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(hash))) {
        throw new Error("Invalid Identity profile revocation frontier")
      }
      observedOperationCount += hashes.length
      if (observedOperationCount > 512) throw new Error("Identity profile revocation frontier exceeds the limit")
    }
    totalProfileOperations += observedOperationCount
    if (totalProfileOperations > 512) throw new Error("Identity profile revocation history exceeds the limit")
    const signer = byDevice.get(signerId)
    if (!signer?.payload.canEnrollDevices) throw new Error("Identity device lacks revocation authority")
    const signerKey = await verifyDeviceCertificateChain(identity, signerId, evidence.certificates, domain)
    if (!await verifyEnvelope(record, signerKey, domain)) throw new Error("Invalid Identity device revocation signature")
    revoked.add(payload.deviceId)
    if (!(await activeManagementDevices(identity, evidence.certificates, revoked, domain))) {
      throw new Error("Identity device revocation would remove the last management authority")
    }
  }
  const blockedDeviceIds: string[] = []
  for (const deviceId of byDevice.keys()) {
    if (await isChainRevoked(deviceId, revoked, evidence.certificates)) blockedDeviceIds.push(deviceId)
  }
  const authority: VerifiedIdentityDeviceAuthority = { ...evidence, identity: structuredClone(identity),
    revokedDeviceIds: [...revoked], blockedDeviceIds,
    [verifiedDeviceAuthority]: true }
  verifiedDeviceAuthorityState.set(authority, {
    identity: structuredClone(identity),
    certificates: structuredClone(evidence.certificates),
    revocations: structuredClone(ordered),
    revokedDeviceIds: new Set(revoked),
    blockedDeviceIds: new Set(blockedDeviceIds),
  })
  return authority
}

/** Build the portable projection only after validating the signed profile cutoff history. */
export async function createIdentityAuthorityView(
  identity: PublicIdentity,
  evidenceValue: IdentityDeviceAuthorityEvidence,
  profileState: IdentityProfileState,
  domain = "MATCH/1",
): Promise<VerifiedIdentityAuthorityView> {
  const evidence = structuredClone(evidenceValue)
  const authority = await verifyIdentityDeviceAuthority(identity, evidence, domain)
  const profile = await readIdentityProfileState(profileState, identity, authority.certificates)
  const authorizedProfile = await readIdentityProfileStateWithRevocations(profile, identity,
    authority.certificates, authority.revocations)
  if (canonicalizeJson(profile) !== canonicalizeJson(authorizedProfile)) {
    throw new Error("Identity profile history contains operations outside the signed authority view")
  }
  const view = await makeIdentityAuthorityView(identity, authority.certificates, authority.revocations)
  return verifyIdentityAuthorityView(view, domain)
}

/** Explicit local-first genesis path; adopted device certificates cannot bootstrap a person's Rusty authority. */
export async function createLocalRootIdentityAuthorityView(
  profile: LocalProfile,
  evidenceValue: IdentityDeviceAuthorityEvidence,
  profileState: IdentityProfileState,
  domain = "MATCH/1",
): Promise<VerifiedIdentityAuthorityView> {
  const rootKey = profile.privateKeys.identityPrivateKey
  if (!rootKey || profile.identity.personId !== await publicKeyId(profile.identity.publicKey) ||
      profile.device.deviceId !== profile.certificate.payload.deviceId ||
      profile.device.publicKey !== profile.certificate.payload.devicePublicKey ||
      profile.certificate.signerKeyId !== profile.identity.personId ||
      profile.certificate.payload.issuerCertificateHash !== null ||
      !profile.certificate.payload.canEnrollDevices ||
      !evidenceValue.certificates.some(value => canonicalizeJson(value) === canonicalizeJson(profile.certificate))) {
    throw new Error("A local root profile with root authority is required to create Identity authority genesis")
  }
  const seed = await identitySeedFromPrivateKey(rootKey, profile.identity.personId)
  seed.fill(0)
  const authority = await verifyIdentityDeviceAuthority(profile.identity, evidenceValue, domain)
  await authorizeIdentityDevice(authority, profile.device.deviceId, domain)
  return createIdentityAuthorityView(profile.identity, evidenceValue, profileState, domain)
}

/** Verify a portable view before it is stored, merged or used to authorize an actor. */
export async function verifyIdentityAuthorityView(
  value: unknown,
  domain = "MATCH/1",
): Promise<VerifiedIdentityAuthorityView> {
  if (!isRecord(value) || !hasExactKeys(value, ["kind", "version", "personId", "identityPublicKey",
    "certificates", "revocations", "revocationHead", "viewDigest"]) ||
      value.kind !== "mesh-identity-authority-view" || value.version !== 1 ||
      typeof value.personId !== "string" || typeof value.identityPublicKey !== "string" ||
      !Array.isArray(value.certificates) || !Array.isArray(value.revocations) ||
      !isRecord(value.revocationHead) || !hasExactKeys(value.revocationHead, ["revision", "recordHash"]) ||
      !Number.isSafeInteger(value.revocationHead.revision) || typeof value.revocationHead.recordHash !== "string" ||
      typeof value.viewDigest !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value.viewDigest)) {
    throw new Error("Invalid Identity authority view")
  }
  const identity: PublicIdentity = { personId: value.personId, publicKey: value.identityPublicKey, displayName: "" }
  const identityKeyId = await publicKeyId(identity.publicKey)
  if (identityKeyId !== identity.personId) throw new Error("Identity authority view key does not match its person")
  const evidence: IdentityDeviceAuthorityEvidence = {
    certificates: structuredClone(value.certificates) as DeviceCertificate[],
    revocations: structuredClone(value.revocations) as IdentityDeviceRevocation[],
  }
  await verifyIdentityDeviceAuthority(identity, evidence, domain)
  const expectedHead = await identityAuthorityHead(identity, evidence.revocations)
  if (canonicalizeJson(value.revocationHead) !== canonicalizeJson(expectedHead)) {
    throw new Error("Identity authority view has an invalid revocation head")
  }
  const expected = await makeIdentityAuthorityView(identity, evidence.certificates, evidence.revocations)
  if (value.viewDigest !== expected.viewDigest) throw new Error("Identity authority view digest mismatch")
  const verified = structuredClone(expected) as VerifiedIdentityAuthorityView
  Object.defineProperty(verified, verifiedIdentityAuthorityView, { value: true, enumerable: false })
  verifiedIdentityAuthorityViews.set(verified, structuredClone(expected))
  return verified
}

/** Merge an incoming view only when its signed revocation history extends the current head. */
export async function mergeIdentityAuthorityViews(
  currentValue: unknown,
  incomingValue: unknown,
  domain = "MATCH/1",
): Promise<VerifiedIdentityAuthorityView> {
  const current = await verifyIdentityAuthorityView(currentValue, domain)
  const incoming = await verifyIdentityAuthorityView(incomingValue, domain)
  if (current.personId !== incoming.personId || current.identityPublicKey !== incoming.identityPublicKey) {
    throw new Error("Identity authority views belong to different people")
  }
  if (incoming.revocationHead.revision < current.revocationHead.revision) {
    throw new Error("Stale Identity revocation head")
  }
  for (let index = 0; index < current.revocations.length; index += 1) {
    if (canonicalizeJson(current.revocations[index]) !== canonicalizeJson(incoming.revocations[index])) {
      throw new Error("Identity revocation history fork or missing prefix")
    }
  }
  const certificates = new Map<string, DeviceCertificate>()
  for (const certificate of [...current.certificates, ...incoming.certificates]) {
    const previous = certificates.get(certificate.payload.deviceId)
    if (previous && canonicalizeJson(previous) !== canonicalizeJson(certificate)) {
      throw new Error("Conflicting Identity certificate catalog entries")
    }
    certificates.set(certificate.payload.deviceId, certificate)
  }
  return verifyIdentityAuthorityView(await makeIdentityAuthorityView(
    { personId: current.personId, publicKey: current.identityPublicKey, displayName: "" },
    [...certificates.values()], incoming.revocations), domain)
}

/** Return the certified key for an active data actor, including app-scoped certificates. */
export async function authorizeIdentityDataDevice(
  authorityView: VerifiedIdentityAuthorityView,
  deviceId: DeviceId,
  domain = "MATCH/1",
): Promise<string> {
  const view = verifiedIdentityAuthorityViews.get(authorityView)
  if (!view || !authorityView[verifiedIdentityAuthorityView]) throw new Error("Identity authority view was not verified")
  const identity: PublicIdentity = { personId: view.personId, publicKey: view.identityPublicKey, displayName: "" }
  const authority = await verifyIdentityDeviceAuthority(identity,
    { certificates: view.certificates, revocations: view.revocations }, domain)
  const state = verifiedDeviceAuthorityState.get(authority)
  if (!state || state.blockedDeviceIds.has(deviceId)) throw new Error("Identity device access is revoked")
  return verifyDeviceCertificateChain(identity, deviceId, authority.certificates, domain)
}

async function makeIdentityAuthorityView(
  identity: PublicIdentity,
  certificatesValue: readonly DeviceCertificate[],
  revocationsValue: readonly IdentityDeviceRevocation[],
): Promise<IdentityAuthorityView> {
  const certificates = structuredClone(Array.from(certificatesValue))
    .sort((left, right) => left.payload.deviceId.localeCompare(right.payload.deviceId))
  const revocations = structuredClone(Array.from(revocationsValue))
    .sort((left, right) => left.payload.revision - right.payload.revision)
  const head = await identityAuthorityHead(identity, revocations)
  const digestPayload = { kind: "mesh-identity-authority-view" as const, version: 1 as const,
    personId: identity.personId, identityPublicKey: identity.publicKey, certificates, revocations }
  return { ...digestPayload, revocationHead: head,
    viewDigest: await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(digestPayload))) }
}

async function identityAuthorityHead(identity: Pick<PublicIdentity, "personId" | "publicKey">,
  revocations: readonly IdentityDeviceRevocation[]): Promise<IdentityAuthorityHead> {
  const last = revocations.at(-1)
  const material = last ? canonicalizeJson(last) : canonicalizeJson({
    kind: "mesh-identity-revocation-genesis", version: 1, personId: identity.personId,
    identityPublicKey: identity.publicKey,
  })
  return { revision: revocations.length,
    recordHash: await sha256Base64Url(new TextEncoder().encode(material)) }
}

/** Return the certified key only when the device and all its issuers remain authorized. */
export async function authorizeIdentityDevice(
  authority: VerifiedIdentityDeviceAuthority,
  deviceId: DeviceId,
  domain = "MATCH/1",
): Promise<string> {
  const state = verifiedDeviceAuthorityState.get(authority)
  if (!state || !authority[verifiedDeviceAuthority]) throw new Error("Identity device authority was not verified")
  if (state.blockedDeviceIds.has(deviceId)) throw new Error("Identity device access is revoked")
  if (!state.certificates.find(value => value.payload.deviceId === deviceId)?.payload.canEnrollDevices) {
    throw new Error("Device lacks Identity management authority")
  }
  return verifyDeviceCertificateChain(state.identity, deviceId, state.certificates, domain)
}

/** Create one revision against the exact authority view loaded by this profile. */
export async function createDeviceRevocation(
  profile: LocalProfile,
  authority: VerifiedIdentityDeviceAuthority,
  deviceId: DeviceId,
  profileState: IdentityProfileState,
  domain = "MATCH/1",
): Promise<IdentityDeviceRevocation> {
  const signerId = profile.device.deviceId
  const state = verifiedDeviceAuthorityState.get(authority)
  if (!state || !authority[verifiedDeviceAuthority]) throw new Error("Identity device authority was not verified")
  if (state.identity.personId !== profile.identity.personId ||
      state.identity.publicKey !== profile.identity.publicKey || deviceId === signerId ||
      !state.certificates.some(value => canonicalizeJson(value) === canonicalizeJson(profile.certificate)) ||
      !state.certificates.some(value => value.payload.deviceId === deviceId) ||
      await isChainRevoked(signerId, state.revokedDeviceIds, state.certificates)) {
    throw new Error("Current Identity device cannot revoke this device")
  }
  const signer = state.certificates.find(value => value.payload.deviceId === signerId)
  if (!signer?.payload.canEnrollDevices) throw new Error("Current Identity device lacks revocation authority")
  const validatedProfile = await readIdentityProfileState(profileState, profile.identity, state.certificates)
  const currentProfile = await readIdentityProfileStateWithRevocations(validatedProfile, profile.identity,
    state.certificates, state.revocations)
  if (canonicalizeJson(currentProfile) !== canonicalizeJson(validatedProfile)) {
    throw new Error("Identity profile history contains revoked device operations")
  }
  const subtree = await identityDeviceDescendants(deviceId, state.certificates)
  const profileOperationHashes: Record<string, string[]> = {}
  const operations = currentProfile.operations.filter(operation => subtree.has(operation.signed.payload.deviceId))
    .sort((left, right) => left.signed.payload.counter - right.signed.payload.counter)
  for (const operation of operations) {
    const actor = operation.signed.payload.deviceId
    if (!subtree.has(actor)) continue
    const currentCertificate = state.certificates.find(value => value.payload.deviceId === actor)
    const historicalLeaf = operation.certificates.find(value => value.payload.deviceId === actor)
    if (!currentCertificate || !historicalLeaf || canonicalizeJson(currentCertificate) !== canonicalizeJson(historicalLeaf)) {
      throw new Error("Identity profile history does not match current device authority")
    }
    const hashes = profileOperationHashes[actor] ??= []
    const counter = operation.signed.payload.counter
    if (counter !== hashes.length + 1) throw new Error("Identity profile history is not a complete device prefix")
    hashes.push(await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(operation.signed))))
  }
  const record = await signEnvelope(profile.privateKeys.devicePrivateKey, {
    kind: "mesh-identity-device-revocation" as const,
    version: 1 as const,
    personId: profile.identity.personId,
    deviceId,
    revision: state.revocations.length + 1,
    profileOperationHashes,
  }, signerId, domain)
  await verifyIdentityDeviceAuthority(profile.identity, {
    certificates: state.certificates,
    revocations: [...state.revocations, record],
  }, domain)
  return record
}

async function isChainRevoked(deviceId: string, revoked: ReadonlySet<string>, certificates: readonly DeviceCertificate[]): Promise<boolean> {
  const byHash = new Map<string, DeviceCertificate>()
  for (const certificate of certificates) byHash.set(await certificateHash(certificate), certificate)
  let current = certificates.find(certificate => certificate.payload.deviceId === deviceId)
  const seen = new Set<string>()
  while (current) {
    const currentId = current.payload.deviceId
    if (revoked.has(currentId) || seen.has(currentId)) return true
    seen.add(currentId)
    const issuerHash = current.payload.issuerCertificateHash
    if (issuerHash === null) return false
    current = byHash.get(issuerHash)
  }
  return true
}

export async function identityDeviceDescendants(rootId: string, certificates: readonly DeviceCertificate[]): Promise<Set<string>> {
  const subtree = new Set<string>()
  for (const certificate of certificates) {
    if (await isCertificateDescendant(certificate, rootId, certificates)) subtree.add(certificate.payload.deviceId)
  }
  return subtree
}

async function isCertificateDescendant(certificate: DeviceCertificate, rootId: string,
  certificates: readonly DeviceCertificate[]): Promise<boolean> {
  const byHash = new Map<string, DeviceCertificate>()
  for (const item of certificates) byHash.set(await certificateHash(item), item)
  let current: DeviceCertificate | undefined = certificate
  const seen = new Set<string>()
  while (current) {
    const currentId = current.payload.deviceId
    if (currentId === rootId) return true
    if (seen.has(currentId)) return false
    seen.add(currentId)
    const issuerHash = current.payload.issuerCertificateHash
    if (issuerHash === null) return false
    current = byHash.get(issuerHash)
  }
  return false
}

async function activeManagementDevices(identity: PublicIdentity, certificates: readonly DeviceCertificate[],
  revoked: ReadonlySet<string>, domain: string): Promise<boolean> {
  for (const certificate of certificates) {
    if (certificate.payload.canEnrollDevices && !await isChainRevoked(certificate.payload.deviceId, revoked, certificates)) {
      try {
        await verifyDeviceCertificateChain(identity, certificate.payload.deviceId, Array.from(certificates), domain)
        return true
      } catch { /* Invalid certificates do not count as management authorities. */ }
    }
  }
  return false
}

export function signatureInput(payloadKind: string, canonicalPayload: string, domain = "MATCH/1"): Uint8Array {
  const encoder = new TextEncoder()
  const prefix = encoder.encode(`${domain}/${payloadKind}\0`)
  const payload = encoder.encode(canonicalPayload)
  const result = new Uint8Array(prefix.length + payload.length)
  result.set(prefix)
  result.set(payload, prefix.length)
  return result
}

export async function signEnvelope<T extends { kind: string }>(
  privateKey: CryptoKey,
  payload: T,
  signerKeyId: PersonId | DeviceId,
  domain = "MATCH/1",
): Promise<SignedEnvelope<T>> {
  const input = signatureInput(payload.kind, canonicalizeSignatureJson(payload), domain)
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, input)
  return { payload, signerKeyId, signature: toBase64Url(new Uint8Array(signature)) }
}

export async function verifyEnvelope<T extends { kind: string }>(
  envelope: SignedEnvelope<T>,
  publicKeyRawOrCrypto: string | CryptoKey,
  domain = "MATCH/1",
): Promise<boolean> {
  const key = typeof publicKeyRawOrCrypto === "string"
    ? await crypto.subtle.importKey("raw", fromBase64Url(publicKeyRawOrCrypto), { name: "Ed25519" }, true, ["verify"])
    : publicKeyRawOrCrypto
  const canonical = canonicalizeSignatureJson(envelope.payload)
  const signature = fromBase64Url(envelope.signature)
  if (await crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    signature,
    signatureInput(envelope.payload.kind, canonical, domain),
  )) return true
  // Preserve envelopes signed by browser clients before scalar key ordering was shared.
  const legacyCanonical = canonicalizeJsonWithOrder(envelope.payload)
  return legacyCanonical !== canonical && crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    signature,
    signatureInput(envelope.payload.kind, legacyCanonical, domain),
  )
}

export class BrowserIdentityStore {
  private profile: LocalProfile | null = null
  private booting: Promise<LocalProfile> | null = null
  private presentationRefresh: { profile: LocalProfile | null; expectedRaw: string | undefined; result: Promise<LocalProfile> } | null = null
  private readonly memory = new Map<string, string>()
  private readonly domain: string

  constructor(private readonly options: IdentityStoreOptions) {
    this.domain = options.signatureDomain ?? "MATCH/1"
  }

  private storage() {
    if (this.options.storage) return this.options.storage
    try {
      return typeof localStorage === "undefined" ? undefined : localStorage
    } catch {
      return undefined
    }
  }

  private async get(key: string): Promise<string | null> {
    if (this.options.asyncStorage) return await this.options.asyncStorage.getItem(key)
    try { return this.storage()?.getItem(key) ?? this.memory.get(key) ?? null }
    catch { return this.memory.get(key) ?? null }
  }

  private async set(key: string, value: string, strict = false) {
    if (this.options.asyncStorage) {
      await this.options.asyncStorage.setItem(key, value)
      this.memory.set(key, value)
      return
    }
    try { this.storage()?.setItem(key, value) }
    catch (error) { if (strict) throw error }
    this.memory.set(key, value)
  }

  private async remove(key: string) {
    if (this.options.asyncStorage) await this.options.asyncStorage.removeItem(key)
    else try { this.storage()?.removeItem(key) } catch {}
    this.memory.delete(key)
  }

  clearMemory() {
    this.profile = null
    this.booting = null
  }

  /** A replaced cached identity must invalidate operations still holding its previous profile. */
  isCurrentProfile(profile: LocalProfile): boolean { return this.profile === profile }

  /** Refresh presentation labels after a trusted app transaction updates durable local metadata. */
  refreshPresentation(expectedRaw?: string): Promise<LocalProfile> {
    const running = this.presentationRefresh
    if (running?.profile === this.profile && running.expectedRaw === expectedRaw) return running.result
    const result = this.refreshPresentationSnapshot(expectedRaw)
    this.presentationRefresh = { profile: this.profile, expectedRaw, result }
    const settled = () => { if (this.presentationRefresh?.result === result) this.presentationRefresh = null }
    void result.then(settled, settled)
    return result
  }

  private async refreshPresentationSnapshot(expectedRaw?: string): Promise<LocalProfile> {
    const current = this.profile
    if (!current) throw new Error("Identity must be bootstrapped before presentation refresh")
    const active = current
    const privateKeys = { ...current.privateKeys }
    const baseline: LocalProfile = {
      identity: structuredClone(current.identity),
      device: structuredClone(current.device),
      certificate: structuredClone(current.certificate),
      privateKeys,
    }
    const currentPublic = canonicalizeJson({ identity: baseline.identity, device: baseline.device, certificate: baseline.certificate })
    const ensureCurrent = () => {
      if (this.profile !== active || active.privateKeys.devicePrivateKey !== privateKeys.devicePrivateKey ||
        active.privateKeys.identityPrivateKey !== privateKeys.identityPrivateKey ||
        canonicalizeJson({ identity: active.identity, device: active.device, certificate: active.certificate }) !== currentPublic) {
        throw new Error("Identity changed during presentation refresh")
      }
    }

    const baselineSerialized = JSON.parse(await this.serialize(baseline)) as SerializedProfile
    ensureCurrent()
    const raw = await this.get(this.options.storageKey)
    ensureCurrent()
    if (expectedRaw !== undefined && raw !== expectedRaw) {
      throw new Error("Durable identity presentation changed since it was captured")
    }
    if (raw === null) throw new Error("Durable identity profile is missing")

    let saved: unknown
    try { saved = JSON.parse(raw) as unknown }
    catch { throw new Error("Durable identity profile is malformed") }
    if (!isRecord(saved) || !isRecord(saved.identity) || !isRecord(saved.device) ||
      typeof saved.identity.displayName !== "string" || saved.identity.displayName.length === 0 || saved.identity.displayName.length > 256 ||
      typeof saved.device.displayName !== "string" || saved.device.displayName.length === 0 || saved.device.displayName.length > 256) {
      throw new Error("Durable identity presentation is invalid")
    }
    const expected: SerializedProfile = {
      ...baselineSerialized,
      identity: { ...baselineSerialized.identity, displayName: saved.identity.displayName },
      device: { ...baselineSerialized.device, displayName: saved.device.displayName },
    }
    if (canonicalizeJson(saved) !== canonicalizeJson(expected)) {
      throw new Error("Durable identity changed outside presentation metadata")
    }

    ensureCurrent()
    if (saved.identity.displayName === baseline.identity.displayName && saved.device.displayName === baseline.device.displayName) return active

    const refreshed: LocalProfile = {
      identity: { ...baseline.identity, displayName: saved.identity.displayName },
      device: { ...baseline.device, displayName: saved.device.displayName },
      certificate: baseline.certificate,
      privateKeys,
    }
    ensureCurrent()
    this.profile = refreshed
    return refreshed
  }

  reset() {
    this.clearMemory()
    void this.remove(this.options.storageKey)
  }

  async createRecoverable(
    security: IdentitySecurity = "better",
    displayName = "Mesh user",
  ): Promise<RecoverableIdentity> {
    const created = await createRecoverableIdentity(security, displayName)
    await this.persist(created.profile, true)
    this.profile = created.profile
    return created
  }

  async restoreEnvelope(
    envelope: IdentityRecoveryEnvelope,
    recoveryKey: string,
    displayName = "Mesh user",
    commit?: IdentityAdoptionCommit,
  ): Promise<LocalProfile> {
    const startingProfile = this.profile
    const startingKeys = startingProfile ? { ...startingProfile.privateKeys } : undefined
    const startingPublic = startingProfile
      ? canonicalizeJson({ identity: startingProfile.identity, device: startingProfile.device, certificate: startingProfile.certificate })
      : undefined
    const ensureStartingCurrent = () => {
      if (startingProfile && (this.profile !== startingProfile || startingProfile.privateKeys.devicePrivateKey !== startingKeys!.devicePrivateKey ||
        startingProfile.privateKeys.identityPrivateKey !== startingKeys!.identityPrivateKey ||
        canonicalizeJson({ identity: startingProfile.identity, device: startingProfile.device, certificate: startingProfile.certificate }) !== startingPublic)) {
        throw new Error("Identity changed during recovery")
      }
    }
    ensureStartingCurrent()
    const current = await this.bootstrap()
    ensureStartingCurrent()
    const active = this.profile
    const keys = { ...current.privateKeys }
    const currentPublic = canonicalizeJson({ identity: current.identity, device: current.device, certificate: current.certificate })
    const ensureCurrent = () => {
      if (!active || this.profile !== active || active.privateKeys.devicePrivateKey !== keys.devicePrivateKey ||
        active.privateKeys.identityPrivateKey !== keys.identityPrivateKey ||
        canonicalizeJson({ identity: active.identity, device: active.device, certificate: active.certificate }) !== currentPublic) {
        throw new Error("Identity changed during recovery")
      }
    }
    const baseline: LocalProfile = {
      identity: structuredClone(current.identity),
      device: structuredClone(current.device),
      certificate: structuredClone(current.certificate),
      privateKeys: keys,
    }
    const previous = await this.get(this.options.storageKey)
    ensureCurrent()
    const baselineSerialized = await this.serialize(baseline)
    ensureCurrent()
    if (previous !== null && previous !== baselineSerialized) {
      if (this.profile === current) this.clearMemory()
      throw new Error("Durable identity changed before recovery")
    }
    const candidate = await openIdentityRecoveryEnvelope(envelope, recoveryKey, displayName)
    ensureCurrent()
    const latest = await this.get(this.options.storageKey)
    ensureCurrent()
    if (latest !== previous) {
      if (this.profile === current) this.clearMemory()
      throw new Error("Durable identity changed before recovery")
    }
    let profile = candidate
    if (candidate.identity.personId === baseline.identity.personId) {
      if (candidate.identity.publicKey !== baseline.identity.publicKey) throw new Error("Recovered root key does not match the active identity")
      profile = keys.identityPrivateKey
        ? current
        : { ...baseline, privateKeys: { ...keys, identityPrivateKey: candidate.privateKeys.identityPrivateKey } }
    }
    const candidateProfile = await this.serialize(profile)
    const plan: IdentityAdoptionCommitPlan = {
      storageKey: this.options.storageKey,
      previousProfile: previous,
      candidateProfile,
      publicProfile: {
        identity: structuredClone(profile.identity),
        device: structuredClone(profile.device),
        certificate: structuredClone(profile.certificate),
      },
      ...(previous ? { backup: { key: `${this.options.storageKey}.backup.${baseline.identity.personId}`, value: previous } } : {}),
    }
    ensureCurrent()
    if (commit) {
      await commit(structuredClone(plan), ensureCurrent)
    } else {
      if (plan.backup) await this.set(plan.backup.key, plan.backup.value, true)
      ensureCurrent()
      const beforeWrite = await this.get(this.options.storageKey)
      ensureCurrent()
      if (beforeWrite !== previous) {
        if (this.profile === current) this.clearMemory()
        throw new Error("Durable identity changed before recovery")
      }
      await this.set(this.options.storageKey, candidateProfile, true)
    }
    ensureCurrent()
    this.profile = profile
    return profile
  }

  async createPassphrase(passphrase: string, displayName = "Mesh user"): Promise<PassphraseIdentity> {
    const created = await createPassphraseIdentity(passphrase, displayName)
    await this.persist(created.profile, true)
    this.profile = created.profile
    return created
  }

  async restorePassphraseEnvelope(
    envelope: IdentityPassphraseEnvelope,
    passphrase: string,
    displayName = "Mesh user",
  ): Promise<LocalProfile> {
    const candidate = await openIdentityPassphraseEnvelope(envelope, passphrase, displayName)
    const saved = await this.load()
    if (saved?.identity.personId === candidate.identity.personId) {
      this.profile = saved
      return saved
    }
    await this.persist(candidate, true)
    this.profile = candidate
    return candidate
  }

  private async load(): Promise<LocalProfile | null> {
    try {
      const raw = await this.get(this.options.storageKey)
      if (!raw) return null
      const saved = JSON.parse(raw) as SerializedProfile
      if (!saved.identity || !saved.device || !saved.privateKeys?.devicePrivateKeyPkcs8) return null
      const devicePrivateKey = await crypto.subtle.importKey(
        "pkcs8", fromBase64Url(saved.privateKeys.devicePrivateKeyPkcs8),
        { name: "Ed25519" }, true, ["sign"],
      )
      const identityPrivateKey = saved.privateKeys.identityPrivateKeyPkcs8
        ? await crypto.subtle.importKey(
          "pkcs8", fromBase64Url(saved.privateKeys.identityPrivateKeyPkcs8),
          { name: "Ed25519" }, true, ["sign"],
        )
        : undefined
      return {
        identity: saved.identity,
        device: saved.device,
        certificate: saved.certificate,
        privateKeys: { identityPrivateKey, devicePrivateKey },
      }
    } catch (error) {
      if (this.options.requirePersistence) throw error
      return null
    }
  }

  private async serialize(profile: LocalProfile): Promise<string> {
    const serialized: SerializedProfile = {
      identity: profile.identity,
      device: profile.device,
      certificate: profile.certificate,
      privateKeys: {
        identityPrivateKeyPkcs8: profile.privateKeys.identityPrivateKey
          ? toBase64Url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", profile.privateKeys.identityPrivateKey)))
          : undefined,
        devicePrivateKeyPkcs8: toBase64Url(
          new Uint8Array(await crypto.subtle.exportKey("pkcs8", profile.privateKeys.devicePrivateKey)),
        ),
      },
    }
    return JSON.stringify(serialized)
  }

  private async persist(profile: LocalProfile, strict = false) {
    try {
      await this.set(this.options.storageKey, await this.serialize(profile), strict)
    } catch (error) {
      if (strict || this.options.requirePersistence) throw error
    }
  }

  async bootstrap(displayName = "Mesh user"): Promise<LocalProfile> {
    if (this.profile) return this.profile
    if (this.booting) return this.booting
    this.booting = (async () => {
      const restored = await this.load()
      if (restored) return (this.profile = restored)
      let identityKeys: CryptoKeyPair
      let deviceKeys: CryptoKeyPair
      try {
        identityKeys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
        deviceKeys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
      } catch (error) {
        throw new Error(`Unsupported crypto algorithm or environment: ${error instanceof Error ? error.message : error}`)
      }
      const identityPublic = new Uint8Array(await crypto.subtle.exportKey("raw", identityKeys.publicKey))
      const devicePublic = new Uint8Array(await crypto.subtle.exportKey("raw", deviceKeys.publicKey))
      const personId = await sha256Base64Url(identityPublic)
      const deviceId = await sha256Base64Url(devicePublic)
      const identity: PublicIdentity = { personId, publicKey: toBase64Url(identityPublic), displayName }
      const certificate = await signEnvelope(identityKeys.privateKey, {
        kind: "device-certificate" as const,
        version: 1 as const,
        personId,
        deviceId,
        devicePublicKey: toBase64Url(devicePublic),
        issuerCertificateHash: null,
        canEnrollDevices: true as const,
      }, personId, this.domain)
      const profile: LocalProfile = {
        identity,
        device: { deviceId, publicKey: toBase64Url(devicePublic), displayName: `${displayName}'s device` },
        certificate,
        privateKeys: { identityPrivateKey: identityKeys.privateKey, devicePrivateKey: deviceKeys.privateKey },
      }
      await this.persist(profile)
      if (!this.profile) this.profile = profile
      return this.profile
    })()
    try { return await this.booting } finally { this.booting = null }
  }

  /** Replaces a device key under the same locally held identity root. Old revocations remain valid. */
  async renewDevice(): Promise<LocalProfile> {
    const current = await this.bootstrap()
    const rootKey = current.privateKeys.identityPrivateKey
    if (!rootKey) throw new Error("Use Add your device from another authorized device to renew this device")
    const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
    const publicKey = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)))
    const deviceId = await publicKeyId(publicKey)
    const certificate = await signEnvelope(rootKey, {
      kind: "device-certificate" as const, version: 1 as const, personId: current.identity.personId,
      deviceId, devicePublicKey: publicKey, issuerCertificateHash: null, canEnrollDevices: true as const,
    }, current.identity.personId, this.domain)
    const profile: LocalProfile = { ...current, certificate,
      device: { ...current.device, deviceId, publicKey },
      privateKeys: { ...current.privateKeys, devicePrivateKey: keys.privateKey } }
    const previous = await this.get(this.options.storageKey)
    if (previous) await this.set(`${this.options.storageKey}.backup.device.${current.device.deviceId}`, previous, true)
    await this.persist(profile, true)
    this.profile = profile
    return profile
  }

  async adopt(identity: PublicIdentity, certificate: DeviceCertificate, commit?: IdentityAdoptionCommit): Promise<LocalProfile> {
    const submittedIdentity = structuredClone(identity)
    const submittedCertificate = structuredClone(certificate)
    const current = await this.bootstrap()
    const active = this.profile
    const keys = { ...current.privateKeys }
    const currentPublic = canonicalizeJson({ identity: current.identity, device: current.device, certificate: current.certificate })
    const ensureCurrent = () => {
      if (!active || this.profile !== active || active.privateKeys.devicePrivateKey !== keys.devicePrivateKey ||
        active.privateKeys.identityPrivateKey !== keys.identityPrivateKey ||
        canonicalizeJson({ identity: active.identity, device: active.device, certificate: active.certificate }) !== currentPublic) {
        throw new Error("Identity changed during adoption")
      }
    }
    const previous = await this.get(this.options.storageKey)
    ensureCurrent()
    const saved = previous ? JSON.parse(previous) as SerializedProfile : null
    if (!saved || canonicalizeJson({ identity: saved.identity, device: saved.device, certificate: saved.certificate }) !== currentPublic) {
      if (this.profile === current) this.clearMemory()
      throw new Error("Durable identity changed before adoption")
    }
    if (commit) {
      const profile: LocalProfile = {
        identity: submittedIdentity,
        certificate: submittedCertificate,
        device: structuredClone(current.device),
        privateKeys: current.identity.personId === submittedIdentity.personId
          ? keys
          : { devicePrivateKey: keys.devicePrivateKey },
      }
      const candidateProfile = await this.serialize(profile)
      const plan: IdentityAdoptionCommitPlan = {
        storageKey: this.options.storageKey,
        previousProfile: previous,
        candidateProfile,
        publicProfile: {
          identity: structuredClone(profile.identity),
          device: structuredClone(profile.device),
          certificate: structuredClone(profile.certificate),
        },
        ...(previous ? { backup: { key: `${this.options.storageKey}.backup.${current.identity.personId}`, value: previous } } : {}),
      }
      ensureCurrent()
      await commit(structuredClone(plan), ensureCurrent)
      ensureCurrent()
      this.profile = profile
      return profile
    }
    if (previous) await this.set(`${this.options.storageKey}.backup.${current.identity.personId}`, previous, true)
    const profile: LocalProfile = {
      identity: submittedIdentity,
      certificate: submittedCertificate,
      device: current.device,
      privateKeys: current.identity.personId === submittedIdentity.personId
        ? keys
        : { devicePrivateKey: keys.devicePrivateKey },
    }
    await this.persist(profile, true)
    this.profile = profile
    return profile
  }

  /** Persist an explicitly approved Identity device without replacing its generated device key. */
  async adoptEnrolledDevice(
    submitted: LocalProfile,
    certificates: DeviceCertificate[],
    options: { consentToReplaceExistingIdentity: true; commit?: IdentityAdoptionCommit },
  ): Promise<LocalProfile> {
    const commit = options.commit
    const identity = structuredClone(submitted.identity)
    const device = structuredClone(submitted.device)
    const certificate = structuredClone(submitted.certificate)
    const chain = structuredClone(certificates)
    if (submitted.privateKeys.identityPrivateKey) throw new Error("Enrolled device profile must not include the Identity root key")
    if (certificate.payload.deviceId !== device.deviceId || certificate.payload.devicePublicKey !== device.publicKey ||
      certificate.payload.personId !== identity.personId || !certificate.payload.canEnrollDevices ||
      canonicalizeJson(chain.find(item => item.payload.deviceId === device.deviceId)) !== canonicalizeJson(certificate)) {
      throw new Error("Enrolled device profile does not match its certificate chain")
    }
    const certifiedPublicKey = await verifyDeviceCertificateChain(identity, device.deviceId, chain, this.domain)
    if (certifiedPublicKey !== device.publicKey) throw new Error("Enrolled device key does not match its certificate")
    const proof = await signEnvelope(submitted.privateKeys.devicePrivateKey, {
      kind: "mesh-enrolled-device-key-check", challenge: toBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    }, device.deviceId, this.domain)
    if (!await verifyEnvelope(proof, device.publicKey, this.domain)) throw new Error("Enrolled device private key does not match its certificate")

    const previous = await this.get(this.options.storageKey)
    if (!previous && !this.profile) {
      if (options.consentToReplaceExistingIdentity !== true) throw new Error("Adopting this Identity requires explicit consent")
      const adopted: LocalProfile = { identity, device, certificate,
        privateKeys: { devicePrivateKey: submitted.privateKeys.devicePrivateKey } }
      const candidateProfile = await this.serialize(adopted)
      if (await this.get(this.options.storageKey) !== null) throw new Error("Durable identity changed before device adoption")
      const plan: IdentityAdoptionCommitPlan = {
        storageKey: this.options.storageKey,
        previousProfile: null,
        candidateProfile,
        publicProfile: { identity: structuredClone(identity), device: structuredClone(device), certificate: structuredClone(certificate) },
      }
      if (options.commit) await options.commit(structuredClone(plan), () => {
        if (this.profile) throw new Error("Identity changed during device adoption")
      })
      else {
        if (await this.get(this.options.storageKey) !== null) throw new Error("Durable identity changed before device adoption")
        await this.set(this.options.storageKey, candidateProfile, true)
      }
      if (this.profile) throw new Error("Identity changed during device adoption")
      this.profile = adopted
      return adopted
    }

    const current = await this.bootstrap()
    const active = this.profile
    const keys = { ...current.privateKeys }
    const currentPublic = canonicalizeJson({ identity: current.identity, device: current.device, certificate: current.certificate })
    const ensureCurrent = () => {
      if (!active || this.profile !== active || active.privateKeys.devicePrivateKey !== keys.devicePrivateKey ||
        active.privateKeys.identityPrivateKey !== keys.identityPrivateKey ||
        canonicalizeJson({ identity: active.identity, device: active.device, certificate: active.certificate }) !== currentPublic) {
        throw new Error("Identity changed during device adoption")
      }
    }
    const durableCurrent = await this.get(this.options.storageKey)
    ensureCurrent()
    if (options.consentToReplaceExistingIdentity !== true) throw new Error("Replacing this browser's current identity requires explicit consent")
    const saved = durableCurrent ? JSON.parse(durableCurrent) as SerializedProfile : null
    if (!saved || canonicalizeJson({ identity: saved.identity, device: saved.device, certificate: saved.certificate }) !== currentPublic) {
      if (this.profile === current) this.clearMemory()
      throw new Error("Durable identity changed before device adoption")
    }
    const adopted: LocalProfile = { identity, device, certificate,
      privateKeys: { devicePrivateKey: submitted.privateKeys.devicePrivateKey } }
    const candidateProfile = await this.serialize(adopted)
    const backup = { key: `${this.options.storageKey}.backup.${current.identity.personId}`, value: durableCurrent! }
    const plan: IdentityAdoptionCommitPlan = {
      storageKey: this.options.storageKey,
      previousProfile: durableCurrent,
      candidateProfile,
      publicProfile: { identity: structuredClone(identity), device: structuredClone(device), certificate: structuredClone(certificate) },
      backup,
    }
    ensureCurrent()
    if (commit) await commit(structuredClone(plan), ensureCurrent)
    else {
      await this.set(backup.key, backup.value, true)
      ensureCurrent()
      if (await this.get(this.options.storageKey) !== durableCurrent) throw new Error("Durable identity changed before device adoption")
      await this.set(this.options.storageKey, candidateProfile, true)
    }
    ensureCurrent()
    this.profile = adopted
    return adopted
  }

  /** Updates local presentation metadata without changing the identity keys. */
  async rename(displayName: string, commit?: IdentityAdoptionCommit): Promise<LocalProfile> {
    const clean = displayName.trim()
    if (!clean || clean.length > 256) throw new Error("Identity name must be between 1 and 256 characters")
    const current = await this.bootstrap()
    if (commit) {
      const active = this.profile
      const keys = { ...current.privateKeys }
      const currentPublic = canonicalizeJson({ identity: current.identity, device: current.device, certificate: current.certificate })
      const ensureCurrent = () => {
        if (!active || this.profile !== active || active.privateKeys.devicePrivateKey !== keys.devicePrivateKey ||
          active.privateKeys.identityPrivateKey !== keys.identityPrivateKey ||
          canonicalizeJson({ identity: active.identity, device: active.device, certificate: active.certificate }) !== currentPublic) {
          throw new Error("Identity changed during rename")
        }
      }
      const previous = await this.get(this.options.storageKey)
      ensureCurrent()
      const saved = previous ? JSON.parse(previous) as SerializedProfile : null
      if (!saved || canonicalizeJson({ identity: saved.identity, device: saved.device, certificate: saved.certificate }) !== currentPublic) {
        if (this.profile === current) this.clearMemory()
        throw new Error("Durable identity changed before rename")
      }
      const defaultDeviceName = `${current.identity.displayName}'s device`
      const profile: LocalProfile = {
        ...current,
        identity: { ...current.identity, displayName: clean },
        device: {
          ...current.device,
          ...(current.device.displayName === defaultDeviceName ? { displayName: `${clean}'s device` } : {}),
        },
      }
      const plan: IdentityAdoptionCommitPlan = {
        storageKey: this.options.storageKey,
        previousProfile: previous,
        candidateProfile: await this.serialize(profile),
        publicProfile: {
          identity: structuredClone(profile.identity),
          device: structuredClone(profile.device),
          certificate: structuredClone(profile.certificate),
        },
      }
      ensureCurrent()
      await commit(structuredClone(plan), ensureCurrent)
      ensureCurrent()
      this.profile = profile
      return profile
    }
    const defaultDeviceName = `${current.identity.displayName}'s device`
    const profile: LocalProfile = {
      ...current,
      identity: { ...current.identity, displayName: clean },
      device: {
        ...current.device,
        ...(current.device.displayName === defaultDeviceName ? { displayName: `${clean}'s device` } : {}),
      },
    }
    await this.persist(profile, true)
    this.profile = profile
    return profile
  }
}
