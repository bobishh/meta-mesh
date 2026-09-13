import { getPublicKeyAsync } from "@noble/ed25519"
import { entropyToMnemonic, generateMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39"
import { wordlist } from "@scure/bip39/wordlists/english.js"
import { EFF_LONG_WORDS } from "./eff-long"

export type PersonId = string
export type DeviceId = string
export type RecoveryStrengthBits = 128 | 192 | 256
export type IdentitySecurity = "legacy" | "better" | "insane"

export type IdentityRecoveryEnvelope = {
  kind: "mesh-identity-recovery"
  version: 2
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
  canEnrollDevices: true
}>

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

export type IdentityStoreOptions = {
  storageKey: string
  signatureDomain?: string
  storage?: Pick<Storage, "getItem" | "setItem" | "removeItem">
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

export async function profileFromRecoveryPhrase(value: string, displayName = "Mesh user"): Promise<LocalProfile> {
  return profileFromEntropy(recoveryPhraseToEntropy(value), displayName)
}

export async function profileFromRecoveryPhraseForDevice(
  value: string,
  displayName = "Mesh user",
  deviceEntropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32)),
): Promise<LocalProfile> {
  if (deviceEntropy.byteLength !== 32) throw new Error("Device entropy must contain 32 bytes")
  return profileFromEntropy(recoveryPhraseToEntropy(value), displayName, deviceEntropy)
}

export async function profileFromChatKey(value: string, displayName = "Mesh user"): Promise<LocalProfile> {
  const key = normalizeRecoveryPhrase(value)
  if (!chatKeyIsValid(key)) throw new Error("Invalid chat key")
  const entropy = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)))
  return profileFromEntropy(entropy, displayName)
}

export async function profileFromChatKeyForDevice(
  value: string,
  displayName = "Mesh user",
  deviceEntropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32)),
): Promise<LocalProfile> {
  const key = normalizeRecoveryPhrase(value)
  if (!chatKeyIsValid(key)) throw new Error("Invalid chat key")
  if (deviceEntropy.byteLength !== 32) throw new Error("Device entropy must contain 32 bytes")
  const entropy = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)))
  return profileFromEntropy(entropy, displayName, deviceEntropy)
}

export async function profileFromIdentityRecoveryForDevice(
  value: string,
  displayName = "Mesh user",
  deviceEntropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32)),
): Promise<LocalProfile> {
  const security = identitySecurityForRecovery(value)
  if (!security) throw new Error("Invalid identity recovery")
  return security === "legacy"
    ? profileFromChatKeyForDevice(value, displayName, deviceEntropy)
    : profileFromRecoveryPhraseForDevice(value, displayName, deviceEntropy)
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

async function identitySeedForProfile(profile: LocalProfile): Promise<Uint8Array> {
  const privateKey = profile.privateKeys.identityPrivateKey
  if (!privateKey) throw new Error("Identity private key is unavailable")
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey))
  if (pkcs8.byteLength < 32) throw new Error("Invalid identity private key")
  const seed = pkcs8.slice(-32)
  const personId = await sha256Base64Url(await getPublicKeyAsync(seed))
  if (personId !== profile.identity.personId) throw new Error("Identity private key does not match profile")
  return seed
}

async function sealIdentitySeed(
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
    version: 2,
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
  if (value?.kind !== "mesh-identity-recovery" || value.version !== 2 || !value.personId ||
    !["legacy", "better", "insane"].includes(value.security) ||
    value.kdf?.name !== "PBKDF2" || value.kdf.hash !== "SHA-256" ||
    value.kdf.iterations !== RECOVERY_KDF_ITERATIONS || value.cipher?.name !== "AES-GCM" ||
    fromBase64Url(value.kdf.salt).byteLength !== 16 || fromBase64Url(value.cipher.iv).byteLength !== 12 ||
    fromBase64Url(value.ciphertext).byteLength !== 48) throw new Error("Invalid identity recovery envelope")
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

export async function rewrapIdentityRecoveryEnvelope(
  envelope: IdentityRecoveryEnvelope,
  currentRecoveryKey: string,
  security: IdentitySecurity,
): Promise<Pick<RecoverableIdentity, "recoveryKey" | "recoveryEnvelope">> {
  const identitySeed = await openIdentitySeed(envelope, currentRecoveryKey)
  const recoveryKey = generateIdentityRecovery(security)
  return {
    recoveryKey,
    recoveryEnvelope: await sealIdentitySeed(identitySeed, envelope.personId, recoveryKey, security),
  }
}

export async function migrateIdentityToRecoveryEnvelope(
  profile: LocalProfile,
  recoveryKey: string,
): Promise<IdentityRecoveryEnvelope> {
  const security = identitySecurityForRecovery(recoveryKey)
  if (!security) throw new Error("Invalid identity recovery")
  return sealIdentitySeed(await identitySeedForProfile(profile), profile.identity.personId, recoveryKey, security)
}

export async function profileFromSecretPhrase(value: string, displayName = "Mesh user"): Promise<LocalProfile> {
  const key = normalizeRecoveryPhrase(value)
  if (!key) throw new Error("Secret phrase is empty")
  const entropy = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)))
  return profileFromEntropy(entropy, displayName)
}

export async function profileFromSecretPhraseForDevice(
  value: string,
  displayName = "Mesh user",
  deviceEntropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32)),
): Promise<LocalProfile> {
  const key = normalizeRecoveryPhrase(value)
  if (!key) throw new Error("Secret phrase is empty")
  if (deviceEntropy.byteLength !== 32) throw new Error("Device entropy must contain 32 bytes")
  const entropy = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)))
  return profileFromEntropy(entropy, displayName, deviceEntropy)
}

async function profileFromEntropy(
  entropy: Uint8Array,
  displayName: string,
  deviceEntropy?: Uint8Array,
): Promise<LocalProfile> {
  const identitySeed = await deriveSeed(entropy, "person")
  const deviceSeed = deviceEntropy
    ? await deriveSeed(deviceEntropy, "device")
    : await deriveSeed(entropy, "primary-device")
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

type SerializedProfile = {
  identity: PublicIdentity
  device: LocalProfile["device"]
  certificate: DeviceCertificate
  privateKeys: {
    identityPrivateKeyPkcs8?: string
    devicePrivateKeyPkcs8: string
  }
}

export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error("Non-finite number cannot be canonicalized")
    }
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalizeJson).join(",") + "]"
  const object = value as Record<string, unknown>
  return "{" + Object.keys(object).sort()
    .map(key => `${JSON.stringify(key)}:${canonicalizeJson(object[key])}`).join(",") + "}"
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
  const input = signatureInput(payload.kind, canonicalizeJson(payload), domain)
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
  return crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    fromBase64Url(envelope.signature),
    signatureInput(envelope.payload.kind, canonicalizeJson(envelope.payload), domain),
  )
}

export class BrowserIdentityStore {
  private profile: LocalProfile | null = null
  private booting: Promise<LocalProfile> | null = null
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

  private get(key: string): string | null {
    try { return this.storage()?.getItem(key) ?? this.memory.get(key) ?? null }
    catch { return this.memory.get(key) ?? null }
  }

  private set(key: string, value: string, strict = false) {
    try { this.storage()?.setItem(key, value) }
    catch (error) { if (strict) throw error }
    this.memory.set(key, value)
  }

  private remove(key: string) {
    try { this.storage()?.removeItem(key) } catch {}
    this.memory.delete(key)
  }

  clearMemory() {
    this.profile = null
    this.booting = null
  }

  reset() {
    this.clearMemory()
    this.remove(this.options.storageKey)
  }

  async restore(value: string, displayName = "Mesh user"): Promise<LocalProfile> {
    const profile = await profileFromRecoveryPhrase(value, displayName)
    await this.persist(profile, true)
    this.profile = profile
    return profile
  }

  async restoreRecovery(value: string, displayName = "Mesh user"): Promise<LocalProfile> {
    const candidate = await profileFromRecoveryPhraseForDevice(value, displayName)
    const saved = await this.load()
    if (saved?.identity.personId === candidate.identity.personId) {
      this.profile = saved
      return saved
    }
    await this.persist(candidate, true)
    this.profile = candidate
    return candidate
  }

  async restoreChat(value: string, displayName = "Mesh user"): Promise<LocalProfile> {
    const candidate = await profileFromChatKeyForDevice(value, displayName)
    const saved = await this.load()
    if (saved?.identity.personId === candidate.identity.personId) {
      this.profile = saved
      return saved
    }
    await this.persist(candidate, true)
    this.profile = candidate
    return candidate
  }

  async restoreIdentity(value: string, displayName = "Mesh user"): Promise<LocalProfile> {
    const candidate = await profileFromIdentityRecoveryForDevice(value, displayName)
    const saved = await this.load()
    if (saved?.identity.personId === candidate.identity.personId) {
      this.profile = saved
      return saved
    }
    await this.persist(candidate, true)
    this.profile = candidate
    return candidate
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
  ): Promise<LocalProfile> {
    const candidate = await openIdentityRecoveryEnvelope(envelope, recoveryKey, displayName)
    const saved = await this.load()
    if (saved?.identity.personId === candidate.identity.personId) {
      this.profile = saved
      return saved
    }
    await this.persist(candidate, true)
    this.profile = candidate
    return candidate
  }

  async restoreSecret(value: string, displayName = "Mesh user"): Promise<LocalProfile> {
    const candidate = await profileFromSecretPhraseForDevice(value, displayName)
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
      const raw = this.get(this.options.storageKey)
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
    } catch {
      return null
    }
  }

  private async persist(profile: LocalProfile, strict = false) {
    try {
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
      this.set(this.options.storageKey, JSON.stringify(serialized), strict)
    } catch (error) {
      if (strict) throw error
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

  async adopt(identity: PublicIdentity, certificate: DeviceCertificate): Promise<LocalProfile> {
    const current = await this.bootstrap()
    const previous = this.get(this.options.storageKey)
    if (previous) this.set(`${this.options.storageKey}.backup.${current.identity.personId}`, previous, true)
    const profile: LocalProfile = {
      identity,
      certificate,
      device: current.device,
      privateKeys: current.identity.personId === identity.personId
        ? current.privateKeys
        : { devicePrivateKey: current.privateKeys.devicePrivateKey },
    }
    await this.persist(profile, true)
    this.profile = profile
    return profile
  }
}
