import { canonicalizeJson, fromBase64Url, identitySeedFromPrivateKey,
  openIdentityRecoveryEnvelope, profileFromIdentitySeedForDevice, sealIdentitySeed, toBase64Url,
  type IdentityRecoveryEnvelope, type IdentitySecurity, type LocalProfile } from "./index"
import { createIdentityProfileOperation, emptyIdentityProfileState, identityProfileValue,
  readIdentityProfileState, type IdentityProfileState } from "./identityProfile"
import { isValidIdentityAvatar, isValidIdentityDisplayName } from "./profileValidation"

export type IdentityProfileRecoveryPayload = {
  displayName: string
  avatarData: string | null
  profileState?: IdentityProfileState
}

export type IdentityProfileRecoveryFile = {
  kind: "mesh-identity-profile-recovery"
  version: 1
  personId: string
  recovery: IdentityRecoveryEnvelope
  cipher: { name: "AES-GCM"; kdf: "HKDF-SHA256"; salt: string; iv: string }
  ciphertext: string
}

const context = new TextEncoder().encode("meta-mesh/identity-profile-recovery/v1")
const maximumFileBytes = 512 * 1024

function canonicalBytes(value: string, expectedLength: number): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("Invalid identity recovery encoding")
  const bytes = fromBase64Url(value)
  if (bytes.byteLength !== expectedLength || toBase64Url(bytes) !== value) throw new Error("Invalid identity recovery encoding")
  return new Uint8Array(bytes)
}

function wrappingKey(seed: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  if (seed.byteLength !== 32) throw new Error("Identity root must contain 32 bytes")
  return crypto.subtle.importKey("raw", new Uint8Array(seed), "HKDF", false, ["deriveKey"]).then(source =>
    crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: context }, source,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]))
}

function validatePayload(value: unknown): IdentityProfileRecoveryPayload {
  if (!isRecord(value) || !(hasOnlyKeys(value, ["displayName", "avatarData"]) || hasOnlyKeys(value, ["displayName", "avatarData", "profileState"])) ||
    !isValidIdentityDisplayName(value.displayName) || !(value.avatarData === null || isValidIdentityAvatar(value.avatarData))) {
    throw new Error("Invalid portable identity profile")
  }
  return { displayName: value.displayName, avatarData: value.avatarData,
    ...(value.profileState ? { profileState: structuredClone(value.profileState) as IdentityProfileState } : {}) }
}

function assertFile(value: unknown): asserts value is IdentityProfileRecoveryFile {
  if (!isRecord(value) || !hasOnlyKeys(value, ["kind", "version", "personId", "recovery", "cipher", "ciphertext"]) ||
    value.kind !== "mesh-identity-profile-recovery" || value.version !== 1 ||
    typeof value.personId !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value.personId) ||
    !isRecord(value.recovery) || value.recovery.kind !== "mesh-identity-recovery" || value.recovery.version !== 3 ||
    value.recovery.personId !== value.personId || !isRecord(value.cipher) ||
    !hasOnlyKeys(value.cipher, ["name", "kdf", "salt", "iv"]) || value.cipher.name !== "AES-GCM" ||
    value.cipher.kdf !== "HKDF-SHA256" || typeof value.cipher.salt !== "string" || typeof value.cipher.iv !== "string" ||
    typeof value.ciphertext !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value.ciphertext)) {
    throw new Error("Unsupported identity profile recovery file")
  }
  canonicalBytes(value.cipher.salt, 32)
  canonicalBytes(value.cipher.iv, 12)
  const cipherBytes = fromBase64Url(value.ciphertext)
  if (cipherBytes.byteLength < 17 || cipherBytes.byteLength > maximumFileBytes) {
    throw new Error("Identity profile recovery file is too large or incomplete")
  }
}

export function parseIdentityProfileRecoveryFile(value: unknown): IdentityProfileRecoveryFile {
  let serialized: string | undefined
  try { serialized = JSON.stringify(value) } catch { throw new Error("Unsupported identity profile recovery file") }
  if (!serialized || new TextEncoder().encode(serialized).byteLength > maximumFileBytes) {
    throw new Error("Identity profile recovery file exceeds the size limit")
  }
  const file = JSON.parse(serialized) as unknown
  assertFile(file)
  return structuredClone(file)
}

/** Seal only portable identity presentation under the existing identity root. */
export async function sealIdentityProfileRecovery(
  recovery: IdentityRecoveryEnvelope,
  identitySeed: Uint8Array,
  payloadValue: IdentityProfileRecoveryPayload,
): Promise<IdentityProfileRecoveryFile> {
  const payload = validatePayload(payloadValue)
  const seededProfile = await profileFromIdentitySeedForDevice(identitySeed, payload.displayName)
  if (seededProfile.identity.personId !== recovery.personId) throw new Error("Identity root does not match recovery envelope")
  if (payload.profileState) {
    const state = await readIdentityProfileState(payload.profileState, seededProfile.identity)
    const name = identityProfileValue(state, "name")
    const photo = identityProfileValue(state, "photo")
    if (name.status !== "value" || name.values[0] !== payload.displayName || photo.status === "conflict" ||
      (photo.status === "value" && (typeof photo.values[0] === "string" || photo.values[0].avatarData !== payload.avatarData))) {
      throw new Error("Portable profile does not match signed Identity profile state")
    }
  }
  const salt = crypto.getRandomValues(new Uint8Array(32))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const header = {
    kind: "mesh-identity-profile-recovery" as const,
    version: 1 as const,
    personId: recovery.personId,
    recovery: structuredClone(recovery),
    cipher: { name: "AES-GCM" as const, kdf: "HKDF-SHA256" as const,
      salt: toBase64Url(salt), iv: toBase64Url(iv) },
  }
  const key = await wrappingKey(identitySeed, salt)
  const plaintext = new TextEncoder().encode(JSON.stringify(payload))
  try {
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv,
      additionalData: new TextEncoder().encode(canonicalizeJson(header)), tagLength: 128 }, key, plaintext)
    const result = { ...header, ciphertext: toBase64Url(new Uint8Array(ciphertext)) }
    assertFile(result)
    return result
  } finally { plaintext.fill(0) }
}

/** Create new recovery words and file for an existing profile without changing its person ID. */
export async function createIdentityProfileRecovery(
  profile: LocalProfile,
  payloadValue: Omit<IdentityProfileRecoveryPayload, "profileState"> & { profileState?: IdentityProfileState },
  security: IdentitySecurity = "better",
  certificates?: readonly import("./index").DeviceCertificate[],
): Promise<{ recoveryKey: string; recoveryEnvelope: IdentityRecoveryEnvelope; file: IdentityProfileRecoveryFile }> {
  const seed = await identitySeedFromPrivateKey(profile.privateKeys.identityPrivateKey!, profile.identity.personId)
  try {
    const { generateIdentityRecovery } = await import("./recovery")
    const recoveryKey = generateIdentityRecovery(security)
    const recoveryEnvelope = await sealIdentitySeed(seed, profile.identity.personId, recoveryKey, security)
    const state = payloadValue.profileState ?? await createInitialIdentityProfileState(profile, payloadValue, certificates)
    const file = await sealIdentityProfileRecovery(recoveryEnvelope, seed, { ...payloadValue, profileState: state })
    return { recoveryKey, recoveryEnvelope, file }
  } finally { seed.fill(0) }
}

async function createInitialIdentityProfileState(profile: LocalProfile,
  payload: Omit<IdentityProfileRecoveryPayload, "profileState">, certificates?: readonly import("./index").DeviceCertificate[]): Promise<IdentityProfileState> {
  let state = emptyIdentityProfileState(profile.identity.personId)
  const names = await createIdentityProfileOperation(profile, state, "name", payload.displayName, certificates)
  state = { ...state, operations: [names] }
  const photo = await createIdentityProfileOperation(profile, state, "photo", { avatarData: payload.avatarData, changedAt: new Date(0).toISOString() }, certificates)
  state = { ...state, operations: [...state.operations, photo] }
  return state
}

/** Open encrypted presentation with the root unlocked by the same recovery words. */
export async function openIdentityProfileRecovery(
  fileValue: IdentityProfileRecoveryFile | unknown,
  recoveryWords: string,
): Promise<{ profile: IdentityProfileRecoveryPayload; recovery: IdentityRecoveryEnvelope }> {
  const file = parseIdentityProfileRecoveryFile(fileValue)
  const recovered = await openIdentityRecoveryEnvelope(file.recovery, recoveryWords)
  const seed = await identitySeedFromPrivateKey(recovered.privateKeys.identityPrivateKey!, file.personId)
  try {
    const salt = canonicalBytes(file.cipher.salt, 32)
    const iv = canonicalBytes(file.cipher.iv, 12)
    const key = await wrappingKey(seed, salt)
    const { ciphertext, ...header } = file
    let plaintext: Uint8Array
    try {
      plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv,
        additionalData: new TextEncoder().encode(canonicalizeJson(header)), tagLength: 128 }, key,
      canonicalBytes(ciphertext, fromBase64Url(ciphertext).byteLength)))
    } catch { throw new Error("Identity profile file authentication failed. Check the file and recovery words.") }
    try {
      const profile = validatePayload(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext)))
      if (profile.profileState) {
        const state = await readIdentityProfileState(profile.profileState, recovered.identity)
        const name = identityProfileValue(state, "name"), photo = identityProfileValue(state, "photo")
        if (name.status !== "value" || name.values[0] !== profile.displayName || photo.status === "conflict" ||
          (photo.status === "value" && (typeof photo.values[0] === "string" || photo.values[0].avatarData !== profile.avatarData))) {
          throw new Error("Portable profile does not match signed Identity profile state")
        }
        profile.profileState = state
      }
      return { profile, recovery: structuredClone(file.recovery) }
    } catch { throw new Error("Identity profile file contents are invalid") }
    finally { plaintext.fill(0) }
  } finally { seed.fill(0) }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
}

function hasOnlyKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}
