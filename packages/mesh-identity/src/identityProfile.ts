import { canonicalizeJson, identityDeviceDescendants, sha256Base64Url, signEnvelope, verifyDeviceCertificateChain,
  verifyEnvelope, verifyIdentityDeviceAuthority,
  type DeviceCertificate, type IdentityDeviceRevocation, type LocalProfile, type PublicIdentity, type SignedEnvelope } from "./index"
import { isValidIdentityDisplayName, isValidIdentityProfilePhoto } from "./profileValidation"

export type IdentityProfileField = "name" | "photo"
export type IdentityProfileValue = string | { avatarData: string | null; changedAt: string }
type Clock = Record<string, number>
type ProfilePayload = { kind: "identity-profile-update"; version: 1; personId: string; deviceId: string;
  counter: number; context: Clock; field: IdentityProfileField; value: IdentityProfileValue; supersedesLegacy: string[] }
export type IdentityProfileOperation = { signed: SignedEnvelope<ProfilePayload>; certificates: DeviceCertificate[] }
type LegacyObservation = { id: string; field: IdentityProfileField; value: IdentityProfileValue }
export type IdentityProfileState = { version: 1; personId: string; operations: IdentityProfileOperation[]; legacy: LegacyObservation[] }
const maxOperations = 512
const maxContextEntries = 256
const maxStateBytes = 1024 * 1024
const compareOrdinal = (left: string, right: string) => left < right ? -1 : left > right ? 1 : 0
const operationId = (operation: IdentityProfileOperation) => `${operation.signed.payload.deviceId}:${operation.signed.payload.counter}`
const precedes = (before: IdentityProfileOperation, after: IdentityProfileOperation) =>
  (after.signed.payload.context[before.signed.payload.deviceId] ?? 0) >= before.signed.payload.counter

export function emptyIdentityProfileState(personId: string): IdentityProfileState {
  if (!isPersonId(personId)) throw new Error("Invalid identity profile person")
  return { version: 1, personId, operations: [], legacy: [] }
}

/** Verify complete signed causality and retain deterministic conflict evidence. */
export async function readIdentityProfileState(value: unknown, identity: PublicIdentity,
  certificates: readonly DeviceCertificate[] = []): Promise<IdentityProfileState> {
  const state = boundedSnapshot(value)
  if (!isRecord(state) || !onlyKeys(state, ["version", "personId", "operations", "legacy"]) || state.version !== 1 ||
      state.personId !== identity.personId || !isPersonId(state.personId) || !Array.isArray(state.operations) ||
      state.operations.length > maxOperations || !Array.isArray(state.legacy) || state.legacy.length > maxOperations) {
    throw new Error("Invalid identity profile state")
  }
  const operations = new Map<string, IdentityProfileOperation>()
  for (const candidate of state.operations) {
    const operation = parseOperation(candidate)
    await verifyOperation(operation, identity, certificates)
    const key = operationId(operation), previous = operations.get(key)
    if (previous && canonicalizeJson(previous) !== canonicalizeJson(operation)) throw new Error("Identity profile device equivocation")
    operations.set(key, operation)
  }
  const legacy = new Map<string, LegacyObservation>()
  for (const candidate of state.legacy) {
    if (!isRecord(candidate) || !onlyKeys(candidate, ["id", "field", "value"]) ||
        typeof candidate.id !== "string" || !isProfileField(candidate.field)) throw new Error("Invalid legacy profile observation")
    validateValue(candidate.field, candidate.value)
    const observation = { id: candidate.id, field: candidate.field, value: structuredClone(candidate.value) }
    if (await legacyId(observation.field, observation.value) !== observation.id) throw new Error("Imported profile contents do not match their proof")
    legacy.set(observation.id, observation)
  }
  const result: IdentityProfileState = { version: 1, personId: state.personId,
    operations: [...operations.values()].sort((a, b) => compareOrdinal(operationId(a), operationId(b))),
    legacy: [...legacy.values()].sort((a, b) => compareOrdinal(a.id, b.id)) }
  validateCausality(result.operations)
  for (const operation of result.operations) for (const id of operation.signed.payload.supersedesLegacy) {
    const observation = legacy.get(id)
    if (!observation) throw new Error("Missing original profile observation")
    if (observation.field !== operation.signed.payload.field) throw new Error("Profile observation field does not match its update")
  }
  return result
}

/** Validate profile history while enforcing every signed device-revocation snapshot. */
export async function readIdentityProfileStateWithRevocations(value: unknown, identity: PublicIdentity,
  certificates: readonly DeviceCertificate[], revocations: readonly IdentityDeviceRevocation[]): Promise<IdentityProfileState> {
  await verifyIdentityDeviceAuthority(identity, { certificates: Array.from(certificates), revocations: Array.from(revocations) })
  const snapshot = boundedSnapshot(value)
  if (!Array.isArray(snapshot.operations)) throw new Error("Invalid identity profile state")
  const revokedDevices = new Map<string, string[]>()
  for (const revocation of revocations) {
    const payload = revocation?.payload
    if (!payload || !payload.profileOperationHashes || typeof payload.profileOperationHashes !== "object") {
      throw new Error("Invalid Identity profile revocation frontier")
    }
    const descendants = await identityDeviceDescendants(payload.deviceId, certificates)
    for (const [deviceId, hashes] of Object.entries(payload.profileOperationHashes)) {
      if (!descendants.has(deviceId) || !Array.isArray(hashes) || hashes.length > maxOperations ||
          hashes.some(hash => typeof hash !== "string" || !isHash(hash))) {
        throw new Error("Invalid Identity profile revocation frontier")
      }
      const existing = revokedDevices.get(deviceId)
      if (existing && canonicalizeJson(existing) !== canonicalizeJson(hashes)) {
        throw new Error("Conflicting Identity profile revocation history")
      }
      revokedDevices.set(deviceId, structuredClone(hashes))
    }
    for (const deviceId of descendants) {
      if (!revokedDevices.has(deviceId)) revokedDevices.set(deviceId, [])
    }
  }

  const candidates = snapshot.operations as unknown[]
  const kept = new Set<number>()
  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = candidates[index]
    const payload = isRecord(candidate) && isRecord(candidate.signed) && isRecord(candidate.signed.payload)
      ? candidate.signed.payload : undefined
    const actor = payload && typeof payload.deviceId === "string" ? payload.deviceId : undefined
    const counter = payload && Number.isSafeInteger(payload.counter) ? payload.counter as number : undefined
    const hashes = actor ? revokedDevices.get(actor) : undefined
    if (hashes && (counter === undefined || counter < 1 || counter > hashes.length ||
        !isRecord(candidate) || !isRecord(candidate.signed) ||
        hashes[counter - 1] !== await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(candidate.signed))))) continue
    kept.add(index)
  }

  let changed = true
  while (changed) {
    changed = false
    const removed = new Set<string>()
    for (let index = 0; index < candidates.length; index += 1) {
      if (kept.has(index)) continue
      const candidate = candidates[index]
      if (isRecord(candidate) && isRecord(candidate.signed) && isRecord(candidate.signed.payload)) {
        const payload = candidate.signed.payload
        if (typeof payload.deviceId === "string" && Number.isSafeInteger(payload.counter)) {
          removed.add(`${payload.deviceId}:${payload.counter}`)
        }
      }
    }
    for (const index of kept) {
      const candidate = candidates[index]
      if (isRecord(candidate) && isRecord(candidate.signed) && isRecord(candidate.signed.payload)) {
        const payload = candidate.signed.payload
        if (typeof payload.deviceId === "string" && Number.isSafeInteger(payload.counter)) {
          removed.delete(`${payload.deviceId}:${payload.counter}`)
        }
      }
    }
    for (const index of [...kept]) {
      const candidate = candidates[index]
      if (!isRecord(candidate) || !isRecord(candidate.signed) || !isRecord(candidate.signed.payload)) continue
      const context = candidate.signed.payload.context
      if (!isRecord(context)) continue
      if ([...removed].some(key => {
        const separator = key.lastIndexOf(":")
        const actor = key.slice(0, separator), counter = Number(key.slice(separator + 1))
        return (context[actor] ?? 0) >= counter
      })) {
        kept.delete(index)
        changed = true
      }
    }
  }
  const operations = candidates.filter((_, index) => kept.has(index))
  return readIdentityProfileState({ ...snapshot, operations }, identity, certificates)
}

export async function mergeIdentityProfileState(left: IdentityProfileState, right: IdentityProfileState,
  identity: PublicIdentity, certificates: readonly DeviceCertificate[] = []): Promise<IdentityProfileState> {
  const [a, b] = await Promise.all([readIdentityProfileState(left, identity, certificates),
    readIdentityProfileState(right, identity, certificates)])
  const operations = new Map(a.operations.map(operation => [operationId(operation), operation]))
  for (const operation of b.operations) {
    const previous = operations.get(operationId(operation))
    if (previous && canonicalizeJson(previous) !== canonicalizeJson(operation)) throw new Error("Identity profile device equivocation")
    operations.set(operationId(operation), operation)
  }
  const legacy = new Map([...a.legacy, ...b.legacy].map(observation => [observation.id, observation]))
  return readIdentityProfileState({ version: 1, personId: identity.personId,
    operations: [...operations.values()], legacy: [...legacy.values()] }, identity, certificates)
}

/** Local display name and avatar are signed per field by an authorized identity device. */
export async function createIdentityProfileOperation(profileValue: LocalProfile, stateValue: IdentityProfileState,
  field: IdentityProfileField, value: IdentityProfileValue, certificatesValue?: readonly DeviceCertificate[],
  ensureCurrent: () => void | Promise<void> = () => {}): Promise<IdentityProfileOperation> {
  const profile = { ...profileValue, identity: structuredClone(profileValue.identity), device: structuredClone(profileValue.device),
    certificate: structuredClone(profileValue.certificate), privateKeys: { ...profileValue.privateKeys } }
  value = structuredClone(value)
  validateValue(field, value)
  const certificates = structuredClone(Array.from(certificatesValue ?? [profile.certificate]))
  const current = await readIdentityProfileState(stateValue, profile.identity, certificates)
  if (profile.certificate.payload.deviceId !== profile.device.deviceId || !profile.certificate.payload.canEnrollDevices) {
    throw new Error("Device lacks identity management authority")
  }
  const key = await verifyDeviceCertificateChain(profile.identity, profile.device.deviceId, certificates, "MATCH/1")
  if (key !== profile.device.publicKey || profile.certificate.payload.devicePublicKey !== key) {
    throw new Error("Identity profile device key mismatch")
  }
  await ensureCurrent()
  const clock: Clock = {}
  for (const operation of current.operations) {
    const payload = operation.signed.payload
    clock[payload.deviceId] = Math.max(clock[payload.deviceId] ?? 0, payload.counter)
  }
  const next = (clock[profile.device.deviceId] ?? 0) + 1
  if (!Number.isSafeInteger(next)) throw new Error("Identity profile revision exhausted")
  const supersedesLegacy = [...new Set([...current.legacy.filter(item => item.field === field).map(item => item.id),
    ...current.operations.filter(item => item.signed.payload.field === field).flatMap(item => item.signed.payload.supersedesLegacy)])].sort()
  const payload: ProfilePayload = { kind: "identity-profile-update", version: 1, personId: current.personId,
    deviceId: profile.device.deviceId, counter: next, context: clock, field, value,
    supersedesLegacy }
  await ensureCurrent()
  const signed = await signEnvelope(profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId, "MATCH/1")
  await ensureCurrent()
  const operation = { signed, certificates: Array.from(certificates) }
  await readIdentityProfileState({ ...current, operations: [...current.operations, operation] }, profile.identity, certificates)
  return operation
}

/** Import old unsigned presentation once, retaining it until an explicit signed edit supersedes it. */
export async function observeLegacyIdentityProfile(stateValue: IdentityProfileState, identity: PublicIdentity,
  field: IdentityProfileField, value: IdentityProfileValue): Promise<IdentityProfileState> {
  value = structuredClone(value)
  validateValue(field, value)
  const current = await readIdentityProfileState(stateValue, identity)
  const observation = { field, value, id: await legacyId(field, value) }
  if (current.legacy.some(item => item.id === observation.id)) return current
  return readIdentityProfileState({ ...current, legacy: [...current.legacy, observation] }, identity)
}

/** A conflict retains every incompatible value; only a later causal operation resolves it. */
export function identityProfileValue(state: IdentityProfileState, field: IdentityProfileField):
  { status: "empty" | "value" | "conflict"; values: IdentityProfileValue[] } {
  const operations = state.operations.filter(item => item.signed.payload.field === field)
  const superseded = new Set(operations.flatMap(item => item.signed.payload.supersedesLegacy))
  const values = [...operations.filter(item => !operations.some(other => precedes(item, other))).map(item => item.signed.payload.value),
    ...state.legacy.filter(item => item.field === field && !superseded.has(item.id)).map(item => item.value)]
  const distinct = new Map(values.map(value => [typeof value === "string" ? value : value.avatarData ?? "", value]))
  const selected = [...distinct.entries()].sort(([a], [b]) => compareOrdinal(a, b)).map(([, value]) => value)
  return { status: selected.length > 1 ? "conflict" : selected.length ? "value" : "empty", values: selected }
}

export async function identityProfileRevision(state: IdentityProfileState): Promise<string> {
  return sha256Base64Url(new TextEncoder().encode(canonicalizeJson(state)))
}

async function verifyOperation(operation: IdentityProfileOperation, identity: PublicIdentity,
  certificates: readonly DeviceCertificate[]): Promise<void> {
  const payload = operation.signed.payload
  validateValue(payload.field, payload.value)
  if (payload.kind !== "identity-profile-update" || payload.version !== 1 || payload.personId !== identity.personId ||
      payload.deviceId !== operation.signed.signerKeyId || !Number.isSafeInteger(payload.counter) || payload.counter < 1 ||
      !isRecord(payload.context) || Object.keys(payload.context).length > maxContextEntries ||
      (payload.context[payload.deviceId] ?? 0) !== payload.counter - 1 || !Array.isArray(payload.supersedesLegacy) ||
      payload.supersedesLegacy.length > maxOperations || new Set(payload.supersedesLegacy).size !== payload.supersedesLegacy.length ||
      !operation.certificates.length || operation.certificates.length > 32) throw new Error("Invalid identity profile revision")
  for (const [deviceId, counter] of Object.entries(payload.context)) {
    if (!isPersonId(deviceId) || !Number.isSafeInteger(counter) || counter < 0) throw new Error("Invalid identity profile causal context")
  }
  for (const id of payload.supersedesLegacy) if (!isHash(id)) throw new Error("Invalid legacy profile reference")
  const chain = operation.certificates.length ? operation.certificates : certificates
  const leaf = chain.find(certificate => certificate.payload.deviceId === payload.deviceId)
  if (!leaf?.payload.canEnrollDevices) throw new Error("Device lacks identity management authority")
  const key = await verifyDeviceCertificateChain(identity, payload.deviceId, Array.from(chain), "MATCH/1")
  if (!await verifyEnvelope(operation.signed, key, "MATCH/1")) throw new Error("Invalid identity profile signature")
}

function validateCausality(operations: IdentityProfileOperation[]): void {
  const byId = new Map(operations.map(operation => [operationId(operation), operation]))
  for (const operation of operations) for (const [actor, count] of Object.entries(operation.signed.payload.context)) {
    if (!count) continue
    const dependency = byId.get(`${actor}:${count}`)
    if (!dependency) throw new Error("Missing signed identity profile causal evidence")
    for (const [seenActor, seenCount] of Object.entries(dependency.signed.payload.context)) {
      if ((operation.signed.payload.context[seenActor] ?? 0) < seenCount) throw new Error("Contradictory identity profile causal context")
    }
    if (precedes(operation, dependency)) throw new Error("Cyclic identity profile causal context")
  }
}

function parseOperation(value: unknown): IdentityProfileOperation {
  if (!isRecord(value) || !onlyKeys(value, ["signed", "certificates"]) || !isRecord(value.signed) ||
      !onlyKeys(value.signed, ["payload", "signerKeyId", "signature"]) || !isRecord(value.signed.payload) ||
      !Array.isArray(value.certificates) || value.certificates.some(item => !isRecord(item))) throw new Error("Invalid identity profile operation")
  const payload = value.signed.payload
  if (!onlyKeys(payload, ["kind", "version", "personId", "deviceId", "counter", "context", "field", "value", "supersedesLegacy"]) ||
      payload.kind !== "identity-profile-update" || payload.version !== 1 || typeof payload.personId !== "string" ||
      typeof payload.deviceId !== "string" || !Number.isSafeInteger(payload.counter) || !isProfileField(payload.field) ||
      !isRecord(payload.context) || !Array.isArray(payload.supersedesLegacy) || typeof value.signed.signerKeyId !== "string" ||
      typeof value.signed.signature !== "string") throw new Error("Invalid identity profile operation")
  return structuredClone(value) as unknown as IdentityProfileOperation
}

function validateValue(field: IdentityProfileField, value: unknown): asserts value is IdentityProfileValue {
  if (field === "name") {
    if (!isValidIdentityDisplayName(value)) throw new Error("Invalid identity profile name")
  } else if (!isValidIdentityProfilePhoto(value)) {
    throw new Error("Invalid identity profile photo")
  }
}

async function legacyId(field: IdentityProfileField, value: IdentityProfileValue): Promise<string> {
  return sha256Base64Url(new TextEncoder().encode(canonicalizeJson([field, value])))
}

function boundedSnapshot(value: unknown): Record<string, unknown> {
  let raw: string | undefined
  try { raw = JSON.stringify(value) } catch { throw new Error("Invalid identity profile state") }
  if (!raw || new TextEncoder().encode(raw).byteLength > maxStateBytes) throw new Error("Identity profile evidence exceeds size limit")
  const snapshot: unknown = JSON.parse(raw)
  if (isRecord(snapshot) && snapshot.version !== undefined && snapshot.version !== 1) throw new Error("Identity profile state requires an update")
  if (!isRecord(snapshot)) throw new Error("Invalid identity profile state")
  return snapshot
}

function isRecord(value: unknown): value is Record<string, any> { return value !== null && typeof value === "object" && !Array.isArray(value) }
function onlyKeys(value: Record<string, unknown>, keys: string[]): boolean { return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)) }
function isProfileField(value: unknown): value is IdentityProfileField { return value === "name" || value === "photo" }
function isPersonId(value: unknown): value is string { return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/u.test(value) }
function isHash(value: unknown): value is string { return isPersonId(value) }
