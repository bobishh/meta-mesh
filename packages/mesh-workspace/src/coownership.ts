import { signEnvelope, type DeviceCertificate, type LocalProfile, type SignedEnvelope } from "@meta-uber/mesh-identity"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"

/** Opt-in governance only. Existing v1 workspace permissions remain separate. */
export type CoownerPolicy = "majority" | "unanimous"
export type CoownerIdentity = { personId: string; publicKey: string; certificates: DeviceCertificate[] }
export type CoownedGenesisPayload = {
  kind: "scope-coownership-genesis"; version: 2; scopeId: string
  creator: CoownerIdentity; policy: CoownerPolicy; epoch: number
}
export type CoownedTransitionPayload = {
  kind: "scope-coownership-transition"; version: 2; scopeId: string
  parentCertificateHash: string; epoch: number; owners: CoownerIdentity[]; policy: CoownerPolicy
}
export type CoownedResolutionPayload = Omit<CoownedTransitionPayload, "kind"> & {
  kind: "scope-coownership-resolution"; conflictingCertificateHashes: string[]
}
export type CoownedApproval = { signerKeyId: string; signature: string }
export type CoownedTransition = { payload: CoownedTransitionPayload; approvals: CoownedApproval[] }
export type CoownedResolution = { payload: CoownedResolutionPayload; approvals: CoownedApproval[] }
export type CoownershipLedger = {
  genesis: SignedEnvelope<CoownedGenesisPayload>; transitions: CoownedTransition[]; resolutions: CoownedResolution[]
}
export type CoownershipState = {
  scopeId: string; certificateHash: string; epoch: number; owners: CoownerIdentity[]; policy: CoownerPolicy
}
export type CoownershipConflict = { parentCertificateHash: string; conflictingCertificateHashes: string[] }
export type ValidatedCoownership = {
  scopeId: string
  status: { status: "authorized"; value: CoownershipState }
    | { status: "ambiguous"; value: { conflicts: CoownershipConflict[] } }
}

export function coownerIdentity(profile: LocalProfile): CoownerIdentity {
  return { personId: profile.identity.personId, publicKey: profile.identity.publicKey, certificates: [profile.certificate] }
}

export async function createCoownershipLedger(profile: LocalProfile, scopeId: string,
  policy: CoownerPolicy = "majority"): Promise<CoownershipLedger> {
  const payload = meshRustRuntime().state.createCoownershipGenesisPayload({
    scopeId, creator: coownerIdentity(profile), policy,
  }) as CoownedGenesisPayload
  const genesis = await signEnvelope(profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId)
  const ledger = { genesis, transitions: [], resolutions: [] }
  validateCoownershipLedger(ledger)
  return ledger
}

export function validateCoownershipLedger(ledger: CoownershipLedger): ValidatedCoownership {
  return meshRustRuntime().state.validateCoownershipLedger(ledger) as ValidatedCoownership
}

export function mergeCoownershipLedgers(current: CoownershipLedger | null, incoming: CoownershipLedger): CoownershipLedger {
  return meshRustRuntime().state.mergeCoownershipLedgers(current, incoming) as CoownershipLedger
}

export function planCoownershipTransition(ledger: CoownershipLedger, owners: CoownerIdentity[],
  policy: CoownerPolicy): CoownedTransitionPayload {
  return meshRustRuntime().state.planCoownershipTransition({ ledger, owners: sortedOwners(owners), policy }) as CoownedTransitionPayload
}

export function planCoownershipResolution(ledger: CoownershipLedger, parentCertificateHash: string,
  owners: CoownerIdentity[], policy: CoownerPolicy): CoownedResolutionPayload {
  return meshRustRuntime().state.planCoownershipResolution({ ledger, parentCertificateHash, owners: sortedOwners(owners), policy }) as CoownedResolutionPayload
}

function sortedOwners(owners: CoownerIdentity[]): CoownerIdentity[] {
  return [...owners].sort((left, right) => left.personId < right.personId ? -1 : left.personId > right.personId ? 1 : 0)
}

/** Sign the common proposal; callers must gather the parent policy's quorum. */
export async function approveCoownershipPayload(profile: LocalProfile,
  payload: CoownedTransitionPayload | CoownedResolutionPayload): Promise<CoownedApproval> {
  // Restoring the same root creates a new device. Root approval stays bound to
  // the existing owner identity without requiring the old device key to survive.
  const rootKey = profile.privateKeys.identityPrivateKey
  const signed = await signEnvelope(rootKey ?? profile.privateKeys.devicePrivateKey, payload,
    rootKey ? profile.identity.personId : profile.device.deviceId)
  return { signerKeyId: signed.signerKeyId, signature: signed.signature }
}

export async function forkCoownershipLedger(sourceLedger: CoownershipLedger, profile: LocalProfile,
  scopeId: string, policy: CoownerPolicy = "majority"): Promise<CoownershipLedger> {
  const payload = meshRustRuntime().state.planCoownershipFork({
    sourceLedger, scopeId, creator: coownerIdentity(profile), policy,
  }) as CoownedGenesisPayload
  const genesis = await signEnvelope(profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId)
  const ledger = { genesis, transitions: [], resolutions: [] }
  validateCoownershipLedger(ledger)
  return ledger
}
