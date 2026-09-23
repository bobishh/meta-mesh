import type { DeviceCertificate, LocalProfile } from "@meta-uber/mesh-identity"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
import { verifyWorkspaceOwnershipTransfer, type WorkspaceAuthority, type WorkspaceOwnershipTransfer } from "@meta-uber/mesh-workspace"
import type { RuntimeWorkspaceCredential } from "./succession"

export type OwnershipTransferHost<TCredential extends RuntimeWorkspaceCredential = RuntimeWorkspaceCredential> = {
  getProfile: () => Promise<LocalProfile>
  transfers: (credential: TCredential) => WorkspaceOwnershipTransfer[]
  ownershipEpoch: (credential: TCredential) => number
  catalog: (credential: TCredential) => Record<string, unknown>
  authorities: (credential: TCredential) => WorkspaceAuthority[]
  revokedPeople: (credential: TCredential) => Set<string>
  putCredential: (credential: TCredential) => Promise<void>
  transferCredential: (previousOwner: string, credential: TCredential) => Promise<void>
  updateTransferredPeers: (credential: TCredential, payload: WorkspaceOwnershipTransfer["payload"]) => Promise<void>
}

const ordered = (records: Iterable<WorkspaceOwnershipTransfer>) => [...records].sort((a, b) =>
  a.payload.epoch - b.payload.epoch || a.signature.localeCompare(b.signature))

export async function mergeOwnershipTransfers<TCredential extends RuntimeWorkspaceCredential>(
  host: OwnershipTransferHost<TCredential>, initial: TCredential, raw: WorkspaceOwnershipTransfer[],
): Promise<TCredential> {
  let credential = initial
  const known = new Map(host.transfers(credential).map(record => [record.signature, record]))
  for (const record of raw) if (record?.signature) known.set(record.signature, record)
  const accepted = new Map(host.transfers(credential).map(record => [record.signature, record]))
  const persist = async () => {
    credential = { ...credential, catalog: { ...host.catalog(credential), ownershipTransfers: ordered(accepted.values()) } } as TCredential
    await host.putCredential(credential)
  }
  for (const value of known.values()) {
    if (accepted.has(value.signature) || (value.payload?.epoch ?? 0) > host.ownershipEpoch(credential)) continue
    const authority = host.authorities(credential).find(owner => owner.personId === value.payload?.fromOwnerPersonId)
    if (!authority) continue
    accepted.set(value.signature, await verifyWorkspaceOwnershipTransfer(value, credential.workspaceId, authority, value.payload.epoch - 1))
  }
  if (meshRustRuntime().state.hasConflictingOwnershipTransfers(ordered(accepted.values()))) return persist().then(() => credential)
  while (true) {
    const ownerEpoch = host.ownershipEpoch(credential)
    const nextEpoch = Math.min(...[...known.values()].filter(value => value.payload?.epoch > ownerEpoch &&
      value.payload.fromOwnerPersonId === credential.ownerPersonId).map(value => value.payload.epoch))
    const candidates = [...known.values()].filter(value => value.payload?.epoch === nextEpoch &&
      value.payload.fromOwnerPersonId === credential.ownerPersonId).sort((a, b) => a.signature.localeCompare(b.signature))
    if (!candidates.length) return credential
    const authority: WorkspaceAuthority = { personId: credential.ownerPersonId, publicKey: credential.ownerPublicKey,
      certificates: credential.ownerCertificates as DeviceCertificate[] }
    for (const value of candidates) {
      const record = await verifyWorkspaceOwnershipTransfer(value, credential.workspaceId, authority, ownerEpoch)
      if (host.revokedPeople(credential).has(record.payload.toOwnerPersonId)) throw new Error("New owner access is revoked")
      accepted.set(record.signature, record)
    }
    const plan = meshRustRuntime().state.planOwnershipTransitions(ordered(accepted.values()), credential.ownerPersonId, ownerEpoch) as {
      records: WorkspaceOwnershipTransfer[]; conflicted: boolean
    }
    if (plan.conflicted || !plan.records.length) return persist().then(() => credential)
    const record = plan.records[0]!
    const payload = record.payload
    const profile = await host.getProfile()
    const authorityHistory = [...(credential.ownerHistory ?? [])]
    if (!authorityHistory.some(owner => owner.personId === credential.ownerPersonId)) authorityHistory.push(authority)
    const localGrant = profile.identity.personId === payload.toOwnerPersonId ? payload.toOwnerGrant :
      profile.identity.personId === payload.fromOwnerPersonId ? payload.formerOwnerGrant : credential.localGrant
    const next = { ...credential, ownerPersonId: payload.toOwnerPersonId, ownerPublicKey: payload.toOwnerPublicKey,
      ownerCertificates: payload.toOwnerCertificates, ownerHistory: authorityHistory, localGrant,
      epoch: Math.max(credential.epoch, payload.epoch),
      updatedAt: payload.transferredAt, catalog: { ...host.catalog(credential), ownershipTransfers: ordered(accepted.values()), successionPolicy: undefined, successionVotes: [] } } as TCredential
    await host.transferCredential(credential.ownerPersonId, next)
    await host.updateTransferredPeers(next, payload)
    credential = next
  }
}
