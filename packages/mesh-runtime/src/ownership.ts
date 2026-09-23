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
  listPeers: (workspaceId: string) => Promise<unknown[]>
  putPeers: (peers: unknown[]) => Promise<void>
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
    const authority: WorkspaceAuthority = { personId: credential.ownerPersonId, publicKey: credential.ownerPublicKey,
      certificates: credential.ownerCertificates as DeviceCertificate[] }
    const plan = meshRustRuntime().state.nextVerifiedOwnershipTransition(
      [...known.values()], credential.workspaceId, authority, ownerEpoch, [...host.revokedPeople(credential)], Date.now(),
    ) as {
      candidates: WorkspaceOwnershipTransfer[]; selected: WorkspaceOwnershipTransfer | null; conflicted: boolean
    }
    for (const record of plan.candidates) accepted.set(record.signature, record)
    if (plan.conflicted) return persist().then(() => credential)
    if (!plan.selected) return accepted.size > host.transfers(credential).length ? persist().then(() => credential) : credential
    const record = plan.selected
    const profile = await host.getProfile()
    const adoption = meshRustRuntime().state.planOwnershipAdoption({ credential,
      peers: await host.listPeers(credential.workspaceId), localPersonId: profile.identity.personId,
      verifiedCurrentOwnerEpoch: ownerEpoch,
      transition: { kind: "transfer", record, accepted: ordered(accepted.values()) } })
    credential = adoption.credential as TCredential
    await host.transferCredential(adoption.previousOwnerPersonId, credential)
    await host.putPeers(adoption.peers)
  }
}
