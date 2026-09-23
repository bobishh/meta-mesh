import type { LocalProfile } from "@meta-uber/mesh-identity"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
import type { WorkspaceAuthority, WorkspaceOwnershipTransfer } from "@meta-uber/mesh-workspace"
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

export async function mergeOwnershipTransfers<TCredential extends RuntimeWorkspaceCredential>(
  host: OwnershipTransferHost<TCredential>, initial: TCredential, raw: WorkspaceOwnershipTransfer[],
): Promise<TCredential> {
  const plan = meshRustRuntime().state.planOwnershipMerge({ workspaceId: initial.workspaceId,
    currentOwner: { personId: initial.ownerPersonId, publicKey: initial.ownerPublicKey,
      certificates: initial.ownerCertificates }, ownerHistory: host.authorities(initial).slice(1),
    ownerEpoch: host.ownershipEpoch(initial), current: host.transfers(initial), incoming: raw,
    revokedPeople: [...host.revokedPeople(initial)], nowMs: Date.now() }) as {
      accepted: WorkspaceOwnershipTransfer[]; steps: Array<{ record: WorkspaceOwnershipTransfer;
        accepted: WorkspaceOwnershipTransfer[]; previousOwnerEpoch: number }>; persistCatalog: boolean
    }
  let credential = initial
  for (const step of plan.steps) {
    const profile = await host.getProfile()
    const adoption = meshRustRuntime().state.planOwnershipAdoption({ credential,
      peers: await host.listPeers(credential.workspaceId), localPersonId: profile.identity.personId,
      verifiedCurrentOwnerEpoch: step.previousOwnerEpoch,
      transition: { kind: "transfer", record: step.record, accepted: step.accepted } })
    credential = adoption.credential as TCredential
    await host.transferCredential(adoption.previousOwnerPersonId, credential)
    await host.putPeers(adoption.peers)
  }
  if (plan.persistCatalog) {
    credential = { ...credential, catalog: { ...host.catalog(credential), ownershipTransfers: plan.accepted } } as TCredential
    await host.putCredential(credential)
  }
  return credential
}
