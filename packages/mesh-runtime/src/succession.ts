import type { LocalProfile } from "@meta-uber/mesh-identity"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
import type {
  WorkspaceAuthority, WorkspaceSuccessionClaim, WorkspaceSuccessionPolicy, WorkspaceSuccessionVote,
} from "@meta-uber/mesh-workspace"

export type RuntimeWorkspaceCredential = {
  workspaceId: string
  ownerPersonId: string
  ownerPublicKey: string
  ownerCertificates: unknown[]
  ownerHistory?: Array<{ personId: string; publicKey: string; certificates: unknown[] }>
  localGrant?: unknown
  epoch: number
  updatedAt: string
  catalog?: unknown
}

export type SuccessionHost<TCredential extends RuntimeWorkspaceCredential = RuntimeWorkspaceCredential> = {
  getProfile: () => Promise<LocalProfile>
  getPolicy: (credential: TCredential) => WorkspaceSuccessionPolicy | undefined
  getVotes: (credential: TCredential) => WorkspaceSuccessionVote[]
  getClaims: (credential: TCredential) => WorkspaceSuccessionClaim[]
  getCatalog: (credential: TCredential) => Record<string, unknown>
  getAuthorities: (credential: TCredential) => WorkspaceAuthority[]
  revokedPeople: (credential: TCredential) => Set<string>
  revokedBefore: (credential: TCredential, epoch: number) => Set<string>
  putCredential: (credential: TCredential) => Promise<void>
  getCredential: (workspaceId: string) => Promise<TCredential | null>
  transferCredential: (previousOwner: string, credential: TCredential) => Promise<void>
  listPeers: (workspaceId: string) => Promise<unknown[]>
  putPeers: (peers: unknown[]) => Promise<void>
  sessionCount: () => number
  publishAll: () => Promise<void>
}

async function adoptClaim<TCredential extends RuntimeWorkspaceCredential>(host: SuccessionHost<TCredential>, credential: TCredential,
  claim: WorkspaceSuccessionClaim, claims: WorkspaceSuccessionClaim[]): Promise<TCredential> {
  const profile = await host.getProfile()
  const plan = meshRustRuntime().state.planOwnershipAdoption({ credential,
    peers: await host.listPeers(credential.workspaceId), localPersonId: profile.identity.personId,
    verifiedCurrentOwnerEpoch: credential.epoch,
    transition: { kind: "succession", record: claim, claims } })
  const next = plan.credential as TCredential
  await host.transferCredential(plan.previousOwnerPersonId, next)
  await host.putPeers(plan.peers)
  return next
}

export async function mergeSuccessionState<TCredential extends RuntimeWorkspaceCredential>(host: SuccessionHost<TCredential>, initial: TCredential,
  rawPolicy: WorkspaceSuccessionPolicy | undefined, rawVotes: WorkspaceSuccessionVote[],
  rawClaims: WorkspaceSuccessionClaim[]): Promise<TCredential> {
  const plan = meshRustRuntime().state.planSuccessionMerge({
    workspaceId: initial.workspaceId,
    owner: { personId: initial.ownerPersonId, publicKey: initial.ownerPublicKey,
      certificates: initial.ownerCertificates },
    ownerHistory: host.getAuthorities(initial), epoch: initial.epoch,
    currentPolicy: host.getPolicy(initial) ?? null, currentVotes: host.getVotes(initial), currentClaims: host.getClaims(initial),
    incomingPolicy: rawPolicy ?? null, incomingVotes: rawVotes, incomingClaims: rawClaims,
    revokedPeople: [...host.revokedPeople(initial)], revokedBeforeEpoch: [...host.revokedBefore(initial, initial.epoch)],
  }, Date.now()) as { noop: boolean; policy?: WorkspaceSuccessionPolicy; votes: WorkspaceSuccessionVote[];
    claims: WorkspaceSuccessionClaim[]; transitions: WorkspaceSuccessionClaim[]; conflicted: boolean }
  if (plan.noop) return initial
  let credential = initial
  if (!plan.conflicted) {
    for (const claim of plan.transitions) credential = await adoptClaim(host, credential, claim, plan.claims)
  }
  const catalogPlan = meshRustRuntime().state.planSuccessionCatalog({ originalCatalog: host.getCatalog(initial),
    originalOwnerPersonId: initial.ownerPersonId, credential,
    policy: plan.policy ?? null, votes: plan.votes, claims: plan.claims,
    updatedAt: new Date().toISOString() })
  if (catalogPlan.persist) {
    credential = catalogPlan.credential as TCredential
    await host.putCredential(credential)
    credential = await host.getCredential(credential.workspaceId) ?? credential
  }
  if (catalogPlan.publish && host.sessionCount() > 0) queueMicrotask(() => { void host.publishAll() })
  return credential
}
