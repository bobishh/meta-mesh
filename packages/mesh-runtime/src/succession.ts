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

function catalogSnapshot<TCredential extends RuntimeWorkspaceCredential>(host: SuccessionHost<TCredential>, credential: TCredential) {
  return JSON.stringify({ policy: host.getPolicy(credential), votes: host.getVotes(credential), claims: host.getClaims(credential) })
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
  if (!rawPolicy && rawVotes.length === 0 && rawClaims.length === 0 && !host.getPolicy(initial) &&
    host.getVotes(initial).length === 0 && host.getClaims(initial).length === 0) return initial
  const before = catalogSnapshot(host, initial)
  const plan = meshRustRuntime().state.planSuccessionMerge({
    workspaceId: initial.workspaceId,
    owner: { personId: initial.ownerPersonId, publicKey: initial.ownerPublicKey,
      certificates: initial.ownerCertificates },
    ownerHistory: host.getAuthorities(initial), epoch: initial.epoch,
    currentPolicy: host.getPolicy(initial) ?? null, currentVotes: host.getVotes(initial), currentClaims: host.getClaims(initial),
    incomingPolicy: rawPolicy ?? null, incomingVotes: rawVotes, incomingClaims: rawClaims,
    revokedPeople: [...host.revokedPeople(initial)], revokedBeforeEpoch: [...host.revokedBefore(initial, initial.epoch)],
  }, Date.now()) as { policy?: WorkspaceSuccessionPolicy; votes: WorkspaceSuccessionVote[];
    claims: WorkspaceSuccessionClaim[]; transitions: WorkspaceSuccessionClaim[]; conflicted: boolean }
  let credential = initial
  if (!plan.conflicted) {
    for (const claim of plan.transitions) credential = await adoptClaim(host, credential, claim, plan.claims)
  }
  if (credential.ownerPersonId === initial.ownerPersonId) {
    const catalog = { ...host.getCatalog(credential), successionPolicy: plan.policy, successionVotes: plan.votes,
      successionClaims: plan.claims }
    if (JSON.stringify({ policy: plan.policy, votes: plan.votes, claims: plan.claims }) !== before) {
      await host.putCredential({ ...credential, updatedAt: new Date().toISOString(), catalog })
      credential = await host.getCredential(credential.workspaceId) ?? credential
    }
  }
  if (catalogSnapshot(host, credential) !== before && host.sessionCount() > 0) queueMicrotask(() => { void host.publishAll() })
  return credential
}
