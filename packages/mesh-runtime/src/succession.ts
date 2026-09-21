import type { DeviceCertificate, LocalProfile } from "@meta-uber/mesh-identity"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
import {
  verifyWorkspaceSuccessionClaim,
  verifyWorkspaceSuccessionPolicy,
  verifyWorkspaceSuccessionVote,
  type WorkspaceAuthority,
  type WorkspaceSuccessionClaim,
  type WorkspaceSuccessionPolicy,
  type WorkspaceSuccessionVote,
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
  updateTransferredPeers: (credential: TCredential, payload: WorkspaceSuccessionClaim["payload"]) => Promise<void>
  sessionCount: () => number
  publishAll: () => Promise<void>
}

const authorityFor = (credential: RuntimeWorkspaceCredential): WorkspaceAuthority => ({
  personId: credential.ownerPersonId,
  publicKey: credential.ownerPublicKey,
  certificates: credential.ownerCertificates as DeviceCertificate[],
})

function catalogSnapshot<TCredential extends RuntimeWorkspaceCredential>(host: SuccessionHost<TCredential>, credential: TCredential) {
  return JSON.stringify({
    policy: host.getPolicy(credential),
    votes: host.getVotes(credential),
    claims: host.getClaims(credential),
  })
}

async function selectPolicy<TCredential extends RuntimeWorkspaceCredential>(host: SuccessionHost<TCredential>, credential: TCredential,
  rawPolicy: WorkspaceSuccessionPolicy | undefined): Promise<WorkspaceSuccessionPolicy | undefined> {
  let policy = host.getPolicy(credential)
  if (rawPolicy?.payload?.ownerPersonId === credential.ownerPersonId && rawPolicy.payload.epoch === credential.epoch) {
    const verified = await verifyWorkspaceSuccessionPolicy(rawPolicy, credential.workspaceId, authorityFor(credential))
    if (!policy || verified.payload.updatedAt > policy.payload.updatedAt ||
      (verified.payload.updatedAt === policy.payload.updatedAt && verified.signature > policy.signature)) policy = verified
  }
  if (!policy || policy.payload.ownerPersonId !== credential.ownerPersonId || policy.payload.epoch !== credential.epoch) return undefined
  return verifyWorkspaceSuccessionPolicy(policy, credential.workspaceId, authorityFor(credential))
}

async function collectVotes<TCredential extends RuntimeWorkspaceCredential>(host: SuccessionHost<TCredential>, credential: TCredential, policy: WorkspaceSuccessionPolicy | undefined,
  rawVotes: WorkspaceSuccessionVote[]): Promise<WorkspaceSuccessionVote[]> {
  if (!policy) return []
  const votes = new Map<string, WorkspaceSuccessionVote>()
  for (const raw of [...host.getVotes(credential), ...rawVotes]) {
    if (raw?.signed?.payload?.policySignature !== policy.signature) continue
    const vote = await verifyWorkspaceSuccessionVote(raw, policy, raw.signed.payload.candidatePersonId,
      authorityFor(credential), host.revokedPeople(credential), Date.now())
    const prior = votes.get(vote.signed.payload.voterPersonId)
    if (!prior || vote.signed.signature < prior.signed.signature) votes.set(vote.signed.payload.voterPersonId, vote)
  }
  return [...votes.values()].sort((a, b) => a.signed.payload.voterPersonId.localeCompare(b.signed.payload.voterPersonId))
}

async function collectClaims<TCredential extends RuntimeWorkspaceCredential>(host: SuccessionHost<TCredential>, credential: TCredential,
  rawClaims: WorkspaceSuccessionClaim[]): Promise<Map<string, WorkspaceSuccessionClaim>> {
  const claims = new Map<string, WorkspaceSuccessionClaim>()
  for (const claim of host.getClaims(credential)) if (claim?.signature) claims.set(claim.signature, claim)
  for (const claim of rawClaims) await verifyAndStoreClaim(host, credential, claim, claims)
  return claims
}

async function verifyAndStoreClaim<TCredential extends RuntimeWorkspaceCredential>(host: SuccessionHost<TCredential>, credential: TCredential, claim: WorkspaceSuccessionClaim,
  claims: Map<string, WorkspaceSuccessionClaim>): Promise<void> {
  if (!claim?.signature) return
  if (claim.payload?.epoch === credential.epoch + 1 && claim.payload.fromOwnerPersonId === credential.ownerPersonId) {
    const verified = await verifyWorkspaceSuccessionClaim(claim, credential.workspaceId, authorityFor(credential), credential.epoch,
      host.revokedPeople(credential))
    claims.set(verified.signature, verified)
    return
  }
  if (claim.payload?.epoch !== credential.epoch) return
  const previousOwner = host.getAuthorities(credential).find(owner => owner.personId === claim.payload.fromOwnerPersonId)
  if (!previousOwner) return
  const revokedAtClaim = host.revokedBefore(credential, claim.payload.epoch)
  const verified = await verifyWorkspaceSuccessionClaim(claim, credential.workspaceId, previousOwner,
    claim.payload.epoch - 1, revokedAtClaim)
  claims.set(verified.signature, verified)
}

async function adoptPendingClaims<TCredential extends RuntimeWorkspaceCredential>(host: SuccessionHost<TCredential>, initial: TCredential,
  claims: Map<string, WorkspaceSuccessionClaim>): Promise<TCredential> {
  let credential = initial
  const plan = meshRustRuntime().state.planOwnershipTransitions([...claims.values()], credential.ownerPersonId, credential.epoch) as {
    records: WorkspaceSuccessionClaim[]
    conflicted: boolean
  }
  if (plan.conflicted) return credential
  for (const raw of plan.records) {
    credential = await adoptClaim(host, credential, raw, claims)
  }
  return credential
}

async function adoptClaim<TCredential extends RuntimeWorkspaceCredential>(host: SuccessionHost<TCredential>, credential: TCredential, raw: WorkspaceSuccessionClaim,
  claims: Map<string, WorkspaceSuccessionClaim>): Promise<TCredential> {
  const previousOwner = authorityFor(credential)
  const claim = await verifyWorkspaceSuccessionClaim(raw, credential.workspaceId, previousOwner, credential.epoch,
    host.revokedPeople(credential))
  const payload = claim.payload
  const profile = await host.getProfile()
  const history = [...((credential.ownerHistory ?? []) as WorkspaceAuthority[])]
  if (!history.some(owner => owner.personId === previousOwner.personId)) history.push(previousOwner)
  const localGrant = profile.identity.personId === payload.toOwnerPersonId ? undefined
    : profile.identity.personId === payload.fromOwnerPersonId ? payload.formerOwnerGrant : credential.localGrant
  const next = {
    ...credential,
    ownerPersonId: payload.toOwnerPersonId,
    ownerPublicKey: payload.toOwnerPublicKey,
    ownerCertificates: payload.toOwnerCertificates,
    ownerHistory: history,
    ...(localGrant ? { localGrant } : {}),
    epoch: payload.epoch,
    updatedAt: payload.claimedAt,
    catalog: { ...host.getCatalog(credential), successionPolicy: undefined, successionVotes: [],
      successionClaims: [...claims.values()].sort((a, b) => a.payload.epoch - b.payload.epoch) },
  } as TCredential
  await host.transferCredential(previousOwner.personId, next)
  await host.updateTransferredPeers(next, payload)
  return next
}

export async function mergeSuccessionState<TCredential extends RuntimeWorkspaceCredential>(host: SuccessionHost<TCredential>, initial: TCredential,
  rawPolicy: WorkspaceSuccessionPolicy | undefined, rawVotes: WorkspaceSuccessionVote[],
  rawClaims: WorkspaceSuccessionClaim[]): Promise<TCredential> {
  if (!rawPolicy && rawVotes.length === 0 && rawClaims.length === 0 && !host.getPolicy(initial) &&
    host.getVotes(initial).length === 0 && host.getClaims(initial).length === 0) return initial
  const before = catalogSnapshot(host, initial)
  const policy = await selectPolicy(host, initial, rawPolicy)
  const votes = await collectVotes(host, initial, policy, rawVotes)
  const claims = await collectClaims(host, initial, rawClaims)
  let credential = await adoptPendingClaims(host, initial, claims)
  if (credential.ownerPersonId === initial.ownerPersonId) {
    const catalog = { ...host.getCatalog(credential), successionPolicy: policy, successionVotes: votes,
      successionClaims: [...claims.values()].sort((a, b) => a.payload.epoch - b.payload.epoch || a.signature.localeCompare(b.signature)) }
    if (JSON.stringify({ policy, votes, claims: catalog.successionClaims }) !== before) {
      await host.putCredential({ ...credential, updatedAt: new Date().toISOString(), catalog })
      credential = await host.getCredential(credential.workspaceId) ?? credential
    }
  }
  if (catalogSnapshot(host, credential) !== before && host.sessionCount() > 0) queueMicrotask(() => { void host.publishAll() })
  return credential
}
