import type { DeviceCertificate } from "@meta-uber/mesh-identity"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
import {
  verifyWorkspaceBreakGlassClaim,
  type WorkspaceAuthority,
  type WorkspaceBreakGlassClaim,
} from "@meta-uber/mesh-workspace"
import type { RuntimeWorkspaceCredential } from "./succession"

export type BreakGlassHost<TCredential extends RuntimeWorkspaceCredential = RuntimeWorkspaceCredential> = {
  getProfile: () => Promise<{ identity: { personId: string } }>
  claims: (credential: TCredential) => WorkspaceBreakGlassClaim[]
  catalog: (credential: TCredential) => Record<string, unknown>
  authorities: (credential: TCredential) => WorkspaceAuthority[]
  revokedPeople: (credential: TCredential) => Set<string>
  conflict: (claims: WorkspaceBreakGlassClaim[]) => boolean
  putCredential: (credential: TCredential) => Promise<void>
  transferCredential: (previousOwner: string, credential: TCredential) => Promise<void>
}

function ordered(records: Map<string, WorkspaceBreakGlassClaim>) {
  return [...records.values()].sort((a, b) => a.payload.epoch - b.payload.epoch || a.signature.localeCompare(b.signature))
}

async function retainHistorical<TCredential extends RuntimeWorkspaceCredential>(host: BreakGlassHost<TCredential>, credential: TCredential,
  known: Map<string, WorkspaceBreakGlassClaim>, accepted: Map<string, WorkspaceBreakGlassClaim>): Promise<boolean> {
  let changed = false
  for (const value of known.values()) {
    if (accepted.has(value.signature) || (value.payload?.epoch ?? 0) > credential.epoch) continue
    const authority = host.authorities(credential).find(owner => owner.personId === value.payload?.fromOwnerPersonId)
    if (!authority) continue
    const record = await verifyWorkspaceBreakGlassClaim(value, credential.workspaceId, authority,
      value.payload.epoch - 1, host.authorities(credential))
    accepted.set(record.signature, record)
    changed = true
  }
  return changed
}

async function persistClaims<TCredential extends RuntimeWorkspaceCredential>(host: BreakGlassHost<TCredential>, credential: TCredential,
  accepted: Map<string, WorkspaceBreakGlassClaim>): Promise<TCredential> {
  const next = { ...credential, catalog: { ...host.catalog(credential), breakGlassClaims: ordered(accepted) } }
  await host.putCredential(next)
  return next as TCredential
}

function nextClaims(credential: RuntimeWorkspaceCredential, known: Map<string, WorkspaceBreakGlassClaim>) {
  return [...known.values()].filter(value => value.payload?.epoch === credential.epoch + 1 &&
    value.payload.fromOwnerPersonId === credential.ownerPersonId).sort((a, b) => a.signature.localeCompare(b.signature))
}

async function verifyCandidates<TCredential extends RuntimeWorkspaceCredential>(host: BreakGlassHost<TCredential>, credential: TCredential,
  candidates: WorkspaceBreakGlassClaim[], accepted: Map<string, WorkspaceBreakGlassClaim>): Promise<WorkspaceBreakGlassClaim[]> {
  const authority: WorkspaceAuthority = { personId: credential.ownerPersonId, publicKey: credential.ownerPublicKey,
    certificates: credential.ownerCertificates as DeviceCertificate[] }
  const verified: WorkspaceBreakGlassClaim[] = []
  for (const value of candidates) {
    const record = await verifyWorkspaceBreakGlassClaim(value, credential.workspaceId, authority, credential.epoch,
      host.authorities(credential))
    if (host.revokedPeople(credential).has(record.payload.toOwnerPersonId)) throw new Error("New owner access is revoked")
    accepted.set(record.signature, record)
    verified.push(record)
  }
  return verified
}

async function adoptClaim<TCredential extends RuntimeWorkspaceCredential>(host: BreakGlassHost<TCredential>, credential: TCredential, record: WorkspaceBreakGlassClaim,
  accepted: Map<string, WorkspaceBreakGlassClaim>): Promise<TCredential> {
  const payload = record.payload
  const profile = await host.getProfile()
  const authority: WorkspaceAuthority = { personId: credential.ownerPersonId, publicKey: credential.ownerPublicKey,
    certificates: credential.ownerCertificates as DeviceCertificate[] }
  const history = [...((credential.ownerHistory ?? []) as WorkspaceAuthority[])]
  if (!history.some(owner => owner.personId === authority.personId)) history.push(authority)
  const withoutGrant = { ...credential }
  delete withoutGrant.localGrant
  const next = {
    ...withoutGrant,
    ...(profile.identity.personId === payload.toOwnerPersonId ? {} : credential.localGrant ? { localGrant: credential.localGrant } : {}),
    ownerPersonId: payload.toOwnerPersonId,
    ownerPublicKey: payload.toOwnerPublicKey,
    ownerCertificates: payload.toOwnerCertificates,
    ownerHistory: history,
    epoch: payload.epoch,
    updatedAt: payload.claimedAt,
    catalog: { ...host.catalog(credential), breakGlassClaims: ordered(accepted), successionPolicy: undefined, successionVotes: [] },
  } as TCredential
  await host.transferCredential(credential.ownerPersonId, next)
  return next
}

export async function mergeBreakGlassClaims<TCredential extends RuntimeWorkspaceCredential>(host: BreakGlassHost<TCredential>, initial: TCredential,
  raw: WorkspaceBreakGlassClaim[]): Promise<TCredential> {
  let credential = initial
  const known = new Map(host.claims(credential).map(record => [record.signature, record]))
  for (const record of raw) if (record?.signature) known.set(record.signature, record)
  const accepted = new Map(host.claims(credential).map(record => [record.signature, record]))
  let dirty = await retainHistorical(host, credential, known, accepted)
  if (host.conflict(ordered(accepted))) return persistClaims(host, credential, accepted)
  while (true) {
    const candidates = nextClaims(credential, known)
    if (!candidates.length) break
    const verified = await verifyCandidates(host, credential, candidates, accepted)
    const plan = meshRustRuntime().state.planOwnershipTransitions([...accepted.values()],
      credential.ownerPersonId, credential.epoch) as { records: WorkspaceBreakGlassClaim[]; conflicted: boolean }
    if (plan.conflicted || !plan.records.length) return persistClaims(host, credential, accepted)
    credential = await adoptClaim(host, credential, plan.records[0]!, accepted)
    dirty = false
  }
  return dirty ? persistClaims(host, credential, accepted) : credential
}
