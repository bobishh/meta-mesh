export type BrowserMeshAuthorityCredential = { workspaceId: string; ownerPersonId: string }
export type BrowserMeshAuthorityProfile = { personId: string }

export type BrowserMeshAuthorityHost<C extends BrowserMeshAuthorityCredential, P extends BrowserMeshAuthorityProfile, R> = {
  profile(): Promise<P>
  credential(workspaceId: string): Promise<C | undefined>
  createRevocation(profile: P, workspaceId: string, personId: string, nextEpoch: number): Promise<R>
  epoch(credential: C): number
  mergeRevocations(credential: C, records: R[], disconnect: boolean): Promise<void>
  refreshSuccessionPolicy(workspaceId: string): Promise<void>
  publishAll(): Promise<void>
  notify(): Promise<void>
  leave(workspaceId: string): Promise<void>
}

export type BrowserMeshSuccessionHost<C extends BrowserMeshAuthorityCredential, P extends BrowserMeshAuthorityProfile, Policy> = {
  profile(): Promise<P>
  credential(workspaceId: string): Promise<C | undefined>
  eligibleEditors(workspaceId: string): Promise<string[]>
  epoch(credential: C): number
  createPolicy(profile: P, workspaceId: string, successorPersonId: string | null, eligibleEditorPersonIds: string[], epoch: number): Promise<Policy>
  setPolicy(credential: C, policy: Policy): Promise<void>
  notify(): Promise<void>
  publishAll(): Promise<void>
}

export type BrowserMeshRecoveryGrant = { payload: { personId: string; role: string } }
export type BrowserMeshRecoveryPolicy = { payload: { successorPersonId?: string | null; eligibleEditorPersonIds: string[] } }
export type BrowserMeshRecoveryVote = { signed: { payload: { voterPersonId: string; candidatePersonId: string } } }

export type BrowserMeshRecoveryHost<
  C extends BrowserMeshAuthorityCredential,
  P extends BrowserMeshAuthorityProfile,
  Policy extends BrowserMeshRecoveryPolicy,
  Grant extends BrowserMeshRecoveryGrant,
  Vote extends BrowserMeshRecoveryVote,
  Claim,
  Certificate,
> = {
  profile(): Promise<P>
  credential(workspaceId: string): Promise<C | undefined>
  policy(credential: C): Policy | undefined
  grant(credential: C): Grant | undefined
  votes(credential: C): Vote[]
  certificates(profile: P): Promise<Certificate[]>
  createVote(profile: P, policy: Policy, candidatePersonId: string, grant: Grant, certificates: Certificate[]): Promise<Vote>
  createClaim(profile: P, credential: C, policy: Policy, votes: Vote[], grant: Grant, certificates: Certificate[]): Promise<Claim>
  merge(credential: C, policy: Policy, votes: Vote[], claims: Claim[]): Promise<void>
  notify(): Promise<void>
  publishAll(): Promise<void>
}

/** Shared authority workflow; hosts provide local signing, storage and active stream effects. */
export class BrowserMeshAuthority<C extends BrowserMeshAuthorityCredential, P extends BrowserMeshAuthorityProfile, R> {
  constructor(private readonly host: BrowserMeshAuthorityHost<C, P, R>) {}

  async revokePerson(workspaceId: string, personId: string): Promise<void> {
    const profile = await this.host.profile()
    const credential = await this.host.credential(workspaceId)
    if (!credential || credential.ownerPersonId !== profile.personId) throw new Error("Only the workspace owner can revoke access")
    const record = await this.host.createRevocation(profile, workspaceId, personId, this.host.epoch(credential) + 1)
    await this.host.mergeRevocations(credential, [record], false)
    await this.host.refreshSuccessionPolicy(workspaceId)
    // Publish the signed tombstone before severing the revoked session.
    await this.host.publishAll()
    const current = await this.host.credential(workspaceId) ?? credential
    await this.host.mergeRevocations(current, [record], true)
    await this.host.notify()
  }

  async leaveWorkspace(workspaceId: string): Promise<void> {
    if (!workspaceId) throw new Error("No active workspace")
    await this.host.leave(workspaceId)
    await this.host.notify()
  }
}

export class BrowserMeshSuccession<C extends BrowserMeshAuthorityCredential, P extends BrowserMeshAuthorityProfile, Policy> {
  constructor(private readonly host: BrowserMeshSuccessionHost<C, P, Policy>) {}

  async setSuccessor(workspaceId: string, personId: string | null): Promise<void> {
    const [profile, credential] = await Promise.all([this.host.profile(), this.host.credential(workspaceId)])
    if (!credential || credential.ownerPersonId !== profile.personId) throw new Error("Only the workspace owner can set succession")
    const eligible = await this.host.eligibleEditors(workspaceId)
    if (personId && !eligible.includes(personId)) throw new Error("Successor must be an editor")
    await this.host.setPolicy(credential, await this.host.createPolicy(profile, workspaceId, personId, eligible, this.host.epoch(credential)))
    await this.host.notify()
    await this.host.publishAll()
  }
}

/** Shared editor-vote and ownership-claim workflow. Signing and document heads stay behind host callbacks. */
export class BrowserMeshRecovery<
  C extends BrowserMeshAuthorityCredential,
  P extends BrowserMeshAuthorityProfile,
  Policy extends BrowserMeshRecoveryPolicy,
  Grant extends BrowserMeshRecoveryGrant,
  Vote extends BrowserMeshRecoveryVote,
  Claim,
  Certificate,
> {
  constructor(private readonly host: BrowserMeshRecoveryHost<C, P, Policy, Grant, Vote, Claim, Certificate>) {}

  async vote(workspaceId: string, candidatePersonId: string): Promise<void> {
    const profile = await this.host.profile()
    const credential = await this.host.credential(workspaceId)
    if (!credential) throw new Error("Workspace membership is unavailable")
    const policy = this.host.policy(credential)
    if (!policy) throw new Error("The owner has not enabled ownership recovery")
    const grant = this.host.grant(credential)
    if (!grant || grant.payload.role !== "editor" ||
      !policy.payload.eligibleEditorPersonIds.includes(profile.personId)) {
      throw new Error("You are not an eligible editor in the current recovery policy")
    }
    if (policy.payload.successorPersonId) throw new Error("This workspace uses a named successor, not editor voting")
    const votes = this.host.votes(credential)
    const existing = votes.find(vote => vote.signed.payload.voterPersonId === profile.personId)
    if (existing?.signed.payload.candidatePersonId === candidatePersonId) return
    if (existing) throw new Error("Your vote is already recorded for this policy")
    const vote = await this.host.createVote(profile, policy, candidatePersonId, grant,
      await this.host.certificates(profile))
    await this.host.merge(credential, policy, [vote], [])
    await this.finish()
  }

  async claim(workspaceId: string): Promise<void> {
    const profile = await this.host.profile()
    const credential = await this.host.credential(workspaceId)
    if (!credential) throw new Error("Only an eligible editor can claim ownership")
    const policy = this.host.policy(credential)
    const grant = this.host.grant(credential)
    if (!policy || !grant || grant.payload.role !== "editor" || grant.payload.personId !== profile.personId) {
      throw new Error("Only an eligible editor can claim ownership")
    }
    const votes = this.host.votes(credential)
    const claim = await this.host.createClaim(profile, credential, policy, votes, grant,
      await this.host.certificates(profile))
    await this.host.merge(credential, policy, votes, [claim])
    await this.finish()
  }

  private async finish(): Promise<void> {
    await this.host.notify()
    await this.host.publishAll()
  }
}
