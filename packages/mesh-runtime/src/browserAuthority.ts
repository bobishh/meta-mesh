export type BrowserMeshAuthorityCredential = { workspaceId: string; ownerPersonId: string }
export type BrowserMeshAuthorityProfile = { personId: string }

export type BrowserMeshAuthorityHost<C extends BrowserMeshAuthorityCredential, P extends BrowserMeshAuthorityProfile, R> = {
  profile(): Promise<P>
  credential(workspaceId: string): Promise<C | undefined>
  createRevocation(profile: P, workspaceId: string, personId: string, nextEpoch: number): Promise<R>
  nextAccessEpoch(workspaceId: string): Promise<number>
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
    const actions = meshRustRuntime().state.planAuthorityCommand({ kind: "revoke", localPersonId: profile.personId,
      ownerPersonId: credential?.ownerPersonId ?? null })
    let record!: R
    let current = credential!
    for (const action of actions) {
      switch (action) {
        case "createRevocation": record = await this.host.createRevocation(profile, workspaceId, personId,
          await this.host.nextAccessEpoch(workspaceId)); break
        case "mergeRevocation": await this.host.mergeRevocations(current, [record], false); break
        case "refreshSuccessionPolicy": await this.host.refreshSuccessionPolicy(workspaceId); break
        case "publish": await this.host.publishAll(); break
        case "reloadCredential": current = await this.host.credential(workspaceId) ?? current; break
        case "disconnectRevoked": await this.host.mergeRevocations(current, [record], true); break
        case "notify": await this.host.notify(); break
      }
    }
  }

  async leaveWorkspace(workspaceId: string): Promise<void> {
    for (const action of meshRustRuntime().state.planAuthorityCommand({ kind: "leave", workspaceId })) {
      if (action === "leave") await this.host.leave(workspaceId)
      if (action === "notify") await this.host.notify()
    }
  }
}

export class BrowserMeshSuccession<C extends BrowserMeshAuthorityCredential, P extends BrowserMeshAuthorityProfile, Policy> {
  constructor(private readonly host: BrowserMeshSuccessionHost<C, P, Policy>) {}

  async setSuccessor(workspaceId: string, personId: string | null): Promise<void> {
    const [profile, credential] = await Promise.all([this.host.profile(), this.host.credential(workspaceId)])
    const eligible = credential?.ownerPersonId === profile.personId ? await this.host.eligibleEditors(workspaceId) : []
    const actions = meshRustRuntime().state.planAuthorityCommand({ kind: "setSuccessor", localPersonId: profile.personId,
      ownerPersonId: credential?.ownerPersonId ?? null, successorPersonId: personId, eligibleEditorPersonIds: eligible })
    let policy!: Policy
    for (const action of actions) {
      switch (action) {
        case "createPolicy": policy = await this.host.createPolicy(profile, workspaceId, personId, eligible, this.host.epoch(credential!)); break
        case "setPolicy": await this.host.setPolicy(credential!, policy); break
        case "notify": await this.host.notify(); break
        case "publish": await this.host.publishAll(); break
      }
    }
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
    const policy = credential && this.host.policy(credential)
    const grant = credential && this.host.grant(credential)
    const votes = credential ? this.host.votes(credential) : []
    const existing = votes.find(vote => vote.signed.payload.voterPersonId === profile.personId)
    const actions = meshRustRuntime().state.planAuthorityCommand({ kind: "vote", localPersonId: profile.personId,
      hasCredential: Boolean(credential), hasPolicy: Boolean(policy), grantRole: grant?.payload.role ?? null,
      eligibleEditorPersonIds: policy?.payload.eligibleEditorPersonIds ?? [],
      successorPersonId: policy?.payload.successorPersonId ?? null, candidatePersonId,
      existingVoteFor: existing?.signed.payload.candidatePersonId ?? null })
    let vote!: Vote
    for (const action of actions) {
      switch (action) {
        case "createVote": vote = await this.host.createVote(profile, policy!, candidatePersonId, grant!,
          await this.host.certificates(profile)); break
        case "mergeVote": await this.host.merge(credential!, policy!, [vote], []); break
        case "notify": await this.host.notify(); break
        case "publish": await this.host.publishAll(); break
      }
    }
  }

  async claim(workspaceId: string): Promise<void> {
    const profile = await this.host.profile()
    const credential = await this.host.credential(workspaceId)
    const policy = credential && this.host.policy(credential)
    const grant = credential && this.host.grant(credential)
    const votes = credential ? this.host.votes(credential) : []
    const actions = meshRustRuntime().state.planAuthorityCommand({ kind: "claim", localPersonId: profile.personId,
      hasCredential: Boolean(credential), hasPolicy: Boolean(policy), grantRole: grant?.payload.role ?? null,
      grantPersonId: grant?.payload.personId ?? null })
    let claim!: Claim
    for (const action of actions) {
      switch (action) {
        case "createClaim": claim = await this.host.createClaim(profile, credential!, policy!, votes, grant!,
          await this.host.certificates(profile)); break
        case "mergeClaim": await this.host.merge(credential!, policy!, votes, [claim]); break
        case "notify": await this.host.notify(); break
        case "publish": await this.host.publishAll(); break
      }
    }
  }
}
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
