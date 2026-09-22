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
