import type { BrowserMeshAuthorityCredential, BrowserMeshAuthorityProfile, BrowserMeshRecoveryGrant } from "./browserAuthority"

export type BrowserMeshBreakGlassHost<C extends BrowserMeshAuthorityCredential, P extends BrowserMeshAuthorityProfile,
  Grant extends BrowserMeshRecoveryGrant, Claim> = {
  profile(): Promise<P>
  credential(workspaceId: string): Promise<C | undefined>
  policy(credential: C): unknown | undefined
  canOwn(profile: P): boolean
  ownerOnline(credential: C): Promise<boolean>
  grant(credential: C): Grant | undefined
  verifyGrant(credential: C, profile: P, grant: Grant): Promise<boolean>
  createClaim(profile: P, credential: C, grant: Grant): Promise<Claim>
  merge(credential: C, claim: Claim): Promise<void>
  ensureOwner(workspaceId: string, profile: P): Promise<void>
  notify(): Promise<void>
  publishAll(): Promise<void>
}

/** Shared orphaned-owner recovery workflow. Crypto and storage remain host capabilities. */
export class BrowserMeshBreakGlass<C extends BrowserMeshAuthorityCredential, P extends BrowserMeshAuthorityProfile,
  Grant extends BrowserMeshRecoveryGrant, Claim> {
  constructor(private readonly host: BrowserMeshBreakGlassHost<C, P, Grant, Claim>) {}

  async claim(workspaceId: string): Promise<void> {
    const profile = await this.host.profile()
    const credential = await this.host.credential(workspaceId)
    if (!credential) throw new Error("Workspace membership is unavailable")
    if (credential.ownerPersonId === profile.personId) return
    if (this.host.policy(credential)) throw new Error("Use the configured ownership succession policy")
    if (!this.host.canOwn(profile)) throw new Error("This identity cannot own workspaces without its root key")
    if (await this.host.ownerOnline(credential)) throw new Error("Workspace owner is online; use signed ownership transfer")
    const grant = this.host.grant(credential)
    if (!grant || grant.payload.personId !== profile.personId || grant.payload.role !== "editor") {
      throw new Error("Only an editor can recover orphaned ownership")
    }
    if (!await this.host.verifyGrant(credential, profile, grant)) throw new Error("Editor grant cannot be verified")
    await this.host.merge(credential, await this.host.createClaim(profile, credential, grant))
    await this.host.ensureOwner(workspaceId, profile)
    await this.host.notify()
    await this.host.publishAll()
  }
}
