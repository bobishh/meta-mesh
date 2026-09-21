export type BrowserMeshOwnerCredential = { workspaceId: string; ownerPersonId: string }
export type BrowserMeshOwnerProfile = { personId: string; publicKey: string }

export type BrowserMeshCredentialsHost<C extends BrowserMeshOwnerCredential, P extends BrowserMeshOwnerProfile, Cert> = {
  credential(workspaceId: string): Promise<C | undefined>
  putCredential(credential: C): Promise<void>
  createCredential(workspaceId: string, profile: P, certificates: Cert[]): C
  refreshOwnerCertificates(credential: C, profile: P, certificates: Cert[]): Promise<C>
}

/** Canonical owner credential bootstrap shared by browser and native hosts. */
export class BrowserMeshCredentials<C extends BrowserMeshOwnerCredential, P extends BrowserMeshOwnerProfile, Cert> {
  constructor(private readonly host: BrowserMeshCredentialsHost<C, P, Cert>) {}

  async ensureOwnerCredential(workspaceId: string, profile: P, certificates: Cert[]): Promise<C> {
    const existing = await this.host.credential(workspaceId)
    if (existing && existing.ownerPersonId !== profile.personId) throw new Error("Only the workspace owner can invite peers")
    if (existing) return this.host.refreshOwnerCertificates(existing, profile, certificates)
    const credential = this.host.createCredential(workspaceId, profile, certificates)
    await this.host.putCredential(credential)
    return credential
  }
}
