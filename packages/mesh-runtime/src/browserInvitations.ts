export type BrowserMeshInvitationCredential = { workspaceId: string; ownerPersonId: string }
export type BrowserMeshInvitationEnvelope = { workspaceId: string; ownerPersonId: string }

export type BrowserMeshInvitationsHost<C extends BrowserMeshInvitationCredential, E extends BrowserMeshInvitationEnvelope, Grant, Peer, Context> = {
  credential(workspaceId: string): Promise<C | undefined>
  peers(workspaceId: string): Promise<Peer[]>
  createEnvelope(credential: C, peers: Peer[]): E
  isEnvelope(value: unknown): value is E
  ownerPersonId(envelope: E): string
  mergeOwnershipProof(credential: C, envelope: E): Promise<C>
  install(workspaceId: string, envelope: E, context: Context, grant: Grant | undefined): Promise<void>
}

/**
 * Owns the bounded invitation protocol. Hosts retain their document store,
 * crypto verification and authorization records behind the adapter.
 */
export class BrowserMeshInvitations<C extends BrowserMeshInvitationCredential, E extends BrowserMeshInvitationEnvelope, Grant, Peer, Context> {
  constructor(private readonly host: BrowserMeshInvitationsHost<C, E, Grant, Peer, Context>) {}

  async payload(workspaceIds: string[]): Promise<E[]> {
    const result: E[] = []
    for (const workspaceId of workspaceIds) {
      const credential = await this.host.credential(workspaceId)
      if (!credential) throw new Error("Missing workspace mesh credential")
      result.push(this.host.createEnvelope(credential, await this.host.peers(workspaceId)))
    }
    return result
  }

  async receive(raw: unknown, workspaceIds: string[], context: Context, grants: Grant[], grantWorkspaceId: (grant: Grant) => string): Promise<void> {
    if (!Array.isArray(raw) || raw.length !== workspaceIds.length || new Set(workspaceIds).size !== workspaceIds.length ||
      !this.isBounded(raw)) throw new Error("Invalid mesh invitation")
    for (const workspaceId of workspaceIds) {
      const envelope = raw.find(item => this.host.isEnvelope(item) && item.workspaceId === workspaceId)
      if (!envelope || !this.host.isEnvelope(envelope)) throw new Error("Invalid mesh invitation")
      let existing = await this.host.credential(workspaceId)
      if (existing && existing.ownerPersonId !== this.host.ownerPersonId(envelope)) {
        existing = await this.host.mergeOwnershipProof(existing, envelope)
        if (existing.ownerPersonId !== this.host.ownerPersonId(envelope)) {
          throw new Error("Workspace ownership proof is missing")
        }
      }
      await this.host.install(workspaceId, envelope, context, grants.find(grant => grantWorkspaceId(grant) === workspaceId))
    }
  }

  private isBounded(raw: unknown[]): boolean {
    try {
      return new TextEncoder().encode(JSON.stringify(raw)).byteLength <= 8 * 1024 * 1024
    } catch {
      return false
    }
  }
}
