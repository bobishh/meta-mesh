export type BrowserMeshInvitationCredential = { workspaceId: string; ownerPersonId: string }
export type BrowserMeshInvitationEnvelope = { workspaceId: string; ownerPersonId: string }

export type BrowserMeshInvitationsHost<C extends BrowserMeshInvitationCredential, E extends BrowserMeshInvitationEnvelope, Grant, Peer, Context> = {
  credential(workspaceId: string): Promise<C | undefined>
  peers(workspaceId: string): Promise<Peer[]>
  createEnvelope(credential: C, peers: Peer[]): E
  isEnvelope(value: unknown): value is E
  ownerPersonId(envelope: E): string
  mergeOwnershipProof(credential: C, envelope: E): Promise<C>
  /** Verify an invitation without changing durable credentials. */
  validate?(workspaceId: string, envelope: E, context: Context, grant: Grant | undefined): Promise<void>
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
    const entries = await this.prepare(raw, workspaceIds, context, grants, grantWorkspaceId)
    for (const entry of entries) {
      let existing = await this.host.credential(entry.workspaceId)
      if (existing && existing.ownerPersonId !== this.host.ownerPersonId(entry.envelope)) {
        existing = await this.host.mergeOwnershipProof(existing, entry.envelope)
        if (existing.ownerPersonId !== this.host.ownerPersonId(entry.envelope)) {
          throw new Error("Workspace ownership proof is missing")
        }
      }
      await this.host.install(entry.workspaceId, entry.envelope, context, entry.grant)
    }
  }

  async validate(raw: unknown, workspaceIds: string[], context: Context, grants: Grant[], grantWorkspaceId: (grant: Grant) => string): Promise<void> {
    await this.prepare(raw, workspaceIds, context, grants, grantWorkspaceId)
  }

  private async prepare(raw: unknown, workspaceIds: string[], context: Context, grants: Grant[], grantWorkspaceId: (grant: Grant) => string) {
    if (!Array.isArray(raw) || raw.length !== workspaceIds.length || new Set(workspaceIds).size !== workspaceIds.length ||
      !this.isBounded(raw)) throw new Error("Invalid mesh invitation")
    const entries: Array<{ workspaceId: string; envelope: E; grant: Grant | undefined }> = []
    for (const workspaceId of workspaceIds) {
      const envelope = raw.find(item => this.host.isEnvelope(item) && item.workspaceId === workspaceId)
      if (!envelope || !this.host.isEnvelope(envelope)) throw new Error("Invalid mesh invitation")
      const grant = grants.find(grant => grantWorkspaceId(grant) === workspaceId)
      let existing = await this.host.credential(workspaceId)
      if (existing && existing.ownerPersonId !== this.host.ownerPersonId(envelope)) {
        // Ownership proof is verified by the host before it can be merged.
        // Its mutation is deferred until every invitation entry has passed
        // validation, so a later malformed workspace cannot partially install.
        if (!this.host.validate) throw new Error("Workspace ownership proof is missing")
      }
      await this.host.validate?.(workspaceId, envelope, context, grant)
      entries.push({ workspaceId, envelope, grant })
    }
    return entries
  }

  private isBounded(raw: unknown[]): boolean {
    try {
      return new TextEncoder().encode(JSON.stringify(raw)).byteLength <= 8 * 1024 * 1024
    } catch {
      return false
    }
  }
}
