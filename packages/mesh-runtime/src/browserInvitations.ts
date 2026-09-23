export type BrowserMeshInvitationCredential = { workspaceId: string; ownerPersonId: string }
export type BrowserMeshInvitationEnvelope = { workspaceId: string; ownerPersonId: string }

export type BrowserMeshInvitationsHost<C extends BrowserMeshInvitationCredential, E extends BrowserMeshInvitationEnvelope, Grant, Peer, Context> = {
  credential(workspaceId: string): Promise<C | undefined>
  peers(workspaceId: string): Promise<Peer[]>
  createEnvelope(credential: C, peers: Peer[]): E
  isEnvelope(value: unknown): value is E
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
      await this.host.install(entry.workspaceId, entry.envelope, context, entry.grant)
    }
  }

  async validate(raw: unknown, workspaceIds: string[], context: Context, grants: Grant[], grantWorkspaceId: (grant: Grant) => string): Promise<void> {
    await this.prepare(raw, workspaceIds, context, grants, grantWorkspaceId)
  }

  private async prepare(raw: unknown, workspaceIds: string[], context: Context, grants: Grant[], grantWorkspaceId: (grant: Grant) => string) {
    const existing = await Promise.all(workspaceIds.map(id => this.host.credential(id)))
    const plan = meshRustRuntime().state.planInvitation({ raw, workspaceIds,
      grantWorkspaceIds: grants.map(grantWorkspaceId),
      existingOwnerPersonIds: existing.map(value => value?.ownerPersonId ?? null) })
    const entries: Array<{ workspaceId: string; envelope: E; grant: Grant | undefined }> = []
    for (const item of plan) {
      const envelope = (raw as unknown[])[item.envelopeIndex]
      if (!this.host.isEnvelope(envelope)) throw new Error("Invalid mesh invitation")
      const workspaceId = item.workspaceId
      const grant = item.grantIndex === null ? undefined : grants[item.grantIndex]
      await this.host.validate?.(workspaceId, envelope, context, grant)
      entries.push({ workspaceId, envelope, grant })
    }
    return entries
  }
}
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
