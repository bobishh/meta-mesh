import type { MeshHandshakeFeatures } from "./handshake"

export type BrowserDocumentSyncEngine = {
  reset(documentId: string, remoteDeviceId: string): void
}

export type BrowserDocumentSessionInput<C, Credential, Profile> = {
  connection: C
  credential: Credential
  workspaceId: string
  deviceId: string
  instanceId: string
  profile: Profile
  connectionId: string
  remotePersonId: string
  ownerWorkspaceSupported: boolean
  ownerWorkspaceOfferFrame?: MeshHandshakeFeatures["ownerWorkspaceOfferFrame"]
  blobTransferSupported?: boolean
  remoteEndpoint: string
}

export type BrowserIncrementalDocumentSessionInput<C, Credential, Profile, Engine> =
  BrowserDocumentSessionInput<C, Credential, Profile> & {
    secret: string
    localDeviceId: string
    engine: Engine
    onDocumentStatus(error: Error | null): void
    onOwnerWorkspaceOffer?: (bytes: Uint8Array) => Promise<void>
    onGossipPacket?: (packet: Uint8Array) => Promise<void>
  }

export type BrowserMeshDocumentSessionHost<C, S, Credential, Profile, Engine extends BrowserDocumentSyncEngine> = {
  localDeviceId(profile: Profile): string
  localPersonId(profile: Profile): string
  secret(credential: Credential): string
  createEngine(input: { localDeviceId: string; workspaceId: string; deviceId: string; instanceId: string }): Engine
  incremental(input: BrowserIncrementalDocumentSessionInput<C, Credential, Profile, Engine>): S
  ownerWorkspaceOffer(bytes: Uint8Array, remotePersonId: string): Promise<void>
  gossipPacket(workspaceId: string, remoteEndpoint: string, packet: Uint8Array): Promise<void>
  rejected(stage: string, error: Error): void
  cleared(stage: string): void
  trace(event: string, detail?: Record<string, unknown>, level?: "info" | "warn"): void
}

/**
 * Owns browser document-session policy around the Rust Automerge engine.
 * Products provide storage, crypto and stream I/O adapters only.
 */
export class BrowserMeshDocumentSessions<C, S, Credential, Profile, Engine extends BrowserDocumentSyncEngine> {
  private readonly engines = new Map<string, Engine>()

  constructor(private readonly host: BrowserMeshDocumentSessionHost<C, S, Credential, Profile, Engine>) {}

  create(input: BrowserDocumentSessionInput<C, Credential, Profile>): { session: S; reset?(): void } {
    const secret = this.host.secret(input.credential)
    const onGossipPacket = input.remoteEndpoint
      ? (packet: Uint8Array) => this.host.gossipPacket(input.workspaceId, input.remoteEndpoint, packet)
      : undefined
    const localDeviceId = this.host.localDeviceId(input.profile)
    const engine = this.engine(input.workspaceId, input.deviceId, input.instanceId, localDeviceId)
    const stage = `Workspace ${short(input.workspaceId)} from ${short(input.deviceId)}`
    const onOwnerWorkspaceOffer = input.ownerWorkspaceOfferFrame && input.remotePersonId === this.host.localPersonId(input.profile)
      ? (bytes: Uint8Array) => this.host.ownerWorkspaceOffer(bytes, input.remotePersonId)
      : undefined
    const session = this.host.incremental({
      ...input,
      secret,
      localDeviceId,
      engine,
      onDocumentStatus: error => {
        if (error) {
          this.host.trace("document.rejected", {
            connectionId: input.connectionId,
            workspaceId: input.workspaceId,
            peerId: input.deviceId,
            instanceId: input.instanceId,
            reason: error.message,
          }, "warn")
          this.host.rejected(stage, error)
        } else {
          this.host.cleared(stage)
        }
      },
      onOwnerWorkspaceOffer,
      onGossipPacket,
    })
    return { session, reset: () => engine.reset(input.workspaceId, input.deviceId) }
  }

  engine(workspaceId: string, deviceId: string, instanceId: string, localDeviceId: string): Engine {
    const key = `${workspaceId}:${deviceId}:${instanceId}`
    let engine = this.engines.get(key)
    if (!engine) {
      engine = this.host.createEngine({ localDeviceId, workspaceId, deviceId, instanceId })
      this.engines.set(key, engine)
    }
    return engine
  }
}

function short(value: string): string { return value.slice(0, 8) }
