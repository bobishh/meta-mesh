import { MeshHandshakeCodec, type MeshHandshakeFeatures, type MeshHandshakePayload } from "./handshake"
import type { WorkspaceMemberBundle } from "@meta-uber/mesh-workspace"

export type BrowserMeshHandshakeStream = {
  read(): Promise<Uint8Array>
  send(bytes: Uint8Array): Promise<void>
  closeSend(): Promise<void>
}

export type BrowserMeshHandshakeConnection<S extends BrowserMeshHandshakeStream> = {
  acceptStream(): Promise<S>
  close(): Promise<void>
}

export type BrowserMeshHandshakePeer = {
  deviceId: string
  instanceId: string
  issuedAt: string
  routeSequence?: number
  personId: string
  endpoint: string
}

export type BrowserMeshHandshakeHost<C, P extends BrowserMeshHandshakePeer> = {
  credentials(): Promise<C[]>
  secret(credential: C): string
  workspaceId(credential: C): string
  mergeAuthority(credential: C, request: MeshHandshakePayload): Promise<C>
  verifyPeer(credential: C, bundle: WorkspaceMemberBundle): Promise<P>
  revoked(credential: C, personId: string): boolean
  revocations(credential: C): MeshHandshakePayload["revocations"]
  ownBundle(credential: C): Promise<WorkspaceMemberBundle>
  response(credential: C, remotePersonId: string): Promise<MeshHandshakePayload>
  putVerifiedBundle(credential: C, bundle: WorkspaceMemberBundle): Promise<void>
  install(input: { credential: C; remote: P; connection: BrowserMeshHandshakeConnection<BrowserMeshHandshakeStream>
    features: MeshHandshakeFeatures; connectionId: string }): Promise<boolean>
  afterInstalled(input: { credential: C; remote: P; request: MeshHandshakePayload
    connection: BrowserMeshHandshakeConnection<BrowserMeshHandshakeStream>; features: MeshHandshakeFeatures }): Promise<void>
  trace(event: string, detail?: Record<string, unknown>, level?: "info" | "warn"): void
  failed(stage: string, error: unknown): void
}

/**
 * Runs the authenticated inbound protocol. Transport streams and product document
 * installation are callbacks, so native and browser hosts use identical framing,
 * authority merge and revocation ordering.
 */
export class BrowserMeshHandshake<C, P extends BrowserMeshHandshakePeer> {
  constructor(private readonly host: BrowserMeshHandshakeHost<C, P>, private readonly codec = new MeshHandshakeCodec()) {}

  async accept<S extends BrowserMeshHandshakeStream>(connection: BrowserMeshHandshakeConnection<S>,
    initial: { stream: S; frame: Uint8Array } | undefined, connectionId: string, signal?: AbortSignal): Promise<boolean> {
    try {
      const handshake = await this.read(connection, initial, connectionId)
      if (await this.rejectRevoked(connection, handshake)) return false
      await this.host.putVerifiedBundle(handshake.credential, handshake.request.peer)
      if (signal?.aborted) { await connection.close(); return false }
      const features = this.codec.features(handshake.request.capabilities)
      const installed = await this.host.install({ credential: handshake.credential, remote: handshake.remote, connection, features, connectionId })
      if (!installed) return false
      await handshake.stream.send(this.codec.encodeResponse(this.host.secret(handshake.credential),
        await this.host.response(handshake.credential, handshake.remote.personId)))
      await handshake.stream.closeSend()
      await this.host.afterInstalled({ credential: handshake.credential, remote: handshake.remote, request: handshake.request, connection, features })
      return true
    } catch (error) {
      this.host.trace("handshake.incoming.failed", { connectionId, reason: message(error) }, "warn")
      this.host.failed("Incoming handshake", error)
      await connection.close()
      return false
    }
  }

  private async read<S extends BrowserMeshHandshakeStream>(connection: BrowserMeshHandshakeConnection<S>,
    initial: { stream: S; frame: Uint8Array } | undefined, connectionId: string) {
    this.host.trace("handshake.incoming.started", { connectionId })
    const stream = initial?.stream ?? await connection.acceptStream()
    const frame = initial?.frame ?? await stream.read()
    const header = this.codec.inspect(frame)
    if (header.type !== "mesh-handshake-request") throw new Error("Unsupported mesh handshake")
    let credential = (await this.host.credentials()).find(item => this.host.secret(item) === header.secret)
    if (!credential) throw new Error("Unknown mesh credential")
    const request = this.codec.readRequest(frame, this.host.secret(credential), this.host.workspaceId(credential))
    credential = await this.host.mergeAuthority(credential, request)
    const remote = await this.host.verifyPeer(credential, request.peer)
    this.host.trace("handshake.incoming.verified", { connectionId, peerId: remote.deviceId.slice(0, 8),
      workspaceId: this.host.workspaceId(credential).slice(0, 8) })
    return { stream, credential, request, remote }
  }

  private async rejectRevoked<S extends BrowserMeshHandshakeStream>(connection: BrowserMeshHandshakeConnection<S>,
    handshake: { stream: S; credential: C; request: MeshHandshakePayload; remote: P }): Promise<boolean> {
    if (!this.host.revoked(handshake.credential, handshake.remote.personId)) return false
    await handshake.stream.send(this.codec.encodeResponse(this.host.secret(handshake.credential), {
      workspaceId: this.host.workspaceId(handshake.credential), peer: await this.host.ownBundle(handshake.credential),
      revocations: this.host.revocations(handshake.credential), ownershipTransfers: [], breakGlassClaims: [], successionVotes: [], successionClaims: [], capabilities: [],
    }))
    await handshake.stream.closeSend()
    const timeout = setTimeout(() => { void connection.close() }, 10_000)
    try { await connection.acceptStream() } finally { clearTimeout(timeout); await connection.close() }
    return true
  }
}

function message(error: unknown): string { return error instanceof Error ? error.message : String(error) }

export type BrowserMeshOutgoingConnection<S extends BrowserMeshHandshakeStream> = {
  openStream(): Promise<S>
}

export type BrowserMeshOutgoingHandshakeHost<C, P extends BrowserMeshHandshakePeer, Q = undefined> = {
  secret(credential: C): string
  workspaceId(credential: C): string
  request(credential: C, context: Q): Promise<MeshHandshakePayload>
  mergeAuthority(credential: C, response: MeshHandshakePayload): Promise<C>
  verifyPeer(credential: C, bundle: WorkspaceMemberBundle): Promise<P>
  putVerifiedBundle(credential: C, bundle: WorkspaceMemberBundle): Promise<void>
  trace(event: string, detail?: Record<string, unknown>, level?: "info" | "warn"): void
}

/** Shared authenticated outbound handshake after a host has opened its transport connection. */
export class BrowserMeshOutgoingHandshake<C, P extends BrowserMeshHandshakePeer, Q = undefined> {
  constructor(private readonly host: BrowserMeshOutgoingHandshakeHost<C, P, Q>, private readonly codec = new MeshHandshakeCodec()) {}

  async exchange<S extends BrowserMeshHandshakeStream>(connection: BrowserMeshOutgoingConnection<S>, credential: C,
    connectionId: string, peerId: string, context: Q = undefined as Q): Promise<{ credential: C; response: MeshHandshakePayload; remote: P; features: MeshHandshakeFeatures }> {
    const stream = await connection.openStream()
    this.host.trace("handshake.outgoing.started", { connectionId, peerId: peerId.slice(0, 8) })
    await stream.send(this.codec.encodeRequest(this.host.secret(credential), await this.host.request(credential, context)))
    await stream.closeSend()
    const response = this.codec.readResponse(await stream.read(), this.host.secret(credential), this.host.workspaceId(credential))
    credential = await this.host.mergeAuthority(credential, response)
    const remote = await this.host.verifyPeer(credential, response.peer)
    if (remote.deviceId !== peerId) throw new Error("Unexpected mesh peer")
    await this.host.putVerifiedBundle(credential, response.peer)
    this.host.trace("handshake.outgoing.verified", { connectionId, peerId: remote.deviceId.slice(0, 8) })
    return { credential, response, remote, features: this.codec.features(response.capabilities) }
  }
}
