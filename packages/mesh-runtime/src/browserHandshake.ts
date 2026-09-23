import { MeshHandshakeCodec, type MeshHandshakeFeatures, type MeshHandshakePayload } from "./handshake"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
import type { WorkspaceMemberBundle } from "@meta-uber/mesh-workspace"

export type BrowserMeshHandshakeStream = {
  read(): Promise<Uint8Array>
  send(bytes: Uint8Array): Promise<void>
  closeSend(): Promise<void>
}

export type BrowserMeshHandshakeConnection<S extends BrowserMeshHandshakeStream> = {
  remoteEndpointId?: string
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
  admit(credential: C, request: MeshHandshakePayload, remoteEndpointId: string): Promise<Pick<P, "deviceId" | "personId" | "endpoint">>
  revoked(credential: C, personId: string, grant: unknown, deviceId: string): boolean
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

/** Executes host I/O in the order required by the shared Rust handshake flow. */
export class BrowserMeshHandshake<C, P extends BrowserMeshHandshakePeer> {
  constructor(private readonly host: BrowserMeshHandshakeHost<C, P>, private readonly codec = new MeshHandshakeCodec()) {}

  async accept<S extends BrowserMeshHandshakeStream>(connection: BrowserMeshHandshakeConnection<S>,
    initial: { stream: S; frame: Uint8Array } | undefined, connectionId: string, signal?: AbortSignal): Promise<boolean> {
    const flow = meshRustRuntime().createMeshHandshakeFlow("incoming")
    try {
      let stream!: S
      let credential!: C
      let request!: MeshHandshakePayload
      let remote!: P
      let features!: MeshHandshakeFeatures
      for (;;) {
        const step = flow.step()
        switch (step) {
          case "readRequest": {
            this.host.trace("handshake.incoming.started", { connectionId })
            stream = initial?.stream ?? await connection.acceptStream()
            const frame = initial?.frame ?? await stream.read()
            const header = this.codec.inspect(frame)
            if (header.type !== "mesh-handshake-request") throw new Error("Unsupported mesh handshake")
            const found = (await this.host.credentials()).find(item => this.host.secret(item) === header.secret)
            if (!found) throw new Error("Unknown mesh credential")
            credential = found
            request = this.codec.readRequest(frame, this.host.secret(credential), this.host.workspaceId(credential))
            break
          }
          case "mergeAuthority":
            credential = await this.host.mergeAuthority(credential, request)
            break
          case "verifyPeer":
            remote = await this.host.verifyPeer(credential, request.peer)
            this.host.trace("handshake.incoming.verified", { connectionId, peerId: remote.deviceId.slice(0, 8),
              workspaceId: this.host.workspaceId(credential).slice(0, 8) })
            break
          case "checkRevocation":
            flow.advance(step, this.host.revoked(credential, remote.personId, request.peer?.grant, remote.deviceId))
            continue
          case "sendRevocation": {
            await stream.send(this.codec.encodeResponse(this.host.secret(credential), {
              ...await this.host.response(credential, remote.personId),
              revocations: this.host.revocations(credential),
            }))
            await stream.closeSend()
            const timeout = setTimeout(() => { void connection.close() }, 10_000)
            try { await connection.acceptStream() } finally { clearTimeout(timeout); await connection.close() }
            break
          }
          case "persistPeer":
            assertAdmittedPeer(remote, await this.host.admit(credential, request, transportEndpoint(connection)))
            await this.host.putVerifiedBundle(credential, request.peer)
            break
          case "installSession": {
            if (signal?.aborted) { await connection.close(); return false }
            features = this.codec.features(request.capabilities)
            const installed = await this.host.install({ credential, remote, connection, features, connectionId })
            flow.advance(step, installed)
            continue
          }
          case "sendResponse":
            await stream.send(this.codec.encodeResponse(this.host.secret(credential),
              await this.host.response(credential, remote.personId)))
            await stream.closeSend()
            break
          case "afterInstalled":
            await this.host.afterInstalled({ credential, remote, request, connection, features })
            break
          case "complete": return true
          case "revoked":
          case "sessionRejected": return false
          default: throw new Error(`Unexpected incoming mesh handshake step: ${step}`)
        }
        flow.advance(step)
      }
    } catch (error) {
      this.host.trace("handshake.incoming.failed", { connectionId, reason: message(error) }, "warn")
      this.host.failed("Incoming handshake", error)
      await connection.close()
      return false
    } finally {
      flow.free?.()
    }
  }
}

function message(error: unknown): string { return error instanceof Error ? error.message : String(error) }

function transportEndpoint(connection: { remoteEndpointId?: string }): string {
  if (!connection.remoteEndpointId) throw new Error("Mesh transport endpoint unavailable")
  return connection.remoteEndpointId
}

function assertAdmittedPeer(peer: BrowserMeshHandshakePeer, admitted: Pick<BrowserMeshHandshakePeer, "deviceId" | "personId" | "endpoint">): void {
  if (peer.deviceId !== admitted.deviceId || peer.personId !== admitted.personId || peer.endpoint !== admitted.endpoint) {
    throw new Error("Rust mesh admission does not match verified peer")
  }
}

export type BrowserMeshOutgoingConnection<S extends BrowserMeshHandshakeStream> = {
  remoteEndpointId?: string
  openStream(): Promise<S>
}

export type BrowserMeshOutgoingHandshakeHost<C, P extends BrowserMeshHandshakePeer, Q = undefined> = {
  secret(credential: C): string
  workspaceId(credential: C): string
  request(credential: C, context: Q): Promise<MeshHandshakePayload>
  mergeAuthority(credential: C, response: MeshHandshakePayload): Promise<C>
  verifyPeer(credential: C, bundle: WorkspaceMemberBundle): Promise<P>
  admit(credential: C, response: MeshHandshakePayload, remoteEndpointId: string): Promise<Pick<P, "deviceId" | "personId" | "endpoint">>
  putVerifiedBundle(credential: C, bundle: WorkspaceMemberBundle): Promise<void>
  trace(event: string, detail?: Record<string, unknown>, level?: "info" | "warn"): void
}

/** Shared authenticated outbound handshake after a host has opened its transport connection. */
export class BrowserMeshOutgoingHandshake<C, P extends BrowserMeshHandshakePeer, Q = undefined> {
  constructor(private readonly host: BrowserMeshOutgoingHandshakeHost<C, P, Q>, private readonly codec = new MeshHandshakeCodec()) {}

  async exchange<S extends BrowserMeshHandshakeStream>(connection: BrowserMeshOutgoingConnection<S>, credential: C,
    connectionId: string, peerId: string, context: Q = undefined as Q): Promise<{ credential: C; response: MeshHandshakePayload; remote: P; features: MeshHandshakeFeatures }> {
    const flow = meshRustRuntime().createMeshHandshakeFlow("outgoing")
    try {
      const stream = await connection.openStream()
      let response!: MeshHandshakePayload
      let remote!: P
      for (;;) {
        const step = flow.step()
        switch (step) {
          case "sendRequest":
            this.host.trace("handshake.outgoing.started", { connectionId, peerId: peerId.slice(0, 8) })
            await stream.send(this.codec.encodeRequest(this.host.secret(credential), await this.host.request(credential, context)))
            await stream.closeSend()
            break
          case "readResponse":
            response = this.codec.readResponse(await stream.read(), this.host.secret(credential), this.host.workspaceId(credential))
            break
          case "mergeAuthority":
            credential = await this.host.mergeAuthority(credential, response)
            break
          case "verifyPeer":
            remote = await this.host.verifyPeer(credential, response.peer)
            break
          case "checkExpectedPeer":
            flow.advance(step, remote.deviceId === peerId)
            continue
          case "persistPeer":
            assertAdmittedPeer(remote, await this.host.admit(credential, response, transportEndpoint(connection)))
            await this.host.putVerifiedBundle(credential, response.peer)
            this.host.trace("handshake.outgoing.verified", { connectionId, peerId: remote.deviceId.slice(0, 8) })
            break
          case "peerMismatch": throw new Error("Unexpected mesh peer")
          case "complete": return { credential, response, remote, features: this.codec.features(response.capabilities) }
          default: throw new Error(`Unexpected outgoing mesh handshake step: ${step}`)
        }
        flow.advance(step)
      }
    } finally {
      flow.free?.()
    }
  }
}
