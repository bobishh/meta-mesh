import { meshRustRuntime, type RustLiveWorkspaceSession, type RustMeshRuntimeState, type RustMeshScopeRuntime } from "@meta-uber/mesh-replication/runtime"
import type { DialNode, MeshConnection } from "@meta-uber/mesh-transport"

export { BrowserMeshGossip, type BrowserGossipHost, type BrowserGossipSession } from "./browserGossip"
export { BrowserMeshSessions, type BrowserMeshSession, type BrowserMeshSessionEntry, type BrowserMeshSessionHost } from "./browserSessions"
export { BrowserWorkspaceJoinHost, BrowserWorkspaceJoinGuest, BrowserWorkspaceJoinHandoffGuest,
  BrowserWorkspaceJoinHandoffHost, WorkspaceJoinHandoffRollbackError, WorkspaceJoinRejectedError,
  type WorkspaceJoinConnection, type WorkspaceJoinHandoffMachine, type WorkspaceJoinHandoffOutcome,
  type WorkspaceJoinMachine, type WorkspaceJoinResponse, type WorkspaceJoinStream } from "./browserWorkspaceJoin"
export type { BrowserIdentityEnrollmentApproval, BrowserIdentityEnrollmentHost, ConnectedIdentityEnrollment,
  IdentityEnrollmentRecovery, IdentityProfileSyncOptions, PendingIdentityEnrollment } from "./browserIdentityEnrollment"
export type { BrowserIdentityPeerHost, BrowserIdentityPeerRuntime, ConnectedIdentityPeer, CreateBrowserIdentityPeerRuntimeOptions,
  IdentityPeerContact, IdentityPeerHostConnection, StartBrowserIdentityPeerHostOptions, ConnectBrowserIdentityPeerOptions } from "./browserIdentityReconnect"

// Keep identity enrollment and reconnect code out of the workspace runtime's
// startup graph. These features use the full Automerge identity replica and
// are loaded only when a caller explicitly starts an identity operation.
type BrowserIdentityEnrollmentApi = typeof import("./browserIdentityEnrollment")
type BrowserIdentityReconnectApi = typeof import("./browserIdentityReconnect")

export function connectBrowserIdentityEnrollment(...args: Parameters<BrowserIdentityEnrollmentApi["connectBrowserIdentityEnrollment"]>) {
  return import("./browserIdentityEnrollment").then(module => module.connectBrowserIdentityEnrollment(...args))
}

export function createBrowserIdentityEnrollmentHost(...args: Parameters<BrowserIdentityEnrollmentApi["createBrowserIdentityEnrollmentHost"]>) {
  return import("./browserIdentityEnrollment").then(module => module.createBrowserIdentityEnrollmentHost(...args))
}

export function serveIdentityProfileSync(...args: Parameters<BrowserIdentityEnrollmentApi["serveIdentityProfileSync"]>) {
  const serving = import("./browserIdentityEnrollment").then(module => module.serveIdentityProfileSync(...args))
  return {
    done: serving.then(sync => sync.done),
    close: async () => (await serving).close(),
  }
}

export function syncProfileState(...args: Parameters<BrowserIdentityEnrollmentApi["syncProfileState"]>) {
  return import("./browserIdentityEnrollment").then(module => module.syncProfileState(...args))
}

export function connectBrowserIdentityPeer(...args: Parameters<BrowserIdentityReconnectApi["connectBrowserIdentityPeer"]>) {
  return import("./browserIdentityReconnect").then(module => module.connectBrowserIdentityPeer(...args))
}

export function startBrowserIdentityPeerHost(...args: Parameters<BrowserIdentityReconnectApi["startBrowserIdentityPeerHost"]>) {
  return import("./browserIdentityReconnect").then(module => module.startBrowserIdentityPeerHost(...args))
}

export function createBrowserIdentityPeerRuntime(...args: Parameters<BrowserIdentityReconnectApi["createBrowserIdentityPeerRuntime"]>) {
  return import("./browserIdentityReconnect").then(module => module.createBrowserIdentityPeerRuntime(...args))
}
export { MeshHandshakeCodec, type MeshHandshakeFeatures, type MeshHandshakePayload } from "./handshake"
export { BrowserMeshHandshake, BrowserMeshOutgoingHandshake, type BrowserMeshHandshakeConnection, type BrowserMeshHandshakeHost, type BrowserMeshHandshakePeer, type BrowserMeshHandshakeStream, type BrowserMeshOutgoingConnection, type BrowserMeshOutgoingHandshakeHost } from "./browserHandshake"
export { BrowserMeshDialScheduler, type BrowserDialPeer, type BrowserMeshDialHost } from "./browserDial"
export { MeshDialCancelled, MeshNodeRestart, isMeshDialNetworkFailure } from "./errors"

export type { RustMeshRuntimeState as MeshRuntimeState }
export type { RustLiveSessionAction, RustLiveWorkspaceSession, RustMeshScopeFrameEffect, RustMeshScopeRuntime } from "@meta-uber/mesh-replication/runtime"

export function createLiveWorkspaceSession(workspaceId: string, secret: string): RustLiveWorkspaceSession {
  return meshRustRuntime().createLiveWorkspaceSession(workspaceId, secret)
}

export function createMeshScopeRuntime(workspaceId: string, secret: string): RustMeshScopeRuntime {
  return meshRustRuntime().createMeshScopeRuntime(workspaceId, secret)
}

/** Creates the shared Rust/WASM mesh runtime state machine. */
export function createMeshRuntime(): RustMeshRuntimeState {
  return meshRustRuntime().createMeshRuntimeState()
}

export function* controlFrames(workspaceId: string, bytes: Uint8Array): Generator<Uint8Array> {
  const runtime = createMeshRuntime()
  try {
    for (const frame of runtime.controlFrames(workspaceId, bytes)) yield Uint8Array.from(frame)
  } finally {
    runtime.free?.()
  }
}

export class ControlFrameReceiver {
  private readonly runtime = createMeshRuntime()

  constructor(private readonly workspaceId: string) {}

  receive(bytes: Uint8Array): Uint8Array | undefined {
    return this.runtime.receiveControlFrame(this.workspaceId, bytes)
  }

  free() {
    this.runtime.free?.()
  }
}

/**
 * Executes host I/O from a plan owned by the Rust runtime. The fallback timer,
 * relay cooldown and success/failure state never live in product TypeScript.
 */
export class MeshReconnectPolicy {
  private readonly runtime: RustMeshRuntimeState
  private readonly ownsRuntime: boolean

  constructor(runtime?: RustMeshRuntimeState) {
    this.runtime = runtime ?? createMeshRuntime()
    this.ownsRuntime = !runtime
  }

  recordFailure(peerKey: string, networkFailure: boolean, now = Date.now()): void {
    if (networkFailure) this.runtime.recordNetworkFailure(peerKey, now)
  }

  mode(node: Pick<DialNode, "dialRelay">, peerKey: string): "direct" | "relay" {
    return this.runtime.planDial(peerKey, Boolean(node.dialRelay), Date.now()).mode
  }

  async dial<TConnection extends MeshConnection>(node: DialNode<TConnection>, peerKey: string, endpoint: string): Promise<TConnection> {
    const plan = this.runtime.planDial(peerKey, Boolean(node.dialRelay), Date.now())
    if (plan.mode === "relay") {
      const connection = await node.dialRelay!(endpoint)
      this.runtime.recordDialSuccess(peerKey, "relay", Date.now())
      return connection
    }
    if (!node.dialRelay) {
      const connection = await node.dial(endpoint)
      this.runtime.recordDialSuccess(peerKey, "direct", Date.now())
      return connection
    }
    type Result = { mode: "direct" | "relay"; connection: TConnection }
    const direct = node.dial(endpoint).then(connection => ({ mode: "direct", connection }) as Result)
    let timer: ReturnType<typeof setTimeout> | undefined
    let relayStarted = false
    let startRelay!: () => void
    const relay = new Promise<Result>((resolve, reject) => {
      startRelay = () => {
        if (relayStarted) return
        relayStarted = true
        node.dialRelay!(endpoint).then(connection => resolve({ mode: "relay", connection }), reject)
      }
      timer = setTimeout(startRelay, Math.max(0, (plan.relayFallbackAtMs ?? Date.now()) - Date.now()))
    })
    void direct.catch(startRelay)
    const winner = await Promise.any([direct, relay])
    clearTimeout(timer)
    this.runtime.recordDialSuccess(peerKey, winner.mode, Date.now())
    void direct.then(result => { if (result.connection !== winner.connection) void result.connection.close() }).catch(() => undefined)
    void relay.then(result => { if (result.connection !== winner.connection) void result.connection.close() }).catch(() => undefined)
    return winner.connection
  }

  free(): void { if (this.ownsRuntime) this.runtime.free?.() }
}

export { BrowserMeshLifecycle, type BrowserMeshLifecycleHost } from "./browserLifecycle"
export { BrowserMeshScopeSync, type MeshScopeExecutor, type MeshScopeHost, type MeshScopeStream } from "./browserScopeSync"
