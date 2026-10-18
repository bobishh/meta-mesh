export type IrohStream = {
  send(bytes: Uint8Array): Promise<void>
  read(maximumBytes?: number): Promise<Uint8Array>
  readPairingFrame(maximumBytes?: number): Promise<Uint8Array>
  readPairingOrRawPrefix?(prefix: Uint8Array, maximumRawBytes?: number): Promise<Uint8Array>
  closeSend(): Promise<void>
  reset?(): Promise<void>
}

export type IrohConnection = {
  readonly remoteEndpointId?: string
  openStream(): Promise<IrohStream>
  acceptStream(): Promise<IrohStream>
  close(): Promise<void>
}

export type IrohNode = {
  endpointId: string
  dialRelay(endpoint: string): Promise<IrohConnection>
  accept(): Promise<{ accept(): Promise<IrohConnection | undefined> }>
  close(reason?: string): Promise<void>
}

export type IrohModule = {
  default(input?: { module_or_path: string }): Promise<void>
  WasmIngressBudgetProfile?: new () => MeshIngressBudgetProfile
  BrowserNode: { start(seed?: Uint8Array): Promise<IrohNode> }
  WasmGossipEngine?: { new(localPeerId: string): any }
  WasmBlobEngine?: { new(): any }
  WasmPairingCodec?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmPairingCodec
  WasmWorkspaceJoinHandshake?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmWorkspaceJoinHandshake
  WasmWorkspaceJoinHandoff?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmWorkspaceJoinHandoff
  WasmStateCore?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmStateCore
  WasmVerifiedReceivedHistoryBaseline?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmVerifiedReceivedHistoryBaseline
  WasmDeviceRouteCatalog?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmDeviceRouteCatalog
  WasmAutomergeSyncEngine?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmAutomergeSyncEngine
  WasmAutomergeDeviceSyncFlow?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmAutomergeDeviceSyncFlow
  WasmMeshBatchDeliveryFlow?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmMeshBatchDeliveryFlow
  WasmMeshRuntimeState?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmMeshRuntimeState
  WasmMeshLifecycleState?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmMeshLifecycleState
  WasmGossipLifecycleState?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmGossipLifecycleState
  WasmMeshSessionLifecycle?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmMeshSessionLifecycle
  WasmLiveWorkspaceSession?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmLiveWorkspaceSession
  WasmMeshScopeRuntime?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmMeshScopeRuntime
  WasmMeshHandshakeFlow?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmMeshHandshakeFlow
  WasmMeshAuthenticatedSessions?: typeof import("../wasm/policy/meta_mesh_policy.js").WasmMeshAuthenticatedSessions
}

export type MeshIngressBudgetProfile = {
  maxHeaderBytes(): number
  maxFrameBytes(frameType: string): number
  maxPayloadBytes(frameType: string): number
  maxLogicalTransferBytes(): number
  maxTransferPages(): number
  maxTransferDeadlineMs(): number
  maxInFlightBytesPerConnection(): number
  maxConcurrentFramesPerConnection(): number
}

export type PolicyModule = typeof import("../wasm/policy/meta_mesh_policy.js")

export type WireHandler = (payload: unknown) => Promise<unknown>

export type MeshStream = {
  send(bytes: Uint8Array): Promise<void>
  /** Bounded pairing frame read; omission uses the core profile. */
  read(maximumBytes?: number): Promise<Uint8Array>
  /** Finite raw read for non-pairing protocols; caller limits only tighten profile cap. */
  readRaw?: (maximumBytes?: number) => Promise<Uint8Array>
  /** Detect one explicit raw protocol prefix; all other input uses bounded pairing framing. */
  readPairingOrRawPrefix?: (prefix: Uint8Array, maximumRawBytes?: number) => Promise<Uint8Array>
  closeSend(): Promise<void>
  /** Cancel both directions of this stream without closing its connection. Older adapters may omit it. */
  reset?(): Promise<void>
}

export type MeshConnection = {
  readonly remoteEndpointId?: string
  openStream(): Promise<MeshStream>
  acceptStream(): Promise<MeshStream>
  close(): Promise<void>
}

export type DialNode<TConnection extends MeshConnection = MeshConnection> = {
  dial(endpoint: string): Promise<TConnection>
  dialRelay?(endpoint: string): Promise<TConnection>
}

export class MeshNetworkError extends Error {}
export class MeshTerminalError extends Error {}

export async function meshNetworkIO<T>(operation: Promise<T>): Promise<T> {
  try { return await operation }
  catch (error) { throw new MeshNetworkError(error instanceof Error ? error.message : String(error)) }
}

type WaitingRead = { resolve: () => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }
type ReadSlots = { active: number; waiting: WaitingRead[]; lastUsed: number }
const peerReadSlots = new Map<string, ReadSlots>()
const connectionReadSlots = new WeakMap<object, ReadSlots>()

function readSlotsFor(connection: IrohConnection, deadlineMs: number): ReadSlots {
  const peerId = connection.remoteEndpointId
  if (!peerId) {
    let slots = connectionReadSlots.get(connection)
    if (!slots) {
      slots = { active: 0, waiting: [], lastUsed: Date.now() }
      connectionReadSlots.set(connection, slots)
    }
    return slots
  }
  const now = Date.now()
  for (const [id, slots] of peerReadSlots) {
    if (slots.active === 0 && slots.waiting.length === 0 && now - slots.lastUsed > deadlineMs) peerReadSlots.delete(id)
  }
  let slots = peerReadSlots.get(peerId)
  if (!slots) {
    if (peerReadSlots.size >= 1024) throw new MeshNetworkError("Mesh peer read budget is full")
    slots = { active: 0, waiting: [], lastUsed: now }
    peerReadSlots.set(peerId, slots)
  }
  slots.lastUsed = now
  return slots
}

export function meshNetworkConnection(connection: IrohConnection,
  ingressProfile: MeshIngressBudgetProfile, frameType = "sync-request"): MeshConnection {
  const frameLimit = ingressProfile.maxFrameBytes(frameType)
  const inFlightLimit = ingressProfile.maxInFlightBytesPerConnection()
  const hardReadLimit = Math.min(frameLimit, inFlightLimit)
  const maxFrames = ingressProfile.maxConcurrentFramesPerConnection()
  const maxConcurrentReads = Math.min(maxFrames, Math.floor(inFlightLimit / hardReadLimit))
  const readDeadlineMs = ingressProfile.maxTransferDeadlineMs()
  if (!Number.isSafeInteger(frameLimit) || frameLimit < 1 || !Number.isSafeInteger(inFlightLimit) || inFlightLimit < 1) {
    throw new RangeError("Invalid hard stream read limit")
  }
  if (!Number.isSafeInteger(maxFrames) || maxConcurrentReads < 1) throw new RangeError("Invalid peer read concurrency")
  if (!Number.isSafeInteger(readDeadlineMs) || readDeadlineMs < 1) throw new RangeError("Invalid stream read deadline")
  const slots = readSlotsFor(connection, readDeadlineMs)
  const acquireRead = async (): Promise<void> => {
    if (slots.active < maxConcurrentReads) {
      slots.active++
      slots.lastUsed = Date.now()
      return
    }
    if (slots.waiting.length >= maxFrames) throw new MeshNetworkError("Mesh stream concurrency limit exceeded")
    await new Promise<void>((resolve, reject) => {
      const waiter: WaitingRead = {
        resolve,
        reject,
        timer: setTimeout(() => {
          const index = slots.waiting.indexOf(waiter)
          if (index >= 0) slots.waiting.splice(index, 1)
          reject(new MeshNetworkError("Mesh stream read deadline exceeded while queued: stage=stream"))
        }, readDeadlineMs * 2),
      }
      slots.waiting.push(waiter)
    })
  }
  const releaseRead = (): void => {
    slots.lastUsed = Date.now()
    const next = slots.waiting.shift()
    if (next) {
      clearTimeout(next.timer)
      next.resolve()
    } else {
      slots.active--
    }
  }
  const stream = (value: IrohStream): MeshStream => {
    const reset = value.reset
    const boundedRead = async (maximumBytes: number | undefined, pairing: boolean | "mixed", prefix?: Uint8Array) => {
      if (maximumBytes !== undefined && (!Number.isInteger(maximumBytes) || maximumBytes < 0 || maximumBytes > 0xffff_ffff)) {
        throw new RangeError("Invalid stream read limit")
      }
      const limit = Math.min(maximumBytes ?? hardReadLimit, hardReadLimit)
      await acquireRead()
      let timer: ReturnType<typeof setTimeout> | undefined
      let timedOut = false
      try {
        const read = pairing === "mixed"
          ? value.readPairingOrRawPrefix
            ? value.readPairingOrRawPrefix(prefix ?? new Uint8Array(), limit)
            : Promise.reject(new MeshNetworkError("Pairing/raw ingress reader is unavailable"))
          : pairing ? value.readPairingFrame(limit) : value.read(limit)
        return await Promise.race([
          meshNetworkIO(read),
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => {
              timedOut = true
              reject(new Error("Mesh stream read deadline exceeded: stage=stream"))
            }, readDeadlineMs)
          }),
        ])
      } catch (error) {
        if (timedOut) {
          try {
            if (value.reset) await meshNetworkIO(Promise.resolve().then(() => value.reset!.call(value)))
            else await connection.close()
          } catch {
            await connection.close().catch(() => undefined)
          }
        }
        throw error
      }
      finally {
        if (timer) clearTimeout(timer)
        releaseRead()
      }
    }
    return {
      read: maximumBytes => boundedRead(maximumBytes, true),
      readRaw: maximumBytes => boundedRead(maximumBytes, false),
      readPairingOrRawPrefix: (prefix, maximumRawBytes) => {
        if (maximumRawBytes !== undefined && (!Number.isInteger(maximumRawBytes) || maximumRawBytes < 0 || maximumRawBytes > 0xffff_ffff)) {
          throw new RangeError("Invalid raw stream read limit")
        }
        return boundedRead(maximumRawBytes, "mixed", prefix)
      },
      send: bytes => meshNetworkIO(value.send(bytes)),
      closeSend: () => meshNetworkIO(value.closeSend()),
      ...(reset ? { reset: () => meshNetworkIO(Promise.resolve().then(() => reset.call(value))) } : {}),
    }
  }
  return {
    ...connection,
    remoteEndpointId: connection.remoteEndpointId,
    openStream: async () => stream(await meshNetworkIO(connection.openStream())),
    acceptStream: async () => stream(await meshNetworkIO(connection.acceptStream())),
    close: () => connection.close().catch(() => undefined),
  }
}

export function isMeshNetworkFailure(error: unknown): boolean {
  if (error instanceof MeshTerminalError) return false
  if (error instanceof AggregateError) {
    return error.errors.length > 0 && error.errors.every(isMeshNetworkFailure)
  }
  return error instanceof MeshNetworkError || /bootstrap|connection|closed by peer|offline|relay|network|stream chunk|timed out|timeout|webrtc/i
    .test(error instanceof Error ? error.message : String(error))
}

export type HeartbeatSession = { heartbeat?: () => Promise<void> }

export function startMeshHeartbeat(
  session: HeartbeatSession,
  onFailure: (error: unknown) => void,
  options: { intervalMs?: number; jitter?: number; random?: () => number } = {},
): () => void {
  const intervalMs = options.intervalMs ?? 5_000
  const jitter = options.jitter ?? 0.2
  const random = options.random ?? Math.random
  let stopped = false
  let timer: ReturnType<typeof setTimeout> | undefined
  const schedule = () => {
    const spread = intervalMs * jitter
    timer = setTimeout(run, intervalMs - spread + random() * spread * 2)
  }
  const run = async () => {
    if (stopped) return
    try {
      await session.heartbeat?.()
      if (!stopped) schedule()
    } catch (error) {
      if (!stopped) onFailure(error)
    }
  }
  schedule()
  return () => {
    stopped = true
    clearTimeout(timer)
  }
}

export type MeshTraceLevel = "info" | "warn"
export type MeshTraceEvent = {
  sequence: number
  timestamp: string
  level: MeshTraceLevel
  event: string
  [key: string]: unknown
}

export class MeshTraceBuffer {
  private readonly events: MeshTraceEvent[] = []
  private sequence = 0

  constructor(
    private readonly namespace = "mesh",
    private readonly limit = 500,
    private readonly consoleSink: Pick<Console, "info" | "warn"> = console,
  ) {}

  trace(event: string, detail: Record<string, unknown> = {}, level: MeshTraceLevel = "info") {
    const entry: MeshTraceEvent = {
      sequence: ++this.sequence,
      timestamp: new Date().toISOString(),
      level,
      event,
      ...detail,
    }
    this.events.push(entry)
    if (this.events.length > this.limit) this.events.splice(0, this.events.length - this.limit)
    const line = `[${this.namespace}] ${JSON.stringify(entry)}`
    if (level === "warn") this.consoleSink.warn(line)
    else this.consoleSink.info(line)
  }

  snapshot(): MeshTraceEvent[] { return this.events.map(event => ({ ...event })) }

  clear() {
    this.events.length = 0
    this.sequence = 0
  }
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()
export async function irohEndpointIdFromSeed(seed: Uint8Array): Promise<string> {
  const publicKey = await getPublicKeyAsync(seed)
  return [...publicKey].map(value => value.toString(16).padStart(2, "0")).join("")
}

export function encodeWireMessage(payload: unknown, maximumBytes: number): Uint8Array {
  const bytes = encoder.encode(JSON.stringify(payload))
  if (bytes.byteLength > maximumBytes) throw new Error(`Wire message exceeds ingress limit: stage=encode bytes=${bytes.byteLength} max=${maximumBytes}`)
  return bytes
}

export function decodeWireMessage(bytes: Uint8Array, maximumBytes: number): unknown {
  if (bytes.byteLength > maximumBytes) throw new Error(`Wire message exceeds ingress limit: stage=decode bytes=${bytes.byteLength} max=${maximumBytes}`)
  try { return JSON.parse(decoder.decode(bytes)) }
  catch { throw new Error("Invalid wire message") }
}

export class IrohMeshNode {
  private stopped = false
  private readonly outbound = new Map<string, { connection: Promise<IrohConnection> }>()

  constructor(
    private readonly node: IrohNode,
    private readonly closeTimeoutMs = 1_500,
    readonly module?: IrohModule,
  ) {}

  private ingressFrameLimit(frameType: string): number {
    const Profile = this.module?.WasmIngressBudgetProfile
    if (!Profile) throw new Error("Mesh ingress budget profile is unavailable")
    return new Profile().maxFrameBytes(frameType)
  }

  static async loadModule(moduleUrl: string): Promise<IrohModule> {
    const sourceUrl = new URL(moduleUrl, window.location.href)
    if (sourceUrl.origin !== window.location.origin) throw new Error("Iroh module must be same-origin")
    const response = await fetch(sourceUrl)
    if (!response.ok) throw new Error(`Iroh module failed to load (${response.status})`)
    const blobUrl = URL.createObjectURL(new Blob([await response.text()], { type: "text/javascript" }))
    let module: IrohModule
    try { module = await import(/* @vite-ignore */ blobUrl) as IrohModule }
    finally { URL.revokeObjectURL(blobUrl) }
    const wasmName = sourceUrl.pathname.includes("meta_mesh") ? "meta_mesh_bg.wasm" : "match_iroh_bg.wasm"
    await module.default({ module_or_path: new URL(wasmName, sourceUrl).href })
    if (!module.WasmIngressBudgetProfile) throw new Error("Mesh ingress budget profile is unavailable")
    return module
  }

  static async start(moduleUrl: string, seed?: Uint8Array): Promise<IrohMeshNode> {
    const module = await IrohMeshNode.loadModule(moduleUrl)
    return new IrohMeshNode(await module.BrowserNode.start(seed), undefined, module)
  }

  createGossipEngine(): any {
    if (this.module?.WasmGossipEngine) {
      return new this.module.WasmGossipEngine(this.endpointId)
    }
    return undefined
  }

  createBlobEngine(): any {
    if (this.module?.WasmBlobEngine) {
      return new this.module.WasmBlobEngine()
    }
    return undefined
  }

  get endpointId(): string { return this.node.endpointId }

  private outboundConnection(endpoint: string): { connection: Promise<IrohConnection> } {
    if (this.stopped) throw new Error("Mesh node is closed")
    const existing = this.outbound.get(endpoint)
    if (existing) return existing
    const session = { connection: this.node.dialRelay(endpoint) }
    this.outbound.set(endpoint, session)
    void session.connection.catch(() => {
      if (this.outbound.get(endpoint) === session) this.outbound.delete(endpoint)
    })
    return session
  }

  private discardOutbound(endpoint: string, session: { connection: Promise<IrohConnection> }): void {
    if (this.outbound.get(endpoint) !== session) return
    this.outbound.delete(endpoint)
    void session.connection.then(connection => connection.close()).catch(() => undefined)
  }

  async request(endpoint: string, payload: unknown, timeoutMs = 8_000): Promise<unknown> {
    const session = this.outboundConnection(endpoint)
    let activeStream: IrohStream | undefined
    const operation = (async () => {
      const connection = await session.connection
      let response: { error?: string }
      try {
        const stream = activeStream = await connection.openStream()
        const maximumBytes = this.ingressFrameLimit("sync-request")
        await stream.send(encodeWireMessage(payload, maximumBytes))
        await stream.closeSend()
        response = decodeWireMessage(await stream.read(maximumBytes), maximumBytes) as { error?: string }
      } catch (error) {
        await activeStream?.reset?.().catch(() => undefined)
        if (!activeStream?.reset) this.discardOutbound(endpoint, session)
        throw error
      }
      if (response?.error) throw new Error(response.error)
      return response
    })()
    let timer: ReturnType<typeof setTimeout> | undefined
    const timeout = new Promise<never>((_, reject) => {
      timer = globalThis.setTimeout(() => {
        if (activeStream?.reset) void activeStream.reset().catch(() => this.discardOutbound(endpoint, session))
        else this.discardOutbound(endpoint, session)
        reject(new Error("Peer is offline"))
      }, timeoutMs)
    })
    try { return await Promise.race([operation, timeout]) }
    finally { clearTimeout(timer) }
  }

  async listen(handler: WireHandler): Promise<void> {
    const acceptor = await this.node.accept()
    void (async () => {
      while (!this.stopped) {
        const connection = await acceptor.accept()
        if (!connection) continue
        void (async () => {
          try {
            while (!this.stopped) {
              const stream = await connection.acceptStream()
              try {
              const maximumBytes = this.ingressFrameLimit("sync-request")
              const result = await handler(decodeWireMessage(await stream.read(maximumBytes), maximumBytes))
                await stream.send(encodeWireMessage(result, maximumBytes))
              } catch (error) {
                const maximumBytes = this.ingressFrameLimit("sync-request")
                await stream.send(encodeWireMessage({
                  error: error instanceof Error ? error.message : "Request failed",
                }, maximumBytes)).catch(() => undefined)
              } finally {
                await stream.closeSend().catch(() => undefined)
              }
            }
          } catch {
            await connection.close().catch(() => undefined)
          }
        })()
      }
    })().catch(() => undefined)
  }

  async close(): Promise<void> {
    this.stopped = true
    const outbound = [...this.outbound.values()]
    this.outbound.clear()
    await Promise.race([
      Promise.allSettled([
        this.node.close("Mesh node closed"),
        ...outbound.map(session => session.connection.then(connection => connection.close())),
      ]).then(() => undefined),
      new Promise<void>(resolve => globalThis.setTimeout(resolve, this.closeTimeoutMs)),
    ])
  }
}
import { getPublicKeyAsync } from "@noble/ed25519"
