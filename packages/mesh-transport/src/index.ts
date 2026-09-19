export type IrohStream = {
  send(bytes: Uint8Array): Promise<void>
  read(): Promise<Uint8Array>
  closeSend(): Promise<void>
}

export type IrohConnection = {
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
  BrowserNode: { start(seed?: Uint8Array): Promise<IrohNode> }
  WasmGossipEngine?: { new(localPeerId: string): any }
  WasmBlobEngine?: { new(): any }
}

export type WireHandler = (payload: unknown) => Promise<unknown>

export type MeshStream = {
  send(bytes: Uint8Array): Promise<void>
  read(): Promise<Uint8Array>
  closeSend(): Promise<void>
}

export type MeshConnection = {
  openStream(): Promise<MeshStream>
  acceptStream(): Promise<MeshStream>
  close(): Promise<void>
}

export type DialNode<TConnection extends MeshConnection = MeshConnection> = {
  dial(endpoint: string): Promise<TConnection>
  dialRelay?(endpoint: string): Promise<TConnection>
}

export class MeshNetworkError extends Error {}

export async function meshNetworkIO<T>(operation: Promise<T>): Promise<T> {
  try { return await operation }
  catch (error) { throw new MeshNetworkError(error instanceof Error ? error.message : String(error)) }
}

export function meshNetworkConnection<TConnection extends MeshConnection>(connection: TConnection): TConnection {
  const stream = (value: MeshStream): MeshStream => ({
    read: () => meshNetworkIO(value.read()),
    send: bytes => meshNetworkIO(value.send(bytes)),
    closeSend: () => meshNetworkIO(value.closeSend()),
  })
  return {
    ...connection,
    openStream: async () => stream(await meshNetworkIO(connection.openStream())),
    acceptStream: async () => stream(await meshNetworkIO(connection.acceptStream())),
    close: () => connection.close().catch(() => undefined),
  }
}

export function isMeshNetworkFailure(error: unknown): boolean {
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

export class MeshReconnectPolicy {
  private readonly relayUntil = new Map<string, number>()
  private readonly now: () => number
  private readonly relayCooldownMs: number
  private readonly fallbackDelayMs: number

  constructor(options: { now?: () => number; relayCooldownMs?: number; fallbackDelayMs?: number } = {}) {
    this.now = options.now ?? Date.now
    this.relayCooldownMs = options.relayCooldownMs ?? 60_000
    this.fallbackDelayMs = options.fallbackDelayMs ?? 1_500
  }

  recordFailure(peerKey: string, error: unknown) {
    if (isMeshNetworkFailure(error)) this.relayUntil.set(peerKey, this.now() + this.relayCooldownMs)
  }

  mode(node: DialNode, peerKey: string): "direct" | "relay" {
    const until = this.relayUntil.get(peerKey) ?? 0
    if (until <= this.now()) this.relayUntil.delete(peerKey)
    return until > this.now() && node.dialRelay ? "relay" : "direct"
  }

  async dial<TConnection extends MeshConnection>(node: DialNode<TConnection>, peerKey: string, endpoint: string): Promise<TConnection> {
    if (this.mode(node, peerKey) === "relay") return node.dialRelay!(endpoint)
    if (!node.dialRelay) return node.dial(endpoint)

    type Result = { mode: "direct" | "relay"; connection: TConnection }
    const direct = node.dial(endpoint).then(connection => ({ mode: "direct", connection }) as Result)
    let timer: ReturnType<typeof setTimeout> | undefined
    let relayStarted = false
    let startRelay!: () => void
    const relay = new Promise<Result>((resolve, reject) => {
      startRelay = () => {
        if (relayStarted) return
        relayStarted = true
        clearTimeout(timer)
        node.dialRelay!(endpoint).then(connection => resolve({ mode: "relay", connection }), reject)
      }
      timer = setTimeout(startRelay, this.fallbackDelayMs)
    })
    void direct.catch(startRelay)
    const winner = await Promise.any([direct, relay])
    clearTimeout(timer)
    if (winner.mode === "direct") this.relayUntil.delete(peerKey)
    else this.relayUntil.set(peerKey, this.now() + this.relayCooldownMs)
    void direct.then(result => { if (result.connection !== winner.connection) void result.connection.close() }).catch(() => undefined)
    void relay.then(result => { if (result.connection !== winner.connection) void result.connection.close() }).catch(() => undefined)
    return winner.connection
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
const MAX_WIRE_BYTES = 16 * 1024 * 1024

export async function irohEndpointIdFromSeed(seed: Uint8Array): Promise<string> {
  const publicKey = await getPublicKeyAsync(seed)
  return [...publicKey].map(value => value.toString(16).padStart(2, "0")).join("")
}

export function encodeWireMessage(payload: unknown): Uint8Array {
  const bytes = encoder.encode(JSON.stringify(payload))
  if (bytes.byteLength > MAX_WIRE_BYTES) throw new Error("Wire message is too large")
  return bytes
}

export function decodeWireMessage(bytes: Uint8Array): unknown {
  if (bytes.byteLength > MAX_WIRE_BYTES) throw new Error("Wire message is too large")
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
    const operation = (async () => {
      const connection = await session.connection
      let response: { error?: string }
      try {
        const stream = await connection.openStream()
        await stream.send(encodeWireMessage(payload))
        await stream.closeSend()
        response = decodeWireMessage(await stream.read()) as { error?: string }
      } catch (error) {
        this.discardOutbound(endpoint, session)
        throw error
      }
      if (response?.error) throw new Error(response.error)
      return response
    })()
    let timer: ReturnType<typeof setTimeout> | undefined
    const timeout = new Promise<never>((_, reject) => {
      timer = globalThis.setTimeout(() => {
        this.discardOutbound(endpoint, session)
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
                const result = await handler(decodeWireMessage(await stream.read()))
                await stream.send(encodeWireMessage(result))
              } catch (error) {
                await stream.send(encodeWireMessage({
                  error: error instanceof Error ? error.message : "Request failed",
                })).catch(() => undefined)
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
