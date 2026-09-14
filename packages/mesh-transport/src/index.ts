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

type IrohModule = {
  default(input?: { module_or_path: string }): Promise<void>
  BrowserNode: { start(seed?: Uint8Array): Promise<IrohNode> }
}

export type WireHandler = (payload: unknown) => Promise<unknown>

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

  constructor(
    private readonly node: IrohNode,
    private readonly closeTimeoutMs = 1_500,
  ) {}

  static async start(moduleUrl: string, seed?: Uint8Array): Promise<IrohMeshNode> {
    const sourceUrl = new URL(moduleUrl, window.location.href)
    if (sourceUrl.origin !== window.location.origin) throw new Error("Iroh module must be same-origin")
    const response = await fetch(sourceUrl)
    if (!response.ok) throw new Error(`Iroh module failed to load (${response.status})`)
    const blobUrl = URL.createObjectURL(new Blob([await response.text()], { type: "text/javascript" }))
    let module: IrohModule
    try { module = await import(/* @vite-ignore */ blobUrl) as IrohModule }
    finally { URL.revokeObjectURL(blobUrl) }
    await module.default({ module_or_path: new URL("match_iroh_bg.wasm", sourceUrl).href })
    return new IrohMeshNode(await module.BrowserNode.start(seed))
  }

  get endpointId(): string { return this.node.endpointId }

  async request(endpoint: string, payload: unknown, timeoutMs = 8_000): Promise<unknown> {
    const operation = (async () => {
      const connection = await this.node.dialRelay(endpoint)
      try {
        const stream = await connection.openStream()
        await stream.send(encodeWireMessage(payload))
        await stream.closeSend()
        const response = decodeWireMessage(await stream.read()) as { error?: string }
        if (response?.error) throw new Error(response.error)
        return response
      } finally {
        await connection.close().catch(() => undefined)
      }
    })()
    let timer = 0
    const timeout = new Promise<never>((_, reject) => {
      timer = window.setTimeout(() => reject(new Error("Peer is offline")), timeoutMs)
    })
    try { return await Promise.race([operation, timeout]) }
    finally { window.clearTimeout(timer) }
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
    await Promise.race([
      this.node.close("Mesh node closed").catch(() => undefined),
      new Promise<void>(resolve => globalThis.setTimeout(resolve, this.closeTimeoutMs)),
    ])
  }
}
import { getPublicKeyAsync } from "@noble/ed25519"
