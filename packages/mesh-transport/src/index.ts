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
  default(): Promise<void>
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

  private constructor(private readonly node: IrohNode) {}

  static async start(moduleUrl: string, seed?: Uint8Array): Promise<IrohMeshNode> {
    const module = await import(/* @vite-ignore */ moduleUrl) as IrohModule
    await module.default()
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

  listen(handler: WireHandler): void {
    void (async () => {
      const acceptor = await this.node.accept()
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
    await this.node.close("Twang closed")
  }
}
import { getPublicKeyAsync } from "@noble/ed25519"
