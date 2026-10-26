import { readFile } from "node:fs/promises"
import { afterEach, describe, expect, it, vi } from "vitest"

describe("transport WASM initialization", () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.resetModules()
  })

  it("shares one in-flight initialization across callers using the real transport artifact", async () => {
    const wasm = new Uint8Array(await readFile(new URL("../transport-wasm/meta_mesh_bg.wasm", import.meta.url)))
    let releaseResponse!: (response: Response) => void
    const deferredResponse = new Promise<Response>((resolve) => {
      releaseResponse = resolve
    })
    const fetchMock = vi.fn(() => deferredResponse)
    vi.stubGlobal("fetch", fetchMock)

    const { default: initializeTransport } = await import("@meta-uber/mesh-transport/transport-wasm")
    const first = initializeTransport({ module_or_path: "https://transport.invalid/meta_mesh_bg.wasm" })
    const second = initializeTransport({ module_or_path: "https://ignored.invalid/other.wasm" })

    expect(second).toBe(first)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledWith("https://transport.invalid/meta_mesh_bg.wasm")

    releaseResponse(new Response(wasm, { headers: { "Content-Type": "application/wasm" } }))
    const [firstExports, secondExports] = await Promise.all([first, second])

    expect(secondExports).toBe(firstExports)
    expect(firstExports.memory).toBeInstanceOf(WebAssembly.Memory)
  })

  it("allows a fresh attempt after initialization rejects", async () => {
    const wasm = new Uint8Array(await readFile(new URL("../transport-wasm/meta_mesh_bg.wasm", import.meta.url)))
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(new Uint8Array([0, 1, 2]), { headers: { "Content-Type": "application/wasm" } }))
      .mockResolvedValueOnce(new Response(wasm, { headers: { "Content-Type": "application/wasm" } }))
    vi.stubGlobal("fetch", fetchMock)

    const { default: initializeTransport } = await import("@meta-uber/mesh-transport/transport-wasm")
    await expect(initializeTransport({ module_or_path: "https://transport.invalid/bad.wasm" })).rejects.toThrow()
    const exports = await initializeTransport({ module_or_path: "https://transport.invalid/meta_mesh_bg.wasm" })

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(exports.memory).toBeInstanceOf(WebAssembly.Memory)
  })

  it("does not permit synchronous initialization to race a pending asynchronous attempt", async () => {
    const wasm = new Uint8Array(await readFile(new URL("../transport-wasm/meta_mesh_bg.wasm", import.meta.url)))
    let releaseResponse!: (response: Response) => void
    const deferredResponse = new Promise<Response>((resolve) => {
      releaseResponse = resolve
    })
    vi.stubGlobal("fetch", vi.fn(() => deferredResponse))

    const transport = await import("@meta-uber/mesh-transport/transport-wasm")
    const pending = transport.default({ module_or_path: "https://transport.invalid/meta_mesh_bg.wasm" })

    expect(() => transport.initSync({ module: wasm })).toThrow("asynchronous initialization is already in progress")
    releaseResponse(new Response(wasm, { headers: { "Content-Type": "application/wasm" } }))
    await pending
  })
})
