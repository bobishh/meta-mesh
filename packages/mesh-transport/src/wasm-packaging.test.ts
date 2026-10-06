import { execFileSync } from "node:child_process"
import { readFile } from "node:fs/promises"
import { describe, expect, it } from "vitest"
import * as policyModule from "../wasm/policy/meta_mesh_policy.js"
import * as transportModule from "../transport-wasm/meta_mesh.js"

const packageRoot = new URL("../", import.meta.url)

describe("WASM package boundary", () => {
  it("routes policy and transport imports to separate generated entrypoints", async () => {
    const manifest = JSON.parse(await readFile(new URL("package.json", packageRoot), "utf8"))
    expect(manifest.exports["./wasm"]).toBe("./wasm/policy/meta_mesh_policy.js")
    expect(manifest.exports["./transport-wasm"]).toBe("./transport-wasm/meta_mesh.js")
    expect(manifest.exports["./wasm"]).not.toBe(manifest.exports["./transport-wasm"])
  })

  it("keeps Iroh and WebRTC outside policy dependency graph", () => {
    const dependencies = execFileSync("cargo", [
      "tree", "--manifest-path", "Cargo.toml", "-p", "meta-mesh-policy", "--edges", "normal",
    ], { cwd: new URL("../../", packageRoot), encoding: "utf8" })
    expect(dependencies).not.toMatch(/\b(?:iroh|iroh-gossip|iroh-blobs|iroh-webrtc-transport)\b/)
  })

  it("initializes policy WASM and leaves BrowserNode in transport WASM", async () => {
    const policyWasm = new Uint8Array(await readFile(new URL("../wasm/policy/meta_mesh_policy_bg.wasm", import.meta.url)))
    const transportWasm = new Uint8Array(await readFile(new URL("../transport-wasm/meta_mesh_bg.wasm", import.meta.url)))
    policyModule.initSync({ module: policyWasm })
    transportModule.initSync({ module: transportWasm })

    expect("BrowserNode" in policyModule).toBe(false)
    expect("BrowserNode" in transportModule).toBe(true)
    const codec = new policyModule.WasmPairingCodec()
    const frame = codec.encode("mesh-handshake-request", "shared-secret", new Uint8Array([1, 2, 3]))
    expect(codec.inspect(frame)).toMatchObject({ type: "mesh-handshake-request", secret: "shared-secret" })
    expect([...codec.decode(frame, "mesh-handshake-request", "shared-secret")]).toEqual([1, 2, 3])
  })
})
