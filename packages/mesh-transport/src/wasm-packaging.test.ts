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

  it("initializes policy WASM and leaves BrowserNode in transport WASM", async () => {
    const policyWasm = new Uint8Array(await readFile(new URL("../wasm/policy/meta_mesh_policy_bg.wasm", import.meta.url)))
    const transportWasm = new Uint8Array(await readFile(new URL("../transport-wasm/meta_mesh_bg.wasm", import.meta.url)))
    const policyExports = policyModule.initSync({ module: policyWasm })
    transportModule.initSync({ module: transportWasm })

    expect("BrowserNode" in policyModule).toBe(false)
    expect("BrowserNode" in transportModule).toBe(true)
    const codec = new policyModule.WasmPairingCodec()
    const frame = codec.encode("mesh-handshake-request", "shared-secret", new Uint8Array([1, 2, 3]))
    expect(codec.inspect(frame)).toMatchObject({ type: "mesh-handshake-request", secret: "shared-secret" })
    expect([...codec.decode(frame, "mesh-handshake-request", "shared-secret")]).toEqual([1, 2, 3])

    const profile = new policyModule.WasmIngressBudgetProfile()
    const encoder = new TextEncoder()
    expect(profile.maxHeaderBytes()).toBe(4 * 1024)
    expect(profile.maxConcurrentHeadersPerConnection()).toBe(32)
    expect(profile.maxFrameBytes("sync-request")).toBe(16 * 1024 * 1024)
    expect(profile.maxPayloadBytes("mesh-control-sync")).toBe(256 * 1024)
    expect(profile.maxPayloadBytes("mesh-automerge-sync")).toBe(512 * 1024)
    expect(profile.maxFrameBytes("mesh-proof-page-v1")).toBe(256 * 1024)
    expect(profile.maxLogicalTransferBytes()).toBe(24 * 1024 * 1024)
    expect(profile.maxTransferPages()).toBe(256)
    expect(typeof profile.maxTransferDeadlineMs()).toBe("number")
    expect(profile.maxTransferDeadlineMs()).toBe(600_000)
    const maxHeaderBytes = profile.maxHeaderBytes()
    const headerWithSecret = (secretLength: number) => encoder.encode(
      `{"type":"sync-request","version":"0.0.1","secret":"${"s".repeat(secretLength)}"}\n`,
    )
    const emptyHeader = headerWithSecret(0)
    const exactHeader = headerWithSecret(maxHeaderBytes - emptyHeader.length)
    expect(codec.inspect(headerWithSecret(maxHeaderBytes - emptyHeader.length - 1))).toMatchObject({ type: "sync-request" })
    expect(exactHeader.length).toBe(maxHeaderBytes)
    expect(codec.inspect(exactHeader)).toMatchObject({ type: "sync-request" })
    expect(() => codec.inspect(headerWithSecret(maxHeaderBytes - emptyHeader.length + 1))).toThrow()

    const frameLimit = profile.maxFrameBytes("sync-request")
    const ordinaryHeader = encoder.encode('{"type":"sync-request","version":"0.0.1","secret":"secret"}\n')
    const exactPayload = new Uint8Array(frameLimit - ordinaryHeader.length).fill(7)
    const belowFrame = codec.encode("sync-request", "secret", exactPayload.subarray(0, exactPayload.length - 1))
    expect(belowFrame.length).toBe(frameLimit - 1)
    expect(codec.inspect(belowFrame)).toMatchObject({ type: "sync-request" })
    const exactFrame = codec.encode("sync-request", "secret", exactPayload)
    expect(exactFrame.length).toBe(frameLimit)
    expect(codec.inspect(exactFrame)).toMatchObject({ type: "sync-request" })
    expect(() => codec.encode("sync-request", "secret", new Uint8Array(exactPayload.length + 1))).toThrow()
    const beyondFrame = new Uint8Array(frameLimit + 1)
    beyondFrame.set(exactFrame)
    expect(() => codec.inspect(beyondFrame)).toThrow()

    const controlPayloadLimit = profile.maxPayloadBytes("mesh-control-sync")
    const controlHeader = encoder.encode('{"type":"mesh-control-sync","version":"0.0.1","secret":"secret"}\n')
    const exactControl = new Uint8Array(controlHeader.length + controlPayloadLimit)
    exactControl.set(controlHeader)
    expect(codec.inspect(exactControl.subarray(0, exactControl.length - 1))).toMatchObject({ type: "mesh-control-sync" })
    expect(codec.inspect(exactControl)).toMatchObject({ type: "mesh-control-sync" })
    const beyondControl = new Uint8Array(exactControl.length + 1)
    beyondControl.set(exactControl)
    expect(() => codec.inspect(beyondControl)).toThrow()
    expect(() => codec.encode("mesh-control-sync", "secret", new Uint8Array(controlPayloadLimit + 1))).toThrow()

    const proofWireLimit = profile.maxFrameBytes("mesh-proof-page-v1")
    const proofHeader = encoder.encode('{"type":"mesh-proof-page-v1","version":"0.0.1","secret":"secret"}\n')
    const exactProof = new Uint8Array(proofWireLimit)
    exactProof.set(proofHeader)
    expect(codec.inspect(exactProof.subarray(0, exactProof.length - 1))).toMatchObject({ type: "mesh-proof-page-v1" })
    expect(codec.inspect(exactProof)).toMatchObject({ type: "mesh-proof-page-v1" })
    const beyondProof = new Uint8Array(proofWireLimit + 1)
    beyondProof.set(exactProof)
    expect(() => codec.inspect(beyondProof)).toThrow()

    const memoryBeforeOversize = policyExports.memory.buffer.byteLength
    expect(() => codec.inspect(new Uint8Array(frameLimit + 1))).toThrow()
    expect(policyExports.memory.buffer.byteLength).toBe(memoryBeforeOversize)
  })

  it("Given optional history parents, when exposing the Native bridge, then keep explicit initial and borrowed-parent entrypoints", () => {
    for (const name of ["verifyReceivedHistoryBaseline", "verifyReceivedHistoryBaselineFromParent",
      "verifyOwnerAttestedHistoryBaseline", "verifyOwnerAttestedHistoryBaselineFromParent",
      "verifyOwnerAttestedPeerHistoryBaseline", "verifyOwnerAttestedPeerHistoryBaselineFromParent", "prepareWorkspaceHistoryFromBasis"] as const) {
      expect(typeof policyModule.WasmStateCore[name]).toBe("function")
    }
    for (const name of ["ownerAttestedProposal", "ownerAttestedProposalFromParent", "confirmOwnerAttestedProposal", "confirmOwnerAttestedProposalFromParent"] as const) {
      expect(typeof policyModule.WasmVerifiedHistoryArchiveCapture.prototype[name]).toBe("function")
    }
  })
})
