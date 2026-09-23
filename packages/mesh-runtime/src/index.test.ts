import { describe, expect, it } from "vitest"
import { createMeshRuntime, MeshHandshakeCodec } from "./index"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"

describe("Rust mesh runtime", () => {
  it("advertises only the renamed owner workspace offer capability", () => {
    expect(meshRustRuntime().state.meshCapabilities()).toContain("owner-workspace-v2")
    expect(meshRustRuntime().state.meshCapabilities()).not.toContain("owner-workspace-v1")
  })

  it("keeps sibling instances and rejects a stale session cleanup", () => {
    const runtime = createMeshRuntime()
    runtime.start()
    const first = runtime.admitSession({
      key: { workspaceId: "workspace", deviceId: "device", instanceId: "one" },
      connectionId: "first", remoteIssuedAt: "2026-09-21T00:00:00Z",
      remoteRouteSequence: 1, direction: "incoming",
    }, "incoming")
    const sibling = runtime.admitSession({
      key: { workspaceId: "workspace", deviceId: "device", instanceId: "two" },
      connectionId: "sibling", remoteIssuedAt: "2026-09-21T00:00:00Z",
      remoteRouteSequence: 1, direction: "incoming",
    }, "incoming")
    const replacement = runtime.admitSession({
      key: { workspaceId: "workspace", deviceId: "device", instanceId: "one" },
      connectionId: "replacement", remoteIssuedAt: "2026-09-21T00:00:00Z",
      remoteRouteSequence: 2, direction: "outgoing",
    }, "incoming")

    expect(first.decision).toBe("accepted")
    expect(sibling.decision).toBe("accepted")
    expect(replacement).toMatchObject({ decision: "accepted", replacedConnectionId: "first" })
    expect(runtime.removeSession({ workspaceId: "workspace", deviceId: "device", instanceId: "one" }, first.generation!))
      .toBeNull()
    expect(runtime.sessions()).toHaveLength(2)
    runtime.free?.()
  })
})

describe("MeshHandshakeCodec", () => {
  it("accepts an empty old field and names a reported device when real legacy authority is rejected", () => {
    const codec = new MeshHandshakeCodec()
    const payload = { workspaceId: "board-1", peer: { advertisement: { payload: {
      deviceId: "device-123456789", deviceName: "Bo's laptop",
    } } }, capabilities: ["iroh-gossip-v1", "automerge-sync-v1"], breakGlassClaims: [] }
    expect(codec.validate(payload, "board-1").workspaceId).toBe("board-1")
    expect(() => codec.validate({ ...payload, breakGlassClaims: [{}] }, "board-1"))
      .toThrow(/Reported device \(unverified\): "Bo's laptop" \(device-123\); workspace: board-1/)
  })
  it("exposes negotiated features", () => {
    const codec = new MeshHandshakeCodec()
    expect(codec.features(["heartbeat-v1", "automerge-sync-v1", "blob-transfer-v1"])).toEqual({
      heartbeatSupported: true, ownershipReceiptSupported: false, ownerWorkspaceSupported: false,
      ownerWorkspaceOfferFrame: undefined,
      blobTransferSupported: true,
    })
  })

  it("uses owner workspace offers only with the renamed v2 protocol capability", () => {
    const codec = new MeshHandshakeCodec()
    expect(codec.features(["owner-workspace-v1"])).toMatchObject({
      ownerWorkspaceSupported: false, ownerWorkspaceOfferFrame: undefined,
    })
    expect(codec.features(["owner-workspace-v2"])).toMatchObject({
      ownerWorkspaceSupported: true, ownerWorkspaceOfferFrame: "mesh-owner-workspace-offer",
    })
  })
})
