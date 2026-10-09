import { describe, expect, it } from "vitest"
import { createMeshRuntime, MeshHandshakeCodec } from "./index"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"

describe("Rust mesh runtime", () => {
  it("advertises only the renamed owner workspace offer capability", () => {
    expect(meshRustRuntime().state.meshCapabilities()).toContain("owner-workspace")
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
    }, "outgoing")

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
    } } }, capabilities: ["iroh-gossip-v1", "automerge-sync-v1", "device-revocation-v1"], breakGlassClaims: [] }
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

  it("uses owner workspace offers with the current capability", () => {
    const codec = new MeshHandshakeCodec()
    expect(codec.features(["owner-workspace-v1"])).toMatchObject({ ownerWorkspaceSupported: false })
    expect(codec.features(["owner-workspace-v1"])).not.toHaveProperty("ownerWorkspaceOfferFrame")
    expect(codec.features(["owner-workspace"])).toMatchObject({
      ownerWorkspaceSupported: true, ownerWorkspaceOfferFrame: "mesh-owner-workspace-offer",
    })
  })
})

function rustReplacesSession(
  previous: { remoteIssuedAt: string; remoteRouteSequence?: number; direction: "incoming" | "outgoing" },
  candidate: { remoteIssuedAt: string; remoteRouteSequence?: number; direction: "incoming" | "outgoing" },
  preferred: "incoming" | "outgoing",
) {
  const runtime = createMeshRuntime()
  const key = { workspaceId: "comparison", deviceId: "comparison", instanceId: "comparison" }
  try {
    runtime.admitSession({ key, connectionId: "previous", ...previous }, previous.direction)
    return runtime.admitSession({ key, connectionId: "candidate", ...candidate }, preferred).decision === "accepted"
  } finally { runtime.free?.() }
}

describe("Canonical session replacement policy", () => {
  it("Given simultaneous dials converge, when the same session arrives again, then only the preferred direction replaces its duplicate", () => {
    const current = { remoteIssuedAt: "2026-09-14T12:00:00.000Z", direction: "incoming" as const }

    expect(rustReplacesSession(current, { ...current }, "incoming")).toBe(false)
    expect(rustReplacesSession(current, { ...current, direction: "outgoing" }, "incoming")).toBe(false)
    expect(rustReplacesSession({ ...current, direction: "outgoing" }, current, "incoming")).toBe(true)
  })

  it("Given a renewed route for one instance, when both sessions arrive, then route sequence beats wall-clock skew", () => {
    const current = { remoteIssuedAt: "2026-09-14T12:05:00.000Z", remoteRouteSequence: 4, direction: "incoming" as const }
    const renewed = { remoteIssuedAt: "2026-09-14T12:00:00.000Z", remoteRouteSequence: 5, direction: "incoming" as const }

    expect(rustReplacesSession(current, renewed, "incoming")).toBe(true)
    expect(rustReplacesSession(renewed, current, "incoming")).toBe(false)
  })

  it("Given equal route sequence with skewed clocks, when duplicate sessions arrive, then time cannot replace the preferred direction", () => {
    const current = { remoteIssuedAt: "2026-09-14T12:00:00.000Z", remoteRouteSequence: 4, direction: "incoming" as const }
    const future = { ...current, remoteIssuedAt: "2099-09-14T12:00:00.000Z", direction: "outgoing" as const }

    expect(rustReplacesSession(current, future, "incoming")).toBe(false)
  })

})
