import { describe, expect, it } from "vitest"
import { createMeshRuntime } from "./index"

describe("Rust mesh runtime", () => {
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
