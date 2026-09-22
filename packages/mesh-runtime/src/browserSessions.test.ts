import { describe, expect, it, vi } from "vitest"
import { BrowserMeshSessions } from "./browserSessions"

describe("BrowserMeshSessions", () => {
  it("resets reconnect only after a session remains established", async () => {
    vi.useFakeTimers()
    const stableSession = vi.fn()
    const done = new Promise<never>(() => {})
    const connection = { close: vi.fn(async () => {}) }
    const session = { publish: vi.fn(async () => {}), close: vi.fn(async () => {}), done }
    const runtime = { admitSession: vi.fn(() => ({ decision: "accepted", generation: 1 })), removeSession: vi.fn(() => "connection") }
    const sessions = new BrowserMeshSessions({
      profile: async () => ({ deviceId: "local" }), deviceId: profile => profile.deviceId,
      credential: async () => ({}), create: () => ({ session }), runtime: () => runtime,
      key: () => "workspace:remote:instance", stopped: () => false, trace: vi.fn(), diagnosticCleared: vi.fn(),
      currentRemoved: vi.fn(async () => {}), notify: vi.fn(async () => {}), publishRecovered: vi.fn(async () => {}),
      protocolFailure: vi.fn(), networkFailure: vi.fn(), stableSession,
    })

    await sessions.install({ workspaceId: "workspace", deviceId: "remote", instanceId: "instance", remoteIssuedAt: "now",
      direction: "outgoing", connection, connectionId: "connection" })
    await vi.advanceTimersByTimeAsync(9_999)
    expect(stableSession).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(stableSession).toHaveBeenCalledWith("workspace:remote:instance", expect.any(Object))
    vi.useRealTimers()
  })
})
