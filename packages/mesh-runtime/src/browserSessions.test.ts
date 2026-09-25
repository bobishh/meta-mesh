import { describe, expect, it, vi } from "vitest"
import { BrowserMeshSessions } from "./browserSessions"

describe("BrowserMeshSessions", () => {
  it("resets reconnect only after a session remains established", async () => {
    vi.useFakeTimers()
    const stableSession = vi.fn()
    const done = new Promise<never>(() => {})
    const connection = {
      close: vi.fn(async () => {}),
      openStream: vi.fn(async () => { throw new Error("Unexpected stream open") }),
      acceptStream: vi.fn(async () => { throw new Error("Unexpected stream accept") }),
    }
    const session = { publish: vi.fn(async () => {}), close: vi.fn(async () => {}), done }
    const runtime = { admitSession: vi.fn(() => ({ decision: "accepted" as const, generation: 1 })), removeSession: vi.fn(() => "connection") }
    const sessions = new BrowserMeshSessions({
      profile: async () => ({ deviceId: "local" }), deviceId: profile => profile.deviceId, instanceId: () => "tab-local",
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

  it("rolls back runtime admission and closes transport when session creation fails", async () => {
    const connection = {
      close: vi.fn(async () => {}),
      openStream: vi.fn(async () => { throw new Error("Unexpected stream open") }),
      acceptStream: vi.fn(async () => { throw new Error("Unexpected stream accept") }),
    }
    const runtime = {
      admitSession: vi.fn(() => ({ decision: "accepted" as const, generation: 2 })),
      removeSession: vi.fn(() => "connection"),
    }
    const lifecycle = {
      register: vi.fn(() => ({ generation: 2, stableAfterMs: 10_000 })),
      evict: vi.fn(() => ({ shouldClose: true, wasCurrent: true, connectionId: "connection" })),
      reportFailure: vi.fn(() => false), markStable: vi.fn(() => false), publishRecovery: vi.fn(() => false),
      callbackPlan: vi.fn(() => ({ publishRecovery: false, stable: false, reportFailure: false, evict: false })),
      publishPlan: vi.fn(() => []),
      clear: vi.fn(),
    }
    const sessions = new BrowserMeshSessions({
      profile: async () => ({ deviceId: "local" }), deviceId: profile => profile.deviceId, instanceId: () => "tab-local",
      credential: async () => ({}), create: () => { throw new Error("Session construction failed") },
      runtime: () => runtime,
      key: () => "workspace:remote:instance", stopped: () => false, trace: vi.fn(), diagnosticCleared: vi.fn(),
      currentRemoved: vi.fn(async () => {}), notify: vi.fn(async () => {}), publishRecovered: vi.fn(async () => {}),
      protocolFailure: vi.fn(), networkFailure: vi.fn(),
    }, undefined, lifecycle)

    await expect(sessions.install({ workspaceId: "workspace", deviceId: "remote", instanceId: "instance",
      remoteIssuedAt: "now", direction: "outgoing", connection, connectionId: "connection" }))
      .rejects.toThrow("Session construction failed")
    expect(lifecycle.evict).toHaveBeenCalledWith({ workspaceId: "workspace", deviceId: "remote", instanceId: "instance" }, 2)
    expect(runtime.removeSession).toHaveBeenCalled()
    expect(connection.close).toHaveBeenCalledOnce()
  })
})
