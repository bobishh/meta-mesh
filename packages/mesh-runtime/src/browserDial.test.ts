import { describe, expect, it, vi } from "vitest"
import { BrowserMeshDialScheduler } from "./browserDial"

describe("BrowserMeshDialScheduler", () => {
  it("dials each healthy remote instance and reports retries", async () => {
    const dial = vi.fn(async () => {})
    const onRetries = vi.fn()
    const scheduler = new BrowserMeshDialScheduler({
      peers: async () => [
        { workspaceId: "workspace", deviceId: "remote", instanceId: "a" },
        { workspaceId: "workspace", deviceId: "remote", instanceId: "b" },
      ],
      hasSession: () => false,
      peerKey: (workspaceId, deviceId, instanceId) => `${workspaceId}:${deviceId}:${instanceId}`,
      routeFailures: () => 0,
      retryAt: () => 0,
      routeAttemptActive: () => false,
      dial,
      onRetries,
    })

    await scheduler.schedule("local", "tab-local", new AbortController().signal, 1)

    expect(dial).toHaveBeenCalledTimes(2)
    expect(dial).toHaveBeenNthCalledWith(1, [expect.objectContaining({ instanceId: "a" })], expect.any(AbortSignal))
    expect(dial).toHaveBeenNthCalledWith(2, [expect.objectContaining({ instanceId: "b" })], expect.any(AbortSignal))
    expect(onRetries).toHaveBeenCalledWith({})
  })

  it("keeps an established instance while dialing its reachable sibling", async () => {
    const dial = vi.fn(async () => {})
    const scheduler = new BrowserMeshDialScheduler({
      peers: async () => [
        { workspaceId: "workspace", deviceId: "remote", instanceId: "connected" },
        { workspaceId: "workspace", deviceId: "remote", instanceId: "missing" },
      ],
      hasSession: (_workspaceId, _deviceId, instanceId) => instanceId === "connected",
      peerKey: (workspaceId, deviceId, instanceId) => `${workspaceId}:${deviceId}:${instanceId}`,
      routeFailures: () => 0,
      retryAt: () => 0,
      routeAttemptActive: () => false,
      dial,
      onRetries: vi.fn(),
    })

    await scheduler.schedule("local", "tab-local", new AbortController().signal, 1)

    expect(dial).toHaveBeenCalledOnce()
    expect(dial).toHaveBeenCalledWith([expect.objectContaining({ instanceId: "missing" })], expect.any(AbortSignal))
  })
})
