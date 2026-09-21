import { describe, expect, it, vi } from "vitest"
import { BrowserMeshDialScheduler } from "./browserDial"

describe("BrowserMeshDialScheduler", () => {
  it("selects healthy routes, keeps one dial per device and reports retries", async () => {
    const dial = vi.fn(async () => {})
    const onRetries = vi.fn()
    const scheduler = new BrowserMeshDialScheduler({
      peers: async () => [
        { workspaceId: "workspace", deviceId: "remote", instanceId: "a" },
        { workspaceId: "workspace", deviceId: "remote", instanceId: "b" },
      ],
      hasSession: () => false,
      deviceKey: (workspaceId, deviceId) => `${workspaceId}:${deviceId}`,
      peerKey: (workspaceId, deviceId, instanceId) => `${workspaceId}:${deviceId}:${instanceId}`,
      routeFailures: () => 0,
      retryAt: () => 0,
      routeAttemptActive: () => false,
      dial,
      onRetries,
    })

    await scheduler.schedule("local", new AbortController().signal, 1)

    expect(dial).toHaveBeenCalledOnce()
    expect(dial).toHaveBeenCalledWith(expect.arrayContaining([
      expect.objectContaining({ instanceId: "a" }), expect.objectContaining({ instanceId: "b" }),
    ]), expect.any(AbortSignal))
    expect(onRetries).toHaveBeenCalledWith({})
  })
})
