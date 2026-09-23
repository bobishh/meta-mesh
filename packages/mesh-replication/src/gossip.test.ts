import { describe, expect, it, vi } from "vitest"
import { BrowserGossipDriver, DEFAULT_GOSSIP_BOUNDS, selectScopedNeighbors, type GossipStateMachine, type GossipStep } from "./gossip"

describe("gossip bridge", () => {
  it("Given a device has several instance routes, when neighbors are selected, then it occupies one bounded replica slot", () => {
    const neighbors = selectScopedNeighbors({
      localDeviceId: "device-local",
      candidates: [
        { deviceId: "device-a", health: 1 },
        { deviceId: "device-a", health: 9 },
        { deviceId: "device-b", health: 2 },
        { deviceId: "device-c", health: 3 },
      ],
      bounds: { ...DEFAULT_GOSSIP_BOUNDS, target: 2 },
      now: 0,
    })

    expect(neighbors).toHaveLength(2)
    expect(new Set(neighbors).size).toBe(2)
  })

  it("Given browser gossip emits fanout, timers, and failed routes, when driven, then no protocol action is discarded", async () => {
    vi.useFakeTimers()
    try {
      const empty = (overrides: Partial<GossipStep> = {}): GossipStep => ({
        sends: [], deliveries: [], timers: [], disconnects: [], neighborsUp: [], neighborsDown: [], ...overrides,
      })
      const state: GossipStateMachine = {
        joinTopic: vi.fn(() => empty({ topicId: "topic-1", timers: [{ timerId: 7, delayMs: 25 }] })),
        leaveTopic: vi.fn(() => empty({ disconnects: ["peer-2"] })),
        broadcast: vi.fn(() => empty({ sends: [
          { peer: "peer-2", packet: new Uint8Array([2]) },
          { peer: "offline-peer", packet: new Uint8Array([3]) },
        ] })),
        handleMessage: vi.fn(() => empty({ deliveries: [
          { topic: "workspace-updates", deliveredFrom: "peer-2", content: new Uint8Array([4]) },
        ] })),
        expireTimer: vi.fn(() => empty({ sends: [{ peer: "peer-3", packet: new Uint8Array([7]) }] })),
        peerDisconnected: vi.fn(() => empty({ disconnects: ["offline-peer"] })),
        activeNeighbors: vi.fn(() => ["peer-2"]),
      }
      const sent: string[] = []
      const disconnected: string[] = []
      const delivered: string[] = []
      const driver = new BrowserGossipDriver(state, {
        send: async peer => {
          if (peer === "offline-peer") throw new Error("offline")
          sent.push(peer)
        },
        disconnect: peer => { disconnected.push(peer) },
        deliver: delivery => { delivered.push(`${delivery.topic}:${delivery.deliveredFrom}`) },
      })

      expect(await driver.joinTopic("workspace-updates", ["peer-2"])).toBe("topic-1")
      await driver.broadcast("workspace-updates", new Uint8Array([1]))
      await driver.handleMessage("peer-2", new Uint8Array([4]))
      await vi.advanceTimersByTimeAsync(25)
      await vi.waitFor(() => expect(sent).toContain("peer-3"))
      expect(state.expireTimer).toHaveBeenCalledWith(7n)
      await driver.leaveTopic("workspace-updates")

      expect(sent).toEqual(["peer-2", "peer-3"])
      expect(state.peerDisconnected).toHaveBeenCalledWith("offline-peer")
      expect(disconnected).toEqual(["offline-peer", "peer-2"])
      expect(delivered).toEqual(["workspace-updates:peer-2"])
      driver.close()
    } finally {
      vi.useRealTimers()
    }
  })
})
