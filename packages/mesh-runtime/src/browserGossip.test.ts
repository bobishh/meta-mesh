import { describe, expect, it, vi } from "vitest"
import type { GossipStateMachine, GossipStep } from "@meta-uber/mesh-replication/gossip"
import { BrowserMeshGossip } from "./browserGossip"

const step = (value: Partial<GossipStep> = {}): GossipStep => ({
  sends: [], deliveries: [], timers: [], disconnects: [], neighborsUp: [], neighborsDown: [], ...value,
})

describe("BrowserMeshGossip", () => {
  it("owns browser gossip lifecycle while the host keeps authenticated streams and documents", async () => {
    const publish = vi.fn(async () => {})
    const send = vi.fn(async () => {})
    const trace = vi.fn()
    const engine: GossipStateMachine = {
      joinTopic: vi.fn(() => step({ topicId: "topic" })),
      leaveTopic: vi.fn(() => step()),
      broadcast: vi.fn(() => step({ sends: [{ peer: "remote", packet: new Uint8Array([1]) }] })),
      handleMessage: vi.fn(() => step({ deliveries: [{
        topic: "mesh-workspace-workspace", deliveredFrom: "remote",
        content: new TextEncoder().encode(JSON.stringify({ version: 1, kind: "workspace-update", workspaceId: "workspace" })),
      }] })),
      expireTimer: vi.fn(() => step()),
      peerDisconnected: vi.fn(() => step()),
      activeNeighbors: vi.fn(() => ["remote"]),
    }
    const gossip = new BrowserMeshGossip({
      isStopped: () => false,
      createEngine: () => engine,
      endpoints: () => ["remote"],
      encodeWorkspaceUpdate: (workspaceId, nonce) => new TextEncoder().encode(JSON.stringify({ version: 1, kind: "workspace-update", workspaceId, nonce })),
      isWorkspaceUpdate: (content, workspaceId) => new TextDecoder().decode(content).includes(`"workspaceId":"${workspaceId}"`),
      transportSecret: async () => "secret",
      session: () => ({ endpoint: "remote", deviceId: "device", publish }),
      send,
      publishAll: async () => {},
      trace,
    })

    await gossip.rebuild("workspace")
    await gossip.broadcast("workspace")
    await gossip.receivePacket("workspace", "remote", new Uint8Array([9]))

    expect(engine.joinTopic).toHaveBeenCalledWith("mesh-workspace-workspace", ["remote"])
    expect(send).toHaveBeenCalledWith("workspace", "remote", "secret", new Uint8Array([1]))
    expect(publish).toHaveBeenCalledOnce()
    expect(trace).toHaveBeenCalledWith("gossip.delivered", expect.objectContaining({ peerId: "device" }))
    gossip.closeAll()
  })
})
