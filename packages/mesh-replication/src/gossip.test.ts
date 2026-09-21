import { describe, expect, it, vi } from "vitest"
import {
  BrowserGossipDriver, DEFAULT_GOSSIP_BOUNDS, SparseGossip, selectScopedNeighbors, IrohGossipTopic,
  type GossipDispatch, type GossipFrame, type GossipStateMachine, type GossipStep,
} from "./gossip"

describe("sparse scoped gossip", () => {
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

  it("Given one neighbor route fails, when topology repairs, then another device replaces the edge without deleting membership", () => {
    let now = 0
    const engine = gossip("device-local", new Set(), () => now)
    const candidates = ["device-a", "device-b", "device-c", "device-d", "device-e"].map(deviceId => ({ deviceId }))
    const before = engine.updateScope("scope-1", candidates)
    engine.markFailure("scope-1", before[0])
    const after = engine.neighborDevices("scope-1")

    expect(after).not.toContain(before[0])
    expect(after).toHaveLength(4)
    now = 61_000
    expect(engine.updateScope("scope-1", candidates)).toContain(before[0])
  })

  it.each([3, 10, 100])("Given %i authorized devices, when one publishes and the overlay runs, then every device converges with bounded degree", async count => {
    const result = await simulate(count)

    expect(result.converged).toBe(true)
    expect(result.maximumDegree).toBeLessThanOrEqual(DEFAULT_GOSSIP_BOUNDS.target)
    expect(result.processedFrames).toBeLessThan(count * 30)
    expect(result.rounds).toBeLessThan(count * 3)
  })

  it("Given two components edit during a partition, when one bridge returns, then both rumors cross and every device heals", async () => {
    const network = createNetwork(10)
    const leftIds = network.ids.slice(0, 5)
    const rightIds = network.ids.slice(5)
    configure(network, id => leftIds.includes(id) ? leftIds : rightIds)
    network.stores.get(leftIds[0])!.add("left-change")
    network.stores.get(rightIds[0])!.add("right-change")
    await drain(network, [
      ...await publishFrom(network, leftIds[0], ["left-change"]),
      ...await publishFrom(network, rightIds[0], ["right-change"]),
    ])
    expect(network.stores.get(leftIds[4])!.has("right-change")).toBe(false)

    configure(network, () => network.ids)
    await drain(network, [
      ...await publishFrom(network, leftIds[4], ["left-change"]),
      ...await publishFrom(network, rightIds[0], ["right-change"]),
    ])
    expect([...network.stores.values()].every(store => store.has("left-change") && store.has("right-change"))).toBe(true)
  })

  it("Given one device sleeps through eager gossip, when it wakes and repair republishes availability, then it catches up", async () => {
    const network = createNetwork(10)
    configure(network, () => network.ids)
    const sleeping = network.ids.at(-1)!
    network.stores.get(network.ids[0])!.add("change-1")
    await drain(network, await publishFrom(network, network.ids[0], ["change-1"]), target => target === sleeping)
    expect(network.stores.get(sleeping)!.has("change-1")).toBe(false)

    await drain(network, await publishFrom(network, network.ids[0], ["change-1"]))
    expect(network.stores.get(sleeping)!.has("change-1")).toBe(true)
  })

  it("Given offers, wants, and changes repeat, when gossip handles them, then content admits once and forwarding stays bounded", async () => {
    const stored = new Set<string>()
    const engine = gossip("receiver", stored)
    engine.updateScope("scope-1", [{ deviceId: "sender" }, { deviceId: "next" }])
    const offer: GossipFrame = { version: 1, kind: "offer", scopeId: "scope-1", documentId: "doc-1", hashes: ["hash-1"] }
    const want = (await engine.receive("sender", offer))[0]
    expect(want.frame.kind).toBe("want")
    const changes: GossipFrame = {
      version: 1, kind: "changes", scopeId: "scope-1", documentId: "doc-1",
      changes: [{ hash: "hash-1", bytes: new Uint8Array([1]) }],
    }
    const first = await engine.receive("sender", changes)
    const duplicate = await engine.receive("sender", changes)

    expect(stored).toEqual(new Set(["hash-1"]))
    expect(first.length).toBeLessThanOrEqual(DEFAULT_GOSSIP_BOUNDS.eagerFanout)
    expect(duplicate).toEqual([])
  })

  it("Given sibling instances race outbound work, when one owns the short claim, then only that instance emits the offer", async () => {
    let owner: string | undefined
    const create = (instanceId: string) => new SparseGossip("device-local", {
      authorize: async () => true,
      hasChange: async () => true,
      loadChange: async () => undefined,
      admitChanges: async () => [],
      claim: async () => {
        if (owner === undefined) owner = instanceId
        return owner === instanceId
      },
    })
    const first = create("tab-a")
    const second = create("tab-b")
    first.updateScope("scope-1", [{ deviceId: "remote" }])
    second.updateScope("scope-1", [{ deviceId: "remote" }])

    expect(await first.publish("scope-1", "doc-1", ["hash-1"])).toHaveLength(1)
    expect(await second.publish("scope-1", "doc-1", ["hash-1"])).toHaveLength(0)
  })

  it("Given unauthorized, oversized, or amplification-prone gossip, when received, then it reveals and admits nothing", async () => {
    const stored = new Set<string>()
    const engine = gossip("receiver", stored, undefined, false)
    const offer: GossipFrame = { version: 1, kind: "offer", scopeId: "forbidden", documentId: "secret", hashes: ["hash-1"] }
    await expect(engine.receive("outsider", offer)).rejects.toThrow("Unauthorized")

    const authorized = gossip("receiver", stored)
    await expect(authorized.receive("sender", {
      ...offer,
      scopeId: "scope-1",
      hashes: Array.from({ length: DEFAULT_GOSSIP_BOUNDS.maximumOfferHashes + 1 }, (_, index) => `hash-${index}`),
    })).rejects.toThrow("item limit")
    await expect(authorized.receive("sender", {
      version: 1, kind: "changes", scopeId: "scope-1", documentId: "doc-1",
      changes: [{ hash: "hash-1", bytes: "not-bytes" as unknown as Uint8Array }],
    })).rejects.toThrow("change bytes")
    expect(stored.size).toBe(0)
  })

  it("Given iroh-gossip topic overlay, when messages are broadcast, then driver deliveries reach the topic", async () => {
    const seen = new Set<string>()
    const mockEngine = {
      joinTopic: vi.fn(async (topic: string) => `topic-hash-${topic}`),
      leaveTopic: vi.fn(async () => undefined),
      broadcast: vi.fn(async () => undefined),
      handleMessage: vi.fn(async (_sender: string, raw: Uint8Array) => {
        const key = new TextDecoder().decode(raw)
        if (seen.has(key)) return []
        seen.add(key)
        return [{ topic: "workspace-updates", deliveredFrom: "peer-2", content: raw }]
      }),
      activeNeighbors: vi.fn(() => ["peer-2", "peer-3"]),
    }

    const topic = new IrohGossipTopic("workspace-updates", mockEngine, ["peer-2"])
    await vi.waitFor(() => expect(topic.topicId).toBe("topic-hash-workspace-updates"))
    expect(topic.topicId).toBe("topic-hash-workspace-updates")
    expect(topic.activeNeighbors()).toEqual(["peer-2", "peer-3"])

    const msg = new TextEncoder().encode("change-notification")
    await topic.broadcast(msg)
    expect(mockEngine.broadcast).toHaveBeenCalledWith("workspace-updates", msg)

    const first = await topic.receive("peer-2", msg)
    expect(first[0]?.content).toEqual(msg)

    const duplicate = await topic.receive("peer-3", msg)
    expect(duplicate).toEqual([])

    await topic.leave()
    expect(mockEngine.leaveTopic).toHaveBeenCalledWith("workspace-updates")
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

function gossip(deviceId: string, stored: Set<string>, now?: () => number, authorized = true): SparseGossip {
  return new SparseGossip(deviceId, {
    now,
    authorize: async () => authorized,
    hasChange: async (_scope, _document, hash) => stored.has(hash),
    loadChange: async (_scope, _document, hash) => stored.has(hash) ? { hash, bytes: new TextEncoder().encode(hash) } : undefined,
    admitChanges: async (_scope, _document, changes) => {
      const accepted: string[] = []
      for (const change of changes) if (!stored.has(change.hash)) { stored.add(change.hash); accepted.push(change.hash) }
      return accepted
    },
  })
}

type Network = {
  ids: string[]
  stores: Map<string, Set<string>>
  engines: Map<string, SparseGossip>
}

function createNetwork(count: number): Network {
  const ids = Array.from({ length: count }, (_, index) => `device-${index.toString().padStart(3, "0")}`)
  const stores = new Map(ids.map(id => [id, new Set<string>()]))
  const engines = new Map(ids.map(id => [id, gossip(id, stores.get(id)!)]))
  return { ids, stores, engines }
}

function configure(network: Network, candidatesFor: (deviceId: string) => readonly string[]): number {
  let maximumDegree = 0
  for (const [id, engine] of network.engines) {
    const candidates = candidatesFor(id).filter(candidate => candidate !== id).map(deviceId => ({ deviceId }))
    maximumDegree = Math.max(maximumDegree, engine.updateScope("scope-1", candidates).length)
  }
  return maximumDegree
}

async function publishFrom(network: Network, from: string, hashes: string[]): Promise<Array<{ from: string; dispatch: GossipDispatch }>> {
  return (await network.engines.get(from)!.publish("scope-1", "doc-1", hashes)).map(dispatch => ({ from, dispatch }))
}

async function drain(
  network: Network,
  initial: Array<{ from: string; dispatch: GossipDispatch }>,
  drop?: (targetDeviceId: string) => boolean,
): Promise<{ processedFrames: number; rounds: number }> {
  const queue = [...initial]
  let processedFrames = 0
  let rounds = 0
  while (queue.length && processedFrames < network.ids.length * 30) {
    const current = queue.splice(0)
    for (const { from, dispatch } of current) {
      if (drop?.(dispatch.targetDeviceId)) continue
      const receiver = network.engines.get(dispatch.targetDeviceId)!
      const next = await receiver.receive(from, dispatch.frame)
      queue.push(...next.map(value => ({ from: dispatch.targetDeviceId, dispatch: value })))
      processedFrames += 1
    }
    rounds += 1
  }
  return { processedFrames, rounds }
}

async function simulate(count: number): Promise<{ converged: boolean; maximumDegree: number; processedFrames: number; rounds: number }> {
  const network = createNetwork(count)
  const maximumDegree = configure(network, () => network.ids)
  network.stores.get(network.ids[0])!.add("change-1")
  const metrics = await drain(network, await publishFrom(network, network.ids[0], ["change-1"]))
  return {
    converged: [...network.stores.values()].every(store => store.has("change-1")),
    maximumDegree,
    ...metrics,
  }
}
