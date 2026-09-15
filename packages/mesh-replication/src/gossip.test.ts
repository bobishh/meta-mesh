import { describe, expect, it } from "vitest"
import { DEFAULT_GOSSIP_BOUNDS, SparseGossip, selectScopedNeighbors, type GossipDispatch, type GossipFrame } from "./gossip"

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
