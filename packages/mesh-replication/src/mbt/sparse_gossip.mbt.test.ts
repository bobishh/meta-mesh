import { describe, expect, it } from "vitest"
import * as fs from "node:fs"
import * as path from "node:path"
import { execSync } from "node:child_process"
import { parseItfTrace } from "./itf"
import { SparseGossipMbtDriver } from "./sparse_gossip_driver"
import { SparseGossip } from "../gossip"

function loadTrace(filename: string) {
  const root = path.resolve(__dirname, "../../../../quint/traces")
  const content = fs.readFileSync(path.join(root, filename), "utf-8")
  return parseItfTrace(content)
}

describe("Sparse Gossip Model-Based Tests (Quint MBT)", () => {
  it("replays 3-way rumor propagation trace (offer -> want -> changes)", async () => {
    const trace = loadTrace("sparse_gossip_propagate.itf.json")
    const driver = new SparseGossipMbtDriver(["d1", "d2", "d3"], new Map([["d1", ["c1"]]]))
    await driver.replay(trace)

    expect(driver.stores.get("d1")).toEqual(new Set(["c1"]))
    expect(driver.stores.get("d2")).toEqual(new Set(["c1"]))
  })

  it("replays deduplication trace (repeated changes frame is ignored)", async () => {
    const trace = loadTrace("sparse_gossip_dedup.itf.json")
    const driver = new SparseGossipMbtDriver(["d1", "d2", "d3"], new Map([["d1", ["c1"]]]))
    await driver.replay(trace)

    expect(driver.stores.get("d2")).toEqual(new Set(["c1"]))
  })

  it("replays failure & partition healing trace", async () => {
    const trace = loadTrace("sparse_gossip_failure_healing.itf.json")
    const driver = new SparseGossipMbtDriver(["d1", "d2", "d3"], new Map([["d1", ["c1"]]]))
    await driver.replay(trace)

    expect(driver.stores.get("d2")).toEqual(new Set(["c1"]))
    expect(driver.stores.get("d3")).toEqual(new Set(["c1"]))
  })

  it("counterexample regression: publish records hashes in seen cache, preventing reflection loops", async () => {
    let admitCount = 0
    const stored = new Set<string>(["c1"])
    const engine = new SparseGossip("d1", {
      authorize: async () => true,
      hasChange: async (_s, _d, h) => stored.has(h),
      loadChange: async () => undefined,
      admitChanges: async (_s, _d, changes) => {
        admitCount += changes.length
        return changes.map(c => c.hash)
      },
    })
    engine.updateScope("scope-1", [{ deviceId: "d2" }, { deviceId: "d3" }])

    // Step 1: d1 publishes c1
    const published = await engine.publish("scope-1", "doc-1", ["c1"])
    expect(published.length).toBeGreaterThan(0)

    // Step 2: d2 reflects changes with c1 back to d1
    const forwardOffers = await engine.receive("d2", {
      version: 1,
      kind: "changes",
      scopeId: "scope-1",
      documentId: "doc-1",
      changes: [{ hash: "c1", bytes: new Uint8Array([1]) }],
    })

    // Fixed implementation: c1 is in seen cache, so 0 admissions and 0 forward offers
    expect(admitCount).toBe(0)
    expect(forwardOffers).toEqual([])
  })

  it("replays dynamically generated Quint simulation trace", async () => {
    const tmpTrace = `/tmp/sparse_gossip_dynamic_${Date.now()}.itf.json`
    try {
      execSync(
        `npx --yes @informalsystems/quint run quint/sparse_gossip.qnt --main=sparse_gossip_instance --out-itf=${tmpTrace} --mbt --max-steps=6 --seed=0x42`,
        { stdio: "pipe", env: process.env },
      )
      if (fs.existsSync(tmpTrace)) {
        const trace = parseItfTrace(fs.readFileSync(tmpTrace, "utf-8"))
        const driver = new SparseGossipMbtDriver(["d1", "d2", "d3"], new Map([["d1", ["c1"]]]))
        await driver.replay(trace)
      }
    } finally {
      if (fs.existsSync(tmpTrace)) fs.unlinkSync(tmpTrace)
    }
  })
})
