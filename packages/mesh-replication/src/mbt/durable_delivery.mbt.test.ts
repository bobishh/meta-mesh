import { describe, expect, it } from "vitest"
import * as fs from "node:fs"
import * as path from "node:path"
import { execSync } from "node:child_process"
import { parseItfTrace } from "./itf"
import { DurableDeliveryMbtDriver } from "./durable_delivery_driver"
import { deliverBatchToDevice } from "../protocol"
import { deviceBatch, deviceRoute, durableAck } from "../testing"

function loadTrace(filename: string) {
  const root = path.resolve(__dirname, "../../../../quint/traces")
  const content = fs.readFileSync(path.join(root, filename), "utf-8")
  return parseItfTrace(content)
}

describe("Durable Delivery Model-Based Tests (Quint MBT)", () => {
  it("replays happy path trace (route-a commits and returns valid ACK)", async () => {
    const trace = loadTrace("durable_delivery_happy.itf.json")
    const driver = new DurableDeliveryMbtDriver(["route-a", "route-b", "route-c"], ["change-1", "change-2"])
    await driver.replay(trace)

    expect(driver.deliveryResult?.route.instanceId).toBe("route-a")
    expect(driver.store.hashes()).toEqual(["change-1", "change-2"])
    expect(driver.store.admissions.length).toBe(1)
  })

  it("replays route switching trace (route-a fails before commit, fallback route-b succeeds)", async () => {
    const trace = loadTrace("durable_delivery_route_switch.itf.json")
    const driver = new DurableDeliveryMbtDriver(["route-a", "route-b", "route-c"], ["change-1", "change-2"])
    await driver.replay(trace)

    expect(driver.deliveryResult?.route.instanceId).toBe("route-b")
    expect(driver.store.hashes()).toEqual(["change-1", "change-2"])
    expect(driver.launchedRoutes).toContain("route-a")
    expect(driver.launchedRoutes).toContain("route-b")
  })

  it("replays retry after lost ACK trace (storage remains idempotent across retry rounds)", async () => {
    const trace = loadTrace("durable_delivery_retry_after_lost_ack.itf.json")
    const driver = new DurableDeliveryMbtDriver(["route-a", "route-b", "route-c"], ["change-1", "change-2"])
    await driver.replay(trace)

    expect(driver.deliveryResult?.route.instanceId).toBe("route-a")
    expect(driver.store.hashes()).toEqual(["change-1", "change-2"])
    // Idempotent: admitted twice, but hashes set contains exactly the batch changes
    expect(driver.store.admissions.length).toBe(2)
    expect(driver.store.admissions[1].duplicate).toBe(true)
  })

  it("verifies losing routes are cancelled when winning route commits", async () => {
    const driver = new DurableDeliveryMbtDriver(["route-fast", "route-slow"], ["change-1"])
    driver.start(0)

    const slow = await driver.waitForRouteLaunch("route-slow")
    const fast = await driver.waitForRouteLaunch("route-fast")

    // Fast route succeeds
    const admission = await driver.store.admit(driver.batch)
    fast.resolve(durableAck(driver.batch, driver.targetDeviceId, admission.acceptedHashes))
    await driver.deliveryPromise

    // Slow route must have received abort signal
    expect(slow.signal.aborted).toBe(true)
    expect(driver.abortedRoutes).toContain("route-slow")
  })

  it("counterexample regression: empty or partial acceptedHashes is rejected by ackMatches", async () => {
    const batch = deviceBatch("batch-1", ["change-1", "change-2"])
    const emptyAck = durableAck(batch, "device-remote", [])
    const partialAck = durableAck(batch, "device-remote", ["change-1", "change-1"])
    const validAck = durableAck(batch, "device-remote", ["change-1", "change-2"])

    let callCount = 0
    const result = await deliverBatchToDevice({
      targetDeviceId: "device-remote",
      routes: [deviceRoute("bad-route-1"), deviceRoute("bad-route-2"), deviceRoute("good-route")],
      batch,
      send: async route => {
        callCount++
        if (route.instanceId === "bad-route-1") return emptyAck
        if (route.instanceId === "bad-route-2") return partialAck
        return validAck
      },
      verifyAck: async () => true,
      fallbackDelayMs: 0,
    })

    // Bad routes failed verification; good route won
    expect(result.route.instanceId).toBe("good-route")
    expect(new Set(result.ack.acceptedHashes)).toEqual(new Set(["change-1", "change-2"]))
    expect(callCount).toBe(3)
  })

  it("replays dynamically generated Quint simulation trace", async () => {
    const tmpTrace = `/tmp/durable_delivery_dynamic_${Date.now()}.itf.json`
    try {
      execSync(
        `npx --yes @informalsystems/quint run quint/durable_delivery.qnt --main=durable_delivery_instance --out-itf=${tmpTrace} --mbt --max-steps=6 --seed=0x42`,
        { stdio: "pipe", env: process.env },
      )
      if (fs.existsSync(tmpTrace)) {
        const trace = parseItfTrace(fs.readFileSync(tmpTrace, "utf-8"))
        const driver = new DurableDeliveryMbtDriver(["route-a", "route-b", "route-c"], ["change-1", "change-2"])
        await driver.replay(trace)
      }
    } finally {
      if (fs.existsSync(tmpTrace)) fs.unlinkSync(tmpTrace)
    }
  })
})
