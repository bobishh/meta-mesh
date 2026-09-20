import * as Automerge from "@automerge/automerge"
import { BrowserIdentityStore } from "@meta-uber/mesh-identity"
import { describe, expect, it, vi } from "vitest"
import {
  DeviceRouteCatalog,
  adaptVerifiedContactCard,
  adaptVerifiedWorkspaceAdvertisement,
  createSignedDeviceRoute,
  createSignedDurableBatchAck,
  deliverBatchToDevice,
  connectToDevice,
  verifySignedDeviceRoute,
  verifySignedDurableBatchAck,
} from "./protocol"
import { reconcileAutomergePeers } from "./automerge"
import { DEFAULT_GOSSIP_BOUNDS, selectScopedNeighbors } from "./gossip"
import { deviceBatch, deviceRoute, durableAck, MemoryDurableBatchStore, ScriptedRouteNetwork } from "./testing"

describe("replica-aware delivery", () => {
  it("Given a device signs a bounded route, when another replica verifies it, then identity and route fields remain bound", async () => {
    const profile = await new BrowserIdentityStore({ storageKey: crypto.randomUUID() }).bootstrap("Route owner")
    const signed = await createSignedDeviceRoute(profile, {
      scopeId: "scope-1",
      instanceId: "tab-a",
      endpoint: "iroh://tab-a",
      sequence: 3,
      issuedAt: "2026-09-15T10:00:00.000Z",
      expiresAt: "2026-09-15T10:10:00.000Z",
    })

    await expect(verifySignedDeviceRoute(signed, profile.device.publicKey, {
      now: Date.parse("2026-09-15T10:05:00.000Z"),
    })).resolves.toMatchObject({ deviceId: profile.device.deviceId, instanceId: "tab-a", sequence: 3 })

    const tampered = structuredClone(signed)
    tampered.payload.endpoint = "iroh://attacker"
    const catalog = new DeviceRouteCatalog()
    await expect(verifySignedDeviceRoute(tampered, profile.device.publicKey, {
      now: Date.parse("2026-09-15T10:05:00.000Z"),
    })).rejects.toThrow("signature")
    expect(catalog.routesFor("scope-1", profile.device.deviceId)).toEqual([])

    await expect(verifySignedDeviceRoute(signed, profile.device.publicKey, {
      now: Date.parse("2026-09-15T10:11:00.000Z"),
    })).rejects.toThrow("expired")
    catalog.admit(await verifySignedDeviceRoute(signed, profile.device.publicKey, {
      now: Date.parse("2026-09-15T10:11:00.000Z"), allowExpired: true,
    }))
    expect(catalog.routesFor("scope-1", profile.device.deviceId)).toHaveLength(1)
  })

  it("Given one device has several routes, when the preferred route fails, then one alternate route durably completes delivery", async () => {
    const store = new MemoryDurableBatchStore()
    const network = new ScriptedRouteNetwork("device-remote", store, {
      preferred: "fail-before-commit",
      alternate: "commit-and-ack",
    })

    const result = await deliverBatchToDevice({
      targetDeviceId: "device-remote",
      routes: [deviceRoute("preferred"), deviceRoute("alternate")],
      batch: deviceBatch(),
      send: network.send,
      verifyAck: async () => true,
      fallbackDelayMs: 0,
    })

    expect(result.route.instanceId).toBe("alternate")
    expect(network.attempts).toEqual(["preferred", "alternate"])
    expect(store.hashes()).toEqual(["change-1"])
  })

  it("Given one device has several live routes, when the preferred connection fails, then the device session uses an alternate route", async () => {
    const attempts: string[] = []
    const result = await connectToDevice({
      targetDeviceId: "device-remote",
      routes: [deviceRoute("preferred"), deviceRoute("alternate")],
      fallbackDelayMs: 0,
      connect: async route => {
        attempts.push(route.instanceId)
        if (route.instanceId === "preferred") throw new Error("route closed")
        return { connectionId: "alternate-connection" }
      },
    })

    expect(result.route.instanceId).toBe("alternate")
    expect(result.value.connectionId).toBe("alternate-connection")
    expect(attempts).toEqual(["preferred", "alternate"])
  })

  it("Given a commit acknowledgement is lost, when another route retries, then storage remains idempotent and returns one logical acknowledgement", async () => {
    const store = new MemoryDurableBatchStore()
    const network = new ScriptedRouteNetwork("device-remote", store, {
      first: "commit-and-lose-ack",
      second: "commit-and-ack",
    })

    const result = await deliverBatchToDevice({
      targetDeviceId: "device-remote",
      routes: [deviceRoute("first"), deviceRoute("second")],
      batch: deviceBatch(),
      send: network.send,
      verifyAck: async () => true,
      fallbackDelayMs: 0,
    })

    expect(result.ack.acceptedHashes).toEqual(["change-1"])
    expect(store.hashes()).toEqual(["change-1"])
    expect(store.admissions.map(value => value.duplicate)).toEqual([false, true])
  })

  it("Given two raced routes commit one batch, when either acknowledgement wins, then one device delivery completes and storage stays idempotent", async () => {
    const store = new MemoryDurableBatchStore()
    const releases = new Map<string, () => void>()
    const attempts: string[] = []
    const delivery = deliverBatchToDevice({
      targetDeviceId: "device-remote",
      routes: [deviceRoute("slow"), deviceRoute("fast")],
      batch: deviceBatch(),
      fallbackDelayMs: 0,
      send: async (route, batch) => {
        attempts.push(route.instanceId)
        const admission = await store.admit(batch)
        await new Promise<void>(resolve => releases.set(route.instanceId, resolve))
        return durableAck(batch, "device-remote", admission.acceptedHashes)
      },
      verifyAck: async () => true,
    })
    await vi.waitFor(() => expect(attempts).toEqual(["slow", "fast"]))
    releases.get("fast")!()
    const result = await delivery
    releases.get("slow")!()

    expect(result.route.instanceId).toBe("fast")
    expect(store.hashes()).toEqual(["change-1"])
    expect(store.admissions.map(value => value.duplicate)).toEqual([false, true])
  })

  it("Given durable admission completed, when the receiving device signs its bounded acknowledgement, then batch and frontier verify", async () => {
    const profile = await new BrowserIdentityStore({ storageKey: crypto.randomUUID() }).bootstrap("Ack receiver")
    const signed = await createSignedDurableBatchAck(profile, {
      scopeId: "scope-1", documentId: "document-1", batchId: "batch-1",
      acceptedHashes: ["change-1"], acceptedHeads: ["head-1"], committedAt: "2026-09-15T10:00:00.000Z",
    })

    await expect(verifySignedDurableBatchAck(signed, profile.device.publicKey)).resolves.toMatchObject({
      receiverDeviceId: profile.device.deviceId,
      batchId: "batch-1",
      acceptedHeads: ["head-1"],
    })
    const forged = structuredClone(signed)
    forged.payload.batchId = "other-batch"
    await expect(verifySignedDurableBatchAck(forged, profile.device.publicKey)).rejects.toThrow("signature")
  })

  it("Given every route is temporarily offline, when a retry round begins after backoff, then the device can recover without catalog mutation", async () => {
    let attempts = 0
    const routes = [deviceRoute("first"), deviceRoute("second")]
    const result = await deliverBatchToDevice({
      targetDeviceId: "device-remote",
      routes,
      batch: deviceBatch(),
      fallbackDelayMs: 0,
      retryDelaysMs: [0],
      send: async (_route, batch) => {
        attempts += 1
        if (attempts <= 2) throw new Error("offline")
        return durableAck(batch, "device-remote", ["change-1"])
      },
      verifyAck: async () => true,
    })

    expect(result.route.instanceId).toBe("first")
    expect(result.attemptedRouteIds).toEqual(["first", "second", "first"])
    expect(routes).toHaveLength(2)
  })

  it("Given a route returns an unauthorized acknowledgement, when delivery validates it, then no delivery completes", async () => {
    await expect(deliverBatchToDevice({
      targetDeviceId: "device-remote",
      routes: [deviceRoute("only")],
      batch: deviceBatch(),
      send: async (_route, batch) => durableAck(batch, "device-remote", ["change-1"]),
      verifyAck: async () => false,
    })).rejects.toThrow("Delivery retries exhausted")
  })

  it("Given delivery is pending, when the caller cancels, then route work is aborted", async () => {
    const controller = new AbortController()
    const delivery = deliverBatchToDevice({
      targetDeviceId: "device-remote",
      routes: [deviceRoute("only")],
      batch: deviceBatch(),
      signal: controller.signal,
      send: async (_route, _batch, signal) => new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(signal.reason), { once: true })
      }),
      verifyAck: async () => true,
    })
    controller.abort(new Error("caller stopped"))

    await expect(delivery).rejects.toThrow("caller stopped")
  })

  it("Given one instance publishes a newer route sequence, when catalogs merge, then the new endpoint replaces only that instance", () => {
    const catalog = new DeviceRouteCatalog()
    catalog.admit(deviceRoute("tab-a", 1, { endpoint: "iroh://old" }))
    catalog.admit(deviceRoute("tab-b", 1))
    catalog.admit(deviceRoute("tab-a", 2, { endpoint: "iroh://new" }))
    catalog.admit(deviceRoute("tab-a", 1, { endpoint: "iroh://late-old" }))

    expect(catalog.routesFor("scope-1", "device-remote").map(route => [route.instanceId, route.endpoint])).toEqual([
      ["tab-a", "iroh://new"],
      ["tab-b", "iroh://tab-b"],
    ])
  })

  it("Given verified legacy workspace and contact routes, when adapted, then endpoints and device identities survive under stable synthetic instances", async () => {
    const workspace = await adaptVerifiedWorkspaceAdvertisement({
      payload: {
        kind: "peer-advertisement", version: 1, workspaceId: "workspace-1", personId: "person-1",
        deviceId: "device-1", endpoint: "iroh://legacy", issuedAt: "2026-09-15T10:00:00.000Z",
      },
      signerKeyId: "device-1",
      signature: "workspace-signature",
    })
    const contact = await adaptVerifiedContactCard("room-1", {
      kind: "twang-contact",
      version: 1,
      deviceId: "device-1",
      endpoint: "iroh://legacy",
      signed: {
        payload: {
          kind: "contact-card", version: 1, personId: "person-1", deviceId: "device-1",
          endpoint: "iroh://legacy", createdAt: "2026-09-15T10:00:00.000Z",
        },
        signerKeyId: "device-1",
        signature: "contact-signature",
      },
    })

    expect(workspace).toMatchObject({ scopeId: "workspace-1", personId: "person-1", deviceId: "device-1", endpoint: "iroh://legacy" })
    expect(contact).toMatchObject({ scopeId: "room-1", personId: "person-1", deviceId: "device-1", endpoint: "iroh://legacy" })
    expect(workspace.instanceId).toBe(contact.instanceId)
    expect(workspace.instanceId).toMatch(/^legacy:/)
  })

  it("Given a verified stable contact locator, when adapted for room delivery, then its rendezvous endpoint remains authenticated evidence", async () => {
    const locator = await adaptVerifiedContactCard("room-1", {
      kind: "twang-contact",
      version: 3,
      identity: { personId: "person-1" },
      deviceId: "device-1",
      rendezvousEndpoint: "iroh://stable-contact",
      publishedAt: "2026-09-15T10:00:00.000Z",
      signed: {
        payload: {
          kind: "contact-locator", version: 1, personId: "person-1", deviceId: "device-1",
          rendezvousEndpoint: "iroh://stable-contact", publishedAt: "2026-09-15T10:00:00.000Z",
        },
        signerKeyId: "device-1",
        signature: "locator-signature",
      },
    })

    expect(locator).toMatchObject({
      scopeId: "room-1",
      personId: "person-1",
      deviceId: "device-1",
      endpoint: "iroh://stable-contact",
      signerKeyId: "device-1",
    })
    expect(locator.instanceId).toMatch(/^legacy:/)
    expect(locator.legacyEvidence).toMatchObject({ version: 3 })
  })
})

describe("sparse gossip and anti-entropy", () => {
  it("Given one hundred authorized devices, when neighbors are selected, then degree remains bounded and deterministic", () => {
    const candidates = Array.from({ length: 100 }, (_, index) => `device-${index.toString().padStart(3, "0")}`)
    const bounds = { ...DEFAULT_GOSSIP_BOUNDS, target: 6, high: 8 }
    const first = selectScopedNeighbors({ localDeviceId: "device-local", candidates: candidates.map(deviceId => ({ deviceId })), bounds })
    const second = selectScopedNeighbors({ localDeviceId: "device-local", candidates: [...candidates].reverse().map(deviceId => ({ deviceId })), bounds })

    expect(first).toHaveLength(6)
    expect(second).toEqual(first)
    expect(first).not.toContain("device-local")
  })

  it("Given eager gossip misses one peer, when anti-entropy runs later, then the missed change arrives", () => {
    const base = Automerge.from({ messages: [] as string[] })
    const sleeping = Automerge.clone(base)
    let author = Automerge.clone(base)
    author = Automerge.change(author, doc => { doc.messages.push("missed") })

    const [healedAuthor, healedSleeping] = reconcileAutomergePeers(Automerge, author, sleeping)

    expect(healedAuthor.messages).toEqual(["missed"])
    expect(healedSleeping.messages).toEqual(["missed"])
    expect(Automerge.getHeads(healedSleeping)).toEqual(Automerge.getHeads(healedAuthor))
  })

  it("Given two devices edit during a partition, when a bridge returns, then anti-entropy preserves both branches and equal heads", () => {
    const base = Automerge.from({ messages: [] as string[] })
    const left = Automerge.change(Automerge.clone(base), doc => { doc.messages.push("left") })
    const right = Automerge.change(Automerge.clone(base), doc => { doc.messages.push("right") })

    const [healedLeft, healedRight] = reconcileAutomergePeers(Automerge, left, right)

    expect([...healedLeft.messages].sort()).toEqual(["left", "right"])
    expect([...healedRight.messages].sort()).toEqual(["left", "right"])
    expect(Automerge.getHeads(healedLeft).sort()).toEqual(Automerge.getHeads(healedRight).sort())
  })
})
