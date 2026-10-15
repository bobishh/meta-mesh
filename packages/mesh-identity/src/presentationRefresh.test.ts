import { expect, it } from "vitest"
import { BrowserIdentityStore } from "./index"

function storeFor(values: Map<string, string>, getItem: (key: string) => Promise<string | null> = async key => values.get(key) ?? null) {
  return new BrowserIdentityStore({ storageKey: "identity", asyncStorage: {
    getItem,
    setItem: async (key, value) => { values.set(key, value) },
    removeItem: async key => { values.delete(key) },
  } })
}

type SavedProfileParts = {
  identity: Record<string, unknown>
  device: Record<string, unknown>
  certificate: Record<string, unknown>
  privateKeys: Record<string, unknown>
}

it("Given unchanged durable presentation, when concurrent refreshes run, then retain the active profile and signing identity", async () => {
  const values = new Map<string, string>()
  const store = storeFor(values)
  const active = await store.bootstrap("Unchanged")
  const before = values.get("identity")

  const results = await Promise.all([store.refreshPresentation(), store.refreshPresentation()])

  expect(results[0]).toBe(active)
  expect(results[1]).toBe(active)
  expect(store.isCurrentProfile(active)).toBe(true)
  expect(values.get("identity")).toBe(before)
})

it("Given one durable presentation update, when matching refreshes overlap, then both receive the same validated current profile", async () => {
  const values = new Map<string, string>()
  let reads = 0
  const store = storeFor(values, async key => { reads++; return values.get(key) ?? null })
  const active = await store.bootstrap("Before")
  const saved = JSON.parse(values.get("identity")!)
  saved.identity.displayName = "After"
  const raw = JSON.stringify(saved)
  values.set("identity", raw)
  reads = 0

  const results = await Promise.all([store.refreshPresentation(raw), store.refreshPresentation(raw)])

  expect(reads).toBe(1)
  expect(results[0]).toBe(results[1])
  expect(results[0]!.identity.displayName).toBe("After")
  expect(results[0]!.privateKeys.devicePrivateKey).toBe(active.privateKeys.devicePrivateKey)
  expect(store.isCurrentProfile(results[0]!)).toBe(true)
})

it("Given different captured bytes, when refreshes overlap, then never share the successful refresh with a stale caller", async () => {
  const values = new Map<string, string>()
  const store = storeFor(values)
  await store.bootstrap("Before")
  const stale = values.get("identity")!
  const saved = JSON.parse(stale)
  saved.identity.displayName = "After"
  const raw = JSON.stringify(saved)
  values.set("identity", raw)

  const results = await Promise.allSettled([store.refreshPresentation(stale), store.refreshPresentation(raw)])

  expect(results[0]).toMatchObject({ status: "rejected", reason: expect.objectContaining({ message: expect.stringMatching(/changed|stale/i) }) })
  expect(results[1]).toMatchObject({ status: "fulfilled", value: { identity: { displayName: "After" } } })
  expect(values.get("identity")).toBe(raw)
})

it("Given only presentation names changed durably, when refreshing, then adopt labels and retain cached key objects", async () => {
  const values = new Map<string, string>()
  const store = storeFor(values)
  const cached = await store.bootstrap("Before")
  const identityKey = cached.privateKeys.identityPrivateKey
  const deviceKey = cached.privateKeys.devicePrivateKey
  const saved = JSON.parse(values.get("identity")!)
  saved.identity.displayName = "After"
  saved.device.displayName = "After's device"
  values.set("identity", JSON.stringify(saved))

  const refreshed = await store.refreshPresentation()

  expect(refreshed.identity.displayName).toBe("After")
  expect(refreshed.device.displayName).toBe("After's device")
  expect(refreshed.privateKeys.identityPrivateKey).toBe(identityKey)
  expect(refreshed.privateKeys.devicePrivateKey).toBe(deviceKey)
  expect(await store.bootstrap()).toBe(refreshed)
})

it("Given a captured durable profile changed before refresh, when refreshing against that snapshot, then reject stale bytes and retain cached metadata", async () => {
  const values = new Map<string, string>()
  const store = storeFor(values)
  const cached = await store.bootstrap("Before")
  const identityKey = cached.privateKeys.identityPrivateKey
  const deviceKey = cached.privateKeys.devicePrivateKey
  const capturedRaw = values.get("identity")!
  const changed = JSON.parse(capturedRaw)
  changed.identity.displayName = "Concurrent presentation"
  const changedRaw = JSON.stringify(changed)
  values.set("identity", changedRaw)

  await expect(store.refreshPresentation(capturedRaw)).rejects.toThrow(/stale|changed/i)

  expect(await store.bootstrap()).toBe(cached)
  expect(cached.identity.displayName).toBe("Before")
  expect(cached.privateKeys.identityPrivateKey).toBe(identityKey)
  expect(cached.privateKeys.devicePrivateKey).toBe(deviceKey)
  expect(values.get("identity")).toBe(changedRaw)

  const refreshed = await store.refreshPresentation()
  expect(refreshed.identity.displayName).toBe("Concurrent presentation")
  expect(refreshed.privateKeys.identityPrivateKey).toBe(identityKey)
  expect(refreshed.privateKeys.devicePrivateKey).toBe(deviceKey)
})

const authorityMutations: Array<[string, (saved: SavedProfileParts) => void]> = [
  ["person", saved => { saved.identity.personId = "another-person" }],
  ["identity key", saved => { saved.identity.publicKey = "another-key" }],
  ["device", saved => { saved.device.deviceId = "another-device" }],
  ["certificate", saved => { saved.certificate.signature = "changed-certificate" }],
  ["private-key bytes", saved => { saved.privateKeys.devicePrivateKeyPkcs8 = "changed-key" }],
]

it.each(authorityMutations)("Given durable %s changed, when refreshing presentation, then reject without replacing cached profile or durable bytes", async (_label, mutate) => {
  const values = new Map<string, string>()
  const store = storeFor(values)
  const cached = await store.bootstrap("Before")
  const raw = JSON.parse(values.get("identity")!)
  mutate(raw as SavedProfileParts)
  const changedRaw = JSON.stringify(raw)
  values.set("identity", changedRaw)

  await expect(store.refreshPresentation()).rejects.toThrow(/identity|profile/i)

  expect(await store.bootstrap()).toBe(cached)
  expect(values.get("identity")).toBe(changedRaw)
})

it("Given the cached profile changes while durable read waits, when refreshing, then reject without replacing it", async () => {
  const values = new Map<string, string>()
  let release!: () => void
  let entered!: () => void
  let pause = false
  const gate = new Promise<void>(resolve => { release = resolve })
  const reading = new Promise<void>(resolve => { entered = resolve })
  const store = storeFor(values, async key => {
    if (pause) { entered(); await gate }
    return values.get(key) ?? null
  })
  const cached = await store.bootstrap("Before")
  const oldRaw = values.get("identity")!
  const changed = JSON.parse(oldRaw)
  changed.identity.displayName = "Durable change"
  values.set("identity", JSON.stringify(changed))
  pause = true
  const refresh = store.refreshPresentation()
  await reading
  cached.identity.publicKey = "concurrent mutation"
  release()

  await expect(refresh).rejects.toThrow(/identity changed/i)
  expect(await store.bootstrap()).toBe(cached)
  expect(values.get("identity")).toBe(JSON.stringify(changed))
})

it("Given durable profile is missing or malformed, when refreshing presentation, then fail closed without generating or clearing identity", async () => {
  const values = new Map<string, string>()
  const store = storeFor(values)
  const cached = await store.bootstrap("Before")
  const priorRaw = values.get("identity")!
  values.set("identity", "{")

  await expect(store.refreshPresentation()).rejects.toThrow()

  expect(await store.bootstrap()).toBe(cached)
  expect(values.get("identity")).toBe("{")
  expect(values.get("identity")).not.toBe(priorRaw)
})

it.each([["missing", null], ["malformed", "{"]])("Given a cold store has %s durable identity, when refreshing, then do not bootstrap or overwrite it", async (_label, raw) => {
  const values = new Map<string, string>()
  if (raw !== null) values.set("identity", raw)
  const store = storeFor(values)

  await expect(store.refreshPresentation()).rejects.toThrow(/identity|profile/i)

  expect(values.get("identity") ?? null).toBe(raw)
})
