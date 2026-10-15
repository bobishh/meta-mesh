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
