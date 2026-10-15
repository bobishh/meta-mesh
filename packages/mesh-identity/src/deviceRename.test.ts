import { expect, it } from "vitest"
import { BrowserIdentityStore, type IdentityAdoptionCommitPlan } from "./index"

function storeFor(values: Map<string, string>, getItem: (key: string) => Promise<string | null> = async key => values.get(key) ?? null) {
  return new BrowserIdentityStore({ storageKey: "identity", asyncStorage: {
    getItem,
    setItem: async (key, value) => { values.set(key, value) },
    removeItem: async key => { values.delete(key) },
  } })
}

it("Given a rename transaction, when commit succeeds, then publish cache only after atomic profile and app-state commit", async () => {
  const values = new Map<string, string>()
  const store = storeFor(values)
  const before = await store.bootstrap("Original")
  const oldRaw = values.get("identity")!
  let captured: IdentityAdoptionCommitPlan | undefined

  const renamed = await store.rename(" New name ", async (plan, ensureCurrent) => {
    ensureCurrent()
    captured = structuredClone(plan)
    expect((await store.bootstrap()).identity.displayName).toBe("Original")
    expect(values.get("identity")).toBe(oldRaw)
    values.set(plan.storageKey, plan.candidateProfile)
    values.set("application.personal-name", JSON.stringify({ displayName: "New name" }))
  })

  const persisted = JSON.parse(values.get("identity")!)
  expect(renamed.identity.displayName).toBe("New name")
  expect(renamed.device.displayName).toBe("New name's device")
  expect(renamed.privateKeys).toEqual(before.privateKeys)
  expect(persisted.identity.displayName).toBe("New name")
  expect(persisted.privateKeys.devicePrivateKeyPkcs8).toBeTruthy()
  expect(captured?.previousProfile).toBe(oldRaw)
  expect(captured?.backup).toBeUndefined()
  expect(captured?.publicProfile).toEqual({ identity: renamed.identity, device: renamed.device, certificate: renamed.certificate })
  expect(captured?.publicProfile).not.toHaveProperty("privateKeys")
  expect(JSON.parse(values.get("application.personal-name")!).displayName).toBe("New name")
})

it("Given a failed rename transaction, when atomic commit rejects, then keep old durable and cached profile", async () => {
  const values = new Map<string, string>()
  const store = storeFor(values)
  const original = await store.bootstrap("Original")
  const oldRaw = values.get("identity")!

  await expect(store.rename("Replacement", async () => { throw new Error("atomic rename failed") }))
    .rejects.toThrow("atomic rename failed")

  expect(values.get("identity")).toBe(oldRaw)
  expect((await store.bootstrap()).identity.displayName).toBe(original.identity.displayName)
  store.clearMemory()
  expect((await store.bootstrap()).identity.displayName).toBe(original.identity.displayName)
})

it("Given another tab replaces durable identity during rename, when the stale tab prepares a commit, then reject without overwriting it", async () => {
  const values = new Map<string, string>()
  const left = storeFor(values)
  const right = storeFor(values)
  await left.bootstrap("Original")
  await right.bootstrap()
  await right.rename("Changed elsewhere")
  const latestRaw = values.get("identity")!
  let commits = 0

  await expect(left.rename("Stale update", async () => { commits++ })).rejects.toThrow(/durable identity changed/i)

  expect(commits).toBe(0)
  expect(values.get("identity")).toBe(latestRaw)
  expect((await left.bootstrap()).identity.displayName).toBe("Changed elsewhere")
})

it("Given the active profile changes during async commit preparation, when rename resumes, then reject without publishing stale state", async () => {
  const values = new Map<string, string>()
  const store = storeFor(values)
  const active = await store.bootstrap("Original")
  const oldRaw = values.get("identity")!
  let commits = 0
  const rename = store.rename("Requested name", async (_plan, ensureCurrent) => {
    await Promise.resolve()
    active.identity.displayName = "Concurrent mutation"
    ensureCurrent()
    commits++
  })

  await expect(rename).rejects.toThrow(/identity changed/i)
  expect(commits).toBe(0)
  expect(values.get("identity")).toBe(oldRaw)
})
