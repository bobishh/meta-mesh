import { expect, it } from "vitest"
import { BrowserIdentityStore, signEnvelope, type DeviceCertificate, type IdentityAdoptionCommitPlan } from "./index"

function storeFor(values: Map<string, string>, getItem: (key: string) => Promise<string | null> = async key => values.get(key) ?? null) {
  return new BrowserIdentityStore({ storageKey: "identity", asyncStorage: {
    getItem,
    setItem: async (key, value) => { values.set(key, value) },
    removeItem: async key => { values.delete(key) },
  } })
}

async function validAdoptionTarget() {
  const guestValues = new Map<string, string>()
  const guestStore = storeFor(guestValues)
  const guest = await guestStore.bootstrap("Guest")
  const ownerStore = storeFor(new Map())
  const owner = await ownerStore.bootstrap("Owner")
  const certificate: DeviceCertificate = await signEnvelope(owner.privateKeys.identityPrivateKey!, {
    kind: "device-certificate", version: 1, personId: owner.identity.personId, deviceId: guest.device.deviceId,
    devicePublicKey: guest.device.publicKey, issuerCertificateHash: null, canEnrollDevices: true,
  }, owner.identity.personId)
  return { guestStore, guestValues, guest, owner, certificate }
}

it("Given an adoption commit failure, when candidate persistence rejects, then old identity stays active and reopens", async () => {
  const { guestStore, guestValues, guest, owner, certificate } = await validAdoptionTarget()
  const oldRaw = guestValues.get("identity")!
  const store = storeFor(guestValues)
  await store.bootstrap()

  await expect(store.adopt(owner.identity, certificate, async () => { throw new Error("atomic commit failed") })).rejects.toThrow("atomic commit failed")

  expect((await store.bootstrap()).identity.personId).toBe(guest.identity.personId)
  expect(guestValues.get("identity")).toBe(oldRaw)
  expect(guestValues.has(`identity.backup.${guest.identity.personId}`)).toBe(false)
  store.clearMemory()
  expect((await store.bootstrap()).identity.personId).toBe(guest.identity.personId)
  expect(guestStore).toBeDefined()
})

it("Given another tab replaces durable identity while this tab remains cached, when adoption starts, then reject before committing and reopen the current identity", async () => {
  const { guestValues, owner, certificate } = await validAdoptionTarget()
  const left = storeFor(guestValues)
  const right = storeFor(guestValues)
  await left.bootstrap()
  await right.bootstrap()
  await right.adopt(owner.identity, certificate)
  let commits = 0
  await expect(left.adopt(owner.identity, certificate, async () => { commits++ })).rejects.toThrow(/durable identity changed/i)
  expect(commits).toBe(0)
  expect((await left.bootstrap()).identity.personId).toBe(owner.identity.personId)
})

it("Given the active key map changes while adoption reads wait, when preparing its transaction, then reject before publishing a mismatched device key", async () => {
  const { guestValues, owner, certificate } = await validAdoptionTarget()
  let release!: () => void
  let entered!: () => void
  let pause = false
  const gate = new Promise<void>(resolve => { release = resolve })
  const reading = new Promise<void>(resolve => { entered = resolve })
  const store = storeFor(guestValues, async key => {
    if (pause) { entered(); await gate }
    return guestValues.get(key) ?? null
  })
  const active = await store.bootstrap()
  pause = true
  let commits = 0
  const adoption = store.adopt(owner.identity, certificate, async () => { commits++ })
  await reading
  active.privateKeys.devicePrivateKey = owner.privateKeys.devicePrivateKey
  release()
  await expect(adoption).rejects.toThrow(/identity changed/i)
  expect(commits).toBe(0)
})

it("Given a successful commit callback, when adopting, then receive detached profile and atomic profile, backup, and application writes", async () => {
  const { guest, guestValues, owner, certificate } = await validAdoptionTarget()
  const values = guestValues
  const store = storeFor(values)
  await store.bootstrap("Guest")
  const oldRaw = values.get("identity")!
  let captured: IdentityAdoptionCommitPlan | undefined

  const adopted = await store.adopt(owner.identity, certificate, async (plan, ensureCurrent) => {
    ensureCurrent()
    captured = structuredClone(plan)
    values.set(plan.backup!.key, plan.backup!.value)
    values.set(plan.storageKey, plan.candidateProfile)
    values.set("application.activation", JSON.stringify({ version: 1, personId: owner.identity.personId }))
  })

  expect(adopted.identity.personId).toBe(owner.identity.personId)
  expect(captured?.previousProfile).toBe(oldRaw)
  expect(values.get(captured!.backup!.key)).toBe(oldRaw)
  expect(JSON.parse(values.get("application.activation")!).personId).toBe(owner.identity.personId)
  expect(JSON.parse(values.get("identity")!).identity.personId).toBe(owner.identity.personId)
  expect(JSON.parse(values.get("identity")!).privateKeys.identityPrivateKeyPkcs8).toBeUndefined()
  expect(captured?.publicProfile).toEqual({ identity: owner.identity, device: guest.device, certificate })
  expect(captured?.publicProfile).not.toHaveProperty("privateKeys")
})

it("Given adoption inputs are mutated while local reads wait, when the callback receives a plan, then candidate uses invocation snapshots", async () => {
  const { guestValues, owner, certificate } = await validAdoptionTarget()
  const values = guestValues
  let release!: () => void
  let delayReads = false
  const gate = new Promise<void>(resolve => { release = resolve })
  const delayedStore = storeFor(values, async key => {
    if (delayReads) await gate
    return values.get(key) ?? null
  })
  await delayedStore.bootstrap("Guest")
  delayReads = true
  let candidatePersonId = ""
  let candidateCertificatePersonId = ""
  let candidateCertificateSignature = ""
  const adoption = delayedStore.adopt(owner.identity, certificate, async plan => {
    const candidate = JSON.parse(plan.candidateProfile)
    candidatePersonId = candidate.identity.personId
    candidateDisplayName = candidate.identity.displayName
    candidateCertificatePersonId = candidate.certificate.payload.personId
    candidateCertificateSignature = candidate.certificate.signature
  })
  let candidateDisplayName = ""
  const ownerPersonId = owner.identity.personId
  const originalCertificateSignature = certificate.signature
  owner.identity.displayName = "Mutated after call"
  ;(certificate.payload as DeviceCertificate["payload"]).personId = "forged-person"
  release()

  await adoption
  expect(candidatePersonId).toBe(ownerPersonId)
  expect(candidateDisplayName).toBe("Owner")
  expect(candidateCertificatePersonId).toBe(ownerPersonId)
  expect(candidateCertificateSignature).toBe(originalCertificateSignature)
})

it("Given the active identity changes during an async commit, when the callback resumes, then do not publish the stale candidate in memory", async () => {
  const { guest, guestValues, owner, certificate } = await validAdoptionTarget()
  const values = guestValues
  const store = storeFor(values)
  let release!: () => void
  const gate = new Promise<void>(resolve => { release = resolve })
  let started!: () => void
  const entered = new Promise<void>(resolve => { started = resolve })
  const adopting = store.adopt(owner.identity, certificate, async () => { started(); await gate })
  await entered
  const replacement = await store.bootstrap("Guest")
  // A second adoption changes cached authority while the first transaction is waiting.
  const secondOwnerValues = new Map<string, string>()
  const secondOwnerStore = storeFor(secondOwnerValues)
  const secondOwner = await secondOwnerStore.bootstrap("Second owner")
  const secondCertificate: DeviceCertificate = await signEnvelope(secondOwner.privateKeys.identityPrivateKey!, {
    kind: "device-certificate", version: 1, personId: secondOwner.identity.personId, deviceId: replacement.device.deviceId,
    devicePublicKey: replacement.device.publicKey, issuerCertificateHash: null, canEnrollDevices: true,
  }, secondOwner.identity.personId)
  await store.adopt(secondOwner.identity, secondCertificate)
  release()

  await expect(adopting).rejects.toThrow(/identity changed/i)
  expect((await store.bootstrap()).identity.personId).toBe(secondOwner.identity.personId)
  expect(guest.identity.personId).not.toBe(owner.identity.personId)
})
