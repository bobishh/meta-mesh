import { expect, it, vi } from "vitest"
import { BrowserIdentityStore, signEnvelope, verifyDeviceCertificateChain, type IdentityAdoptionCommitPlan } from "./index"

function storeFor(values: Map<string, string>) {
  return new BrowserIdentityStore({ storageKey: "identity", asyncStorage: {
    getItem: async key => values.get(key) ?? null,
    setItem: async (key, value) => { values.set(key, value) },
    removeItem: async key => { values.delete(key) },
  } })
}

async function recoverable() {
  const values = new Map<string, string>()
  const store = storeFor(values)
  const created = await store.createRecoverable("better", "Recovered")
  return { values, store, created }
}

it("Given an enrolled device for the recovered identity, when restoring its recovery envelope, then import the root key and preserve its active device", async () => {
  const recovery = await recoverable()
  const targetValues = new Map<string, string>()
  const target = storeFor(targetValues)
  const guest = await target.bootstrap("Guest")
  const certificate = await signEnvelope(recovery.created.profile.privateKeys.identityPrivateKey!, {
    kind: "device-certificate" as const, version: 1 as const, personId: recovery.created.profile.identity.personId,
    deviceId: guest.device.deviceId, devicePublicKey: guest.device.publicKey,
    issuerCertificateHash: null, canEnrollDevices: true as const,
  }, recovery.created.profile.identity.personId)
  await target.adopt(recovery.created.profile.identity, certificate)
  const enrolled = await target.bootstrap()
  expect(enrolled.privateKeys.identityPrivateKey).toBeUndefined()

  const restored = await target.restoreEnvelope(recovery.created.recoveryEnvelope, recovery.created.recoveryKey, "Ignored")

  expect(restored.identity).toEqual(enrolled.identity)
  expect(restored.device).toEqual(enrolled.device)
  expect(restored.certificate).toEqual(enrolled.certificate)
  expect(restored.privateKeys.devicePrivateKey).toBe(enrolled.privateKeys.devicePrivateKey)
  expect(restored.privateKeys.identityPrivateKey).toBeDefined()
  expect(JSON.parse(targetValues.get("identity")!).privateKeys.identityPrivateKeyPkcs8).toBeDefined()
})

it("Given same-person recovery, when the recovered root key is already present, then keep the exact active device keys and certificate", async () => {
  const recovery = await recoverable()
  const active = await recovery.store.bootstrap()
  const restored = await recovery.store.restoreEnvelope(recovery.created.recoveryEnvelope, recovery.created.recoveryKey, "Changed")

  expect(restored).toBe(active)
  expect(restored.device).toEqual(active.device)
  expect(restored.certificate).toEqual(active.certificate)
  expect(restored.privateKeys.devicePrivateKey).toBe(active.privateKeys.devicePrivateKey)
  expect(restored.privateKeys.identityPrivateKey).toBe(active.privateKeys.identityPrivateKey)
})

it("Given a rejected recovery commit, when replacing identity, then retain the current profile and durable bytes", async () => {
  const recovery = await recoverable()
  const targetValues = new Map<string, string>()
  const target = storeFor(targetValues)
  const active = await target.bootstrap("Current")
  const previous = targetValues.get("identity")!

  await expect(target.restoreEnvelope(recovery.created.recoveryEnvelope, recovery.created.recoveryKey, "Recovered",
    async () => { throw new Error("activation transaction failed") })).rejects.toThrow("activation transaction failed")

  expect(await target.bootstrap()).toBe(active)
  expect(targetValues.get("identity")).toBe(previous)
  expect(targetValues.has(`identity.backup.${active.identity.personId}`)).toBe(false)
})

it("Given identity replacement, when restore commits, then include the old profile backup and recovered device profile in one plan", async () => {
  const recovery = await recoverable()
  const targetValues = new Map<string, string>()
  const target = storeFor(targetValues)
  const active = await target.bootstrap("Current")
  const previous = targetValues.get("identity")!
  let captured: IdentityAdoptionCommitPlan | undefined

  const restored = await target.restoreEnvelope(recovery.created.recoveryEnvelope, recovery.created.recoveryKey, "Recovered",
    async plan => {
      captured = structuredClone(plan)
      if (plan.backup) targetValues.set(plan.backup.key, plan.backup.value)
      targetValues.set(plan.storageKey, plan.candidateProfile)
    })

  expect(captured?.previousProfile).toBe(previous)
  expect(captured?.backup).toEqual({ key: `identity.backup.${active.identity.personId}`, value: previous })
  expect(captured?.publicProfile).toEqual({ identity: restored.identity, device: restored.device, certificate: restored.certificate })
  expect(JSON.parse(captured!.candidateProfile).identity.personId).toBe(recovery.created.profile.identity.personId)
  expect(restored.device.deviceId).not.toBe(active.device.deviceId)
  expect(restored.privateKeys.identityPrivateKey).toBeDefined()
  await expect(verifyDeviceCertificateChain(restored.identity, restored.device.deviceId, [restored.certificate]))
    .resolves.toBe(restored.device.publicKey)
  expect(targetValues.get(captured!.backup!.key)).toBe(previous)
  expect((await target.bootstrap()).identity.personId).toBe(recovery.created.profile.identity.personId)
})

it("Given active identity metadata changes during envelope decryption, when restore continues, then reject before committing", async () => {
  const recovery = await recoverable()
  const values = new Map<string, string>()
  const store = storeFor(values)
  const active = await store.bootstrap("Current")
  let release!: () => void
  let started!: () => void
  const gate = new Promise<void>(resolve => { release = resolve })
  const entered = new Promise<void>(resolve => { started = resolve })
  const decrypt = crypto.subtle.decrypt.bind(crypto.subtle)
  const decryptSpy = vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => {
    started()
    await gate
    return decrypt(...args)
  })
  let commits = 0
  const restoring = store.restoreEnvelope(recovery.created.recoveryEnvelope, recovery.created.recoveryKey, "Recovered",
    async () => { commits++ })
  await entered
  active.identity.displayName = "Changed while decrypting"
  release()

  await expect(restoring).rejects.toThrow("Identity changed during recovery")
  expect(commits).toBe(0)
  expect(values.get("identity")).toBeDefined()
  decryptSpy.mockRestore()
})
