import { expect, it } from "vitest"
import { BrowserIdentityStore, signEnvelope, verifyEnvelope, verifyDeviceCertificateChain } from "./index"

function fixture() {
  const values = new Map<string, string>()
  let fail = false
  const storage = { getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { if (fail) throw new Error("Storage failed"); values.set(key, value) },
    removeItem: (key: string) => { values.delete(key) } }
  return { store: new BrowserIdentityStore({ storageKey: "identity", storage }), values, fail: () => { fail = true } }
}

it("Given a root identity, when renewing its device, then person and old signatures survive and the new device persists", async () => {
  const { store, values } = fixture()
  const old = await store.bootstrap("Member")
  const signed = await signEnvelope(old.privateKeys.devicePrivateKey, { kind: "test" }, old.device.deviceId)
  const renewed = await store.renewDevice()
  expect(renewed.identity).toEqual(old.identity)
  expect(renewed.device.deviceId).not.toBe(old.device.deviceId)
  await expect(verifyDeviceCertificateChain(renewed.identity, renewed.device.deviceId, [renewed.certificate])).resolves.toBe(renewed.device.publicKey)
  await expect(verifyEnvelope(signed, old.device.publicKey)).resolves.toBe(true)
  expect(values.has(`identity.backup.device.${old.device.deviceId}`)).toBe(true)
  store.clearMemory()
  expect((await store.bootstrap()).device.deviceId).toBe(renewed.device.deviceId)
})

it("Given failed persistence, when renewing, then the previous device remains current", async () => {
  const { store, fail } = fixture()
  const old = await store.bootstrap()
  fail()
  await expect(store.renewDevice()).rejects.toThrow("Storage failed")
  expect((await store.bootstrap()).device.deviceId).toBe(old.device.deviceId)
  store.clearMemory()
  expect((await store.bootstrap()).device.deviceId).toBe(old.device.deviceId)
})

it("Given an enrolled device without the root key, when renewing, then enrollment is required and identity stays intact", async () => {
  const { store } = fixture()
  const old = await store.bootstrap()
  delete old.privateKeys.identityPrivateKey
  await expect(store.renewDevice()).rejects.toThrow("Add your device")
  expect((await store.bootstrap()).device.deviceId).toBe(old.device.deviceId)
})
