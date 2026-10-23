import { expect, it } from "vitest"
import { BrowserIdentityStore, createIdentityAuthorityView, createRecoverableIdentity,
  emptyIdentityProfileState, type LocalProfile } from "./index"
import { createIdentityRootReplacementOffer, createIdentityRootReplacementRequest } from "./identityRootReplacement"

async function fixture(previous?: LocalProfile) {
  previous ??= (await createRecoverableIdentity("better", "Previous", new Uint8Array(32).fill(51))).profile
  const previousProfileState = emptyIdentityProfileState(previous.identity.personId)
  const previousAuthority = await createIdentityAuthorityView(previous.identity,
    { certificates: [previous.certificate], revocations: [] }, previousProfileState)
  const freshApp = (await createRecoverableIdentity("better", "Fresh app", new Uint8Array(32).fill(53))).profile
  const request = await createIdentityRootReplacementRequest({ identity: previous.identity, device: previous.device,
    privateKeys: { devicePrivateKey: previous.privateKeys.devicePrivateKey } }, {
    successorDevice: { deviceId: freshApp.device.deviceId, publicKey: freshApp.device.publicKey,
      privateKey: freshApp.privateKeys.devicePrivateKey },
    applicationOrigin: "https://boards.example", challenge: "e".repeat(64), expiresAt: Date.now() + 60_000,
    rustyServicePins: [] })
  const successor = (await createRecoverableIdentity("better", "Successor", new Uint8Array(32).fill(54))).profile
  const offer = await createIdentityRootReplacementOffer(previous, successor, request, previousAuthority,
    previousProfileState, { consentedRustyServicePins: [] })
  const candidate: LocalProfile = { identity: offer.successorIdentity,
    device: { deviceId: freshApp.device.deviceId, publicKey: freshApp.device.publicKey, displayName: "Fresh app" },
    certificate: offer.certificate, privateKeys: { devicePrivateKey: freshApp.privateKeys.devicePrivateKey } }
  return { previous, successor, offer, candidate }
}

it("Given a verified root-replacement offer, when adopted, then persist fresh app-only key and back up the old identity without moving root keys", async () => {
  const values = new Map<string, string>()
  const existingStore = new BrowserIdentityStore({ storageKey: "current", asyncStorage: {
    getItem: async key => values.get(key) ?? null,
    setItem: async (key, value) => { values.set(key, value) },
    removeItem: async key => { values.delete(key) },
  } })
  await existingStore.createRecoverable("better", "Previous")
  const f = await fixture(await existingStore.bootstrap())
  const adopted = await existingStore.adoptRootReplacementDevice(f.candidate, f.offer,
    { consentToReplaceExistingIdentity: true })
  expect(adopted.identity.personId).toBe(f.offer.successorIdentity.personId)
  expect(adopted.device.deviceId).toBe(f.candidate.device.deviceId)
  expect(adopted.certificate.payload.canEnrollDevices).toBe(false)
  expect(adopted.privateKeys.identityPrivateKey).toBeUndefined()
  expect(JSON.parse(values.get("current")!).privateKeys.identityPrivateKeyPkcs8).toBeUndefined()
  expect(values.has(`current.backup.${f.previous.identity.personId}`)).toBe(true)
})

it("rejects a root-replacement candidate with an Identity root private key", async () => {
  const f = await fixture()
  const store = new BrowserIdentityStore({ storageKey: "identity" })
  const candidate = { ...f.candidate, privateKeys: { ...f.candidate.privateKeys,
    identityPrivateKey: f.offer.acceptance ? f.previous.privateKeys.identityPrivateKey : undefined } }
  await expect(store.adoptRootReplacementDevice(candidate, f.offer,
    { consentToReplaceExistingIdentity: true })).rejects.toThrow(/root key/i)
})

it("activates the recovery-authorized successor root with an atomic backup of the old profile", async () => {
  const values = new Map<string, string>()
  const store = new BrowserIdentityStore({ storageKey: "portal", asyncStorage: {
    getItem: async key => values.get(key) ?? null,
    setItem: async (key, value) => { values.set(key, value) },
    removeItem: async key => { values.delete(key) },
  } })
  await store.createRecoverable("better", "Previous")
  const f = await fixture(await store.bootstrap())
  const activated = await store.activateRootReplacementIdentity(f.successor, f.offer,
    { consentToReplaceExistingIdentity: true })
  expect(activated.identity.personId).toBe(f.successor.identity.personId)
  expect(activated.privateKeys.identityPrivateKey).toBe(f.successor.privateKeys.identityPrivateKey)
  expect(JSON.parse(values.get("portal")!).identity.personId).toBe(f.successor.identity.personId)
  expect(values.has(`portal.backup.${f.previous.identity.personId}`)).toBe(true)
})
