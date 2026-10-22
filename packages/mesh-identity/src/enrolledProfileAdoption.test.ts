import { expect, it } from "vitest"
import { BrowserIdentityStore, signEnvelope, type LocalProfile } from "./index"

it("Given an approved identity device profile, when adopted, then persist that exact device key without importing a root key", async () => {
  const values = new Map<string, string>()
  const store = new BrowserIdentityStore({ storageKey: "identity", asyncStorage: {
    getItem: async key => values.get(key) ?? null,
    setItem: async (key, value) => { values.set(key, value) },
    removeItem: async key => { values.delete(key) },
  } })
  const temporary = await store.bootstrap("Temporary")
  const issuerStore = new BrowserIdentityStore({ storageKey: "issuer" })
  const issuer = await issuerStore.bootstrap("Identity")
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
  const publicKey = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")
  const { publicKeyId } = await import("./index")
  const deviceId = await publicKeyId(publicKey)
  const certificate = await signEnvelope(issuer.privateKeys.identityPrivateKey!, {
    kind: "device-certificate" as const, version: 1 as const, personId: issuer.identity.personId,
    deviceId, devicePublicKey: publicKey, issuerCertificateHash: null, canEnrollDevices: true,
  }, issuer.identity.personId)
  const approved: LocalProfile = {
    identity: issuer.identity,
    device: { deviceId, publicKey, displayName: "Identity device" },
    certificate,
    privateKeys: { devicePrivateKey: keys.privateKey },
  }

  const adopted = await store.adoptEnrolledDevice(approved, [certificate], { consentToReplaceExistingIdentity: true })
  expect(adopted.device.deviceId).toBe(deviceId)
  expect(adopted.privateKeys.devicePrivateKey).toBe(keys.privateKey)
  expect(adopted.privateKeys.identityPrivateKey).toBeUndefined()
  expect(JSON.parse(values.get("identity")!).device.deviceId).toBe(deviceId)
  expect(JSON.parse(values.get("identity")!).privateKeys.identityPrivateKeyPkcs8).toBeUndefined()
  expect(values.has(`identity.backup.${temporary.identity.personId}`)).toBe(true)
})

it("Given no explicit replacement consent, when an enrolled profile would replace local identity, then preserve old durable bytes", async () => {
  const values = new Map<string, string>()
  const store = new BrowserIdentityStore({ storageKey: "identity", asyncStorage: {
    getItem: async key => values.get(key) ?? null,
    setItem: async (key, value) => { values.set(key, value) },
    removeItem: async key => { values.delete(key) },
  } })
  const temporary = await store.bootstrap("Temporary")
  const previous = values.get("identity")!
  const other = await new BrowserIdentityStore({ storageKey: "issuer" }).bootstrap("Identity")
  const guestProfile = { ...other, privateKeys: { devicePrivateKey: other.privateKeys.devicePrivateKey } }
  await expect(store.adoptEnrolledDevice(guestProfile, [other.certificate],
    { consentToReplaceExistingIdentity: false } as unknown as { consentToReplaceExistingIdentity: true }))
    .rejects.toThrow(/explicit consent/i)
  expect(values.get("identity")).toBe(previous)
  expect((await store.bootstrap()).identity.personId).toBe(temporary.identity.personId)
})


it("Given a fresh browser, when it adopts an approved device, then persist that key without creating or backing up a temporary identity", async () => {
  const values = new Map<string, string>()
  const store = new BrowserIdentityStore({ storageKey: "identity", asyncStorage: {
    getItem: async key => values.get(key) ?? null,
    setItem: async (key, value) => { values.set(key, value) },
    removeItem: async key => { values.delete(key) },
  } })
  const issuer = await new BrowserIdentityStore({ storageKey: "issuer" }).bootstrap("Identity")
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
  const publicKey = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")
  const { publicKeyId } = await import("./index")
  const deviceId = await publicKeyId(publicKey)
  const certificate = await signEnvelope(issuer.privateKeys.identityPrivateKey!, {
    kind: "device-certificate" as const, version: 1 as const, personId: issuer.identity.personId,
    deviceId, devicePublicKey: publicKey, issuerCertificateHash: null, canEnrollDevices: true,
  }, issuer.identity.personId)
  const approved: LocalProfile = { identity: issuer.identity,
    device: { deviceId, publicKey, displayName: "Identity device" }, certificate,
    privateKeys: { devicePrivateKey: keys.privateKey } }

  const adopted = await store.adoptEnrolledDevice(approved, [certificate], { consentToReplaceExistingIdentity: true })
  expect(adopted.identity.personId).toBe(issuer.identity.personId)
  expect(adopted.device.deviceId).toBe(deviceId)
  expect(adopted.privateKeys.identityPrivateKey).toBeUndefined()
  expect(values.size).toBe(1)
  expect([...values.keys()]).toEqual(["identity"])
})
