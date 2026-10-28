import { expect, it } from "vitest"
import { BrowserIdentityStore, certificateHash, createDelegatedCertificate, createDeviceRevocation,
  createIdentityEnrollmentDevice, createIdentityProfileOperation, emptyIdentityProfileState,
  filterIdentityProfileRevocations, readIdentityProfileStateWithRevocations, signEnvelope,
  verifyIdentityDeviceAuthority } from "./index"

async function ownerFixture() {
  const values = new Map<string, string>()
  return new BrowserIdentityStore({ storageKey: "cutoff-owner", storage: {
    getItem: key => values.get(key) ?? null, setItem: (key, value) => { values.set(key, value) },
    removeItem: key => { values.delete(key) },
  } }).bootstrap("Owner")
}

it("Given an accepted profile prefix and later revoked edits with dependent operations, when the strict reader applies its signed cutoff, then retain only the accepted prefix", async () => {
  const owner = await ownerFixture(), device = await createIdentityEnrollmentDevice("Removed manager")
  const certificate = await createDelegatedCertificate(owner.privateKeys.devicePrivateKey, owner.device.deviceId,
    owner.identity.personId, device.device.deviceId, device.device.publicKey, await certificateHash(owner.certificate))
  const remote = { identity: owner.identity, device: device.device, certificate,
    privateKeys: { devicePrivateKey: device.privateKey } }
  const certificates = [owner.certificate, certificate], initial = emptyIdentityProfileState(owner.identity.personId)
  const accepted = await createIdentityProfileOperation(remote, initial, "name", "Accepted name", certificates)
  const prefix = { ...initial, operations: [accepted] }
  const excluded = await createIdentityProfileOperation(remote, prefix, "name", "Unseen name", certificates)
  const offline = { ...prefix, operations: [accepted, excluded] }
  const dependent = await createIdentityProfileOperation(owner, offline, "name", "Depends on unseen edit", certificates)
  const authority = await verifyIdentityDeviceAuthority(owner.identity, { certificates, revocations: [] })
  const revocation = await createDeviceRevocation(owner, authority, device.device.deviceId, prefix)

  expect(await readIdentityProfileStateWithRevocations({ ...offline, operations: [...offline.operations, dependent] },
    owner.identity, certificates, [revocation])).toEqual(prefix)
})

it("Given an app-only signed presentation candidate, when cutoff filtering completes, then strict Identity validation still refuses manager authority", async () => {
  const owner = await ownerFixture(), device = await createIdentityEnrollmentDevice("App presentation")
  const certificate = await signEnvelope(owner.privateKeys.identityPrivateKey!, { kind: "device-certificate" as const,
    version: 1 as const, personId: owner.identity.personId, deviceId: device.device.deviceId,
    devicePublicKey: device.device.publicKey, issuerCertificateHash: null, canEnrollDevices: false }, owner.identity.personId)
  const certificates = [owner.certificate, certificate]
  const signed = await signEnvelope(device.privateKey, { kind: "identity-profile-update" as const, version: 1 as const,
    personId: owner.identity.personId, deviceId: device.device.deviceId, counter: 1, context: {}, field: "name" as const,
    value: "Application name", supersedesLegacy: [] }, device.device.deviceId)
  const state = { ...emptyIdentityProfileState(owner.identity.personId), operations: [{ signed, certificates: [certificate] }] }

  expect(await filterIdentityProfileRevocations(state, owner.identity, certificates, [])).toEqual(state)
  await expect(readIdentityProfileStateWithRevocations(state, owner.identity, certificates, []))
    .rejects.toThrow(/identity management/i)
  expect(certificate.payload.canEnrollDevices).toBe(false)
})
