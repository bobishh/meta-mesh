import { describe, expect, it } from "vitest"
import { createRecoverableIdentity, openIdentityRecoveryEnvelope, publicKeyId, signEnvelope } from "./index"
import { createIdentityProfileOperation, createIdentityRustyServicePinOperation, emptyIdentityProfileState, identityProfileValue,
  identityProfileRustyServicePins, mergeIdentityProfileState, readIdentityProfileState } from "./identityProfile"

describe("portable Identity profile causality", () => {
  it("Given an approved Rusty pin operation, when profile replicas merge, then retain the normalized service catalog", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const servicePublicKey = owner.device.publicKey
    const pin = { origin: "https://rusty.example", serviceId: await publicKeyId(servicePublicKey), servicePublicKey }
    const signed = await signEnvelope(owner.privateKeys.devicePrivateKey, { kind: "identity-profile-update", version: 1,
      personId: owner.identity.personId, deviceId: owner.device.deviceId, counter: 1, context: {},
      field: "rustyServicePin", value: pin, supersedesLegacy: [] }, owner.device.deviceId, "MATCH/1")
    const operation = { signed, certificates: [owner.certificate] }
    const state = await readIdentityProfileState({ version: 1, personId: owner.identity.personId,
      operations: [operation], legacy: [] }, owner.identity, [owner.certificate])
    const merged = await mergeIdentityProfileState(state, state, owner.identity, [owner.certificate])
    expect(identityProfileRustyServicePins(merged)).toEqual([pin])
  })

  it("Given conflicting service keys for one origin, when the signed catalog is projected, then fail closed", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const first = { origin: "https://rusty.example", serviceId: await publicKeyId(owner.device.publicKey),
      servicePublicKey: owner.device.publicKey }
    const second = { origin: "https://rusty.example", serviceId: await publicKeyId(owner.identity.publicKey),
      servicePublicKey: owner.identity.publicKey }
    const firstOperation = await createIdentityProfileOperation(owner, emptyIdentityProfileState(owner.identity.personId),
      "rustyServicePin", first, [owner.certificate])
    const secondOperation = { signed: await signEnvelope(owner.privateKeys.devicePrivateKey, { kind: "identity-profile-update", version: 1,
      personId: owner.identity.personId, deviceId: owner.device.deviceId, counter: 2, context: { [owner.device.deviceId]: 1 },
      field: "rustyServicePin", value: second, supersedesLegacy: [] }, owner.device.deviceId, "MATCH/1"),
      certificates: [owner.certificate] }
    await expect(readIdentityProfileState({ version: 1, personId: owner.identity.personId,
      operations: [firstOperation, secondOperation], legacy: [] }, owner.identity, [owner.certificate]))
      .rejects.toThrow(/conflicting.*service|origin.*conflict/i)
  })

  it("Given two replicas with concurrent edits, when merged, then retain conflict until explicit resolution", async () => {
    const recovered = await createRecoverableIdentity("better", "Owner")
    const owner = recovered.profile
    const secondDevice = await openIdentityRecoveryEnvelope(recovered.recoveryEnvelope, recovered.recoveryKey, "Owner")
    const base = emptyIdentityProfileState(owner.identity.personId)
    const left = await createIdentityProfileOperation(owner, base, "name", "Left name")
    const right = await createIdentityProfileOperation(secondDevice, base, "name", "Right name")
    const merged = await mergeIdentityProfileState(
      { ...base, operations: [left] }, { ...base, operations: [right] }, owner.identity,
      [owner.certificate, secondDevice.certificate])

    expect(identityProfileValue(merged, "name")).toEqual({ status: "conflict", values: ["Left name", "Right name"] })
    const resolution = await createIdentityProfileOperation(owner, merged, "name", "Chosen name", [owner.certificate])
    const resolved = await readIdentityProfileState({ ...merged, operations: [...merged.operations, resolution] },
      owner.identity, [owner.certificate])
    expect(identityProfileValue(resolved, "name")).toEqual({ status: "value", values: ["Chosen name"] })
  })

  it("Given an application-only device certificate, when it edits identity profile, then reject without identity management authority", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const appDevice = (await createRecoverableIdentity("better", "App device")).profile
    const appCertificate = { ...appDevice.certificate, payload: { ...appDevice.certificate.payload,
      personId: owner.identity.personId, issuerCertificateHash: null, canEnrollDevices: false } }
    const state = emptyIdentityProfileState(owner.identity.personId)
    await expect(createIdentityProfileOperation({ ...appDevice,
      identity: owner.identity, certificate: appCertificate }, state, "name", "Forged", [appCertificate]))
      .rejects.toThrow(/identity management/i)
  })

  it("Given an app-only device key, when it tries to register a Rusty service pin, then reject without manager authority", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const app = (await createRecoverableIdentity("better", "App device")).profile
    const appCertificate = await signEnvelope(owner.privateKeys.identityPrivateKey!, {
      kind: "device-certificate" as const, version: 1 as const, personId: owner.identity.personId,
      deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey, issuerCertificateHash: null,
      canEnrollDevices: false,
    }, owner.identity.personId)
    const appProfile = { ...app, identity: owner.identity, certificate: appCertificate,
      privateKeys: { devicePrivateKey: app.privateKeys.devicePrivateKey } }
    const pin = { origin: "https://rusty.example", serviceId: await publicKeyId(app.device.publicKey),
      servicePublicKey: app.device.publicKey }
    await expect(createIdentityRustyServicePinOperation(appProfile, emptyIdentityProfileState(owner.identity.personId),
      pin, [owner.certificate, appCertificate])).rejects.toThrow(/identity management/i)
  })

  it("Given altered causal evidence, when a replica validates the profile, then reject it", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const first = await createIdentityProfileOperation(owner, emptyIdentityProfileState(owner.identity.personId), "name", "One")
    const second = await createIdentityProfileOperation(owner, { version: 1, personId: owner.identity.personId,
      operations: [first], legacy: [] }, "name", "Two", [owner.certificate])
    await expect(readIdentityProfileState({ version: 1, personId: owner.identity.personId,
      operations: [{ ...second, signed: { ...second.signed,
        payload: { ...second.signed.payload, context: {} } } }], legacy: [] }, owner.identity, [owner.certificate]))
      .rejects.toThrow(/causal|revision|signature/i)
  })
})
