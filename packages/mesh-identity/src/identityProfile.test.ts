import { describe, expect, it } from "vitest"
import { createRecoverableIdentity, openIdentityRecoveryEnvelope } from "./index"
import { createIdentityProfileOperation, emptyIdentityProfileState, identityProfileValue,
  mergeIdentityProfileState, readIdentityProfileState } from "./identityProfile"

describe("portable Identity profile causality", () => {
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
