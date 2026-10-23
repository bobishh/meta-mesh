import { describe, expect, it } from "vitest"
import { createRecoverableIdentity, createIdentityAuthorityView, verifyIdentityAuthorityView,
  mergeIdentityAuthorityViews, authorizeIdentityDataDevice, authorizeIdentityDevice, verifyIdentityDeviceAuthority, signEnvelope,
  type DeviceCertificate } from "./index"
import { createIdentityEnrollmentDevice } from "./identityEnrollment"
import { emptyIdentityProfileState } from "./identityProfile"

describe("portable Identity authority view", () => {
  it("Given a delegated app certificate, when authority view is created and verified, then data access is allowed without management authority", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const app = await createIdentityEnrollmentDevice("App key")
    const appCertificate = await signEnvelope(owner.privateKeys.identityPrivateKey!, {
      kind: "device-certificate" as const, version: 1 as const, personId: owner.identity.personId,
      deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey, issuerCertificateHash: null,
      canEnrollDevices: false,
    }, owner.identity.personId)
    const certificates: DeviceCertificate[] = [owner.certificate, appCertificate]
    const first = await createIdentityAuthorityView(owner.identity, { certificates, revocations: [] },
      emptyIdentityProfileState(owner.identity.personId))
    const verified = await verifyIdentityAuthorityView(JSON.parse(JSON.stringify(first)))

    await expect(authorizeIdentityDataDevice(verified, app.device.deviceId)).resolves.toBe(app.device.publicKey)
    const deviceAuthority = await verifyIdentityDeviceAuthority(owner.identity,
      { certificates, revocations: [] })
    await expect(authorizeIdentityDevice(deviceAuthority, app.device.deviceId)).rejects.toThrow(/management authority/i)
  })

  it("Given a verified view, when a new certificate is enrolled without revocation, then digest advances while revocation head stays fixed", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const profileState = emptyIdentityProfileState(owner.identity.personId)
    const base = await createIdentityAuthorityView(owner.identity,
      { certificates: [owner.certificate], revocations: [] }, profileState)
    const app = await createIdentityEnrollmentDevice("App key")
    const appCertificate = await signEnvelope(owner.privateKeys.identityPrivateKey!, {
      kind: "device-certificate" as const, version: 1 as const, personId: owner.identity.personId,
      deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey, issuerCertificateHash: null,
      canEnrollDevices: false,
    }, owner.identity.personId)
    const expanded = await createIdentityAuthorityView(owner.identity,
      { certificates: [owner.certificate, appCertificate], revocations: [] }, profileState)

    expect(expanded.revocationHead).toEqual(base.revocationHead)
    expect(expanded.viewDigest).not.toBe(base.viewDigest)
    await expect(mergeIdentityAuthorityViews(base, expanded)).resolves.toMatchObject({
      revocationHead: base.revocationHead,
      certificates: expect.arrayContaining([appCertificate]),
    })
  })

  it("Given a known newer revocation head, when an older view or same-revision fork is merged, then reject it", async () => {
    const recovery = await createRecoverableIdentity("better", "Owner")
    const owner = recovery.profile
    const removed = await (await import("./index")).openIdentityRecoveryEnvelope(
      recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
    const certificates = [owner.certificate, removed.certificate]
    const state = emptyIdentityProfileState(owner.identity.personId)
    const base = await createIdentityAuthorityView(owner.identity, { certificates, revocations: [] }, state)
    const record = await (await import("./index")).createDeviceRevocation(owner,
      await (await import("./index")).verifyIdentityDeviceAuthority(owner.identity,
        { certificates, revocations: [] }), removed.device.deviceId, state)
    const current = await createIdentityAuthorityView(owner.identity, { certificates, revocations: [record] }, state)

    await expect(mergeIdentityAuthorityViews(current, base)).rejects.toThrow(/stale|prefix/i)
    const fork = { ...current, revocationHead: { ...current.revocationHead, recordHash: "A".repeat(43) } }
    await expect(verifyIdentityAuthorityView(fork)).rejects.toThrow(/head|digest/i)
  })
})
