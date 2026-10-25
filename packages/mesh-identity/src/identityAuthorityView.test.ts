import { describe, expect, it } from "vitest"
import { createRecoverableIdentity, createIdentityAuthorityView, createIdentityManagerAuthorityView, createLocalRootIdentityAuthorityView, verifyIdentityAuthorityView,
  mergeIdentityAuthorityViews, authorizeIdentityDataDevice, authorizeIdentityDevice, verifyIdentityDeviceAuthority, signEnvelope,
  createDeviceRevocation, type DeviceCertificate, type LocalProfile } from "./index"
import { createIdentityEnrollmentDevice } from "./identityEnrollment"
import { emptyIdentityProfileState } from "./identityProfile"

describe("portable Identity authority view", () => {
  it.each([true, false])("Given a rootless device with canEnrollDevices=%s, when building management authority, then enforce the certified role", async canEnrollDevices => {
    const root = (await createRecoverableIdentity("better", "Owner")).profile
    const device = await createIdentityEnrollmentDevice("Delegated device")
    const certificate = await signEnvelope(root.privateKeys.identityPrivateKey!, {
      kind: "device-certificate" as const, version: 1 as const, personId: root.identity.personId,
      deviceId: device.device.deviceId, devicePublicKey: device.device.publicKey,
      issuerCertificateHash: null, canEnrollDevices,
    }, root.identity.personId)
    const profile: LocalProfile = { identity: root.identity, device: device.device, certificate,
      privateKeys: { devicePrivateKey: device.privateKey } }
    const evidence = { certificates: [root.certificate, certificate], revocations: [] }
    const state = emptyIdentityProfileState(root.identity.personId)
    const result = createIdentityManagerAuthorityView(profile, evidence, state)
    if (canEnrollDevices) {
      await expect(result).resolves.toMatchObject({ personId: root.identity.personId })
      await expect(createLocalRootIdentityAuthorityView(profile, evidence, state)).rejects.toThrow(/root authority/i)
    } else await expect(result).rejects.toThrow(/management authority/i)
  })

  it("Given a revoked rootless manager, when building management authority, then reject its valid key", async () => {
    const root = (await createRecoverableIdentity("better", "Owner")).profile
    const device = await createIdentityEnrollmentDevice("Manager")
    const certificate = await signEnvelope(root.privateKeys.identityPrivateKey!, {
      kind: "device-certificate" as const, version: 1 as const, personId: root.identity.personId,
      deviceId: device.device.deviceId, devicePublicKey: device.device.publicKey,
      issuerCertificateHash: null, canEnrollDevices: true,
    }, root.identity.personId)
    const profile: LocalProfile = { identity: root.identity, device: device.device, certificate,
      privateKeys: { devicePrivateKey: device.privateKey } }
    const state = emptyIdentityProfileState(root.identity.personId)
    const certificates = [root.certificate, certificate]
    const authority = await verifyIdentityDeviceAuthority(root.identity, { certificates, revocations: [] })
    const revocation = await createDeviceRevocation(root, authority, profile.device.deviceId, state)
    await expect(createIdentityManagerAuthorityView(profile, { certificates, revocations: [revocation] }, state))
      .rejects.toThrow(/revoked/i)
  })

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

  it("Given mixed-case device IDs, when authority view is published, then use stable Rust bytewise certificate order", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const certificates: DeviceCertificate[] = [owner.certificate]
    for (let index = 0; index < 24; index += 1) {
      const device = await createIdentityEnrollmentDevice(`Device ${index}`)
      certificates.push(await signEnvelope(owner.privateKeys.identityPrivateKey!, {
        kind: "device-certificate", version: 1, personId: owner.identity.personId,
        deviceId: device.device.deviceId, devicePublicKey: device.device.publicKey,
        issuerCertificateHash: null, canEnrollDevices: false,
      }, owner.identity.personId))
    }
    const localeOrder = [...certificates].sort((left, right) => left.payload.deviceId.localeCompare(right.payload.deviceId))
    const bytewiseOrder = [...certificates].sort((left, right) => left.payload.deviceId < right.payload.deviceId ? -1 :
      left.payload.deviceId > right.payload.deviceId ? 1 : 0)
    const expected = bytewiseOrder.map(certificate => certificate.payload.deviceId)
    expect(localeOrder.map(certificate => certificate.payload.deviceId)).not.toEqual(expected)

    const state = emptyIdentityProfileState(owner.identity.personId)
    const view = await createIdentityAuthorityView(owner.identity, { certificates, revocations: [] }, state)
    const permuted = await createIdentityAuthorityView(owner.identity, { certificates: [...certificates].reverse(), revocations: [] }, state)
    expect(view.certificates.map(certificate => certificate.payload.deviceId)).toEqual(expected)
    expect(permuted).toEqual(view)
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

  it("Given a genuinely local root profile, when its first Rusty authority view is created, then allow genesis; adopted app profiles cannot create it", async () => {
    const root = (await createRecoverableIdentity("better", "Root owner")).profile
    await expect(createLocalRootIdentityAuthorityView(root,
      { certificates: [root.certificate], revocations: [] }, emptyIdentityProfileState(root.identity.personId)))
      .resolves.toMatchObject({ revocationHead: { revision: 0 } })

    const app = await createIdentityEnrollmentDevice("App")
    const appCertificate = await signEnvelope(root.privateKeys.identityPrivateKey!, {
      kind: "device-certificate" as const, version: 1 as const, personId: root.identity.personId,
      deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey, issuerCertificateHash: null,
      canEnrollDevices: false,
    }, root.identity.personId)
    const adoptedApp = { ...app, identity: root.identity, certificate: appCertificate,
      privateKeys: { devicePrivateKey: app.privateKey } }
    await expect(createLocalRootIdentityAuthorityView(adoptedApp as never,
      { certificates: [root.certificate, appCertificate], revocations: [] },
      emptyIdentityProfileState(root.identity.personId))).rejects.toThrow(/root authority/i)
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
