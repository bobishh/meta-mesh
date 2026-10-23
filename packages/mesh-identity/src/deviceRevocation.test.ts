import { describe, expect, it } from "vitest"
import { createRecoverableIdentity, openIdentityRecoveryEnvelope, createDeviceRevocation, verifyIdentityDeviceAuthority,
  authorizeIdentityDevice, certificateHash, type DeviceCertificate } from "./index"
import { createIdentityEnrollmentDevice } from "./identityEnrollment"
import { createDelegatedCertificate } from "./deviceAuthorization"
import { signEnvelope } from "./index"
import { emptyIdentityProfileState } from "./identityProfile"

async function fixture() {
  const recovery = await createRecoverableIdentity("better", "Owner")
  const owner = recovery.profile
  const removed = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
  const child = await createIdentityEnrollmentDevice("Child")
  const childCertificate = await createDelegatedCertificate(removed.privateKeys.devicePrivateKey,
    removed.device.deviceId, owner.identity.personId, child.device.deviceId, child.device.publicKey,
    await certificateHash(removed.certificate))
  const certificates: DeviceCertificate[] = [owner.certificate, removed.certificate, childCertificate]
  const evidence = { certificates, revocations: [] }
  return { owner, removed, child, childCertificate, evidence,
    profileState: emptyIdentityProfileState(owner.identity.personId) }
}

describe("Identity device revocation", () => {
  it("Given an authorized peer and its delegated child, when the peer is revoked, then every certificate and descendant chain is denied while history stays", async () => {
    const f = await fixture()
    const active = await verifyIdentityDeviceAuthority(f.owner.identity, f.evidence)
    await expect(authorizeIdentityDevice(active, f.removed.device.deviceId)).resolves.toBe(f.removed.device.publicKey)
    await expect(authorizeIdentityDevice(active, f.child.device.deviceId)).resolves.toBe(f.child.device.publicKey)

    const record = await createDeviceRevocation(f.owner, active, f.removed.device.deviceId, f.profileState)
    const revoked = await verifyIdentityDeviceAuthority(f.owner.identity, {
      certificates: f.evidence.certificates, revocations: [record],
    })

    await expect(authorizeIdentityDevice(revoked, f.removed.device.deviceId)).rejects.toThrow(/revoked/i)
    await expect(authorizeIdentityDevice(revoked, f.child.device.deviceId)).rejects.toThrow(/revoked/i)
    expect(revoked.revokedDeviceIds).toContain(f.removed.device.deviceId)
    expect(revoked.certificates).toHaveLength(3)
  })

  it("Given an old alternate certificate for a revoked device ID, when checked against current authority, then it cannot restore access", async () => {
    const f = await fixture()
    const active = await verifyIdentityDeviceAuthority(f.owner.identity, f.evidence)
    const record = await createDeviceRevocation(f.owner, active, f.removed.device.deviceId, f.profileState)
    const alternate = { ...f.removed.certificate, payload: { ...f.removed.certificate.payload,
      canEnrollDevices: false } } as DeviceCertificate
    const current = await verifyIdentityDeviceAuthority(f.owner.identity, {
      certificates: [...f.evidence.certificates, alternate], revocations: [record],
    }).catch(() => null)
    expect(current).toBeNull()
  })

  it("Given a verified authority snapshot, when its public view is mutated, then authorization still uses the verified state", async () => {
    const f = await fixture()
    const active = await verifyIdentityDeviceAuthority(f.owner.identity, f.evidence)
    const record = await createDeviceRevocation(f.owner, active, f.removed.device.deviceId, f.profileState)
    const revoked = await verifyIdentityDeviceAuthority(f.owner.identity, {
      certificates: f.evidence.certificates, revocations: [record],
    })
    revoked.blockedDeviceIds = []
    revoked.revokedDeviceIds = []
    revoked.certificates.splice(0, revoked.certificates.length)
    await expect(authorizeIdentityDevice(revoked, f.removed.device.deviceId)).rejects.toThrow(/revoked/i)
  })

  it("Given an object shaped like verified evidence, when used to authorize, then it is rejected", async () => {
    const f = await fixture()
    const forged = { ...f.evidence, identity: f.owner.identity, revokedDeviceIds: [], blockedDeviceIds: [] }
    await expect(authorizeIdentityDevice(forged as never, f.owner.device.deviceId)).rejects.toThrow(/not verified/i)
  })

  it("Given known revocation state, when evidence is omitted or malformed, then authorization fails closed", async () => {
    const f = await fixture()
    const active = await verifyIdentityDeviceAuthority(f.owner.identity, f.evidence)
    const record = await createDeviceRevocation(f.owner, active, f.removed.device.deviceId, f.profileState)
    await expect(verifyIdentityDeviceAuthority(f.owner.identity, {
      certificates: f.evidence.certificates,
    } as Parameters<typeof verifyIdentityDeviceAuthority>[1])).rejects.toThrow(/revocation|evidence/i)
    await expect(verifyIdentityDeviceAuthority(f.owner.identity, {
      certificates: f.evidence.certificates, revocations: [{ ...record, signature: "forged" }],
    })).rejects.toThrow()
  })

  it("Given a signed revocation history, when a revoked signer or final authority is removed, then the new state is rejected", async () => {
    const f = await fixture()
    const active = await verifyIdentityDeviceAuthority(f.owner.identity, f.evidence)
    const first = await createDeviceRevocation(f.owner, active, f.removed.device.deviceId, f.profileState)
    const afterFirst = await verifyIdentityDeviceAuthority(f.owner.identity, {
      certificates: f.evidence.certificates, revocations: [first],
    })
    await expect(createDeviceRevocation(f.removed, afterFirst, f.owner.device.deviceId, f.profileState)).rejects.toThrow()
    await expect(createDeviceRevocation(f.owner, afterFirst, f.owner.device.deviceId, f.profileState)).rejects.toThrow(/current|self|authority/i)
  })

  it("Given a delegated controller, when it revokes its only root issuer, then reject loss of all management authority", async () => {
    const f = await fixture()
    const delegated = await createIdentityEnrollmentDevice("Delegated controller")
    const delegatedCertificate = await createDelegatedCertificate(f.owner.privateKeys.devicePrivateKey,
      f.owner.device.deviceId, f.owner.identity.personId, delegated.device.deviceId, delegated.device.publicKey,
      await certificateHash(f.owner.certificate))
    const childProfile = { identity: f.owner.identity, device: delegated.device, certificate: delegatedCertificate,
      privateKeys: { devicePrivateKey: delegated.privateKey } }
    const authority = await verifyIdentityDeviceAuthority(f.owner.identity, {
      certificates: [f.owner.certificate, delegatedCertificate], revocations: [],
    })
    await expect(createDeviceRevocation(childProfile, authority, f.owner.device.deviceId, f.profileState))
      .rejects.toThrow(/last management authority/i)
  })

  it("Given an application-scoped certificate, when it tries to authorize or revoke Identity devices, then it is denied", async () => {
    const f = await fixture()
    const app = await createIdentityEnrollmentDevice("App key")
    const appCertificate = await signEnvelope(f.owner.privateKeys.identityPrivateKey!, {
      kind: "device-certificate" as const, version: 1 as const, personId: f.owner.identity.personId,
      deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey, issuerCertificateHash: null,
      canEnrollDevices: false,
    }, f.owner.identity.personId)
    const authority = await verifyIdentityDeviceAuthority(f.owner.identity, {
      certificates: [...f.evidence.certificates, appCertificate], revocations: [],
    })

    await expect(authorizeIdentityDevice(authority, app.device.deviceId)).rejects.toThrow(/management authority/i)
    const removal = await createDeviceRevocation(f.owner, authority, app.device.deviceId, f.profileState)
    const updated = await verifyIdentityDeviceAuthority(f.owner.identity, {
      certificates: authority.certificates, revocations: [removal],
    })
    await expect(authorizeIdentityDevice(updated, app.device.deviceId)).rejects.toThrow(/revoked/i)
    await expect(createDeviceRevocation({ ...f.owner, device: app.device, certificate: appCertificate,
      privateKeys: { devicePrivateKey: app.privateKey } }, authority, f.removed.device.deviceId, f.profileState)).rejects.toThrow(/authority/i)
  })
})
