import { describe, expect, it } from "vitest"
import { createDeviceRevocation, createRecoverableIdentity, identityDeviceCertificateChain,
  openIdentityRecoveryEnvelope, verifyIdentityDeviceAuthority } from "./index"
import { createDeviceAuthorizationRequest, issueDeviceAuthorization } from "./deviceAuthorization"
import { emptyIdentityProfileState } from "./identityProfile"

describe("active Identity device certificate chain", () => {
  it("Given a catalog with an unrelated app certificate, when preparing a Rusty request, then return only the active signer chain", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const app = (await createRecoverableIdentity("better", "App")).profile
    const request = await createDeviceAuthorizationRequest(app, {
      applicationOrigin: "https://boards.example", challenge: "a".repeat(64),
      expiresAt: Date.now() + 90_000, personId: owner.identity.personId,
    })
    const appCertificate = await issueDeviceAuthorization(owner, request, { applicationOrigin: "https://boards.example",
      challenge: "a".repeat(64) })
    const evidence = { certificates: [owner.certificate, appCertificate], revocations: [] }

    await expect(identityDeviceCertificateChain(owner.identity, evidence, owner.device.deviceId))
      .resolves.toEqual([owner.certificate])
    await expect(identityDeviceCertificateChain(owner.identity, evidence, app.device.deviceId))
      .resolves.toEqual([appCertificate, owner.certificate])
  })

  it("Given a revoked app key, when deriving its Rusty signer chain, then reject the key", async () => {
    const recovered = await createRecoverableIdentity("better", "Owner")
    const owner = recovered.profile
    const remainingManager = await openIdentityRecoveryEnvelope(recovered.recoveryEnvelope, recovered.recoveryKey, "Owner")
    const app = (await createRecoverableIdentity("better", "App")).profile
    const request = await createDeviceAuthorizationRequest(app, {
      applicationOrigin: "https://boards.example", challenge: "b".repeat(64),
      expiresAt: Date.now() + 90_000, personId: owner.identity.personId,
    })
    const appCertificate = await issueDeviceAuthorization(owner, request, { applicationOrigin: "https://boards.example",
      challenge: "b".repeat(64) })
    const certificates = [owner.certificate, remainingManager.certificate, appCertificate]
    const authority = await verifyIdentityDeviceAuthority(owner.identity, { certificates, revocations: [] })
    const revocation = await createDeviceRevocation(remainingManager, authority, app.device.deviceId,
      emptyIdentityProfileState(owner.identity.personId))
    await expect(identityDeviceCertificateChain(owner.identity, { certificates, revocations: [revocation] }, app.device.deviceId))
      .rejects.toThrow(/revoked/i)
  })
})
