import { describe, expect, it } from "vitest"
import { createRecoverableIdentity, verifyDeviceCertificateChain } from "./index"
import { createDeviceAuthorizationRequest, issueDeviceAuthorization } from "./deviceAuthorization"

const applicationOrigin = "https://boards.example"
const challenge = "a".repeat(64)
const expiresAt = Date.now() + 90_000

describe("application device enrollment", () => {
  it("Given an application-owned device key, when Identity approves, then certify that key without transferring private keys", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const client = (await createRecoverableIdentity("better", "Temporary client")).profile
    const request = await createDeviceAuthorizationRequest(client, { applicationOrigin, challenge, expiresAt })
    const certificate = await issueDeviceAuthorization(identity, request, { applicationOrigin, challenge })
    expect(certificate.payload).toMatchObject({ personId: identity.identity.personId,
      deviceId: client.device.deviceId, devicePublicKey: client.device.publicKey, canEnrollDevices: false })
    expect(await verifyDeviceCertificateChain(identity.identity, client.device.deviceId, [certificate]))
      .toBe(client.device.publicKey)
    expect(JSON.stringify({ request, certificate })).not.toMatch(/privateKey|recoveryKey/u)
  })

  it("Given a substituted device key or another application challenge, when approved, then refuse enrollment", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const client = (await createRecoverableIdentity("better", "Client")).profile
    const request = await createDeviceAuthorizationRequest(client, { applicationOrigin, challenge, expiresAt })
    await expect(issueDeviceAuthorization(identity, { ...request,
      payload: { ...request.payload, devicePublicKey: identity.device.publicKey } }, { applicationOrigin, challenge }))
      .rejects.toThrow()
    await expect(issueDeviceAuthorization(identity, request, { applicationOrigin, challenge: "b".repeat(64) }))
      .rejects.toThrow()
    await expect(issueDeviceAuthorization(identity, request, { applicationOrigin: "https://other.example", challenge }))
      .rejects.toThrow()
  })

  it("Given an expired, selected-other-person, or replaced profile, when approved, then refuse enrollment", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const client = (await createRecoverableIdentity("better", "Client")).profile
    const request = await createDeviceAuthorizationRequest(client, { applicationOrigin, challenge, expiresAt,
      personId: client.identity.personId })
    await expect(issueDeviceAuthorization(identity, request, { applicationOrigin, challenge })).rejects.toThrow(/person/iu)
    const current = await createDeviceAuthorizationRequest(client, { applicationOrigin, challenge, expiresAt })
    await expect(issueDeviceAuthorization(identity, current, { applicationOrigin, challenge, now: () => expiresAt }))
      .rejects.toThrow(/expired/iu)
    await expect(issueDeviceAuthorization(identity, current, { applicationOrigin, challenge,
      ensureCurrent: () => { throw new Error("Identity changed") } })).rejects.toThrow(/changed/iu)
  })
})
