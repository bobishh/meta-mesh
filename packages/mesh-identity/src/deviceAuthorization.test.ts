import { describe, expect, it } from "vitest"
import { certificateHash, createRecoverableIdentity, verifyDeviceCertificateChain } from "./index"
import { createDelegatedCertificate, createDeviceAuthorizationApproval, createDeviceAuthorizationRequest,
  issueDeviceAuthorization, verifyDeviceAuthorizationApproval } from "./deviceAuthorization"

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

describe("delegated app device authorization", () => {
  it("Given an authorized Identity device without the root key, when it approves an app key, then issues a non-enrolling certificate", async () => {
    const root = (await createRecoverableIdentity("better", "Root")).profile
    const delegated = (await createRecoverableIdentity("better", "Temporary")).profile
    const app = (await createRecoverableIdentity("better", "App device")).profile
    const delegatedCertificate = await createDelegatedCertificate(root.privateKeys.devicePrivateKey,
      root.device.deviceId, root.identity.personId, delegated.device.deviceId, delegated.device.publicKey,
      await certificateHash(root.certificate))
    const delegatedProfile = { ...delegated, identity: root.identity, certificate: delegatedCertificate,
      privateKeys: { devicePrivateKey: delegated.privateKeys.devicePrivateKey } }
    const chain = [root.certificate, delegatedCertificate]
    const request = await createDeviceAuthorizationRequest(app, { applicationOrigin, challenge, expiresAt,
      personId: root.identity.personId })
    const leaf = await issueDeviceAuthorization(delegatedProfile, request, {
      applicationOrigin, challenge, certificates: chain,
    })
    expect(leaf.payload).toMatchObject({ personId: root.identity.personId, deviceId: app.device.deviceId,
      devicePublicKey: app.device.publicKey, issuerCertificateHash: await certificateHash(delegatedCertificate),
      canEnrollDevices: false })
    expect(await verifyDeviceCertificateChain(root.identity, app.device.deviceId, [...chain, leaf])).toBe(app.device.publicKey)
  })

  it("Given an ordinary non-enrolling app certificate, when that app tries to authorize another device, then reject", async () => {
    const root = (await createRecoverableIdentity("better", "Root")).profile
    const app = (await createRecoverableIdentity("better", "App device")).profile
    const next = (await createRecoverableIdentity("better", "Next device")).profile
    const request = await createDeviceAuthorizationRequest(app, { applicationOrigin, challenge, expiresAt })
    const leaf = await issueDeviceAuthorization(root, request, { applicationOrigin, challenge })
    const appProfile = { ...app, identity: root.identity, certificate: leaf,
      privateKeys: { devicePrivateKey: app.privateKeys.devicePrivateKey } }
    const nextRequest = await createDeviceAuthorizationRequest(next, { applicationOrigin, challenge, expiresAt })
    await expect(issueDeviceAuthorization(appProfile, nextRequest, {
      applicationOrigin, challenge, certificates: [root.certificate, leaf],
    })).rejects.toThrow(/authorize|enroll|permission/iu)
  })
})

describe("signed app device authorization roundtrip", () => {
  it("Given a fresh app request, when Identity approves it, then only the exact request and non-enrolling app key return", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const app = (await createRecoverableIdentity("better", "App device")).profile
    const request = await createDeviceAuthorizationRequest(app, { applicationOrigin, challenge, expiresAt,
      personId: identity.identity.personId })
    const approval = await createDeviceAuthorizationApproval(identity, request, {
      applicationOrigin, challenge, now: () => Date.now(),
    })
    const verified = await verifyDeviceAuthorizationApproval(approval, request)
    expect(verified.certificate.payload).toMatchObject({ personId: identity.identity.personId,
      deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey, canEnrollDevices: false })
    await expect(verifyDeviceAuthorizationApproval(approval, { ...request,
      payload: { ...request.payload, challenge: "b".repeat(64) } })).rejects.toThrow(/match|request/iu)
    await expect(verifyDeviceAuthorizationApproval({ ...approval,
      certificate: { ...approval.certificate, payload: { ...approval.certificate.payload, devicePublicKey: identity.device.publicKey } } }, request))
      .rejects.toThrow()
  })
})
