import { describe, expect, it } from "vitest"
import { authorizeIdentityDataDevice, certificateHash, createRecoverableIdentity, createDeviceRevocation,
  openIdentityRecoveryEnvelope, publicKeyId, signEnvelope, verifyDeviceCertificateChain, verifyIdentityDeviceAuthority } from "./index"
import { createDelegatedCertificate, createDeviceAuthorizationApproval, createDeviceAuthorizationRequest,
  issueDeviceAuthorization, verifyDeviceAuthorizationApproval, verifyRetainedDeviceAuthorizationApproval,
  verifyDeviceAuthorizationRequest } from "./deviceAuthorization"
import { createIdentityRustyServicePinOperation, emptyIdentityProfileState, readIdentityProfileState } from "./identityProfile"

const applicationOrigin = "https://boards.example"
const challenge = "a".repeat(64)
const expiresAt = Date.now() + 90_000

describe("application device enrollment", () => {
  it("Given a signed app pin inventory, when Identity validates the request, then bind normalized service origins to the app key", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const client = (await createRecoverableIdentity("better", "Client")).profile
    const pin = { origin: "https://rusty.example", serviceId: await publicKeyId(client.device.publicKey),
      servicePublicKey: client.device.publicKey }
    const request = await createDeviceAuthorizationRequest(client, { applicationOrigin, challenge, expiresAt,
      personId: identity.identity.personId, rustyServicePins: [pin] })
    expect(request.payload).toMatchObject({ version: 2, rustyServicePins: [pin] })
    const initial = emptyIdentityProfileState(identity.identity.personId)
    const pinOperation = await createIdentityRustyServicePinOperation(identity, initial, pin, [identity.certificate])
    const profileState = await readIdentityProfileState({ ...initial, operations: pinOperation ? [pinOperation] : [] },
      identity.identity, [identity.certificate])
    const approval = await createDeviceAuthorizationApproval(identity, request, { applicationOrigin, challenge,
      certificates: [identity.certificate], profileState, revocations: [] })
    await expect(verifyDeviceAuthorizationApproval(approval, request)).resolves.toMatchObject({
      proof: { payload: { request: { payload: { rustyServicePins: [pin] } } } },
    })
    await expect(verifyDeviceAuthorizationRequest({ ...request, payload: { ...request.payload,
      rustyServicePins: [{ ...pin, serviceId: "b".repeat(43) }] } } as typeof request, { applicationOrigin, challenge }))
      .rejects.toThrow()
    expect(approval.proof.payload.version).toBe(3)
    await expect(verifyDeviceAuthorizationApproval({ ...approval, rustyServicePins: [
      { ...pin, origin: "https://substituted.example" },
    ] }, request)).rejects.toThrow(/catalog/i)
  })

  it("Given an approved Rusty catalog, when its redirect request expires, then retained evidence stays verifiable without renewing consent", async () => {
    const now = Date.now()
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const client = (await createRecoverableIdentity("better", "Client")).profile
    const service = (await createRecoverableIdentity("better", "Rusty")).profile
    const pin = { origin: "https://rusty.example", serviceId: await publicKeyId(service.identity.publicKey),
      servicePublicKey: service.identity.publicKey }
    const request = await createDeviceAuthorizationRequest(client, { applicationOrigin, challenge,
      expiresAt: now + 10_000, personId: identity.identity.personId, rustyServicePins: [pin] })
    const initial = emptyIdentityProfileState(identity.identity.personId)
    const operation = await createIdentityRustyServicePinOperation(identity, initial, pin, [identity.certificate])
    const profileState = await readIdentityProfileState({ ...initial, operations: operation ? [operation] : [] },
      identity.identity, [identity.certificate])
    const approval = await createDeviceAuthorizationApproval(identity, request, { applicationOrigin, challenge,
      certificates: [identity.certificate], profileState, revocations: [], now: () => now + 1_000 })

    await expect(verifyDeviceAuthorizationApproval(approval, request, { now: () => now + 2_000 })).resolves.toBeDefined()
    await expect(verifyDeviceAuthorizationApproval(approval, request, { now: () => now + 10_001 })).rejects.toThrow(/does not match/u)
    await expect(verifyRetainedDeviceAuthorizationApproval(approval, request)).resolves.toMatchObject({ rustyServicePins: [pin] })
  })

  it("Given an app request for a Rusty service, when the Identity catalog lacks its signed manager operation, then refuse approval", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const client = (await createRecoverableIdentity("better", "Client")).profile
    const pin = { origin: "https://rusty.example", serviceId: await publicKeyId(client.device.publicKey),
      servicePublicKey: client.device.publicKey }
    const request = await createDeviceAuthorizationRequest(client, { applicationOrigin, challenge, expiresAt,
      personId: identity.identity.personId, rustyServicePins: [pin] })
    await expect(createDeviceAuthorizationApproval(identity, request, { applicationOrigin, challenge,
      certificates: [identity.certificate], profileState: emptyIdentityProfileState(identity.identity.personId),
      revocations: [] })).rejects.toThrow(/not committed/i)
  })

  it("Given an application-owned device key, when Identity approves, then certify that key without transferring private keys", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const client = (await createRecoverableIdentity("better", "Temporary client")).profile
    const request = await createDeviceAuthorizationRequest(client, { applicationOrigin, challenge, expiresAt })
    const certificate = await issueDeviceAuthorization(identity, request, { applicationOrigin, challenge })
    expect(certificate.payload).toMatchObject({ personId: identity.identity.personId,
      deviceId: client.device.deviceId, devicePublicKey: client.device.publicKey, canEnrollDevices: false })
    expect(certificate.payload.issuerCertificateHash).toBe(await certificateHash(identity.certificate))
    expect(await verifyDeviceCertificateChain(identity.identity, client.device.deviceId, [identity.certificate, certificate]))
      .toBe(client.device.publicKey)
    expect(JSON.stringify({ request, certificate })).not.toMatch(/privateKey|recoveryKey/u)
  })

  it("Given a root-capable manager approving an app key, when that manager is revoked, then the approved app key is revoked with it", async () => {
    const recovered = await createRecoverableIdentity("better", "Owner")
    const manager = recovered.profile
    const remainingManager = await openIdentityRecoveryEnvelope(recovered.recoveryEnvelope, recovered.recoveryKey, "Owner")
    const client = (await createRecoverableIdentity("better", "Client")).profile
    const request = await createDeviceAuthorizationRequest(client, { applicationOrigin, challenge, expiresAt })
    const appCertificate = await issueDeviceAuthorization(manager, request, { applicationOrigin, challenge,
      certificates: [manager.certificate, remainingManager.certificate] })
    expect(appCertificate.payload.issuerCertificateHash).toBe(await certificateHash(manager.certificate))
    const certificates = [manager.certificate, remainingManager.certificate, appCertificate]
    const before = await verifyIdentityDeviceAuthority(manager.identity, { certificates, revocations: [] })
    const revocation = await createDeviceRevocation(remainingManager, before, manager.device.deviceId,
      { version: 1, personId: manager.identity.personId, operations: [], legacy: [] })
    const after = await verifyIdentityDeviceAuthority(manager.identity, { certificates, revocations: [revocation] })
    expect(after.blockedDeviceIds).toContain(client.device.deviceId)
  })

  it("Given a legacy root-sibling app certificate, when the same device ID is reparented, then reject conflicting certificate history", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const app = (await createRecoverableIdentity("better", "App")).profile
    const payload = { kind: "device-certificate" as const, version: 1 as const,
      personId: owner.identity.personId, deviceId: app.device.deviceId,
      devicePublicKey: app.device.publicKey, canEnrollDevices: false }
    const legacy = await signEnvelope(owner.privateKeys.identityPrivateKey!, {
      ...payload, issuerCertificateHash: null,
    }, owner.identity.personId)
    const reparented = await signEnvelope(owner.privateKeys.devicePrivateKey, {
      ...payload, issuerCertificateHash: await certificateHash(owner.certificate),
    }, owner.device.deviceId)
    await expect(verifyIdentityDeviceAuthority(owner.identity, {
      certificates: [owner.certificate, legacy, reparented], revocations: [],
    })).rejects.toThrow(/conflicting Identity device certificate/i)
  })

  it("Given an existing legacy root-sibling app key, when it signs in again, then retain its verified certificate without reparenting", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const app = (await createRecoverableIdentity("better", "Existing app")).profile
    const legacyCertificate = await signEnvelope(owner.privateKeys.identityPrivateKey!, {
      kind: "device-certificate" as const, version: 1 as const, personId: owner.identity.personId,
      deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey,
      issuerCertificateHash: null, canEnrollDevices: false,
    }, owner.identity.personId)
    const request = await createDeviceAuthorizationRequest(app, { applicationOrigin, challenge, expiresAt,
      personId: owner.identity.personId })
    const profileState = emptyIdentityProfileState(owner.identity.personId)
    const approval = await createDeviceAuthorizationApproval(owner, request, {
      applicationOrigin, challenge, certificates: [owner.certificate, legacyCertificate],
      profileState, revocations: [],
    })
    expect(approval.certificate).toEqual(legacyCertificate)
    expect(new Set(approval.certificates.map(item => item.payload.deviceId)).size).toBe(approval.certificates.length)
    await expect(verifyDeviceAuthorizationApproval(approval, request)).resolves.toMatchObject({
      certificate: { signature: legacyCertificate.signature },
    })
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

  it("Given a complete Identity profile, when approving an app device, then bind a verified portable authority view to the signed approval", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const app = (await createRecoverableIdentity("better", "App device")).profile
    const request = await createDeviceAuthorizationRequest(app, { applicationOrigin, challenge, expiresAt,
      personId: identity.identity.personId })
    const profileState = { version: 1 as const, personId: identity.identity.personId, operations: [], legacy: [] }
    const approval = await createDeviceAuthorizationApproval(identity, request, {
      applicationOrigin, challenge, now: () => Date.now(), profileState, revocations: [],
    })
    expect(approval.authorityView).toMatchObject({ kind: "mesh-identity-authority-view", version: 1,
      personId: identity.identity.personId })
    expect(approval.proof.payload).toMatchObject({ version: 2,
      authorityViewDigest: approval.authorityView!.viewDigest,
      revocationHead: approval.authorityView!.revocationHead })
    await expect(verifyDeviceAuthorizationApproval(approval, request)).resolves.toMatchObject({
      certificate: { payload: { deviceId: app.device.deviceId } },
    })
    await expect(verifyDeviceAuthorizationApproval({ ...approval,
      authorityView: { ...approval.authorityView!, viewDigest: "A".repeat(43) },
    }, request)).rejects.toThrow(/digest|authority view/i)
  })

  it("Given a previously authorized app key, when delegated Identity reauthorizes it, then verify the newly approved certificate", async () => {
    const root = (await createRecoverableIdentity("better", "Root")).profile
    const delegated = (await createRecoverableIdentity("better", "Authorizing device")).profile
    const app = (await createRecoverableIdentity("better", "Returning app device")).profile
    const delegatedCertificate = await createDelegatedCertificate(root.privateKeys.devicePrivateKey,
      root.device.deviceId, root.identity.personId, delegated.device.deviceId, delegated.device.publicKey,
      await certificateHash(root.certificate))
    const delegatedProfile = { ...delegated, identity: root.identity, certificate: delegatedCertificate,
      privateKeys: { devicePrivateKey: delegated.privateKeys.devicePrivateKey } }
    const chain = [root.certificate, delegatedCertificate]
    const request = await createDeviceAuthorizationRequest(app, { applicationOrigin, challenge, expiresAt,
      personId: root.identity.personId })
    const previousCertificate = await issueDeviceAuthorization(root, request, { applicationOrigin, challenge })
    const approval = await createDeviceAuthorizationApproval(delegatedProfile, request, {
      applicationOrigin, challenge, certificates: [...chain, previousCertificate],
    })

    await expect(verifyDeviceAuthorizationApproval(approval, request)).resolves.toMatchObject({
      certificate: { signature: approval.certificate.signature },
    })
    await expect(verifyDeviceAuthorizationApproval({ ...approval,
      certificates: approval.certificates.filter(value => value.signature !== approval.certificate.signature),
    }, request)).rejects.toThrow(/missing app device certificate/iu)
  })

  it("Given an approval certificate omitted from its chain, when verifying, then reject the incomplete proof", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const app = (await createRecoverableIdentity("better", "App device")).profile
    const request = await createDeviceAuthorizationRequest(app, { applicationOrigin, challenge, expiresAt,
      personId: identity.identity.personId })
    const approval = await createDeviceAuthorizationApproval(identity, request, { applicationOrigin, challenge })

    await expect(verifyDeviceAuthorizationApproval({ ...approval,
      certificates: approval.certificates.filter(value => value.signature !== approval.certificate.signature),
    }, request)).rejects.toThrow(/certificate/u)
  })
})
