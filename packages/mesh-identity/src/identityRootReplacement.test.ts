import { describe, expect, it } from "vitest"
import { canonicalizeJson, createRecoverableIdentity, createIdentityAuthorityView, emptyIdentityProfileState, sha256Base64Url,
  signEnvelope, certificateHash, createIdentityRustyServicePinOperation, identityProfileRustyServicePins, toBase64Url,
  readIdentityProfileState, publicKeyId, type DeviceCertificate } from "./index"
import { createIdentityRootReplacementRequest, createIdentityRootReplacementOffer,
  verifyIdentityRootReplacementOffer, verifyIdentityRootReplacementRequest,
  decryptIdentityRootReplacementScopeHandoff } from "./identityRootReplacement"

async function recipientKey() {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]) as CryptoKeyPair
  return { publicKey: toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))), privateKey: pair.privateKey }
}

async function fixture() {
  const previous = (await createRecoverableIdentity("better", "Previous", new Uint8Array(32).fill(31))).profile
  const app = (await createRecoverableIdentity("better", "Local app", new Uint8Array(32).fill(32))).profile
  const appCertificate: DeviceCertificate = await signEnvelope(previous.privateKeys.devicePrivateKey, {
    kind: "device-certificate", version: 1, personId: previous.identity.personId,
    deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey,
    issuerCertificateHash: await certificateHash(previous.certificate), canEnrollDevices: false,
  }, previous.device.deviceId)
  const previousProfileState = emptyIdentityProfileState(previous.identity.personId)
  const previousAuthority = await createIdentityAuthorityView(previous.identity, {
    certificates: [previous.certificate, appCertificate], revocations: [],
  }, previousProfileState)
  const successorApp = (await createRecoverableIdentity("better", "Successor app key", new Uint8Array(32).fill(34))).profile
  const recipient = await recipientKey()
  const request = await createIdentityRootReplacementRequest({
    identity: previous.identity, device: app.device, privateKeys: { devicePrivateKey: app.privateKeys.devicePrivateKey },
  }, { successorDevice: { deviceId: successorApp.device.deviceId, publicKey: successorApp.device.publicKey,
      privateKey: successorApp.privateKeys.devicePrivateKey },
      applicationOrigin: "https://boards.example",
      challenge: "a".repeat(64), expiresAt: Date.now() + 60_000, scopeHandoffPublicKey: recipient.publicKey, rustyServicePins: [] })
  const successor = (await createRecoverableIdentity("better", "Successor", new Uint8Array(32).fill(33))).profile
  return { previous, app, successorApp, previousAuthority, previousProfileState, request, successor, recipient }
}

describe("Identity root replacement offer", () => {
  it("returns a fresh app key under the successor root with both roots bound to the exact request", async () => {
    const f = await fixture()
    const offer = await createIdentityRootReplacementOffer(f.previous, f.successor, f.request, f.previousAuthority,
      f.previousProfileState, { consentedRustyServicePins: [], successorScopeConnections: [] })
    const verified = await verifyIdentityRootReplacementOffer(offer, f.request, f.previous.identity)
    expect(verified.successorPersonId).toBe(f.successor.identity.personId)
    expect(verified.certificate.payload.deviceId).toBe(f.successorApp.device.deviceId)
    expect(verified.certificate.payload.devicePublicKey).toBe(f.successorApp.device.publicKey)
    expect(verified.authorityView.personId).toBe(f.successor.identity.personId)
    expect(offer.authorization.payload.transitionHash).toBe(await sha256Base64Url(new TextEncoder().encode(
      canonicalizeJson(offer.succession))))
    expect(offer.authorization.payload.previousAuthorityHead).toEqual(offer.previousAuthorityView.revocationHead)
    expect(offer.authorization.payload.previousViewDigest).toBe(offer.previousAuthorityView.viewDigest)
    expect(offer.authorization.payload.previousProfileStateHash).toBe(await sha256Base64Url(new TextEncoder().encode(
      canonicalizeJson(offer.previousProfileState))))
    expect(JSON.stringify(offer)).not.toContain("identityPrivateKey")
  })

  it("GIVEN request ECDH key and approved successor scope config WHEN offer is opened THEN only bound config decrypts", async () => {
    const f = await fixture()
    const rusty = (await createRecoverableIdentity("better", "Rusty", new Uint8Array(32).fill(46))).profile
    const pin = { origin: "https://rusty.example", serviceId: rusty.identity.personId,
      servicePublicKey: rusty.identity.publicKey }
    const request = await createIdentityRootReplacementRequest({ identity: f.previous.identity, device: f.app.device,
      privateKeys: { devicePrivateKey: f.app.privateKeys.devicePrivateKey } }, {
      successorDevice: { deviceId: f.successorApp.device.deviceId, publicKey: f.successorApp.device.publicKey,
        privateKey: f.successorApp.privateKeys.devicePrivateKey }, applicationOrigin: "https://boards.example",
      challenge: "f".repeat(64), expiresAt: Date.now() + 60_000,
      scopeHandoffPublicKey: f.recipient.publicKey, rustyServicePins: [pin] })
    const config = { purpose: "identity", personId: f.successor.identity.personId, origin: pin.origin,
      servicePublicKey: pin.servicePublicKey, scopeId: "opaque-scope", contentKey: "private-content-key",
      readToken: "private-read-token", writeToken: "private-write-token", keyEpoch: 0 }
    const offer = await createIdentityRootReplacementOffer(f.previous, f.successor, request, f.previousAuthority,
      f.previousProfileState, { consentedRustyServicePins: [pin], successorScopeConnections: [{ ...pin, connection: config }] })
    const opened = await decryptIdentityRootReplacementScopeHandoff(offer, f.recipient.privateKey, f.previous.identity)
    expect(opened).toEqual([{ ...pin, connection: config }])
    expect(JSON.stringify(offer)).not.toContain("private-read-token")
    const modified = structuredClone(offer)
    modified.scopeHandoff.contextHash = "A".repeat(43)
    await expect(decryptIdentityRootReplacementScopeHandoff(modified, f.recipient.privateKey, f.previous.identity)).rejects.toThrow()
  })

  it("carries validated portal history without requiring the app cache to be current", async () => {
    const f = await fixture()
    const rusty = (await createRecoverableIdentity("better", "Rusty", new Uint8Array(32).fill(35))).profile
    const pin = { origin: "https://rusty.example", serviceId: rusty.identity.personId,
      servicePublicKey: rusty.identity.publicKey }
    const operation = await createIdentityRustyServicePinOperation(f.previous, f.previousProfileState, pin)
    const portalState = await readIdentityProfileState({ ...f.previousProfileState,
      operations: operation ? [operation] : [] }, f.previous.identity, f.previousAuthority.certificates)
    const portalAuthority = await createIdentityAuthorityView(f.previous.identity,
      { certificates: f.previousAuthority.certificates, revocations: [] }, portalState)
    const request = await createIdentityRootReplacementRequest({ identity: f.previous.identity, device: f.app.device,
      privateKeys: { devicePrivateKey: f.app.privateKeys.devicePrivateKey } }, {
      successorDevice: { deviceId: f.successorApp.device.deviceId, publicKey: f.successorApp.device.publicKey,
        privateKey: f.successorApp.privateKeys.devicePrivateKey },
      applicationOrigin: "https://boards.example", challenge: "c".repeat(64), expiresAt: Date.now() + 60_000,
      scopeHandoffPublicKey: (await recipientKey()).publicKey, rustyServicePins: [pin] })
    const offer = await createIdentityRootReplacementOffer(f.previous, f.successor, request, portalAuthority, portalState,
      { consentedRustyServicePins: [pin], successorScopeConnections: [{ ...pin, connection: { purpose: "identity" } }] })
    const verified = await verifyIdentityRootReplacementOffer(offer, request, f.previous.identity)
    expect(identityProfileRustyServicePins(await readIdentityProfileState(verified.successorProfileState,
      f.successor.identity, verified.certificates))).toEqual([pin])
  })

  it("rejects an offer replayed against a different app request", async () => {
    const f = await fixture()
    const offer = await createIdentityRootReplacementOffer(f.previous, f.successor, f.request, f.previousAuthority,
      f.previousProfileState, { consentedRustyServicePins: [], successorScopeConnections: [] })
    const substituted = await createIdentityRootReplacementRequest({
      identity: f.previous.identity, device: f.app.device,
      privateKeys: { devicePrivateKey: f.app.privateKeys.devicePrivateKey },
      }, {
        successorDevice: { deviceId: f.successorApp.device.deviceId, publicKey: f.successorApp.device.publicKey,
        privateKey: f.successorApp.privateKeys.devicePrivateKey },
      applicationOrigin: "https://boards.example", challenge: "b".repeat(64), expiresAt: f.request.authorization.payload.expiresAt,
      scopeHandoffPublicKey: (await recipientKey()).publicKey, rustyServicePins: [] })
    await expect(verifyIdentityRootReplacementOffer(offer, substituted, f.previous.identity)).rejects.toThrow(/request|binding/i)
  })

  it("rejects a signed request whose recipient point is not on P-256", async () => {
    const f = await fixture()
    const forged = structuredClone(f.request)
    forged.authorization.payload.scopeHandoffPublicKey = toBase64Url(new Uint8Array([4, ...new Uint8Array(64)]))
    forged.authorization = await signEnvelope(f.app.privateKeys.devicePrivateKey, forged.authorization.payload,
      f.app.device.deviceId, "MESH-DEVICE-AUTHORIZATION/1")
    forged.successorKeyProof = await signEnvelope(f.successorApp.privateKeys.devicePrivateKey, {
      kind: "mesh-identity-root-replacement-key-proof", version: 1,
      requestHash: await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(forged.authorization))),
      applicationOrigin: forged.authorization.payload.applicationOrigin,
      challenge: forged.authorization.payload.challenge, expiresAt: forged.authorization.payload.expiresAt,
      previousPersonId: forged.authorization.payload.previousPersonId,
      requesterDeviceId: forged.authorization.payload.requesterDeviceId,
      successorDeviceId: forged.authorization.payload.successorDeviceId,
      successorDevicePublicKey: forged.authorization.payload.successorDevicePublicKey,
      scopeHandoffPublicKey: forged.authorization.payload.scopeHandoffPublicKey,
    }, f.successorApp.device.deviceId, "MESH-IDENTITY-ROOT-REPLACEMENT-KEY/1")
    await expect(verifyIdentityRootReplacementRequest(forged, f.previousAuthority, {
      applicationOrigin: "https://boards.example", challenge: "a".repeat(64),
    })).rejects.toThrow(/P-256/i)
  })

  it("Given a root-signed offer already durably staged, when a retry resumes after request expiry, then verify the exact accepted offer", async () => {
    const f = await fixture()
    const offer = await createIdentityRootReplacementOffer(f.previous, f.successor, f.request, f.previousAuthority,
      f.previousProfileState, { consentedRustyServicePins: [], successorScopeConnections: [] })
    const now = () => f.request.authorization.payload.expiresAt + 5_000
    await expect(verifyIdentityRootReplacementOffer(offer, f.request, f.previous.identity, { now }))
      .rejects.toThrow(/expired/i)
    await expect(verifyIdentityRootReplacementOffer(offer, f.request, f.previous.identity,
      { now, allowExpiredRequest: true })).resolves.toMatchObject({ successorPersonId: f.successor.identity.personId })
  })

  it("rejects a candidate certificate for a different app device key", async () => {
    const f = await fixture()
    const offer = await createIdentityRootReplacementOffer(f.previous, f.successor, f.request, f.previousAuthority,
      f.previousProfileState, { consentedRustyServicePins: [], successorScopeConnections: [] })
    offer.certificate.payload.devicePublicKey = f.previous.device.publicKey
    await expect(verifyIdentityRootReplacementOffer(offer, f.request, f.previous.identity)).rejects.toThrow()
  })

  it("preserves every accepted Rusty service pin in successor-signed profile history", async () => {
    const f = await fixture()
    const rusty = (await createRecoverableIdentity("better", "Rusty", new Uint8Array(32).fill(35))).profile
    const pin = { origin: "https://rusty.example", serviceId: rusty.identity.personId,
      servicePublicKey: rusty.identity.publicKey }
    const previousState = emptyIdentityProfileState(f.previous.identity.personId)
    const pinOperation = await createIdentityRustyServicePinOperation(f.previous, previousState, pin)
    const oldProfileState = await readIdentityProfileState({ ...previousState,
      operations: pinOperation ? [pinOperation] : [] }, f.previous.identity, [f.previous.certificate])
    const previousAuthority = await createIdentityAuthorityView(f.previous.identity,
      { certificates: f.previousAuthority.certificates, revocations: [] }, oldProfileState)

    const request = await createIdentityRootReplacementRequest({ identity: f.previous.identity, device: f.app.device,
      privateKeys: { devicePrivateKey: f.app.privateKeys.devicePrivateKey } }, {
      successorDevice: { deviceId: f.successorApp.device.deviceId, publicKey: f.successorApp.device.publicKey,
        privateKey: f.successorApp.privateKeys.devicePrivateKey }, applicationOrigin: "https://boards.example",
      challenge: "b".repeat(64), expiresAt: Date.now() + 60_000, scopeHandoffPublicKey: (await recipientKey()).publicKey, rustyServicePins: [] })
    const offer = await createIdentityRootReplacementOffer(f.previous, f.successor, request, previousAuthority,
      oldProfileState, { consentedRustyServicePins: [], successorScopeConnections: [{ ...pin,
        connection: { purpose: "identity", origin: pin.origin, servicePublicKey: pin.servicePublicKey } }] })
    const verified = await verifyIdentityRootReplacementOffer(offer, request, f.previous.identity)
    const newState = await readIdentityProfileState(verified.successorProfileState, f.successor.identity,
      verified.certificates)
    expect(identityProfileRustyServicePins(newState)).toEqual([pin])
    expect(newState.operations.every(operation => operation.signed.payload.personId === f.successor.identity.personId)).toBe(true)
    expect(await publicKeyId(f.successor.identity.publicKey)).toBe(f.successor.identity.personId)
  })

  it("imports first-upgrade app pins only after explicit Identity manager consent", async () => {
    const f = await fixture()
    const rusty = (await createRecoverableIdentity("better", "Workspace Rusty", new Uint8Array(32).fill(36))).profile
    const pin = { origin: "https://workspace-rusty.example", serviceId: rusty.identity.personId,
      servicePublicKey: rusty.identity.publicKey }
    const request = await createIdentityRootReplacementRequest({ identity: f.previous.identity, device: f.app.device,
      privateKeys: { devicePrivateKey: f.app.privateKeys.devicePrivateKey } }, {
      successorDevice: { deviceId: f.successorApp.device.deviceId, publicKey: f.successorApp.device.publicKey,
        privateKey: f.successorApp.privateKeys.devicePrivateKey }, applicationOrigin: "https://boards.example",
      challenge: "d".repeat(64), expiresAt: Date.now() + 60_000, scopeHandoffPublicKey: (await recipientKey()).publicKey, rustyServicePins: [pin] })
    await expect(createIdentityRootReplacementOffer(f.previous, f.successor, request, f.previousAuthority,
      f.previousProfileState, { consentedRustyServicePins: [], successorScopeConnections: [] })).rejects.toThrow(/consent/i)
    const offer = await createIdentityRootReplacementOffer(f.previous, f.successor, request, f.previousAuthority,
      f.previousProfileState, { consentedRustyServicePins: [pin], successorScopeConnections: [{ ...pin, connection: { purpose: "identity" } }] })
    const verified = await verifyIdentityRootReplacementOffer(offer, request, f.previous.identity)
    const previousState = await readIdentityProfileState(offer.previousProfileState, f.previous.identity,
      offer.previousAuthorityView.certificates)
    const successorState = await readIdentityProfileState(verified.successorProfileState, f.successor.identity,
      verified.certificates)
    expect(identityProfileRustyServicePins(previousState)).toEqual([pin])
    expect(identityProfileRustyServicePins(successorState)).toEqual([pin])
    expect(offer.previousAuthorityView.viewDigest).toBe(offer.authorization.payload.previousViewDigest)
    const forged = structuredClone(request)
    forged.authorization.payload.rustyServicePins[0]!.serviceId = "x".repeat(43)
    await expect(verifyIdentityRootReplacementOffer(offer, forged, f.previous.identity)).rejects.toThrow()
  })
})
