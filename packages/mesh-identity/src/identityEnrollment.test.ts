import { expect, it } from "vitest"
import { readFileSync } from "node:fs"
import * as transportModule from "../../mesh-transport/transport-wasm/meta_mesh.js"
import { BrowserIdentityStore, createIdentityDeviceEnrollmentRequest,
  issueIdentityDeviceEnrollment, signEnvelope, verifyEnvelope, verifyIdentityDeviceEnrollmentRequest,
  type DeviceCertificate } from "./index"
import { createDeviceEnrollmentInvite } from "@meta-uber/mesh-pairing"

transportModule.initSync({ module: readFileSync(new URL("../../mesh-transport/transport-wasm/meta_mesh_bg.wasm", import.meta.url)) })

it("Given an active enrollment invitation, when an Identity device signs a request, then an authorized device can issue an identity-wide certificate", async () => {
  const root = await new BrowserIdentityStore({ storageKey: "root" }).bootstrap("Identity")
  const invitation = createDeviceEnrollmentInvite("endpoint-root", "secret-value", root)
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
  const devicePublicKey = (await import("./index")).toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)))
  const deviceId = await (await import("./index")).publicKeyId(devicePublicKey)
  const request = await createIdentityDeviceEnrollmentRequest({
    device: { deviceId, publicKey: devicePublicKey, displayName: "New device" },
    privateKey: keys.privateKey,
  }, invitation, { displayName: "New device", fullRecoveryConsent: false })
  expect(request.payload.fullRecoveryConsent).toBe(false)
  await expect(verifyIdentityDeviceEnrollmentRequest(request, invitation)).resolves.toBeUndefined()

  const intermediateKeys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
  const intermediatePublic = (await import("./index")).toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", intermediateKeys.publicKey)))
  const intermediateId = await (await import("./index")).publicKeyId(intermediatePublic)
  const delegatedCertificate: DeviceCertificate = await (await import("./index")).signEnvelope(root.privateKeys.identityPrivateKey!, {
    kind: "device-certificate", version: 1, personId: root.identity.personId, deviceId: intermediateId,
    devicePublicKey: intermediatePublic, issuerCertificateHash: null, canEnrollDevices: true,
  }, root.identity.personId)
  const delegatedIssuer = { ...root,
    device: { deviceId: intermediateId, publicKey: intermediatePublic, displayName: "Authorized device" },
    certificate: delegatedCertificate, privateKeys: { devicePrivateKey: intermediateKeys.privateKey } }
  const reorderedDelegatedCertificate = {
    signature: delegatedCertificate.signature,
    payload: structuredClone(delegatedCertificate.payload),
    signerKeyId: delegatedCertificate.signerKeyId,
  }
  expect(JSON.stringify(reorderedDelegatedCertificate)).not.toBe(JSON.stringify(delegatedCertificate))
  const certificate = await issueIdentityDeviceEnrollment(delegatedIssuer, request, invitation,
    [root.certificate, reorderedDelegatedCertificate])

  expect(certificate.payload).toMatchObject({ personId: root.identity.personId, deviceId, devicePublicKey, canEnrollDevices: true })
  expect(certificate.payload.issuerCertificateHash).toBe(await (await import("./index")).certificateHash(delegatedCertificate))
})

it("Given another person's invitation, when a signed device request is approved, then reject before issuing a certificate", async () => {
  const owner = await new BrowserIdentityStore({ storageKey: "owner" }).bootstrap("Owner")
  const other = await new BrowserIdentityStore({ storageKey: "other" }).bootstrap("Other")
  const invitation = createDeviceEnrollmentInvite("endpoint-owner", "secret-value", owner)
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
  const devicePublicKey = (await import("./index")).toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)))
  const deviceId = await (await import("./index")).publicKeyId(devicePublicKey)
  const request = await createIdentityDeviceEnrollmentRequest({
    device: { deviceId, publicKey: devicePublicKey, displayName: "Other device" },
    privateKey: keys.privateKey,
  }, createDeviceEnrollmentInvite("endpoint-other", "other-secret", other), { displayName: "Other device", fullRecoveryConsent: false })
  await expect(issueIdentityDeviceEnrollment(other, request, invitation, [other.certificate])).rejects.toThrow(/enrollment request/i)
})

it("Given a denied recovery transfer, when a device request is signed, then the issuer sees consent and cannot accept a tampered opt-in", async () => {
  const identity = await new BrowserIdentityStore({ storageKey: "consent" }).bootstrap("Identity")
  const invitation = createDeviceEnrollmentInvite("endpoint-root", "secret-value", identity)
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
  const publicKey = (await import("./index")).toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)))
  const deviceId = await (await import("./index")).publicKeyId(publicKey)
  const request = await createIdentityDeviceEnrollmentRequest({
    device: { deviceId, publicKey, displayName: "Guest" }, privateKey: keys.privateKey,
  }, invitation, { displayName: "Guest", fullRecoveryConsent: false })

  expect(request.payload.fullRecoveryConsent).toBe(false)
  expect((await import("./index")).identityRequestAllowsRecoveryTransfer(request)).toBe(false)
  await expect(verifyIdentityDeviceEnrollmentRequest({ ...request,
    payload: { ...request.payload, fullRecoveryConsent: true } }, invitation)).rejects.toThrow(/enrollment request/i)
})

it("Given a signed recovery-consent request, when the actual enrollment frame is encoded and parsed, then request and route signatures still verify", async () => {
  const identity = await new BrowserIdentityStore({ storageKey: "wire-roundtrip" }).bootstrap("Identity")
  const invitation = createDeviceEnrollmentInvite("endpoint-root", "secret-value", identity)
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
  const publicKey = (await import("./index")).toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)))
  const deviceId = await (await import("./index")).publicKeyId(publicKey)
  const request = await createIdentityDeviceEnrollmentRequest({
    device: { deviceId, publicKey, displayName: "Guest" }, privateKey: keys.privateKey,
  }, invitation, { displayName: "Guest", fullRecoveryConsent: true })
  const route = await signEnvelope(keys.privateKey, {
    kind: "mesh-device-route" as const, version: 1 as const, scopeId: `identity:${identity.identity.personId}`,
    personId: identity.identity.personId, deviceId, instanceId: "guest-instance",
    endpoint: JSON.stringify({ kind: "mesh-browser-endpoint-address", version: 1, endpointId: "guest-endpoint", relayUrl: "https://relay.example" }),
    sequence: 1, issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(),
  }, deviceId, "META-MESH-ROUTE/1")
  const codec = new transportModule.WasmPairingCodec()
  try {
    const wireFrame = codec.encode("enroll-request", invitation.secret,
      new TextEncoder().encode(JSON.stringify({ request, route })))
    const decodedBytes = codec.decode(wireFrame, "enroll-request", invitation.secret)
    const parsed = JSON.parse(new TextDecoder().decode(decodedBytes)) as {
      request: typeof request
      route: typeof route
    }

    await expect(verifyIdentityDeviceEnrollmentRequest(parsed.request, invitation)).resolves.toBeUndefined()
    expect(parsed.request.payload.fullRecoveryConsent).toBe(true)
    await expect(verifyEnvelope(parsed.route, publicKey, "META-MESH-ROUTE/1")).resolves.toBe(true)
  } finally {
    codec.free()
  }
})

it("Given a new browser joining an existing Identity, when it creates an enrollment device, then it has no temporary person or root key", async () => {
  const { createIdentityEnrollmentDevice } = await import("./index")
  const device = await createIdentityEnrollmentDevice("  Work laptop  ")
  expect(device.device).toMatchObject({ displayName: "Work laptop" })
  expect(device.device.deviceId).toBe(await (await import("./index")).publicKeyId(device.device.publicKey))
  expect(device.privateKey.type).toBe("private")
})
