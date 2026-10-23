import { describe, expect, it } from "vitest"
import { createRecoverableIdentity, createIdentityAuthorityView, createIdentityEnrollmentDevice,
  emptyIdentityProfileState, publicKeyId, sha256Base64Url, signEnvelope, type DeviceCertificate } from "@meta-uber/mesh-identity"
import { createRustyIdentityRequestProof, type RustyIdentityRequestProofPayload } from "./rustyIdentityRequestProof"

describe("Rusty Identity request proof", () => {
  it("Given an active app-only device, when it signs a scope request, then bind proof to exact request bytes and active view", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const app = await createIdentityEnrollmentDevice("App key")
    const appCertificate = await signEnvelope(owner.privateKeys.identityPrivateKey!, {
      kind: "device-certificate" as const, version: 1 as const, personId: owner.identity.personId,
      deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey,
      issuerCertificateHash: null, canEnrollDevices: false,
    }, owner.identity.personId)
    const certificates: DeviceCertificate[] = [owner.certificate, appCertificate]
    const view = await createIdentityAuthorityView(owner.identity, { certificates, revocations: [] },
      emptyIdentityProfileState(owner.identity.personId))
    let signedPayload: unknown
    const signed = await createRustyIdentityRequestProof({
      origin: "https://rusty.example", servicePublicKey: owner.identity.publicKey,
      identity: owner.identity, view, deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey,
      scopeId: "scope_123", token: "secret-token", method: "PUT",
      url: "https://rusty.example/v2/scopes/scope_123/objects/a?version=1",
      bodyBytes: new TextEncoder().encode('{"value":1}'), action: "write", grantId: "grant-123", policyEpoch: 7,
      signAuthorization: async payload => {
        signedPayload = payload
        return signEnvelope(app.privateKey, payload, app.device.deviceId, "MATCH/1")
      }, now: () => 1_000_000,
    })

    expect(signed.url).toBe("https://rusty.example/v2/scopes/scope_123/objects/a?version=1")
    expect(signed.authorization.payload).toMatchObject({
      kind: "rusty-identity-request-proof", version: 1, serviceId: await publicKeyId(owner.identity.publicKey),
      origin: "https://rusty.example", personId: owner.identity.personId, deviceId: app.device.deviceId,
      authorityHead: view.revocationHead, viewDigest: view.viewDigest,
      resourceKind: "scope", resourceId: "scope_123", scopeId: "scope_123", action: "write",
      grantId: "grant-123", policyEpoch: 7, method: "PUT",
      path: "/v2/scopes/scope_123/objects/a?version=1", bodyHash: expect.any(String),
      tokenHash: expect.any(String), nonce: expect.any(String), issuedAt: 1_000_000,
    })
    expect(signed.authorization.payload.bodyHash).toBe(await sha256Base64Url(new TextEncoder().encode('{"value":1}')))
    expect(signed.authorization.payload.tokenHash).toBe(await sha256Base64Url(new TextEncoder().encode("secret-token")))
    expect(signed.authorization.payload.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/u)
    expect(signed.headers.authorization).toBe("Bearer secret-token")
    expect(signed.headers["X-Rusty-Identity-Proof"]).toBe(signed.headerValue)
    expect(signed.authorization.payload).toEqual(signedPayload)
    expect(signed.headerValue).toMatch(/^[A-Za-z0-9_-]+$/u)
    const standardBase64 = signed.headerValue.replace(/-/g, "+").replace(/_/g, "/")
    const decoded = atob(standardBase64 + "=".repeat((4 - standardBase64.length % 4) % 4))
    expect(JSON.parse(new TextDecoder().decode(Uint8Array.from(decoded, c => c.charCodeAt(0)))))
      .toEqual(signed.authorization)
  })

  it("Given a revoked app device, when it requests a new Rusty proof, then deny before signing", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const removed = await createIdentityEnrollmentDevice("Removed app")
    const appCertificate = await signEnvelope(owner.privateKeys.identityPrivateKey!, {
      kind: "device-certificate" as const, version: 1 as const, personId: owner.identity.personId,
      deviceId: removed.device.deviceId, devicePublicKey: removed.device.publicKey,
      issuerCertificateHash: null, canEnrollDevices: false,
    }, owner.identity.personId)
    const certificates: DeviceCertificate[] = [owner.certificate, appCertificate]
    const profileState = emptyIdentityProfileState(owner.identity.personId)
    const authority = await (await import("@meta-uber/mesh-identity")).verifyIdentityDeviceAuthority(owner.identity,
      { certificates, revocations: [] })
    const revocation = await (await import("@meta-uber/mesh-identity")).createDeviceRevocation(owner,
      authority, removed.device.deviceId, profileState)
    const view = await createIdentityAuthorityView(owner.identity, { certificates, revocations: [revocation] }, profileState)
    const signAuthorization = async () => { throw new Error("must not sign") }

    await expect(createRustyIdentityRequestProof({
      origin: "https://rusty.example", servicePublicKey: owner.identity.publicKey,
      identity: owner.identity, view, deviceId: removed.device.deviceId, devicePublicKey: removed.device.publicKey,
      scopeId: "scope_123", token: "secret-token", method: "GET",
      url: "https://rusty.example/v2/scopes/scope_123/objects/a", bodyBytes: new Uint8Array(),
      action: "read", grantId: null, policyEpoch: 1, signAuthorization,
    })).rejects.toThrow(/revok|active|device/i)
  })

  it("Given a configured service origin, when request URL or signer binding escapes it, then reject", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const view = await createIdentityAuthorityView(owner.identity,
      { certificates: [owner.certificate], revocations: [] }, emptyIdentityProfileState(owner.identity.personId))
    const signAuthorization = async (payload: RustyIdentityRequestProofPayload) => signEnvelope(owner.privateKeys.devicePrivateKey!, payload,
      owner.device.deviceId, "MATCH/1")
    const base = {
      origin: "https://rusty.example", servicePublicKey: owner.identity.publicKey,
      identity: owner.identity, view, deviceId: owner.device.deviceId, devicePublicKey: owner.device.publicKey,
      scopeId: "scope_123", token: "secret-token", method: "GET", bodyBytes: new Uint8Array(),
      action: "read" as const, grantId: null, policyEpoch: 1, signAuthorization,
    }

    await expect(createRustyIdentityRequestProof({ ...base, url: "https://attacker.example/v2/scopes/scope_123/objects" }))
      .rejects.toThrow(/origin/i)
    await expect(createRustyIdentityRequestProof({ ...base, url: "https://rusty.example/v2/scopes/other/objects" }))
      .rejects.toThrow(/scope/i)
    await expect(createRustyIdentityRequestProof({ ...base, url: "https://rusty.example/v2/scopes/scope_123/objects",
      signAuthorization: async payload => signEnvelope(owner.privateKeys.devicePrivateKey!, payload,
        owner.device.deviceId, "RUSTY/2") }))
      .rejects.toThrow(/signature/i)
  })
})
