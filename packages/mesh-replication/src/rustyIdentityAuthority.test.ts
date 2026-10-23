import { describe, expect, it } from "vitest"
import { createRecoverableIdentity, createIdentityAuthorityView, emptyIdentityProfileState,
  createIdentityEnrollmentDevice, canonicalizeJson, publicKeyId, sha256Base64Url, signEnvelope,
  type DeviceCertificate, type IdentityAuthorityView } from "@meta-uber/mesh-identity"
import { publishRustyIdentityAuthorityView, readRustyIdentityAuthorityStatus,
  isRustyIdentityAuthorityStrict, mergeRustyIdentityEnforcement, RustyIdentityAuthorityStaleError } from "./rustyIdentityAuthority"

describe("Rusty Identity authority high-water update", () => {
  it("Given a persisted strict service epoch, when a signed status claims additive mode, then reject the downgrade", () => {
    const strict = { mode: "strict" as const, epoch: 1 as const }
    const additive = { mode: "additive" as const, epoch: 0 as const }
    expect(mergeRustyIdentityEnforcement(null, additive)).toEqual(additive)
    expect(mergeRustyIdentityEnforcement(additive, strict)).toEqual(strict)
    expect(() => mergeRustyIdentityEnforcement(strict, additive)).toThrow(/downgraded/i)
  })

  it("Given a validated Identity view, when Rusty durably accepts it, then verify the signed receipt before success", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const service = (await createRecoverableIdentity("better", "Rusty service")).profile
    const view = await createIdentityAuthorityView(identity.identity,
      { certificates: [identity.certificate], revocations: [] }, emptyIdentityProfileState(identity.identity.personId))
    let sent: { version: number; view: IdentityAuthorityView; authorization: unknown } | undefined
    const result = await publishRustyIdentityAuthorityView({
      origin: "https://rusty.example", servicePublicKey: service.identity.publicKey,
      identity: identity.identity, deviceId: identity.device.deviceId, devicePublicKey: identity.device.publicKey,
      view, now: () => 1_000_000,
      signAuthorization: async payload => signEnvelope(identity.privateKeys.devicePrivateKey, payload,
        identity.device.deviceId, "MATCH/1"),
      fetcher: async (_input, init) => {
        sent = JSON.parse(String(init?.body))
        const posted = sent!
        const requestHash = posted.authorization as { payload: { requestHash: string } }
        const authorization = (posted.authorization as { payload: Record<string, unknown> }).payload
        const receipt = await signEnvelope(service.privateKeys.identityPrivateKey!, {
          kind: "rusty-identity-authority-receipt" as const, version: 1 as const,
          serviceId: await publicKeyId(service.identity.publicKey), origin: "https://rusty.example",
          personId: identity.identity.personId,
          authorityHead: view.revocationHead, viewDigest: view.viewDigest,
          requestHash: requestHash.payload.requestHash, committedAt: authorization.issuedAt as number,
          enforcement: { mode: "additive" as const, epoch: 0 as const },
        }, service.identity.personId, "RUSTY/2")
        return Response.json({ receipt })
      },
    })
    expect(sent?.version).toBe(1)
    expect(result.payload).toMatchObject({ kind: "rusty-identity-authority-receipt",
      authorityHead: view.revocationHead, viewDigest: view.viewDigest })
    expect(isRustyIdentityAuthorityStrict(result.payload.enforcement)).toBe(false)
  })

  it("Given a service response with a mismatched high-water receipt, when publishing, then do not report success", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const service = (await createRecoverableIdentity("better", "Rusty service")).profile
    const view = await createIdentityAuthorityView(identity.identity,
      { certificates: [identity.certificate], revocations: [] }, emptyIdentityProfileState(identity.identity.personId))
    await expect(publishRustyIdentityAuthorityView({
      origin: "https://rusty.example", servicePublicKey: service.identity.publicKey,
      identity: identity.identity, deviceId: identity.device.deviceId, devicePublicKey: identity.device.publicKey,
      view,
      signAuthorization: async payload => signEnvelope(identity.privateKeys.devicePrivateKey, payload,
        identity.device.deviceId, "MATCH/1"),
      fetcher: async () => Response.json({ receipt: await signEnvelope(service.privateKeys.identityPrivateKey!, {
        kind: "rusty-identity-authority-receipt" as const, version: 1 as const,
        serviceId: await publicKeyId(service.identity.publicKey), origin: "https://rusty.example",
        personId: identity.identity.personId, authorityHead: { revision: 1, recordHash: "A".repeat(43) },
        viewDigest: view.viewDigest, requestHash: "A".repeat(43), committedAt: Date.now(),
        enforcement: { mode: "additive" as const, epoch: 0 as const },
      }, service.identity.personId, "RUSTY/2") }),
    })).rejects.toThrow(/receipt|authority/i)
  })

  it("Given Rusty's ready authority state, when reading status, then verify nonce, exact request hash, and complete signed view", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const service = (await createRecoverableIdentity("better", "Rusty service")).profile
    const view = await createIdentityAuthorityView(identity.identity,
      { certificates: [identity.certificate], revocations: [] }, emptyIdentityProfileState(identity.identity.personId))
    let requestedUrl = ""
    const status = await readRustyIdentityAuthorityStatus({
      origin: "https://rusty.example", servicePublicKey: service.identity.publicKey, identity: identity.identity,
      now: () => 10_000,
      fetcher: async input => {
        requestedUrl = String(input)
        const url = new URL(requestedUrl)
        const nonce = url.searchParams.get("nonce")!
        const path = `${url.pathname}${url.search}`
        const requestHash = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson({ method: "GET", path })))
        return Response.json({ status: await signEnvelope(service.privateKeys.identityPrivateKey!, {
          kind: "rusty-identity-authority-status" as const, version: 1 as const,
          serviceId: await publicKeyId(service.identity.publicKey), origin: "https://rusty.example",
          personId: identity.identity.personId, state: "ready" as const,
          requestNonce: nonce, requestHash, issuedAt: 10_000, view,
          enforcement: { mode: "strict" as const, epoch: 1 as const },
        }, service.identity.personId, "RUSTY/2") })
      },
    })
    expect(new URL(requestedUrl).pathname).toBe(`/v2/identity/authority/${identity.identity.personId}/status`)
    expect(new URL(requestedUrl).searchParams.get("nonce")).toMatch(/^[A-Za-z0-9_-]{43}$/u)
    expect(status.payload.state).toBe("ready")
    expect(status.payload.view).toMatchObject({ personId: identity.identity.personId, revocationHead: view.revocationHead })
    expect(isRustyIdentityAuthorityStrict(status.payload.enforcement)).toBe(true)
  })

  it("Given a signed but inconsistent enforcement marker, when reading status, then reject it", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const service = (await createRecoverableIdentity("better", "Rusty service")).profile
    await expect(readRustyIdentityAuthorityStatus({
      origin: "https://rusty.example", servicePublicKey: service.identity.publicKey, identity: identity.identity,
      now: () => 10_000,
      fetcher: async input => {
        const url = new URL(String(input))
        const path = `${url.pathname}${url.search}`
        const requestHash = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson({ method: "GET", path })))
        return Response.json({ status: await signEnvelope(service.privateKeys.identityPrivateKey!, {
          kind: "rusty-identity-authority-status" as const, version: 1 as const,
          serviceId: await publicKeyId(service.identity.publicKey), origin: "https://rusty.example",
          personId: identity.identity.personId, state: "missing" as const,
          requestNonce: url.searchParams.get("nonce")!, requestHash, issuedAt: 10_000, view: null,
          enforcement: { mode: "strict" as const, epoch: 0 as const },
        }, service.identity.personId, "RUSTY/2") })
      },
    })).rejects.toThrow(/match this request/i)
  })

  it("Given no Rusty authority record, when status returns a signed missing state, then preserve missing as explicit state", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const service = (await createRecoverableIdentity("better", "Rusty service")).profile
    const status = await readRustyIdentityAuthorityStatus({
      origin: "https://rusty.example", servicePublicKey: service.identity.publicKey, identity: identity.identity,
      now: () => 10_000,
      fetcher: async input => {
        const url = new URL(String(input))
        const path = `${url.pathname}${url.search}`
        const requestHash = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson({ method: "GET", path })))
        return Response.json({ status: await signEnvelope(service.privateKeys.identityPrivateKey!, {
          kind: "rusty-identity-authority-status" as const, version: 1 as const,
          serviceId: await publicKeyId(service.identity.publicKey), origin: "https://rusty.example",
          personId: identity.identity.personId, state: "missing" as const,
          requestNonce: url.searchParams.get("nonce")!, requestHash, issuedAt: 10_000, view: null,
          enforcement: { mode: "additive" as const, epoch: 0 as const },
        }, service.identity.personId, "RUSTY/2") })
      },
    })
    expect(status.payload).toMatchObject({ state: "missing", view: null })
  })

  it("Given a signed status with the wrong request nonce, when reading, then reject instead of treating it as current", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const service = (await createRecoverableIdentity("better", "Rusty service")).profile
    await expect(readRustyIdentityAuthorityStatus({
      origin: "https://rusty.example", servicePublicKey: service.identity.publicKey, identity: identity.identity,
      now: () => 10_000,
      fetcher: async input => {
        const url = new URL(String(input))
        const path = `${url.pathname}${url.search}`
        const requestHash = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson({ method: "GET", path })))
        return Response.json({ status: await signEnvelope(service.privateKeys.identityPrivateKey!, {
          kind: "rusty-identity-authority-status" as const, version: 1 as const,
          serviceId: await publicKeyId(service.identity.publicKey), origin: "https://rusty.example",
          personId: identity.identity.personId, state: "missing" as const,
          requestNonce: "A".repeat(43), requestHash, issuedAt: 10_000, view: null,
          enforcement: { mode: "additive" as const, epoch: 0 as const },
        }, service.identity.personId, "RUSTY/2") })
      },
    })).rejects.toThrow(/match this request/i)
  })

  it("Given a stale PUT, when Rusty returns a signed current view bound to that PUT, then expose verified view for merge and retry", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const service = (await createRecoverableIdentity("better", "Rusty service")).profile
    const view = await createIdentityAuthorityView(identity.identity,
      { certificates: [identity.certificate], revocations: [] }, emptyIdentityProfileState(identity.identity.personId))
    let staleError: unknown
    try { await publishRustyIdentityAuthorityView({
      origin: "https://rusty.example", servicePublicKey: service.identity.publicKey,
      identity: identity.identity, deviceId: identity.device.deviceId, devicePublicKey: identity.device.publicKey,
      view, now: () => 10_000,
      signAuthorization: async payload => signEnvelope(identity.privateKeys.devicePrivateKey!, payload,
        identity.device.deviceId, "MATCH/1"),
      fetcher: async (_input, init) => {
        const request = JSON.parse(String(init?.body)) as { authorization: { payload: { nonce: string; requestHash: string } } }
        const status = await signEnvelope(service.privateKeys.identityPrivateKey!, {
          kind: "rusty-identity-authority-status" as const, version: 1 as const,
          serviceId: await publicKeyId(service.identity.publicKey), origin: "https://rusty.example",
          personId: identity.identity.personId, state: "ready" as const,
          requestNonce: request.authorization.payload.nonce, requestHash: request.authorization.payload.requestHash,
          issuedAt: 10_000, view, enforcement: { mode: "strict" as const, epoch: 1 as const },
        }, service.identity.personId, "RUSTY/2")
        return Response.json({ code: "identity_authority_stale", message: "stale", authorityStatus: status }, { status: 409 })
      },
    }) } catch (cause) { staleError = cause }
    expect(staleError).toBeInstanceOf(RustyIdentityAuthorityStaleError)
    expect(staleError).toMatchObject({ view: { personId: identity.identity.personId, revocationHead: view.revocationHead } })
  })

  it("Given a stale PUT response bound to another request, when publishing, then reject it without exposing a view", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const service = (await createRecoverableIdentity("better", "Rusty service")).profile
    const view = await createIdentityAuthorityView(identity.identity,
      { certificates: [identity.certificate], revocations: [] }, emptyIdentityProfileState(identity.identity.personId))
    await expect(publishRustyIdentityAuthorityView({
      origin: "https://rusty.example", servicePublicKey: service.identity.publicKey,
      identity: identity.identity, deviceId: identity.device.deviceId, devicePublicKey: identity.device.publicKey,
      view,
      signAuthorization: async payload => signEnvelope(identity.privateKeys.devicePrivateKey!, payload,
        identity.device.deviceId, "MATCH/1"),
      fetcher: async () => Response.json({ code: "identity_authority_stale", message: "stale",
        authorityStatus: await signEnvelope(service.privateKeys.identityPrivateKey!, {
          kind: "rusty-identity-authority-status" as const, version: 1 as const,
          serviceId: await publicKeyId(service.identity.publicKey), origin: "https://rusty.example",
          personId: identity.identity.personId, state: "ready" as const,
          requestNonce: "A".repeat(43), requestHash: "B".repeat(43), issuedAt: Date.now(), view,
          enforcement: { mode: "strict" as const, epoch: 1 as const },
        }, service.identity.personId, "RUSTY/2") }, { status: 409 }),
    })).rejects.toThrow(/stale-authority response/i)
  })

  it("Given an active app-only Identity device, when relaying a root-signed current view, then permit publication without manager rights", async () => {
    const identity = (await createRecoverableIdentity("better", "Owner")).profile
    const app = await createIdentityEnrollmentDevice("App relay")
    const appCertificate = await signEnvelope(identity.privateKeys.identityPrivateKey!, {
      kind: "device-certificate" as const, version: 1 as const, personId: identity.identity.personId,
      deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey,
      issuerCertificateHash: null, canEnrollDevices: false,
    }, identity.identity.personId)
    const certificates: DeviceCertificate[] = [identity.certificate, appCertificate]
    const view = await createIdentityAuthorityView(identity.identity, { certificates, revocations: [] },
      emptyIdentityProfileState(identity.identity.personId))
    const service = (await createRecoverableIdentity("better", "Rusty service")).profile
    const receipt = await publishRustyIdentityAuthorityView({
      origin: "https://rusty.example", servicePublicKey: service.identity.publicKey,
      identity: identity.identity, deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey,
      view, now: () => 10_000,
      signAuthorization: async payload => signEnvelope(app.privateKey, payload, app.device.deviceId, "MATCH/1"),
      fetcher: async (_input, init) => {
        const posted = JSON.parse(String(init?.body)) as { authorization: { payload: { requestHash: string; issuedAt: number } } }
        return Response.json({ receipt: await signEnvelope(service.privateKeys.identityPrivateKey!, {
          kind: "rusty-identity-authority-receipt" as const, version: 1 as const,
          serviceId: await publicKeyId(service.identity.publicKey), origin: "https://rusty.example",
          personId: identity.identity.personId, authorityHead: view.revocationHead,
          viewDigest: view.viewDigest, requestHash: posted.authorization.payload.requestHash,
          committedAt: posted.authorization.payload.issuedAt,
          enforcement: { mode: "strict" as const, epoch: 1 as const },
        }, service.identity.personId, "RUSTY/2") })
      },
    })
    expect(receipt.payload).toMatchObject({ personId: identity.identity.personId, authorityHead: view.revocationHead })
  })
})
