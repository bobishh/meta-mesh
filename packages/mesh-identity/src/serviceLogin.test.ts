import { describe, expect, it } from "vitest"
import {
  assertServiceLoginRequest,
  createServiceLoginApproval,
  parseServiceLoginRequest,
  serviceLoginPayload,
  snapshotServiceLoginRequest,
  createRecoverableIdentity,
  verifyEnvelope,
  type ServiceLoginApproval,
  type ServiceLoginRequest,
} from "./index"
import { serviceLoginApprovalReturnUrl } from "./serviceLoginBrowser"
import { beginServiceLogin, captureServiceLoginCallback } from "./serviceLoginBrowser"

const request: ServiceLoginRequest = {
  kind: "mesh-service-login-request",
  version: 2,
  origin: "https://boards.example",
  challenge: "a".repeat(64),
  expires_at: Math.floor(Date.now() / 1000) + 90,
  return_to: "https://boards.example/.well-known/mesh-service-login/callback",
}

function encode(value: unknown): string {
  return btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(value))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

describe("mesh service login", () => {
  it("Given an explicitly negotiated same-origin request, when parsed, then preserve its nonce binding", () => {
    expect(parseServiceLoginRequest(encode(request), Math.floor(Date.now() / 1000))).toEqual(request)
    expect(snapshotServiceLoginRequest(request)).toEqual(request)
    expect(serviceLoginPayload(request, Math.floor(Date.now() / 1000))).toMatchObject({ kind: "mesh-service-login", version: 1 })
  })

  it.each([
    ["wrong protocol", { ...request, kind: "tinsink-login" }],
    ["wrong version", { ...request, version: 1 }],
    ["HTTP remote origin", { ...request, origin: "http://boards.example" }],
    ["malformed nonce", { ...request, challenge: "too short" }],
    ["external callback", { ...request, return_to: "https://attacker.example/.well-known/mesh-service-login/callback" }],
    ["callback path override", { ...request, return_to: "https://boards.example/redirect?to=https://attacker.example" }],
  ])("Given %s, when parsed, then reject without legacy fallback", (_label, value) => {
    expect(() => parseServiceLoginRequest(encode(value), Math.floor(Date.now() / 1000))).toThrow()
  })

  it("Given a long lifetime, when parsed against the same clock, then reject without legacy fallback", () => {
    const now = Math.floor(Date.now() / 1000)
    const value = { ...request, expires_at: now + 121 }
    expect(() => parseServiceLoginRequest(encode(value), now)).toThrow()
  })

  it("Given a request-bound active profile, when approved, then emit only a short-lived service proof", async () => {
    const created = await createRecoverableIdentity("better", "Owner")
    const approval = await createServiceLoginApproval(created.profile, request)

    expect(approval.identity.personId).toBe(created.profile.identity.personId)
    expect(approval.proof.payload).toEqual({ kind: "mesh-service-login", version: 1,
      origin: request.origin, challenge: request.challenge,
      issuedAt: expect.any(Number), expiresAt: request.expires_at * 1000 })
    expect(await verifyEnvelope(approval.proof, created.profile.device.publicKey, "MESH-SERVICE-LOGIN/1")).toBe(true)
    expect(Object.keys(approval).sort()).toEqual(["certificates", "deviceId", "identity", "proof"])
    expect(Object.keys(approval.proof.payload).sort()).toEqual(["challenge", "expiresAt", "issuedAt", "kind", "origin", "version"])
  })

  it("Given an active signed approval, when returned, then encode it only for the fixed service callback", async () => {
    const created = await createRecoverableIdentity("better", "Owner")
    const approval = await createServiceLoginApproval(created.profile, request)
    const returned = new URL(serviceLoginApprovalReturnUrl(request, approval))

    expect(returned.origin).toBe(request.origin)
    expect(returned.pathname).toBe("/.well-known/mesh-service-login/callback")
    expect(returned.search).toBe("")
    expect(returned.hash).toContain("mesh_service_login_approval=")
  })

  it("Given a fresh server challenge, when login starts, then redirect this tab to Identity with only the request", async () => {
    const assigned: string[] = []
    const location = { assign: (url: string) => assigned.push(url) } as unknown as Location
    await beginServiceLogin(async () => ({ ...request, identity_origin: "https://identity.example" }), location)
    const target = new URL(assigned[0])

    expect(target.origin).toBe("https://identity.example")
    expect(target.pathname).toBe("/login")
    expect(parseServiceLoginRequest(target.hash.slice(1).replace(/^request=/u, ""), Math.floor(Date.now() / 1000)))
      .toMatchObject({ origin: request.origin, challenge: request.challenge, return_to: request.return_to })
  })

  it("Given a same-origin callback, when captured, then clear the proof fragment before exchanging it", async () => {
    const created = await createRecoverableIdentity("better", "Owner")
    const approval = await createServiceLoginApproval(created.profile, request)
    const callback = new URL(serviceLoginApprovalReturnUrl(request, approval))
    let cleanPath = ""
    const exchanged: { value?: { challenge: string; approval: ServiceLoginApproval } } = {}
    const history = { replaceState: (_state: unknown, _title: string, url?: string | URL | null) => { cleanPath = String(url) } } as unknown as History
    const captured = await captureServiceLoginCallback(async (challenge, evidence) => {
      expect(cleanPath).toBe("/.well-known/mesh-service-login/callback")
      exchanged.value = { challenge, approval: evidence }
    }, { href: callback.href, origin: callback.origin, pathname: callback.pathname, search: callback.search, hash: callback.hash } as Location, history)

    expect(captured).toBe(true)
    expect(exchanged.value?.challenge).toBe(request.challenge)
    expect(exchanged.value?.approval).toEqual(approval)
  })

  it("Given a stale or expired request, when approved, then refuse to sign", async () => {
    const created = await createRecoverableIdentity("better", "Owner")
    const expired = { ...request, expires_at: Math.floor(Date.now() / 1000) - 1 }
    await expect(createServiceLoginApproval(created.profile, expired)).rejects.toThrow(/expired/i)
    const overlong = { ...request, expires_at: Math.floor(Date.now() / 1000) + 121 }
    await expect(createServiceLoginApproval(created.profile, overlong)).rejects.toThrow(/invalid|expired/i)

    expect(() => assertServiceLoginRequest({ ...request, challenge: "b".repeat(64) }, request))
      .toThrow(/changed/i)
  })

  it("Given an attempted reusable credential in a login request, when parsed, then reject it", () => {
    expect(() => parseServiceLoginRequest(encode({ ...request, deviceAuthorizationRequest: {} }),
      Math.floor(Date.now() / 1000))).toThrow()
  })
})
