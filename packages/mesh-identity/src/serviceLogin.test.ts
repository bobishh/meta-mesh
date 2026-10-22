import { describe, expect, it } from "vitest"
import {
  assertServiceLoginSession,
  createServiceLoginApproval,
  parseServiceLoginRequest,
  serviceLoginPayload,
  snapshotServiceLoginRequest,
  createRecoverableIdentity,
  verifyEnvelope,
  type ServiceLoginRequest,
} from "./index"

const request: ServiceLoginRequest = {
  kind: "mesh-service-login-request",
  version: 1,
  origin: "https://boards.example",
  challenge: "a".repeat(64),
  expires_at: Math.floor(Date.now() / 1000) + 90,
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
    ["wrong version", { ...request, version: 2 }],
    ["HTTP remote origin", { ...request, origin: "http://boards.example" }],
    ["malformed nonce", { ...request, challenge: "too short" }],
    ["long lifetime", { ...request, expires_at: Math.floor(Date.now() / 1000) + 121 }],
  ])("Given %s, when parsed, then reject without legacy fallback", (_label, value) => {
    expect(() => parseServiceLoginRequest(encode(value), Math.floor(Date.now() / 1000))).toThrow()
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

  it("Given a stale or expired request, when approved, then refuse to sign", async () => {
    const created = await createRecoverableIdentity("better", "Owner")
    const expired = { ...request, expires_at: Math.floor(Date.now() / 1000) - 1 }
    await expect(createServiceLoginApproval(created.profile, expired)).rejects.toThrow(/expired/i)
    const overlong = { ...request, expires_at: Math.floor(Date.now() / 1000) + 121 }
    await expect(createServiceLoginApproval(created.profile, overlong)).rejects.toThrow(/invalid|expired/i)

    const opener = {} as Window
    expect(() => assertServiceLoginSession({ ...request, challenge: "b".repeat(64) }, request, opener, opener))
      .toThrow(/changed/i)
  })

  it("Given an attempted reusable credential in a login request, when parsed, then reject it", () => {
    expect(() => parseServiceLoginRequest(encode({ ...request, deviceAuthorizationRequest: {} }),
      Math.floor(Date.now() / 1000))).toThrow()
  })
})
