import { describe, expect, it } from "vitest"
import { createRecoverableIdentity, createServiceLoginApproval } from "./index"
import { createServiceLoginRequest, verifyServiceLoginApproval } from "./serviceLoginClient"

describe("session-only Identity login client", () => {
  it("Given a fresh application browser without local identity, when it starts login, then request only a short session", () => {
    const request = createServiceLoginRequest("https://boards.example")
    expect(Object.keys(request).sort()).toEqual(["challenge", "expires_at", "kind", "origin", "return_to", "version"])
    expect(request.return_to).toBe("https://boards.example/.well-known/mesh-service-login/callback")
    expect(request.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000))
    expect(request.expires_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 120)
  })

  it("Given an approved login, when consumed, then receive no reusable application signing credential", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const request = createServiceLoginRequest("https://boards.example")
    const approval = await createServiceLoginApproval(owner, request)
    const accepted = await verifyServiceLoginApproval(approval, request)

    expect(accepted.identity.personId).toBe(owner.identity.personId)
    expect(Object.keys(accepted).sort()).toEqual(["certificates", "deviceId", "identity", "proof"])
    expect(accepted).not.toHaveProperty("deviceCertificate")
    expect(accepted).not.toHaveProperty("deviceAuthorizationRequest")
  })

  it("Given another nonce, origin, expired response, or injected app credential, when consumed, then reject", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const request = createServiceLoginRequest("https://boards.example")
    const approval = await createServiceLoginApproval(owner, request)
    await expect(verifyServiceLoginApproval(approval, { ...request, challenge: "b".repeat(64) })).rejects.toThrow()
    await expect(verifyServiceLoginApproval(approval, { ...request, origin: "https://other.example" })).rejects.toThrow()
    await expect(verifyServiceLoginApproval({ ...approval, deviceCertificate: owner.certificate }, request)).rejects.toThrow()
    await expect(verifyServiceLoginApproval(approval, request, { now: () => request.expires_at * 1000 })).rejects.toThrow()
    await expect(verifyServiceLoginApproval({ ...approval, proof: { ...approval.proof, signature: "bad" } }, request))
      .rejects.toThrow()
  })
})
