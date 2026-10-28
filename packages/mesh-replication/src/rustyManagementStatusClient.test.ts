import { expect, it, vi } from "vitest"
import { BrowserIdentityStore, canonicalizeJson, publicKeyId, sha256Base64Url, signEnvelope } from "@meta-uber/mesh-identity"
import { requestRustyManagementStatus, type ManagementStatusAuthorization } from "./rustyManagementStatus"

async function fixture() {
  const values = new Map<string, string>()
  const profile = await new BrowserIdentityStore({ storageKey: "status-client-owner", storage: {
    getItem: key => values.get(key) ?? null, setItem: (key, value) => { values.set(key, value) },
    removeItem: key => { values.delete(key) },
  } }).bootstrap("Status owner")
  const service = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])
  const servicePublicKey = Buffer.from(await crypto.subtle.exportKey("raw", service.publicKey)).toString("base64url")
  const serviceId = await publicKeyId(servicePublicKey)
  const binding = { origin: "https://status.example/", servicePublicKey, resourceKind: "person" as const,
    resourceId: profile.identity.personId }
  const signAuthorization = (payload: ManagementStatusAuthorization) => signEnvelope(profile.privateKeys.devicePrivateKey,
    payload, profile.device.deviceId)
  const fetcher = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body))
    const authorization = request.authorization
    const { kind: _kind, expiresAt: _expiresAt, ...binding } = authorization.payload
    const receipt = await signEnvelope(service.privateKey, { kind: "rusty-management-policy-status-receipt", version: 1,
      ...binding, authorizationHash: await sha256Base64Url(
        new TextEncoder().encode(canonicalizeJson(authorization))), capabilityHash: null, revision: 0,
      migrationPending: false, issuedAt: Date.now() }, serviceId, "RUSTY/2")
    return Response.json({ capability: null, migrationPending: false, receipt })
  })
  const options = { binding, identity: profile.identity, deviceId: profile.device.deviceId, devicePublicKey: profile.device.publicKey,
    certificates: [profile.certificate], minimumRevision: 0, ensureCurrent: () => {}, signAuthorization, fetcher }
  return { options, fetcher, profile, signAuthorization }
}

it("Given a pinned management service, when requesting signed status, then normalize and verify one read without provisioning policies", async () => {
  const f = await fixture()
  const result = await requestRustyManagementStatus(f.options)
  expect(result.verified).toEqual({ capability: null, revision: 0, migrationPending: false })
  expect(f.fetcher).toHaveBeenCalledOnce()
  const [url, init] = f.fetcher.mock.calls[0]!
  expect(url).toBe(`https://status.example/v2/management/person/${f.profile.identity.personId}/status`)
  expect(init?.method).toBe("POST")
  expect(Object.keys(JSON.parse(String(init?.body))).sort()).toEqual(["authorization", "certificates", "deviceId", "identity", "version"])
})

it("Given a signer returning a different resource binding, when requesting status, then reject before sending", async () => {
  const f = await fixture()
  await expect(requestRustyManagementStatus({ ...f.options, signAuthorization: payload =>
    f.signAuthorization({ ...payload, resourceId: "other-resource" }) })).rejects.toThrow(/binding|authorization/i)
  expect(f.fetcher).not.toHaveBeenCalled()
})

it("Given a saved revision floor, when Rusty returns a signed empty policy, then reject rollback", async () => {
  const f = await fixture()
  await expect(requestRustyManagementStatus({ ...f.options, minimumRevision: 1 })).rejects.toThrow(/missing|rolled back/i)
})

it("Given a status reply lost after the server reads it, when explicitly retried, then use a fresh nonce and perform only status reads", async () => {
  const f = await fixture(), read = f.fetcher.getMockImplementation()!
  f.fetcher.mockImplementationOnce(async (url, init) => { await (await read(url, init)).body?.cancel(); throw new Error("Lost status reply") })
  await expect(requestRustyManagementStatus(f.options)).rejects.toThrow("Lost status reply")
  await expect(requestRustyManagementStatus(f.options)).resolves.toMatchObject({ verified: { revision: 0 } })
  const requests = f.fetcher.mock.calls.map(([, init]) => JSON.parse(String(init?.body)))
  expect(requests[0].authorization.payload.requestId).not.toBe(requests[1].authorization.payload.requestId)
  expect(f.fetcher.mock.calls.every(([url, init]) => String(url).endsWith("/status") && init?.method === "POST")).toBe(true)
})
