import { describe, expect, it } from "vitest"
import { createRecoverableIdentity, createIdentityAuthorityView, emptyIdentityProfileState,
  publicKeyId, signEnvelope, type IdentityAuthorityView } from "@meta-uber/mesh-identity"
import { publishRustyIdentityAuthorityView } from "./rustyIdentityAuthority"

describe("Rusty Identity authority high-water update", () => {
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
        }, service.identity.personId, "RUSTY/2")
        return Response.json(receipt)
      },
    })
    expect(sent?.version).toBe(1)
    expect(result.payload).toMatchObject({ kind: "rusty-identity-authority-receipt",
      authorityHead: view.revocationHead, viewDigest: view.viewDigest })
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
      fetcher: async () => Response.json(await signEnvelope(service.privateKeys.identityPrivateKey!, {
        kind: "rusty-identity-authority-receipt" as const, version: 1 as const,
        serviceId: await publicKeyId(service.identity.publicKey), origin: "https://rusty.example",
        personId: identity.identity.personId, authorityHead: { revision: 1, recordHash: "A".repeat(43) },
        viewDigest: view.viewDigest, requestHash: "A".repeat(43), committedAt: Date.now(),
      }, service.identity.personId, "RUSTY/2")),
    })).rejects.toThrow(/receipt|authority/i)
  })
})
