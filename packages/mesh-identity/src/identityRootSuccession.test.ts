import { describe, expect, it } from "vitest"
import { createIdentityAuthorityView, createRecoverableIdentity, signEnvelope, type DeviceCertificate } from "./index"
import { createIdentityRootSuccession, verifyIdentityRootSuccession } from "./identityRootSuccession"

describe("Identity root succession", () => {
  it("Given a verified old authority and a new recovery root, when both roots approve succession, then bind the exact old and new identities", async () => {
    const previous = (await createRecoverableIdentity("better", "Current owner")).profile
    const successor = (await createRecoverableIdentity("better", "Successor")).profile
    const authority = await createIdentityAuthorityView(previous.identity,
      { certificates: [previous.certificate], revocations: [] }, { version: 1, personId: previous.identity.personId, operations: [], legacy: [] })

    const succession = await createIdentityRootSuccession(previous, successor, authority)
    await expect(verifyIdentityRootSuccession(succession, authority)).resolves.toMatchObject({
      previousPersonId: previous.identity.personId,
      successorPersonId: successor.identity.personId,
      authorityHead: authority.revocationHead,
      authorityViewDigest: authority.viewDigest,
    })
  })

  it("Given a different successor root or authority view, when verifying succession, then reject it", async () => {
    const previous = (await createRecoverableIdentity("better", "Current owner")).profile
    const successor = (await createRecoverableIdentity("better", "Successor")).profile
    const other = (await createRecoverableIdentity("better", "Other")).profile
    const authority = await createIdentityAuthorityView(previous.identity,
      { certificates: [previous.certificate], revocations: [] }, { version: 1, personId: previous.identity.personId, operations: [], legacy: [] })
    const otherAuthority = await createIdentityAuthorityView(other.identity,
      { certificates: [other.certificate], revocations: [] }, { version: 1, personId: other.identity.personId, operations: [], legacy: [] })
    const succession = await createIdentityRootSuccession(previous, successor, authority)

    await expect(verifyIdentityRootSuccession(succession, otherAuthority)).rejects.toThrow(/authority|identity/i)
    const substituted = structuredClone(succession)
    substituted.acceptance = await signEnvelope(other.privateKeys.identityPrivateKey!, {
      kind: "mesh-identity-root-succession-acceptance", version: 1,
      successionHash: succession.acceptance.payload.successionHash,
      previousPersonId: previous.identity.personId,
      successorPersonId: successor.identity.personId,
    }, other.identity.personId, "MESH-IDENTITY-ROOT-SUCCESSION/1")
    await expect(verifyIdentityRootSuccession(substituted, authority)).rejects.toThrow(/accept|successor|signature/i)
  })

  it("Given certificate growth without a revocation, when verifying a stale succession view, then reject the stale catalog digest", async () => {
    const previous = (await createRecoverableIdentity("better", "Current owner")).profile
    const successor = (await createRecoverableIdentity("better", "Successor")).profile
    const added = (await createRecoverableIdentity("better", "New device")).profile
    const authority = await createIdentityAuthorityView(previous.identity,
      { certificates: [previous.certificate], revocations: [] }, { version: 1, personId: previous.identity.personId, operations: [], legacy: [] })
    const successorProof = await createIdentityRootSuccession(previous, successor, authority)
    const additional = await signEnvelope(previous.privateKeys.identityPrivateKey!, {
      kind: "device-certificate" as const, version: 1 as const, personId: previous.identity.personId,
      deviceId: added.device.deviceId, devicePublicKey: added.device.publicKey,
      issuerCertificateHash: null, canEnrollDevices: true,
    }, previous.identity.personId)
    const changedCatalog = await createIdentityAuthorityView(previous.identity,
      { certificates: [previous.certificate, additional as DeviceCertificate], revocations: [] },
      { version: 1, personId: previous.identity.personId, operations: [], legacy: [] })

    expect(changedCatalog.revocationHead).toEqual(authority.revocationHead)
    expect(changedCatalog.viewDigest).not.toBe(authority.viewDigest)
    await expect(verifyIdentityRootSuccession(successorProof, changedCatalog)).rejects.toThrow(/authority|view/i)
  })
})
