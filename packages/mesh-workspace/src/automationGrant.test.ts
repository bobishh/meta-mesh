import { expect, it } from "vitest"
import { BrowserIdentityStore, signEnvelope, verifyEnvelope } from "@meta-uber/mesh-identity"
import { createAutomationWorkspaceGrant, parseAutomationGrantScope } from "./automationGrant"
import { verifyWorkspaceGrant } from "./index"

const scope = () => ({ version: 2 as const, boardId: "board", columns: {
  lead: "lead", applied: "applied", interview: "interview", rejected: "rejected",
}, fieldIds: ["company", "source"], expiresAt: Date.now() + 60_000 })

it("Given an approved scope and retained grant ID, when signing twice, then issue identical grants without changing permissions", async () => {
  const owner = await new BrowserIdentityStore({ storageKey: crypto.randomUUID(), signatureDomain: "MATCH/1" }).bootstrap("Owner")
  const intent = { workspaceId: "workspace", personId: "automation-person", scope: scope(), grantId: crypto.randomUUID() }
  const first = await createAutomationWorkspaceGrant(owner, intent)
  const second = await createAutomationWorkspaceGrant(owner, intent)
  expect(first).toEqual(second)
  expect(first.payload.automation).toEqual(intent.scope)
  expect(first.payload.role).toBe("automation")
  expect(await verifyEnvelope(first, owner.device.publicKey)).toBe(true)
  const authority = { workspaceId: intent.workspaceId, personId: intent.personId,
    ownerPersonId: owner.identity.personId, ownerPublicKey: owner.identity.publicKey,
    ownerCertificates: [owner.certificate] }
  await expect(verifyWorkspaceGrant(first, authority)).resolves.toBe("automation")
  const forged = structuredClone(first)
  forged.payload.automation!.fieldIds.push("not-approved")
  await expect(verifyWorkspaceGrant(forged, authority)).rejects.toThrow()
  intent.scope.fieldIds.push("not-approved")
  expect(first.payload.automation!.fieldIds).toEqual(["company", "source"])
})

it("Given bounded protocol scopes, when parsing repeatedly, then preserve exact scope and reject every added key", () => {
  for (const version of [1, 2] as const) for (const fieldCount of [0, 1, 127, 128]) {
    const input = { ...scope(), version, fieldIds: Array.from({ length: fieldCount }, (_, i) => `field-${i}`) }
    expect(parseAutomationGrantScope(parseAutomationGrantScope(input))).toEqual(input)
    expect(() => parseAutomationGrantScope({ ...input, extra: true })).toThrow()
    expect(() => parseAutomationGrantScope({ ...input, columns: { ...input.columns, extra: "other" } })).toThrow()
  }
  const input = scope()
  for (const invalid of [
    { ...input, expiresAt: 0 },
    { ...input, fieldIds: ["same", "same"] },
    { ...input, fieldIds: Array.from({ length: 129 }, (_, i) => `field-${i}`) },
    { ...input, columns: { ...input.columns, rejected: input.columns.lead } },
  ]) expect(() => parseAutomationGrantScope(invalid)).toThrow()
})

it("Given a signer that broadens the requested scope, when issuing a grant, then reject the changed signed payload", async () => {
  const owner = await new BrowserIdentityStore({ storageKey: crypto.randomUUID(), signatureDomain: "MATCH/1" }).bootstrap("Owner")
  await expect(createAutomationWorkspaceGrant(owner, {
    workspaceId: "workspace", personId: "automation-person", scope: scope(),
  }, {
    personId: owner.identity.personId, deviceId: owner.device.deviceId, publicKey: owner.identity.publicKey,
    certificates: [owner.certificate],
    sign: payload => signEnvelope(owner.privateKeys.devicePrivateKey, {
      ...payload, automation: { ...scope(), fieldIds: ["not-approved"] },
    }, owner.device.deviceId),
  })).rejects.toThrow(/authorization/i)
})
