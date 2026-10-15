import { expect, it } from "vitest"
import { BrowserIdentityStore, signEnvelope } from "@meta-uber/mesh-identity"
import { BLOB_SIGNATURE_DOMAIN, createBlobRequest, verifyBlobRequest, type BlobRequestSigner } from "./index"

it("Given an injected blob signer, when requesting a chunk, then preserve the signed protocol fields and domain", async () => {
  const profile = await new BrowserIdentityStore({ storageKey: "blob-signing-port" }).bootstrap("Reader")
  let calls = 0
  const signing: BlobRequestSigner = { personId: profile.identity.personId, deviceId: profile.device.deviceId,
    sign: async payload => { calls += 1
      return signEnvelope(profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId, BLOB_SIGNATURE_DOMAIN)
    } }
  const request = await createBlobRequest(profile, "workspace", `sha256:${"A".repeat(43)}`, 12, 32, Date.now(), signing)
  expect(calls).toBe(1)
  expect(request.payload).toMatchObject({ conversationId: "workspace", offset: 12, length: 32,
    requesterPersonId: profile.identity.personId, requesterDeviceId: profile.device.deviceId })
  expect(await verifyBlobRequest(request, profile.identity, [profile.certificate], "workspace")).toEqual(request)
})

it("Given a signer for another device, when creating a blob request, then reject before invoking that signer", async () => {
  const profile = await new BrowserIdentityStore({ storageKey: "blob-signing-mismatch" }).bootstrap("Reader")
  let called = false
  await expect(createBlobRequest(profile, "workspace", `sha256:${"A".repeat(43)}`, 0, 32, Date.now(), {
    personId: profile.identity.personId, deviceId: "another-device", sign: async () => { called = true; throw new Error("Unexpected signing") },
  })).rejects.toThrow(/signer.*device|profile/i)
  expect(called).toBe(false)
})
