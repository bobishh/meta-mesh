import { expect, it } from "vitest"
import { BrowserIdentityStore, signEnvelope } from "@meta-uber/mesh-identity"
import { createWorkspaceDeviceRevocation, createWorkspaceOwnershipTransfer, createPeerAdvertisement } from "./index"
import type { WorkspaceRecordSigner } from "./signing"

it("Given an injected verified signer, when creating a workspace route and device revocation, then use its signing boundary and retained certificate chain", async () => {
  const profile = await new BrowserIdentityStore({ storageKey: "record-signer-port" }).bootstrap("Owner")
  const signedKinds: string[] = []
  const signer: WorkspaceRecordSigner = { personId: profile.identity.personId, deviceId: profile.device.deviceId,
    publicKey: profile.identity.publicKey, certificates: [profile.certificate], sign: async payload => {
      signedKinds.push(payload.kind)
      return signEnvelope(profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId)
    } }
  const route = await createPeerAdvertisement(profile, "workspace", "endpoint", { signing: signer })
  const removed = await createWorkspaceDeviceRevocation(profile, "workspace", "member", "device", ["head"], [], signer)
  expect(signedKinds).toEqual(["peer-advertisement", "workspace-device-revocation"])
  expect(route.certificates).toEqual(signer.certificates)
  expect(removed.authority.certificates).toEqual(signer.certificates)
})

it("Given ownership transfer signing, when constructing embedded grants, then every signature crosses the same injected boundary", async () => {
  const owner = await new BrowserIdentityStore({ storageKey: "transfer-owner" }).bootstrap("Owner")
  const target = await new BrowserIdentityStore({ storageKey: "transfer-target" }).bootstrap("Target")
  const kinds: string[] = []
  const signer: WorkspaceRecordSigner = { personId: owner.identity.personId, deviceId: owner.device.deviceId,
    publicKey: owner.identity.publicKey, certificates: [owner.certificate], sign: async payload => {
      kinds.push(payload.kind)
      return signEnvelope(owner.privateKeys.devicePrivateKey, payload, owner.device.deviceId)
    } }
  await createWorkspaceOwnershipTransfer(owner, "workspace", { personId: target.identity.personId,
    publicKey: target.identity.publicKey, certificates: [target.certificate] }, ["head"], 2, new Date().toISOString(), signer)
  expect(kinds).toEqual(["workspace-grant", "workspace-grant", "workspace-ownership-transfer"])
})

it("Given a route signature in flight, when caller-owned profile and certificate arrays change, then preserve the captured author and public evidence", async () => {
  const owner = await new BrowserIdentityStore({ storageKey: "route-capture-owner" }).bootstrap("Owner")
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  let release!: () => void
  const gate = new Promise<void>(resolve => { release = resolve })
  const personId = owner.identity.personId
  const publicKey = owner.identity.publicKey
  const signer: WorkspaceRecordSigner = { personId, deviceId: owner.device.deviceId, publicKey,
    certificates: [owner.certificate], sign: async payload => {
      entered(); await gate
      return signEnvelope(owner.privateKeys.devicePrivateKey, payload, owner.device.deviceId)
    } }
  const routePromise = createPeerAdvertisement(owner, "workspace", "endpoint", { signing: signer })
  await started
  owner.identity.personId = "changed-person"
  owner.identity.publicKey = "changed-key"
  release()
  const route = await routePromise
  expect(route.publicKey).toBe(publicKey)
  expect(route.advertisement.payload.personId).toBe(personId)
})
