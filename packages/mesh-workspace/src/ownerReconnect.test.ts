import * as Automerge from "@automerge/automerge"
import { describe, expect, it } from "vitest"
import { BrowserIdentityStore, canonicalizeJson, createIdentityAuthorityView, emptyIdentityProfileState,
  sha256Base64Url, signEnvelope, toBase64Url, type LocalProfile } from "@meta-uber/mesh-identity"
import { createOwnerReconnectInvite } from "@meta-uber/mesh-pairing"
import type { WorkspaceAuthority } from "./index"
import {
  createOwnerReconnectApproval, createOwnerReconnectChallenge, createOwnerReconnectHello,
  createOwnerReconnectOffer, decodeOwnerReconnectMessage, encodeOwnerReconnectMessage,
  ownerReconnectAuthenticatedPeer, verifyOwnerReconnectOffer,
  type OwnerReconnectOffer, type OwnerReconnectSession, type OwnerReconnectSourceState,
} from "./ownerReconnect"

const authority = (profile: LocalProfile): WorkspaceAuthority => ({ personId: profile.identity.personId,
  publicKey: profile.identity.publicKey, certificates: [profile.certificate] })

async function profile(name: string) {
  return new BrowserIdentityStore({ storageKey: crypto.randomUUID(), signatureDomain: "MATCH/1" }).bootstrap(name)
}

async function fixture() {
  const owner = await profile("Bo")
  const source = await profile("Ray")
  const workspaceId = "existing-job-workspace"
  const scopeId = "existing-rusty-scope"
  const doc = Automerge.from({ id: workspaceId, ownerPersonId: owner.identity.personId, title: "Existing workspace" })
  const document = Automerge.save(doc)
  const head = Automerge.getHeads(doc)[0]!
  const record = { signed: await signEnvelope(owner.privateKeys.devicePrivateKey, {
    kind: "workspace-changes", version: 1, workspaceId, hashes: [head], personId: owner.identity.personId,
    deviceId: owner.device.deviceId,
  }, owner.device.deviceId), publicKey: owner.identity.publicKey, certificates: [owner.certificate] }
  const ownerAuthority = authority(owner)
  const workspaceAuthority = { genesisOwner: ownerAuthority, genesisEpoch: 1, currentOwner: ownerAuthority, currentEpoch: 1,
    ownershipTransfers: [], successionClaims: [], revocations: [], deviceRevocations: [], departures: [] }
  const grant = await (await import("./index")).createWorkspaceGrant(owner, workspaceId, source.identity.personId, "editor")
  const grantHash = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(grant)))
  const changed = Automerge.change(Automerge.clone(doc), { message: JSON.stringify({ kind: "workspace-change-metadata", version: 1,
    personId: source.identity.personId, deviceId: source.device.deviceId, authorityGrantHash: grantHash }) }, draft => {
      draft.title = "Ray edit"
    })
  const changedBytes = Automerge.save(changed)
  const changedHead = Automerge.getHeads(changed)[0]!
  const memberRecord = { signed: await signEnvelope(source.privateKeys.devicePrivateKey, {
    kind: "workspace-changes", version: 1, workspaceId, hashes: [changedHead], personId: source.identity.personId,
    deviceId: source.device.deviceId,
  }, source.device.deviceId), publicKey: source.identity.publicKey, certificates: [source.certificate], grant }
  const scopeAuthoritySnapshot = {
    genesis: await signEnvelope(owner.privateKeys.devicePrivateKey, { kind: "scope-genesis", version: 1, scopeId: workspaceId,
      creator: ownerAuthority, controlEpoch: 1 }, owner.device.deviceId),
    grants: [], grantIssuers: [], revocations: [], controlTransfers: [], successionTransfers: [],
  }
  const ownerView = await createIdentityAuthorityView(owner.identity, { certificates: [owner.certificate], revocations: [] },
    emptyIdentityProfileState(owner.identity.personId))
  const sourceView = await createIdentityAuthorityView(source.identity, { certificates: [source.certificate], revocations: [] },
    emptyIdentityProfileState(source.identity.personId))
  const replicaConfig = { purpose: "workspace" as const, origin: "https://rusty.example", scopeId, servicePublicKey: "service", readToken: "owner-read",
    writeToken: "owner-write", policyRevision: 1, workspaceId, keyEpoch: 1, contentKey: toBase64Url(new Uint8Array(32).fill(7)),
    cursor: 0, lastUploaded: "", preferenceRevision: "peer:1" }
  const ownerStorageAuthorization = await signEnvelope(owner.privateKeys.devicePrivateKey, {
    kind: "workspace-rusty-access" as const, version: 1 as const, ownerPersonId: owner.identity.personId, workspaceId,
    connection: Object.fromEntries(Object.entries(replicaConfig).filter(([key]) =>
      !["writeToken", "cursor", "lastUploaded", "preferenceRevision"].includes(key))),
    writeTokenHash: await sha256Base64Url(new TextEncoder().encode(replicaConfig.writeToken)),
  }, owner.device.deviceId)
  const sourceState: OwnerReconnectSourceState = {
    workspace: { id: workspaceId, bytes: toBase64Url(changedBytes) },
    workspaceAuthority: { version: 1, records: [record, memberRecord], authority: workspaceAuthority },
    workspaceAccessSnapshot: { workspaceId, genesisOwner: ownerAuthority, genesisEpoch: 1, expectedCurrentOwner: ownerAuthority,
      document: changedBytes, ownershipTransfers: [], successionClaims: [], revocations: [], deviceRevocations: [], departures: [] },
    scopeAuthoritySnapshot,
    grant,
    replicaConfig,
    ownerStorageProof: { authorization: ownerStorageAuthorization, certificates: [owner.certificate] },
    history: { readBaseline: async () => undefined, readDocument: async () => undefined, readObject: async () => undefined },
  }
  const secret = "owner-reconnect-secret"
  const invite = createOwnerReconnectInvite("source-endpoint", secret, source, workspaceId,
    { now: Date.now(), lifetimeMs: 300_000, relayUrl: "https://relay.example" })
  const session: OwnerReconnectSession = { invitationId: invite.invitationId, workspaceId, issuerPersonId: invite.issuerPersonId,
    issuerDeviceId: invite.issuerDeviceId, issuerPublicKey: invite.issuerPublicKey, issuerEndpoint: invite.issuerEndpoint,
    issuerRelayUrl: invite.issuerRelayUrl, expiresAt: invite.expiresAt, secret }
  return { owner, source, ownerView, sourceView, session, sourceState, workspaceId }
}

describe("identity-authorized owner reconnect proof", () => {
  it("Given an authorized participant copy without Rusty credentials, when owner receives the serialized offer, then verify and return the exact board without storage fields", async () => {
    const f = await fixture()
    const source = { ...f.sourceState } as Partial<OwnerReconnectSourceState>
    delete source.replicaConfig
    delete source.ownerStorageProof
    const sourceState = source as OwnerReconnectSourceState
    const hello = await createOwnerReconnectHello({ session: f.session, profile: f.owner, authorityView: f.ownerView,
      endpointId: "owner-ephemeral-endpoint" })
    const challenge = await createOwnerReconnectChallenge({ session: f.session, hello, profile: f.source,
      authorityView: f.sourceView, source: sourceState, sourceEndpointId: "source-endpoint" })
    const approval = await createOwnerReconnectApproval({ session: f.session, hello, challenge, profile: f.owner,
      authorityView: f.ownerView })
    const offer = await createOwnerReconnectOffer({ session: f.session, hello, challenge, approval, profile: f.source,
      authorityView: f.sourceView, source: sourceState, sourceEndpointId: "source-endpoint" })
    const received = decodeOwnerReconnectMessage(encodeOwnerReconnectMessage(offer)) as OwnerReconnectOffer

    expect(Object.hasOwn(received.content, "replicaConfig")).toBe(false)
    expect(Object.hasOwn(received.content, "ownerStorageProof")).toBe(false)
    const verified = await verifyOwnerReconnectOffer({ session: f.session, hello, challenge, approval, offer: received,
      profile: f.owner, authorityView: f.ownerView, ownerEndpointId: "owner-ephemeral-endpoint" })

    expect(verified.workspace).toEqual(f.sourceState.workspace)
    expect(Object.hasOwn(verified, "replicaConfig")).toBe(false)
    expect(Object.hasOwn(verified, "ownerStorageProof")).toBe(false)
  })

  it("Given only one Rusty storage field or a forged owner proof, when source authorization is checked, then reject before creating the offer", async () => {
    const f = await fixture()
    const hello = await createOwnerReconnectHello({ session: f.session, profile: f.owner, authorityView: f.ownerView,
      endpointId: "owner-ephemeral-endpoint" })
    const missingProof = { ...f.sourceState } as Partial<OwnerReconnectSourceState>
    delete missingProof.ownerStorageProof
    await expect(createOwnerReconnectChallenge({ session: f.session, hello, profile: f.source,
      authorityView: f.sourceView, source: missingProof as OwnerReconnectSourceState, sourceEndpointId: "source-endpoint" }))
      .rejects.toThrow(/must be supplied together/i)

    const missingConfig = { ...f.sourceState } as Partial<OwnerReconnectSourceState>
    delete missingConfig.replicaConfig
    await expect(createOwnerReconnectChallenge({ session: f.session, hello, profile: f.source,
      authorityView: f.sourceView, source: missingConfig as OwnerReconnectSourceState, sourceEndpointId: "source-endpoint" }))
      .rejects.toThrow(/must be supplied together/i)

    const forged = { ...f.sourceState, ownerStorageProof: { ...f.sourceState.ownerStorageProof!,
      authorization: { ...f.sourceState.ownerStorageProof!.authorization, signature: toBase64Url(new Uint8Array(64)) } } }
    await expect(createOwnerReconnectChallenge({ session: f.session, hello, profile: f.source,
      authorityView: f.sourceView, source: forged, sourceEndpointId: "source-endpoint" }))
      .rejects.toThrow(/not signed by a current owner device/i)
  })

  it("Given a source-signed offer, when one storage field is removed or its owner proof is forged, then receiver rejects instead of downgrading", async () => {
    const f = await fixture()
    const hello = await createOwnerReconnectHello({ session: f.session, profile: f.owner, authorityView: f.ownerView,
      endpointId: "owner-ephemeral-endpoint" })
    const challenge = await createOwnerReconnectChallenge({ session: f.session, hello, profile: f.source,
      authorityView: f.sourceView, source: f.sourceState, sourceEndpointId: "source-endpoint" })
    const approval = await createOwnerReconnectApproval({ session: f.session, hello, challenge, profile: f.owner,
      authorityView: f.ownerView })
    const offer = await createOwnerReconnectOffer({ session: f.session, hello, challenge, approval, profile: f.source,
      authorityView: f.sourceView, source: f.sourceState, sourceEndpointId: "source-endpoint" })
    const resign = async (content: OwnerReconnectOffer["content"]): Promise<OwnerReconnectOffer> => {
      const contentDigest = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(content)))
      const envelope = await signEnvelope(f.source.privateKeys.devicePrivateKey,
        { ...offer.envelope.payload, contentDigest }, f.source.device.deviceId, "MESH-OWNER-RECONNECT/1")
      return { envelope: envelope as OwnerReconnectOffer["envelope"], content }
    }

    const oneSidedContent = { ...offer.content }
    delete oneSidedContent.ownerStorageProof
    const oneSided = await resign(oneSidedContent)
    await expect(verifyOwnerReconnectOffer({ session: f.session, hello, challenge, approval, offer: oneSided,
      profile: f.owner, authorityView: f.ownerView, ownerEndpointId: "owner-ephemeral-endpoint" }))
      .rejects.toThrow(/must be supplied together/i)

    const forgedContent = { ...offer.content, ownerStorageProof: { ...offer.content.ownerStorageProof!,
      authorization: { ...offer.content.ownerStorageProof!.authorization, signature: toBase64Url(new Uint8Array(64)) } } }
    const forged = await resign(forgedContent)
    await expect(verifyOwnerReconnectOffer({ session: f.session, hello, challenge, approval, offer: forged,
      profile: f.owner, authorityView: f.ownerView, ownerEndpointId: "owner-ephemeral-endpoint" }))
      .rejects.toThrow(/not signed by a current owner device/i)
  })

  it("Given a participant-held existing workspace, when current owner approves, then only post-approval offer carries owner config and native causal proof admits it", async () => {
    const f = await fixture()
    const hello = await createOwnerReconnectHello({ session: f.session, profile: f.owner, authorityView: f.ownerView,
      endpointId: "owner-ephemeral-endpoint" })
    await expect(ownerReconnectAuthenticatedPeer(f.session, JSON.parse(JSON.stringify(hello)))).resolves.toEqual({
      workspaceId: f.workspaceId, personId: f.owner.identity.personId, deviceId: f.owner.device.deviceId,
    })
    const challenge = await createOwnerReconnectChallenge({ session: f.session, hello, profile: f.source,
      authorityView: f.sourceView, source: f.sourceState, sourceEndpointId: "source-endpoint" })
    expect(challenge.payload).not.toHaveProperty("workspace")
    expect(challenge.payload).not.toHaveProperty("replicaConfig")
    expect(challenge.payload.sourceWorkspaceAccessProof.grant.payload.role).toBe("editor")

    const approval = await createOwnerReconnectApproval({ session: f.session, hello, challenge, profile: f.owner,
      authorityView: f.ownerView })
    const offer = await createOwnerReconnectOffer({ session: f.session, hello, challenge, approval, profile: f.source,
      authorityView: f.sourceView, source: f.sourceState, sourceEndpointId: "source-endpoint" })
    const verified = await verifyOwnerReconnectOffer({ session: f.session, hello, challenge, approval, offer,
      profile: f.owner, authorityView: f.ownerView, ownerEndpointId: "owner-ephemeral-endpoint" })

    expect(verified).toMatchObject({ workspaceId: f.workspaceId, sourcePersonId: f.source.identity.personId,
      sourceDeviceId: f.source.device.deviceId, sourceRole: "editor" })
    expect(verified.workspace).toEqual(f.sourceState.workspace)
    expect(verified.replicaConfig!.writeToken).toBe("owner-write")
    expect(verified.replicaConfig!.scopeId).toBe("existing-rusty-scope")
    expect(verified.replicaConfig!.workspaceId).toBe("existing-job-workspace")
    expect(verified.replicaConfig!.purpose).toBe("workspace")
    expect(verified.replicaConfig).not.toHaveProperty("cursor")
    expect(verified.replicaConfig).not.toHaveProperty("lastUploaded")
    expect(verified.replicaConfig).not.toHaveProperty("boardAccess")
    expect((verified.workspaceAccessSnapshot as { document: Uint8Array }).document).toBeInstanceOf(Uint8Array)
  })

  it("Given a signed source offer, when source adds an unsigned loaded Automerge change and updates both byte copies, then reject before a verified result can be committed", async () => {
    const f = await fixture()
    const hello = await createOwnerReconnectHello({ session: f.session, profile: f.owner, authorityView: f.ownerView,
      endpointId: "owner-ephemeral-endpoint" })
    const challenge = await createOwnerReconnectChallenge({ session: f.session, hello, profile: f.source,
      authorityView: f.sourceView, source: f.sourceState, sourceEndpointId: "source-endpoint" })
    const approval = await createOwnerReconnectApproval({ session: f.session, hello, challenge, profile: f.owner,
      authorityView: f.ownerView })

    const loaded = Automerge.load<{ id: string; ownerPersonId: string; title: string }>(
      new Uint8Array(f.sourceState.workspaceAccessSnapshot.document))
    const unsigned = Automerge.change(loaded, draft => { draft.title = "Unsigned source append" })
    const unsignedBytes = Automerge.save(unsigned)
    const maliciousSource: OwnerReconnectSourceState = {
      ...f.sourceState,
      workspace: { id: f.workspaceId, bytes: toBase64Url(unsignedBytes) },
      workspaceAccessSnapshot: { ...f.sourceState.workspaceAccessSnapshot, document: unsignedBytes },
    }
    const signedOffer = await createOwnerReconnectOffer({ session: f.session, hello, challenge, approval,
      profile: f.source, authorityView: f.sourceView, source: maliciousSource, sourceEndpointId: "source-endpoint" })

    await expect(verifyOwnerReconnectOffer({ session: f.session, hello, challenge, approval, offer: signedOffer,
      profile: f.owner, authorityView: f.ownerView, ownerEndpointId: "owner-ephemeral-endpoint" }))
      .rejects.toThrow(/workspace history is not fully admitted/i)
  })

  it("Given distinct logical and opaque scope IDs, when the authority snapshot is substituted, then reject it", async () => {
    const f = await fixture()
    const changedSource = { ...f.sourceState, scopeAuthoritySnapshot: structuredClone(f.sourceState.scopeAuthoritySnapshot) }
    const changedSnapshot = changedSource.scopeAuthoritySnapshot as { genesis: { payload: { scopeId: string } } }
    changedSnapshot.genesis.payload.scopeId = changedSource.replicaConfig!.scopeId
    const invalidSnapshot = await signEnvelope(f.owner.privateKeys.devicePrivateKey, { kind: "scope-genesis", version: 1,
      scopeId: f.sourceState.replicaConfig!.scopeId,
      creator: authority(f.owner), controlEpoch: 1 }, f.owner.device.deviceId)
    changedSnapshot.genesis = invalidSnapshot
    await expect(createOwnerReconnectChallenge({ session: f.session,
      hello: await createOwnerReconnectHello({ session: f.session, profile: f.owner, authorityView: f.ownerView,
        endpointId: "owner-ephemeral-endpoint" }), profile: f.source, authorityView: f.sourceView,
      source: changedSource, sourceEndpointId: "source-endpoint" })).rejects.toThrow(/scope authority/i)
  })

  it("Given an approved challenge, when the opaque storage scope is swapped, then reject the offer", async () => {
    const f = await fixture()
    const hello = await createOwnerReconnectHello({ session: f.session, profile: f.owner, authorityView: f.ownerView,
      endpointId: "owner-ephemeral-endpoint" })
    const challenge = await createOwnerReconnectChallenge({ session: f.session, hello, profile: f.source,
      authorityView: f.sourceView, source: f.sourceState, sourceEndpointId: "source-endpoint" })
    const approval = await createOwnerReconnectApproval({ session: f.session, hello, challenge, profile: f.owner,
      authorityView: f.ownerView })
    const changedSource = { ...f.sourceState, replicaConfig: { ...f.sourceState.replicaConfig! } }
    changedSource.replicaConfig.scopeId = "another-opaque-scope"
    await expect(createOwnerReconnectOffer({ session: f.session, hello, challenge, approval, profile: f.source,
      authorityView: f.sourceView, source: changedSource, sourceEndpointId: "source-endpoint" })).rejects.toThrow(/storage proof/i)
  })

  it("Given a signed offer, when its exact workspace or scope is changed, then reject before commit", async () => {
    const f = await fixture()
    const hello = await createOwnerReconnectHello({ session: f.session, profile: f.owner, authorityView: f.ownerView,
      endpointId: "owner-ephemeral-endpoint" })
    const challenge = await createOwnerReconnectChallenge({ session: f.session, hello, profile: f.source,
      authorityView: f.sourceView, source: f.sourceState, sourceEndpointId: "source-endpoint" })
    const approval = await createOwnerReconnectApproval({ session: f.session, hello, challenge, profile: f.owner,
      authorityView: f.ownerView })
    const offer = await createOwnerReconnectOffer({ session: f.session, hello, challenge, approval, profile: f.source,
      authorityView: f.sourceView, source: f.sourceState, sourceEndpointId: "source-endpoint" })
    const changed = structuredClone(offer)
    changed.content.workspace = { ...(changed.content.workspace as Record<string, unknown>), id: "another-workspace" }
    await expect(verifyOwnerReconnectOffer({ session: f.session, hello, challenge, approval, offer: changed,
      profile: f.owner, authorityView: f.ownerView, ownerEndpointId: "owner-ephemeral-endpoint" })).rejects.toThrow(/content changed/i)
  })
})
