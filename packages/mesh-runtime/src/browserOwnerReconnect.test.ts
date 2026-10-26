import * as Automerge from "@automerge/automerge"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { BrowserIdentityStore, createIdentityAuthorityView, emptyIdentityProfileState, sha256Base64Url, signEnvelope, toBase64Url,
  type LocalProfile } from "@meta-uber/mesh-identity"
import { createPeerAdvertisement, createWorkspaceGrant, type OwnerReconnectSourceState, type WorkspaceAuthority } from "@meta-uber/mesh-workspace"
import { installPairingCodec } from "@meta-uber/mesh-pairing"

const runtime = vi.hoisted(() => ({ BrowserNode: { start: vi.fn() }, WasmIngressBudgetProfile: class {} as any }))
vi.mock("./browserIdentityEnrollment", () => ({ initializeBrowserIdentityRuntime: async () => runtime }))

import { connectBrowserOwnerReconnect, startBrowserOwnerReconnectHost } from "./browserOwnerReconnect"

class Queue<T> {
  private values: T[] = []
  private waiters: Array<(value: T) => void> = []
  push(value: T) { const waiter = this.waiters.shift(); waiter ? waiter(value) : this.values.push(value) }
  take(): Promise<T> { const value = this.values.shift(); return value === undefined ? new Promise(resolve => this.waiters.push(resolve)) : Promise.resolve(value) }
}

class PairedStream {
  static resets = 0
  peer?: PairedStream
  private incoming = new Queue<Uint8Array | undefined>()
  async send(bytes: Uint8Array) { this.peer?.incoming.push(bytes.slice()) }
  async read() { const bytes = await this.incoming.take(); if (!bytes) throw new Error("stream closed"); return bytes }
  async readPairingFrame() { return this.read() }
  async closeSend() { this.peer?.incoming.push(undefined) }
  async reset() { PairedStream.resets += 1; this.peer?.incoming.push(undefined) }
}

class PairedConnection {
  readonly incoming = new Queue<PairedStream>()
  private streams: PairedStream[] = []
  remoteEndpointId = ""
  peer?: PairedConnection
  async openStream() { const [local, remote] = streamPair(); this.streams.push(local); this.peer?.streams.push(remote); this.peer?.incoming.push(remote); return local }
  async acceptStream() { return this.incoming.take() }
  async close() { await Promise.all(this.streams.map(stream => stream.reset())) }
}

class PairedAcceptor {
  constructor(private readonly connections: Queue<PairedConnection>) {}
  async accept() { return this.connections.take() }
  async close() {}
}

class PairedNode {
  readonly connections = new Queue<PairedConnection>()
  readonly endpointId: string
  readonly relayUrl = "https://relay.example"
  constructor(endpointId: string) { this.endpointId = endpointId }
  async waitForRelayUrl() { return this.relayUrl }
  async accept() { return new PairedAcceptor(this.connections) }
  async dialRelay(endpoint: string) {
    const source = nodes.get(endpoint)
    if (!source) throw new Error("unknown endpoint")
    const [local, remote] = connectionPair(this.endpointId, source.endpointId)
    source.connections.push(remote)
    return local
  }
  async close() {}
}

function streamPair(): [PairedStream, PairedStream] {
  const left = new PairedStream(), right = new PairedStream()
  left.peer = right; right.peer = left
  return [left, right]
}
function connectionPair(leftEndpoint: string, rightEndpoint: string): [PairedConnection, PairedConnection] {
  const left = new PairedConnection(), right = new PairedConnection()
  left.remoteEndpointId = rightEndpoint; right.remoteEndpointId = leftEndpoint
  left.peer = right; right.peer = left
  return [left, right]
}

const nodes = new Map<string, PairedNode>()
let corruptNextChunk = false
let sentWireKinds: string[] = []
const profile = (name: string) => new BrowserIdentityStore({ storageKey: crypto.randomUUID(), signatureDomain: "MATCH/1" }).bootstrap(name)
const identityAuthority = (value: LocalProfile): WorkspaceAuthority => ({ personId: value.identity.personId,
  publicKey: value.identity.publicKey, certificates: [value.certificate] })

async function sourceFixture() {
  const owner = await profile("Bo")
  const source = await profile("Ray")
  const workspaceId = "workspace-owner-reconnect"
  const scopeId = "rusty-owner-reconnect-scope"
  const ownerRecord = identityAuthority(owner)
  const document = Automerge.save(Automerge.from({ id: workspaceId, ownerPersonId: owner.identity.personId, title: "Existing" }))
  const hash = Automerge.getHeads(Automerge.load(document))[0]!
  const genesis = { signed: await signEnvelope(owner.privateKeys.devicePrivateKey, { kind: "workspace-changes", version: 1,
    workspaceId, hashes: [hash], personId: owner.identity.personId, deviceId: owner.device.deviceId }, owner.device.deviceId),
    publicKey: owner.identity.publicKey, certificates: [owner.certificate] }
  const grant = await createWorkspaceGrant(owner, workspaceId, source.identity.personId, "editor")
  const sourceView = await createIdentityAuthorityView(source.identity, { certificates: [source.certificate], revocations: [] },
    emptyIdentityProfileState(source.identity.personId))
  const ownerView = await createIdentityAuthorityView(owner.identity, { certificates: [owner.certificate], revocations: [] },
    emptyIdentityProfileState(owner.identity.personId))
  const persistentSourceBundle = await createPeerAdvertisement(source, workspaceId, "iroh://source-persistent-route", {
    instanceId: "source-workspace-instance", grant, ownerPublicKey: owner.identity.publicKey,
    ownerCertificates: [owner.certificate],
  })
  const scopeAuthoritySnapshot = { genesis: await signEnvelope(owner.privateKeys.devicePrivateKey, { kind: "scope-genesis", version: 1,
    scopeId: workspaceId, creator: ownerRecord, controlEpoch: 1 }, owner.device.deviceId), grants: [], grantIssuers: [], revocations: [],
    controlTransfers: [], successionTransfers: [] }
  const meshEnvelope = { version: 1 as const, workspaceId, ownerPersonId: owner.identity.personId,
    ownerPublicKey: owner.identity.publicKey, ownerCertificates: [owner.certificate], transportSecret: "shared-workspace-secret",
    epoch: 1, peers: [persistentSourceBundle], scopeAuthoritySnapshot }
  const replicaConfig = { purpose: "workspace" as const, origin: "https://rusty.example", scopeId, servicePublicKey: "service", readToken: "read-owner",
    writeToken: "write-owner", policyRevision: 1, workspaceId, keyEpoch: 1, contentKey: toBase64Url(new Uint8Array(32).fill(4)),
    cursor: 0, lastUploaded: "" }
  const ownerStorageAuthorization = await signEnvelope(owner.privateKeys.devicePrivateKey, {
    kind: "workspace-rusty-access" as const, version: 1 as const, ownerPersonId: owner.identity.personId, workspaceId,
    connection: Object.fromEntries(Object.entries(replicaConfig).filter(([key]) => !["writeToken", "cursor", "lastUploaded"].includes(key))),
    writeTokenHash: await sha256Base64Url(new TextEncoder().encode(replicaConfig.writeToken)),
  }, owner.device.deviceId)
  const state: OwnerReconnectSourceState = {
    workspace: { id: workspaceId, bytes: toBase64Url(document) },
    workspaceAuthority: { version: 1, records: [genesis], authority: { genesisOwner: ownerRecord, genesisEpoch: 1,
      currentOwner: ownerRecord, currentEpoch: 1, ownershipTransfers: [], successionClaims: [], revocations: [],
      deviceRevocations: [], departures: [] } },
    workspaceAccessSnapshot: { workspaceId, genesisOwner: ownerRecord, genesisEpoch: 1, expectedCurrentOwner: ownerRecord,
      document, ownershipTransfers: [], successionClaims: [], revocations: [], deviceRevocations: [], departures: [] },
    scopeAuthoritySnapshot, grant, meshEnvelope,
    replicaConfig,
    ownerStorageProof: { authorization: ownerStorageAuthorization, certificates: [owner.certificate] },
    history: { readBaseline: async () => undefined, readDocument: async () => undefined, readObject: async () => undefined },
  }
  return { owner, source, ownerView, sourceView, state, workspaceId }
}

describe("browser owner reconnect transport", () => {
  let restoreCodec: (() => void) | undefined
  beforeEach(() => {
    nodes.clear()
    PairedStream.resets = 0
    corruptNextChunk = false
    sentWireKinds = []
    let nextNode = 0
    runtime.BrowserNode.start.mockImplementation(async () => {
      const node = new PairedNode(nextNode++ === 0 ? "source-endpoint" : "owner-endpoint")
      nodes.set(node.endpointId, node)
      return node
    })
    runtime.WasmIngressBudgetProfile = class {
      maxFrameBytes() { return 16 * 1024 * 1024 }
      maxInFlightBytesPerConnection() { return 32 * 1024 * 1024 }
      maxConcurrentFramesPerConnection() { return 2 }
      maxConcurrentHeadersPerConnection() { return 32 }
      maxHeaderBytes() { return 4096 }
      maxTransferDeadlineMs() { return 60_000 }
      maxLogicalTransferBytes() { return 256 * 1024 * 1024 }
      maxTransferPages() { return 64 }
      maxPayloadBytes() { return 16 * 1024 * 1024 }
    }
    restoreCodec = installPairingCodec({
      encode(type, secret, bytes) {
        try {
          const value = JSON.parse(new TextDecoder().decode(bytes)) as { kind?: unknown; index?: unknown }
          if (typeof value.kind === "string") {
            sentWireKinds.push(value.kind)
            if (corruptNextChunk && value.kind === "owner-reconnect-content-chunk") {
              value.index = Number(value.index) + 1
              bytes = new TextEncoder().encode(JSON.stringify(value))
              corruptNextChunk = false
            }
          }
        } catch { /* Signed frames are recorded only when their payload is ordinary JSON. */ }
        const header = new TextEncoder().encode(`${JSON.stringify({ type, secret })}\n`)
        const out = new Uint8Array(header.length + bytes.length); out.set(header); out.set(bytes, header.length); return out
      },
      inspect(frame) { return JSON.parse(new TextDecoder().decode(frame.subarray(0, frame.indexOf(10)))) },
      decode(frame, type, secret) {
        const split = frame.indexOf(10)
        const header = JSON.parse(new TextDecoder().decode(frame.subarray(0, split)))
        if (header.type !== type || header.secret !== secret) throw new Error("wrong frame binding")
        return frame.slice(split + 1)
      },
    })
  })
  afterEach(() => restoreCodec?.())

  it("Given an approved current owner, when both endpoints exchange framed streams, then commit receives verified workspace and history reader before receipt", async () => {
    const f = await sourceFixture()
    const host = await startBrowserOwnerReconnectHost({ profile: f.source, authorityView: f.sourceView,
      origin: "https://app.example", workspaceId: f.workspaceId,
      expectedOwner: { personId: f.owner.identity.personId, publicKey: f.owner.identity.publicKey }, readSource: async () => f.state })
    const committed: string[] = []
    const result = await connectBrowserOwnerReconnect({ invitation: host.invitation, profile: f.owner, authorityView: f.ownerView,
      approve: async intent => intent.workspaceId === f.workspaceId && intent.sourcePersonId === f.source.identity.personId,
      commit: async (verified, history) => {
        committed.push(verified.offerDigest)
        expect(verified.workspace).toEqual(f.state.workspace)
        expect(verified.meshEnvelope).toEqual(f.state.meshEnvelope)
        expect(await history.readBaseline(f.workspaceId)).toBeUndefined()
      } })
    await host.done
    expect(result.workspaceId).toBe(f.workspaceId)
    expect(committed).toEqual([result.offerDigest])
    await host.close()
  })

  it("Given an authorized participant copy without Rusty credentials, when the owner reconnects, then complete the framed flow without storage fields", async () => {
    const f = await sourceFixture()
    const source = { ...f.state } as Partial<OwnerReconnectSourceState>
    delete source.replicaConfig
    delete source.ownerStorageProof
    const sourceState = source as OwnerReconnectSourceState
    const host = await startBrowserOwnerReconnectHost({ profile: f.source, authorityView: f.sourceView,
      origin: "https://app.example", workspaceId: f.workspaceId,
      expectedOwner: { personId: f.owner.identity.personId, publicKey: f.owner.identity.publicKey }, readSource: async () => sourceState })
    const commit = vi.fn(async verified => {
      expect(verified.workspace).toEqual(f.state.workspace)
      expect(verified.meshEnvelope).toEqual(f.state.meshEnvelope)
      expect(Object.hasOwn(verified, "replicaConfig")).toBe(false)
      expect(Object.hasOwn(verified, "ownerStorageProof")).toBe(false)
    })

    const result = await connectBrowserOwnerReconnect({ invitation: host.invitation, profile: f.owner, authorityView: f.ownerView,
      approve: async intent => intent.workspaceId === f.workspaceId && intent.scopeId === f.workspaceId, commit })
    await host.done

    expect(result.workspaceId).toBe(f.workspaceId)
    expect(commit).toHaveBeenCalledOnce()
    await host.close()
  })

  it("Given an unapproved owner request, when approval declines, then host never reads workspace source", async () => {
    const f = await sourceFixture()
    const readSource = vi.fn(async () => f.state)
    const host = await startBrowserOwnerReconnectHost({ profile: f.source, authorityView: f.sourceView,
      origin: "https://app.example", workspaceId: f.workspaceId,
      expectedOwner: { personId: f.owner.identity.personId, publicKey: f.owner.identity.publicKey }, readSource })
    await expect(connectBrowserOwnerReconnect({ invitation: host.invitation, profile: f.owner, authorityView: f.ownerView,
      approve: async () => false, commit: async () => { throw new Error("must not commit") } })).rejects.toThrow(/declined/i)
    await expect(host.done).rejects.toThrow(/declined/i)
    expect(readSource).toHaveBeenCalledOnce()
    await host.close()
  })

  it("Given a signed hello from another Identity, when that candidate is rejected, then the same invitation serves the owner", async () => {
    const f = await sourceFixture()
    const wrongOwner = await profile("Wrong owner")
    const wrongOwnerView = await createIdentityAuthorityView(wrongOwner.identity,
      { certificates: [wrongOwner.certificate], revocations: [] }, emptyIdentityProfileState(wrongOwner.identity.personId))
    const readSource = vi.fn(async () => f.state)
    const host = await startBrowserOwnerReconnectHost({ profile: f.source, authorityView: f.sourceView,
      origin: "https://app.example", workspaceId: f.workspaceId,
      expectedOwner: { personId: f.owner.identity.personId, publicKey: f.owner.identity.publicKey }, readSource })
    await expect(connectBrowserOwnerReconnect({ invitation: host.invitation, profile: wrongOwner, authorityView: wrongOwnerView,
      approve: async () => true, commit: async () => { throw new Error("must not commit") } })).rejects.toThrow()
    expect(readSource).not.toHaveBeenCalled()
    const commit = vi.fn()
    const result = await connectBrowserOwnerReconnect({ invitation: host.invitation, profile: f.owner, authorityView: f.ownerView,
      approve: async () => true, commit })
    await host.done
    expect(result.workspaceId).toBe(f.workspaceId)
    expect(commit).toHaveBeenCalledOnce()
    expect(readSource).toHaveBeenCalledTimes(2)
    await host.close()
  })

  it("Given a valid offer, when a content chunk is corrupted, then commit and receipt do not happen", async () => {
    const f = await sourceFixture()
    const host = await startBrowserOwnerReconnectHost({ profile: f.source, authorityView: f.sourceView,
      origin: "https://app.example", workspaceId: f.workspaceId,
      expectedOwner: { personId: f.owner.identity.personId, publicKey: f.owner.identity.publicKey }, readSource: async () => f.state })
    corruptNextChunk = true
    const commit = vi.fn()
    await expect(connectBrowserOwnerReconnect({ invitation: host.invitation, profile: f.owner, authorityView: f.ownerView,
      approve: async () => true, commit })).rejects.toThrow(/chunk order mismatch/i)
    expect(commit).not.toHaveBeenCalled()
    expect(sentWireKinds).not.toContain("mesh-owner-reconnect-receipt")
    await host.close()
  })

  it("Given an approved and verified offer, when durable commit fails, then no receipt is sent", async () => {
    const f = await sourceFixture()
    const host = await startBrowserOwnerReconnectHost({ profile: f.source, authorityView: f.sourceView,
      origin: "https://app.example", workspaceId: f.workspaceId,
      expectedOwner: { personId: f.owner.identity.personId, publicKey: f.owner.identity.publicKey }, readSource: async () => f.state })
    await expect(connectBrowserOwnerReconnect({ invitation: host.invitation, profile: f.owner, authorityView: f.ownerView,
      approve: async () => true, commit: async () => { throw new Error("durable commit failed") } })).rejects.toThrow(/durable commit failed/i)
    expect(sentWireKinds).not.toContain("mesh-owner-reconnect-receipt")
    await host.close()
  })

  it("Given an owner waiting to approve, when the owner aborts, then the owned stream resets and commit does not run", async () => {
    const f = await sourceFixture()
    let enterApproval!: () => void
    let releaseApproval!: (value: boolean) => void
    const approval = new Promise<boolean>(resolve => { releaseApproval = resolve })
    const approvalStarted = new Promise<void>(resolve => { enterApproval = resolve })
    const host = await startBrowserOwnerReconnectHost({ profile: f.source, authorityView: f.sourceView,
      origin: "https://app.example", workspaceId: f.workspaceId,
      expectedOwner: { personId: f.owner.identity.personId, publicKey: f.owner.identity.publicKey }, readSource: async () => f.state })
    const controller = new AbortController()
    const commit = vi.fn()
    const reconnect = connectBrowserOwnerReconnect({ invitation: host.invitation, profile: f.owner, authorityView: f.ownerView,
      approve: () => { enterApproval(); return approval }, commit, signal: controller.signal })
    await approvalStarted
    controller.abort()
    await expect(reconnect).rejects.toThrow(/cancelled/i)
    releaseApproval(false)
    expect(commit).not.toHaveBeenCalled()
    expect(PairedStream.resets).toBeGreaterThan(0)
    await host.close()
  })
})
