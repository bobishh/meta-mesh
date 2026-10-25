import { createRecoverableIdentity, openIdentityRecoveryEnvelope, signEnvelope } from "@meta-uber/mesh-identity"
import type { IrohConnection } from "@meta-uber/mesh-transport"
import { beforeEach, describe, expect, it, vi } from "vitest"

const mocks = vi.hoisted(() => ({
  initialize: vi.fn(),
  waitForRelayUrl: vi.fn(),
  meshNetworkConnection: vi.fn(),
}))

vi.mock("./browserIdentityEnrollment", () => ({ initializeBrowserIdentityRuntime: mocks.initialize }))
vi.mock("@meta-uber/mesh-transport", () => ({
  waitForRelayUrl: mocks.waitForRelayUrl,
  meshNetworkConnection: mocks.meshNetworkConnection,
}))

import { adoptBrowserIdentityPeerRuntime, connectBrowserIdentityPeer, createBrowserIdentityPeerRuntime,
  type IdentityPeerContact, type IdentityPeerHostConnection } from "./browserIdentityReconnect"
import { createSignedDeviceRoute } from "@meta-uber/mesh-replication"

const reconnectDomain = "META-MESH-IDENTITY-RECONNECT/1"
const endpointAddress = (endpointId: string) => JSON.stringify({ kind: "mesh-browser-endpoint-address", version: 1,
  endpointId, relayUrl: "https://relay.example" })

describe("browser Identity peer reconnect", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.waitForRelayUrl.mockResolvedValue("https://local-relay.example")
  })

  it("Given an expired signed address hint, when the peer answers a fresh signed challenge, then reconnect succeeds", async () => {
    const fixture = await createFixture()
    const result = await connectBrowserIdentityPeer(fixture.options)
    expect(fixture.dialRelay).toHaveBeenCalledWith("remote-endpoint", "https://relay.example")
    expect(result.remoteContact.route.payload.sequence).toBe(2)
    await result.close()
  })

  it("Given a signed response with a different challenge, when reconnect verifies it, then reject and close transport", async () => {
    const fixture = await createFixture({ tamperChallenge: true })
    await expect(connectBrowserIdentityPeer(fixture.options)).rejects.toThrow("did not prove the expected device")
    expect(fixture.connectionClose).toHaveBeenCalledOnce()
    expect(fixture.nodeClose).toHaveBeenCalledOnce()
  })

  it("Given a response signed by another enrolled device, when reconnect targets a known peer, then reject", async () => {
    const fixture = await createFixture({ foreignResponder: true })
    await expect(connectBrowserIdentityPeer(fixture.options)).rejects.toThrow("did not prove the expected device")
    expect(fixture.connectionClose).toHaveBeenCalledOnce()
  })

  it("Given an enrolled transport node, when promoted runtime accepts a replacement while its callback waits, then it reuses one node and bounds ownership", async () => {
    const fixture = await createRuntimeFixture()
    const started = vi.fn(async () => fixture.node)
    mocks.initialize.mockResolvedValue({ BrowserNode: { start: started }, WasmIngressBudgetProfile: class {} })
    const runtime = await createBrowserIdentityPeerRuntime({ transportSeed: new Uint8Array(32).fill(7) })
    const peers: IdentityPeerHostConnection[] = []
    const callbackGate = deferred<void>()
    const host = await runtime.startHost({
      profile: fixture.local,
      certificates: fixture.certificates,
      contacts: [fixture.contact],
      nextSequence: async () => 10,
      onConnected: async peer => { peers.push(peer); await callbackGate.promise },
    })
    fixture.pushIncoming()
    await vi.waitFor(() => expect(peers).toHaveLength(1))
    fixture.pushIncoming()
    await vi.waitFor(() => expect(peers).toHaveLength(2))

    expect(started).toHaveBeenCalledOnce()
    expect(fixture.node.accept).toHaveBeenCalledOnce()
    expect(fixture.incomingConnections[0].close).toHaveBeenCalledOnce()
    expect(fixture.nodeClose).not.toHaveBeenCalled()
    await host.close()
    expect(fixture.incomingConnections[1].close).toHaveBeenCalledOnce()
    await runtime.close()
    expect(fixture.nodeClose).toHaveBeenCalledOnce()
    callbackGate.resolve()
  })

  it("Given an inherited enrollment connection, when its owner closes it, then the runtime releases capacity for the next peer", async () => {
    const fixture = await createRuntimeFixture()
    let releaseInitial: (() => void) | undefined
    const initialConnection = { close: vi.fn(async () => undefined) } as unknown as IrohConnection
    const runtime = adoptBrowserIdentityPeerRuntime({ node: fixture.node, transport: fixture.transport,
      relayUrl: "https://local-relay.example", acceptor: fixture.acceptor, initialConnection,
      onInitialConnectionClose: release => { releaseInitial = release } })
    const peers: IdentityPeerHostConnection[] = []
    const host = await runtime.startHost({ profile: fixture.local, certificates: fixture.certificates,
      contacts: [fixture.contact], nextSequence: async () => 10, onConnected: peer => { peers.push(peer) } })
    fixture.pushIncoming()
    await vi.waitFor(() => expect(peers).toHaveLength(1))
    fixture.pushIncoming()
    await vi.waitFor(() => expect(peers).toHaveLength(2))
    expect(fixture.incomingConnections[0].close).toHaveBeenCalledOnce()

    releaseInitial?.()
    fixture.pushIncoming()
    await vi.waitFor(() => expect(peers).toHaveLength(3))
    expect(fixture.incomingConnections[1].close).toHaveBeenCalledOnce()
    await host.close()
    await runtime.close()
  })

  it.each([true, false])("Given simultaneous authenticated dials, when local device is lexically lower=%s, then one direction wins deterministically", async localIsLower => {
    const fixture = await createRuntimeFixture(localIsLower)
    const initialClose = vi.fn(async () => undefined)
    const initialConnection = { close: initialClose } as unknown as IrohConnection
    const response = deferred<Uint8Array>()
    const outgoingClose = vi.fn(async () => undefined)
    const outgoingStream = { send: vi.fn(async () => undefined), closeSend: vi.fn(async () => undefined), read: () => response.promise }
    const outgoingConnection = { remoteEndpointId: "remote-endpoint", openStream: vi.fn(async () => outgoingStream),
      close: outgoingClose } as unknown as IrohConnection
    fixture.node.dialRelay.mockResolvedValue(outgoingConnection)
    const runtime = adoptBrowserIdentityPeerRuntime({ node: fixture.node, transport: fixture.transport,
      relayUrl: "https://local-relay.example", acceptor: fixture.acceptor, initialConnection })
    const delivered: IdentityPeerHostConnection[] = []
    const host = await runtime.startHost({ profile: fixture.local, certificates: fixture.certificates,
      contacts: [fixture.contact], nextSequence: async () => 10, onConnected: peer => { delivered.push(peer) } })
    const dial = runtime.connect({ profile: fixture.local, certificates: fixture.certificates,
      contact: fixture.contact, nextSequence: async () => 11 }).then(() => undefined, error => error as Error)
    await vi.waitFor(() => expect(fixture.node.dialRelay).toHaveBeenCalledOnce())
    await vi.waitFor(() => expect(outgoingConnection.openStream).toHaveBeenCalledOnce())
    const requestGate = deferred<void>()
    fixture.pushIncoming(requestGate.promise)
    await vi.waitFor(() => expect(fixture.incomingStreams[0].read).toHaveBeenCalledOnce())
    expect([initialClose, outgoingClose, fixture.incomingConnections[0].close].filter(close => !close.mock.calls.length)).toHaveLength(3)
    expect(delivered).toHaveLength(0)
    requestGate.resolve()

    if (localIsLower) {
      await vi.waitFor(() => expect(fixture.incomingConnections[0].close).toHaveBeenCalledOnce())
      expect(delivered).toHaveLength(0)
      expect([initialClose, outgoingClose, fixture.incomingConnections[0].close].filter(close => !close.mock.calls.length)).toHaveLength(2)
      await runtime.close()
      await expect(dial).resolves.toBeInstanceOf(Error)
      expect([initialClose, outgoingClose, fixture.incomingConnections[0].close].filter(close => !close.mock.calls.length)).toHaveLength(0)
    } else {
      await vi.waitFor(() => expect(delivered).toHaveLength(1))
      const result = await dial
      expect(result).toBeInstanceOf(Error)
      expect(result).toHaveProperty("message", expect.stringContaining("superseded"))
      expect(outgoingClose).toHaveBeenCalledOnce()
      expect([initialClose, outgoingClose, fixture.incomingConnections[0].close].filter(close => !close.mock.calls.length)).toHaveLength(2)
      await host.close()
      await runtime.close()
    }
  })
})

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  const promise = new Promise<T>(res => { resolve = res })
  return { promise, resolve }
}

async function createRuntimeFixture(localIsLower = true) {
  const recovery = await createRecoverableIdentity("better", "Owner")
  const first = recovery.profile
  const second = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
  const [local, remote] = localIsLower === (first.device.deviceId < second.device.deviceId)
    ? [first, second] : [second, first]
  const now = Date.now()
  const route = await createSignedDeviceRoute(remote, {
    scopeId: `mesh-identity:${local.identity.personId}`,
    instanceId: "saved-peer",
    endpoint: endpointAddress("remote-endpoint"),
    sequence: 1,
    issuedAt: new Date(now - 120_000).toISOString(),
    expiresAt: new Date(now - 60_000).toISOString(),
  })
  const contact: IdentityPeerContact = { kind: "mesh-identity-peer-contact", version: 1,
    personId: local.identity.personId, deviceId: remote.device.deviceId, route }
  const pendingAccepts: Array<ReturnType<typeof deferred<IrohConnection | undefined>>> = []
  const acceptor = {
    accept: vi.fn(() => {
      const next = deferred<IrohConnection | undefined>()
      pendingAccepts.push(next)
      return next.promise
    }),
    close: vi.fn(async () => {
      for (const next of pendingAccepts) next.resolve(undefined)
    }),
  }
  const incomingConnections: Array<{ close: ReturnType<typeof vi.fn> }> = []
  const incomingStreams: Array<{ read: ReturnType<typeof vi.fn> }> = []
  const pushIncoming = (readGate?: Promise<void>) => {
    const challenge = crypto.randomUUID()
    const issuedAt = Date.now()
    void createSignedDeviceRoute(remote, {
      scopeId: `mesh-identity:${local.identity.personId}`,
      instanceId: `remote-${challenge}`,
      endpoint: endpointAddress("remote-endpoint"),
      sequence: 2,
      issuedAt: new Date(issuedAt).toISOString(),
      expiresAt: new Date(issuedAt + 60_000).toISOString(),
    }).then(async remoteRoute => {
      const request = await signEnvelope(remote.privateKeys.devicePrivateKey,
        { kind: "mesh-identity-peer-reconnect-request", version: 1, challenge, route: remoteRoute },
        remote.device.deviceId, reconnectDomain)
      const stream = { read: vi.fn(async () => {
        await readGate
        return new TextEncoder().encode(JSON.stringify(request))
      }),
        send: vi.fn(async () => undefined), closeSend: vi.fn(async () => undefined) }
      incomingStreams.push(stream)
      const close = vi.fn(async () => undefined)
      incomingConnections.push({ close })
      pendingAccepts.at(-1)?.resolve({ remoteEndpointId: "remote-endpoint", acceptStream: async () => stream,
        openStream: vi.fn(), close } as unknown as IrohConnection)
    })
  }
  const nodeClose = vi.fn(async () => undefined)
  const dialRelay = vi.fn(async (): Promise<IrohConnection> => { throw new Error("Unexpected test dial") })
  const node = { endpointId: "local-endpoint", waitForRelayUrl: vi.fn(async () => "https://local-relay.example"),
    dialRelay, accept: vi.fn(async () => acceptor), close: nodeClose }
  class WasmIngressBudgetProfile {}
  const transport = { WasmIngressBudgetProfile } as unknown as Awaited<ReturnType<typeof import("./browserIdentityEnrollment").initializeBrowserIdentityRuntime>>
  mocks.meshNetworkConnection.mockImplementation((raw: object) => raw)
  return { local, remote, contact, certificates: [first.certificate, second.certificate], node, nodeClose,
    dialRelay, acceptor, incomingConnections, incomingStreams, pushIncoming, transport }
}

async function createFixture(options: { tamperChallenge?: boolean; foreignResponder?: boolean } = {}) {
  const recovery = await createRecoverableIdentity("better", "Owner")
  const first = recovery.profile
  const second = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
  const third = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
  const profile = first
  const responder = options.foreignResponder ? third : second
  const now = Date.now()
  const expiredRoute = await createSignedDeviceRoute(second, {
    scopeId: `mesh-identity:${first.identity.personId}`,
    instanceId: "old-instance",
    endpoint: endpointAddress("remote-endpoint"),
    sequence: 1,
    issuedAt: new Date(now - 120_000).toISOString(),
    expiresAt: new Date(now - 60_000).toISOString(),
  })
  const contact: IdentityPeerContact = { kind: "mesh-identity-peer-contact", version: 1,
    personId: first.identity.personId, deviceId: second.device.deviceId, route: expiredRoute }
  let request: { payload: { challenge: string } } | undefined
  const stream = {
    send: vi.fn(async (bytes: Uint8Array) => { request = JSON.parse(new TextDecoder().decode(bytes)) }),
    closeSend: vi.fn(async () => undefined),
    read: vi.fn(async () => {
      if (!request) throw new Error("Request was not sent")
      const issuedAt = Date.now()
      const route = await createSignedDeviceRoute(responder, {
        scopeId: `mesh-identity:${first.identity.personId}`,
        instanceId: "current-instance",
        endpoint: endpointAddress("remote-endpoint"),
        sequence: 2,
        issuedAt: new Date(issuedAt).toISOString(),
        expiresAt: new Date(issuedAt + 60_000).toISOString(),
      })
      const response = await signEnvelope(responder.privateKeys.devicePrivateKey, {
        kind: "mesh-identity-peer-reconnect-response",
        version: 1,
        challenge: options.tamperChallenge ? crypto.randomUUID() : request.payload.challenge,
        route,
      }, responder.device.deviceId, reconnectDomain)
      return new TextEncoder().encode(JSON.stringify(response))
    }),
  }
  const connectionClose = vi.fn(async () => undefined)
  const rawConnection = {
    remoteEndpointId: "remote-endpoint",
    openStream: vi.fn(async () => stream),
    acceptStream: vi.fn(),
    close: connectionClose,
  }
  const nodeClose = vi.fn(async () => undefined)
  const dialRelay = vi.fn(async () => rawConnection)
  const node = {
    endpointId: "local-endpoint",
    waitForRelayUrl: vi.fn(async () => "https://local-relay.example"),
    dialRelay,
    accept: vi.fn(),
    close: nodeClose,
  }
  class WasmIngressBudgetProfile {}
  mocks.initialize.mockResolvedValue({ BrowserNode: { start: vi.fn(async () => node) }, WasmIngressBudgetProfile })
  mocks.meshNetworkConnection.mockImplementation((raw: typeof rawConnection) => raw)
  return {
    options: {
      profile,
      certificates: [first.certificate, second.certificate, third.certificate],
      contact,
      transportSeed: crypto.getRandomValues(new Uint8Array(32)),
      nextSequence: vi.fn(async () => 3),
    },
    connectionClose,
    nodeClose,
    dialRelay,
  }
}
