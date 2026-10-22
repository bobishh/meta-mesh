import { createRecoverableIdentity, openIdentityRecoveryEnvelope, signEnvelope } from "@meta-uber/mesh-identity"
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

import { connectBrowserIdentityPeer, type IdentityPeerContact } from "./browserIdentityReconnect"
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
})

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
