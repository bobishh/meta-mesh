import {
  canonicalizeJson,
  signEnvelope,
  verifyDeviceCertificateChain,
  verifyEnvelope,
  type DeviceCertificate,
  type LocalProfile,
  type SignedEnvelope,
} from "@meta-uber/mesh-identity"
import {
  createSignedDeviceRoute,
  verifySignedDeviceRoute,
  type DeviceRoute,
  type SignedDeviceRoute,
} from "@meta-uber/mesh-replication"
import {
  meshNetworkConnection,
  waitForRelayUrl,
  type IrohConnection,
  type IrohNode,
  type MeshConnection,
} from "@meta-uber/mesh-transport"
import { initializeBrowserIdentityRuntime } from "./browserIdentityEnrollment"

const reconnectDomain = "META-MESH-IDENTITY-RECONNECT/1"
const maximumReconnectFrameBytes = 32 * 1024
const reconnectTimeoutMs = 15_000
const maximumActivePeerConnections = 2

export type IdentityPeerContact = {
  kind: "mesh-identity-peer-contact"
  version: 1
  personId: string
  deviceId: string
  route: SignedDeviceRoute
}

export type ConnectedIdentityPeer = {
  connection: MeshConnection
  remoteContact: IdentityPeerContact
  localContact: IdentityPeerContact
  close(): Promise<void>
}

export type BrowserIdentityPeerHost = {
  endpointId: string
  relayUrl: string
  instanceId: string
  done: Promise<void>
  close(): Promise<void>
}

export type IdentityPeerHostConnection = Omit<ConnectedIdentityPeer, "close"> & { close(): Promise<void> }

export type StartBrowserIdentityPeerHostOptions = {
  profile: LocalProfile
  certificates: readonly DeviceCertificate[]
  contacts: readonly IdentityPeerContact[]
  nextSequence(): number | Promise<number>
  onConnected(peer: IdentityPeerHostConnection): void | Promise<void>
  signal?: AbortSignal
}

export type ConnectBrowserIdentityPeerOptions = {
  profile: LocalProfile
  certificates: readonly DeviceCertificate[]
  contact: IdentityPeerContact
  nextSequence(): number | Promise<number>
  signal?: AbortSignal
}

export type BrowserIdentityPeerRuntime = {
  startHost(options: StartBrowserIdentityPeerHostOptions): Promise<BrowserIdentityPeerHost>
  connect(options: ConnectBrowserIdentityPeerOptions): Promise<ConnectedIdentityPeer>
  close(): Promise<void>
}

export type CreateBrowserIdentityPeerRuntimeOptions = { transportSeed: Uint8Array; signal?: AbortSignal }

type ReconnectRequest = SignedEnvelope<{
  kind: "mesh-identity-peer-reconnect-request"
  version: 1
  challenge: string
  route: SignedDeviceRoute
}>

type ReconnectResponse = SignedEnvelope<{
  kind: "mesh-identity-peer-reconnect-response"
  version: 1
  challenge: string
  route: SignedDeviceRoute
}>

type BrowserAddress = { kind: "mesh-browser-endpoint-address"; version: 1; endpointId: string; relayUrl: string }

type BrowserPeerAcceptor = { accept(): Promise<IrohConnection | undefined>; close(): Promise<void> }
type PendingPeerDial = { controller: AbortController; settled: Promise<void>; finish(): void; superseded: boolean }

type BrowserIdentityPeerRuntimeTransport = Awaited<ReturnType<typeof initializeBrowserIdentityRuntime>>

/** Start one transport node that can both accept and dial approved Identity peers. */
export async function createBrowserIdentityPeerRuntime(options: CreateBrowserIdentityPeerRuntimeOptions): Promise<BrowserIdentityPeerRuntime> {
  assertTransportSeed(options.transportSeed)
  if (options.signal?.aborted) throw abortError()
  const transport = await initializeBrowserIdentityRuntime()
  const node = await transport.BrowserNode.start(new Uint8Array(options.transportSeed))
  try {
    const relayUrl = await waitForRelayUrl(node, { timeoutMs: 10_000, signal: options.signal })
    const runtime = adoptBrowserIdentityPeerRuntime({ node, transport, relayUrl })
    const closeRuntime = runtime.close.bind(runtime)
    let abortRuntime: (() => void) | undefined
    runtime.close = async () => {
      if (abortRuntime) options.signal?.removeEventListener("abort", abortRuntime)
      abortRuntime = undefined
      await closeRuntime()
    }
    abortRuntime = () => { void runtime.close() }
    options.signal?.addEventListener("abort", abortRuntime, { once: true })
    if (options.signal?.aborted) {
      await runtime.close()
      throw abortError()
    }
    return runtime
  } catch (error) {
    await node.close("Identity peer runtime failed to start").catch(() => undefined)
    throw error
  }
}

/** Accept authenticated reconnects from already enrolled devices. Caller owns contact persistence and sync. */
export async function startBrowserIdentityPeerHost(options: StartBrowserIdentityPeerHostOptions & {
  transportSeed: Uint8Array
}): Promise<BrowserIdentityPeerHost> {
  await assertLocalProfile(options.profile, options.certificates)
  assertTransportSeed(options.transportSeed)
  if (options.signal?.aborted) throw abortError()
  const transport = await initializeBrowserIdentityRuntime()
  const node = await transport.BrowserNode.start(new Uint8Array(options.transportSeed))
  try {
    const relayUrl = await waitForRelayUrl(node, { timeoutMs: 10_000, signal: options.signal })
    const acceptor = await withDeadline(node.accept(), "Identity peer listener timed out", options.signal,
      () => node.close("Identity peer host cancelled"))
    const runtime = adoptBrowserIdentityPeerRuntime({ node, transport, relayUrl, acceptor })
    const host = await runtime.startHost(options)
    const abortRuntime = () => { void runtime.close() }
    options.signal?.addEventListener("abort", abortRuntime, { once: true })
    return { ...host, close: async () => {
      options.signal?.removeEventListener("abort", abortRuntime)
      await host.close()
      await runtime.close()
    } }
  } catch (error) {
    await node.close("Identity peer host failed to start").catch(() => undefined)
    throw error
  }
}

/** Adopt an enrollment BrowserNode without creating a second endpoint for the same transport seed. */
export function adoptBrowserIdentityPeerRuntime(options: {
  node: IrohNode
  transport: BrowserIdentityPeerRuntimeTransport
  relayUrl: string
  acceptor?: BrowserPeerAcceptor
  initialConnection?: IrohConnection
  onInitialConnectionClose?(release: () => void): void
}): BrowserIdentityPeerRuntime {
  const ownedConnections = new Set<IrohConnection>()
  const hostConnections = new Set<IrohConnection>()
  const hostPeers = new Map<IrohConnection, IdentityPeerHostConnection>()
  if (options.initialConnection) {
    ownedConnections.add(options.initialConnection)
    options.onInitialConnectionClose?.(() => ownedConnections.delete(options.initialConnection!))
  }
  let acceptor = options.acceptor
  let closed = false
  let hostClose: (() => Promise<void>) | undefined
  let closePromise: Promise<void> | undefined
  let hostStarted = false
  let pendingOutgoing = 0
  const pendingDials = new Map<string, PendingPeerDial>()
  const activePeers = new Map<string, ConnectedIdentityPeer | IdentityPeerHostConnection>()

  const close = (): Promise<void> => {
    if (closePromise) return closePromise
    closed = true
    closePromise = (async () => {
      for (const pending of pendingDials.values()) pending.controller.abort()
      await Promise.all(Array.from(pendingDials.values(), pending => pending.settled))
      pendingDials.clear()
      await hostClose?.().catch(() => undefined)
      await Promise.all(Array.from(ownedConnections, connection => connection.close().catch(() => undefined)))
      ownedConnections.clear()
      await options.node.close("Identity peer runtime closed").catch(() => undefined)
    })()
    return closePromise
  }

  const startHost = async (hostOptions: StartBrowserIdentityPeerHostOptions): Promise<BrowserIdentityPeerHost> => {
    if (closed) throw new Error("Identity peer runtime is closed")
    if (hostStarted) throw new Error("Identity peer runtime already has a listener")
    await assertLocalProfile(hostOptions.profile, hostOptions.certificates)
    if (hostOptions.signal?.aborted) throw abortError()
    const contacts = new Map<string, IdentityPeerContact>()
    for (const contact of hostOptions.contacts) {
      assertContactShape(contact, hostOptions.profile.identity.personId)
      const key = contactKey(contact.personId, contact.deviceId)
      if (contacts.has(key)) throw new Error("Duplicate Identity peer contact")
      contacts.set(key, structuredClone(contact))
    }
    hostStarted = true

    let listenerAcceptor = acceptor
    try {
      listenerAcceptor ??= await options.node.accept() as BrowserPeerAcceptor
      acceptor = listenerAcceptor
    } catch (cause) {
      hostStarted = false
      throw cause
    }

    let stopped = false
    let stopPromise: Promise<void> | undefined
    const instanceId = crypto.randomUUID()
    const listenerAbort = new AbortController()
    const abortFromCaller = () => { void stopHost() }

    const stopHost = (): Promise<void> => {
      if (stopPromise) return stopPromise
      stopped = true
      listenerAbort.abort(hostOptions.signal?.reason)
      stopPromise = (async () => {
        hostOptions.signal?.removeEventListener("abort", abortFromCaller)
        if (acceptor === listenerAcceptor) acceptor = undefined
        await listenerAcceptor?.close().catch(() => undefined)
        await Promise.all(Array.from(hostConnections, async connection => {
          const peer = hostPeers.get(connection)
          if (peer) await peer.close().catch(() => undefined)
          else await connection.close().catch(() => undefined)
          hostConnections.delete(connection)
          hostPeers.delete(connection)
          ownedConnections.delete(connection)
        }))
      })()
      if (hostClose === stopHost) hostClose = undefined
      hostStarted = false
      return stopPromise
    }
    hostClose = stopHost
    hostOptions.signal?.addEventListener("abort", abortFromCaller, { once: true })

    const done = (async () => {
      while (!stopped && !closed) {
        let rawConnection: IrohConnection | undefined
        let handedOff = false
        try {
          rawConnection = await waitForAccept(listenerAcceptor!.accept(), listenerAbort.signal)
          if (!rawConnection) continue
          if (stopped || closed || ownedConnections.size + pendingOutgoing > maximumActivePeerConnections) {
            continue
          }
          ownedConnections.add(rawConnection)
          hostConnections.add(rawConnection)
          const peer = await acceptPeerConnection({ ...hostOptions, signal: listenerAbort.signal }, contacts,
            rawConnection, options.node.endpointId, options.relayUrl, instanceId, options.transport,
            ownedConnections, hostConnections)
          handedOff = true
          if (stopped || closed || listenerAbort.signal.aborted) {
            await peer.close()
            continue
          }
          const key = contactKey(peer.remoteContact.personId, peer.remoteContact.deviceId)
          const pending = pendingDials.get(key)
          if (pending) {
            if (hostOptions.profile.device.deviceId < peer.remoteContact.deviceId) {
              await peer.close()
              continue
            }
            pending.superseded = true
            pending.controller.abort()
            await pending.settled
          }
          const existing = activePeers.get(key)
          if (existing) await existing.close().catch(() => undefined)
          if (ownedConnections.size > maximumActivePeerConnections) {
            await peer.close()
            continue
          }
          activePeers.set(key, peer)
          const closePeer = peer.close.bind(peer)
          peer.close = async () => {
            if (activePeers.get(key) === peer) activePeers.delete(key)
            hostPeers.delete(rawConnection!)
            await closePeer()
          }
          hostPeers.set(rawConnection, peer)
          peer.connection.close = peer.close
          void Promise.resolve().then(() => hostOptions.onConnected(peer)).catch(async () => {
            await peer.close().catch(() => undefined)
          })
        } catch {
          if (stopped || closed || listenerAbort.signal.aborted) return
          // Unknown, stale, and malformed peers never reach caller callbacks.
        } finally {
          if (rawConnection && !handedOff) {
            ownedConnections.delete(rawConnection)
            hostConnections.delete(rawConnection)
            await rawConnection.close().catch(() => undefined)
          }
        }
      }
    })()

    const host: BrowserIdentityPeerHost = {
      endpointId: options.node.endpointId,
      relayUrl: options.relayUrl,
      instanceId,
      done,
      close: stopHost,
    }
    if (hostOptions.signal?.aborted) await stopHost()
    return host
  }

  const connect = async (connectOptions: ConnectBrowserIdentityPeerOptions): Promise<ConnectedIdentityPeer> => {
    if (closed) throw new Error("Identity peer runtime is closed")
    await assertLocalProfile(connectOptions.profile, connectOptions.certificates)
    assertContactShape(connectOptions.contact, connectOptions.profile.identity.personId)
    const key = contactKey(connectOptions.contact.personId, connectOptions.contact.deviceId)
    if (activePeers.has(key)) throw new Error("Identity peer connection was superseded by an authenticated incoming peer")
    if (pendingDials.has(key)) throw new Error("Identity peer dial is already pending")
    if (ownedConnections.size + pendingOutgoing >= maximumActivePeerConnections) {
      throw new Error("Identity peer connection limit reached")
    }
    const dialController = new AbortController()
    let finishDial!: () => void
    const settled = new Promise<void>(resolve => { finishDial = resolve })
    const pending: PendingPeerDial = { controller: dialController, settled, finish: () => finishDial(), superseded: false }
    const abortDial = () => dialController.abort(connectOptions.signal?.reason)
    if (connectOptions.signal?.aborted) throw abortError()
    connectOptions.signal?.addEventListener("abort", abortDial, { once: true })
    pendingDials.set(key, pending)
    pendingOutgoing += 1
    let opened = false
    try {
      const peer = await connectBrowserIdentityPeerOnNode({ ...connectOptions, signal: dialController.signal }, options.node, options.relayUrl, options.transport,
        connection => { opened = true; pendingOutgoing -= 1; ownedConnections.add(connection) },
        connection => ownedConnections.delete(connection))
      if (activePeers.has(key)) {
        await peer.close()
        throw new Error("Identity peer dial was superseded by an authenticated incoming peer")
      }
      activePeers.set(key, peer)
      const closePeer = peer.close.bind(peer)
      peer.close = async () => {
        if (activePeers.get(key) === peer) activePeers.delete(key)
        await closePeer()
      }
      peer.connection.close = peer.close
      return peer
    } catch (error) {
      if (pending.superseded || (dialController.signal.aborted && activePeers.has(key))) {
        throw new Error("Identity peer dial was superseded by an authenticated incoming peer")
      }
      throw error
    } finally {
      connectOptions.signal?.removeEventListener("abort", abortDial)
      if (pendingDials.get(key) === pending) pendingDials.delete(key)
      if (!opened) pendingOutgoing -= 1
      pending.finish()
    }
  }

  return { startHost, connect, close }
}

/** Dial one saved address hint, then require a fresh signed challenge response before returning a connection. */
export async function connectBrowserIdentityPeer(options: ConnectBrowserIdentityPeerOptions & {
  transportSeed: Uint8Array
}): Promise<ConnectedIdentityPeer> {
  await assertLocalProfile(options.profile, options.certificates)
  assertTransportSeed(options.transportSeed)
  if (options.signal?.aborted) throw abortError()

  const transport = await initializeBrowserIdentityRuntime()
  const node = await transport.BrowserNode.start(new Uint8Array(options.transportSeed))
  let runtime: BrowserIdentityPeerRuntime | undefined
  try {
    const relayUrl = await waitForRelayUrl(node, { timeoutMs: 10_000, signal: options.signal })
    runtime = adoptBrowserIdentityPeerRuntime({ node, transport, relayUrl })
    const connected = await runtime.connect(options)
    return { ...connected, close: async () => { await connected.close(); await runtime!.close() } }
  } catch (error) {
    await (runtime?.close() ?? node.close("Identity peer connection failed")).catch(() => undefined)
    throw error
  }
}

async function connectBrowserIdentityPeerOnNode(options: ConnectBrowserIdentityPeerOptions, node: IrohNode,
  relayUrl: string, transport: BrowserIdentityPeerRuntimeTransport,
  onOpened?: (connection: IrohConnection) => void, onClosed?: (connection: IrohConnection) => void): Promise<ConnectedIdentityPeer> {
  await assertLocalProfile(options.profile, options.certificates)
  assertContactShape(options.contact, options.profile.identity.personId)
  if (options.contact.deviceId === options.profile.device.deviceId) throw new Error("Cannot reconnect to this Identity device")
  if (options.signal?.aborted) throw abortError()
  const remoteKey = await verifyDeviceCertificateChain(options.profile.identity, options.contact.deviceId,
    Array.from(options.certificates))
  const hint = await verifyContactAddressHint(options.contact, remoteKey)
  let rawConnection: IrohConnection | undefined
  let closed = false
  let closeMeshConnection: (() => Promise<void>) | undefined
  const close = async () => {
    if (closed) return
    closed = true
    if (rawConnection) {
      if (closeMeshConnection) await closeMeshConnection().catch(() => undefined)
      else await rawConnection.close().catch(() => undefined)
      onClosed?.(rawConnection)
    }
  }
  const abortListener = () => { void close() }
  options.signal?.addEventListener("abort", abortListener, { once: true })
  try {
    const pendingDial = node.dialRelay(hint.endpointId, hint.relayUrl)
    void pendingDial.then(connection => { if (closed) void connection.close().catch(() => undefined) }, () => undefined)
    rawConnection = await withDeadline(pendingDial, "Identity peer dial timed out", options.signal, close)
    if (closed) throw abortError()
    onOpened?.(rawConnection)
    if (rawConnection.remoteEndpointId !== hint.endpointId) throw new Error("Identity transport connected to the wrong peer endpoint")
    const stream = await withDeadline(rawConnection.openStream(), "Identity peer stream open timed out", options.signal, close)
    const localRoute = await createFreshRoute(options.profile, options.profile.identity.personId, node.endpointId,
      relayUrl, crypto.randomUUID(), await nextRouteSequence(options.nextSequence))
    const challenge = crypto.randomUUID()
    const request = await signEnvelope(options.profile.privateKeys.devicePrivateKey,
      { kind: "mesh-identity-peer-reconnect-request" as const, version: 1 as const, challenge, route: localRoute },
      options.profile.device.deviceId, reconnectDomain) as ReconnectRequest
    await withDeadline(stream.send(encodeFrame(request)), "Identity peer request send timed out", options.signal, close)
    await withDeadline(stream.closeSend(), "Identity peer request close timed out", options.signal, close)
    const responseBytes = await withDeadline(stream.read(maximumReconnectFrameBytes),
      "Identity peer response timed out", options.signal, close)
    const response = decodeEnvelope<ReconnectResponse>(responseBytes, "mesh-identity-peer-reconnect-response")
    if (!isChallenge(response.payload.challenge) || response.payload.challenge !== challenge ||
        response.signerKeyId !== options.contact.deviceId ||
        !await verifyEnvelope(response, remoteKey, reconnectDomain)) {
      throw new Error("Identity peer response did not prove the expected device")
    }
    const remoteRoute = await verifyFreshPeerRoute(response.payload.route, options.profile.identity,
      options.contact.deviceId, options.certificates, rawConnection.remoteEndpointId)
    const connection = meshNetworkConnection(rawConnection, new transport.WasmIngressBudgetProfile())
    closeMeshConnection = connection.close.bind(connection)
    connection.close = close
    options.signal?.removeEventListener("abort", abortListener)
    return { connection, remoteContact: makeContact(remoteRoute), localContact: makeContact(localRoute), close }
  } catch (error) {
    options.signal?.removeEventListener("abort", abortListener)
    await close()
    throw error
  }
}

async function acceptPeerConnection(options: StartBrowserIdentityPeerHostOptions,
  contacts: ReadonlyMap<string, IdentityPeerContact>, rawConnection: IrohConnection,
  endpointId: string, relayUrl: string, instanceId: string,
  transport: Awaited<ReturnType<typeof initializeBrowserIdentityRuntime>>,
  ownedConnections: Set<IrohConnection>, hostConnections: Set<IrohConnection>): Promise<IdentityPeerHostConnection> {
  const stream = await withDeadline(rawConnection.acceptStream(), "Identity peer stream accept timed out", options.signal)
  const requestBytes = await withDeadline(stream.read(maximumReconnectFrameBytes), "Identity peer request timed out", options.signal)
  const request = decodeEnvelope<ReconnectRequest>(requestBytes, "mesh-identity-peer-reconnect-request")
  const peerRoute = request.payload.route
  const key = contactKey(peerRoute.payload.personId, peerRoute.payload.deviceId)
  const contact = contacts.get(key)
  if (!isChallenge(request.payload.challenge) || !contact || request.signerKeyId !== contact.deviceId ||
      peerRoute.signerKeyId !== contact.deviceId) throw new Error("Identity peer is not enrolled")
  const peerPublicKey = await verifyDeviceCertificateChain(options.profile.identity, contact.deviceId,
    Array.from(options.certificates))
  if (!await verifyEnvelope(request, peerPublicKey, reconnectDomain)) throw new Error("Identity peer request signature is invalid")
  const freshRemoteRoute = await verifyFreshPeerRoute(peerRoute, options.profile.identity, contact.deviceId,
    options.certificates, rawConnection.remoteEndpointId)
  const sequence = await nextRouteSequence(options.nextSequence)
  const localRoute = await createFreshRoute(options.profile, options.profile.identity.personId, endpointId,
    relayUrl, instanceId, sequence)
  const response = await signEnvelope(options.profile.privateKeys.devicePrivateKey,
    { kind: "mesh-identity-peer-reconnect-response" as const, version: 1 as const,
      challenge: request.payload.challenge, route: localRoute }, options.profile.device.deviceId, reconnectDomain) as ReconnectResponse
  await withDeadline(stream.send(encodeFrame(response)), "Identity peer response send timed out", options.signal)
  await withDeadline(stream.closeSend(), "Identity peer response close timed out", options.signal)
  const connection = meshNetworkConnection(rawConnection, new transport.WasmIngressBudgetProfile())
  const closeMeshConnection = connection.close.bind(connection)
  let peerClosed = false
  const closePeer = async () => {
    if (peerClosed) return
    peerClosed = true
    ownedConnections.delete(rawConnection)
    hostConnections.delete(rawConnection)
    await closeMeshConnection()
  }
  connection.close = closePeer
  return {
    connection,
    remoteContact: makeContact(freshRemoteRoute),
    localContact: makeContact(localRoute),
    close: closePeer,
  }
}

async function verifyContactAddressHint(contact: IdentityPeerContact, publicKey: string): Promise<BrowserAddress> {
  if (contact.route.signerKeyId !== contact.deviceId) throw new Error("Identity peer contact signer mismatch")
  const route = await verifySignedDeviceRoute(contact.route, publicKey, { allowExpired: true }) as DeviceRoute
  assertRouteIdentity(route, contact.personId, contact.deviceId)
  return parseAddress(route.endpoint)
}

async function verifyFreshPeerRoute(route: SignedDeviceRoute, identity: LocalProfile["identity"], deviceId: string,
  certificates: readonly DeviceCertificate[], remoteEndpointId: string | undefined): Promise<SignedDeviceRoute> {
  if (!remoteEndpointId) throw new Error("Identity transport did not expose the peer endpoint ID")
  const publicKey = await verifyDeviceCertificateChain(identity, deviceId, Array.from(certificates))
  const verified = await verifySignedDeviceRoute(route, publicKey) as DeviceRoute
  if (route.signerKeyId !== deviceId) throw new Error("Identity peer route signer mismatch")
  assertRouteIdentity(verified, identity.personId, deviceId)
  const address = parseAddress(verified.endpoint)
  if (address.endpointId !== remoteEndpointId) throw new Error("Fresh Identity route does not match the connected endpoint")
  const now = Date.now()
  const issuedAt = Date.parse(verified.issuedAt)
  const expiresAt = Date.parse(verified.expiresAt)
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || issuedAt > now + 60_000 || expiresAt <= now) {
    throw new Error("Fresh Identity peer route is expired or not yet valid")
  }
  return route
}

async function createFreshRoute(profile: LocalProfile, personId: string, endpointId: string,
  relayUrl: string, instanceId: string, sequence: number): Promise<SignedDeviceRoute> {
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error("Identity peer route sequence must be a positive safe integer")
  if (!instanceId || instanceId.length > 128) throw new Error("Invalid Identity peer instance ID")
  const issuedAt = Date.now()
  const route = await createSignedDeviceRoute(profile, {
    scopeId: `mesh-identity:${personId}`,
    instanceId,
    endpoint: JSON.stringify({ kind: "mesh-browser-endpoint-address", version: 1, endpointId, relayUrl }),
    sequence,
    issuedAt: new Date(issuedAt).toISOString(),
    expiresAt: new Date(issuedAt + 10 * 60_000).toISOString(),
  })
  return route
}

function makeContact(route: SignedDeviceRoute): IdentityPeerContact {
  return { kind: "mesh-identity-peer-contact", version: 1,
    personId: route.payload.personId, deviceId: route.payload.deviceId, route: structuredClone(route) }
}

async function assertLocalProfile(profile: LocalProfile, certificates: readonly DeviceCertificate[]): Promise<void> {
  if (profile.device.deviceId === profile.identity.personId || profile.certificate.payload.deviceId !== profile.device.deviceId ||
      profile.certificate.payload.personId !== profile.identity.personId ||
      !certificates.some(certificate => certificate.payload.deviceId === profile.device.deviceId &&
        canonicalizeJson(certificate) === canonicalizeJson(profile.certificate))) {
    throw new Error("Identity peer host profile does not match its device certificates")
  }
  const publicKey = await verifyDeviceCertificateChain(profile.identity, profile.device.deviceId, Array.from(certificates))
  if (publicKey !== profile.device.publicKey) throw new Error("Identity peer profile public key does not match its certificate")
  const challenge = crypto.randomUUID()
  const proof = await signEnvelope(profile.privateKeys.devicePrivateKey,
    { kind: "mesh-identity-peer-key-check", version: 1, challenge }, profile.device.deviceId, reconnectDomain)
  if (!await verifyEnvelope(proof, publicKey, reconnectDomain)) throw new Error("Identity peer profile device key is unavailable")
}

function assertContactShape(contact: IdentityPeerContact, personId: string): void {
  if (!contact || contact.kind !== "mesh-identity-peer-contact" || contact.version !== 1 ||
      contact.personId !== personId || typeof contact.deviceId !== "string" || !contact.deviceId ||
      !contact.route || contact.route.payload?.personId !== personId || contact.route.payload?.deviceId !== contact.deviceId ||
      Object.keys(contact).sort().join(",") !== "deviceId,kind,personId,route,version") {
    throw new Error("Invalid saved Identity peer contact")
  }
}

function assertRouteIdentity(route: DeviceRoute, personId: string, deviceId: string): void {
  if (route.kind !== "mesh-device-route" || route.version !== 1 || route.personId !== personId ||
      route.deviceId !== deviceId || route.scopeId !== `mesh-identity:${personId}` || route.sequence < 1) {
    throw new Error("Identity peer route does not match the enrolled device")
  }
}

function isChallenge(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
}

async function nextRouteSequence(nextSequence: () => number | Promise<number>): Promise<number> {
  const sequence = await nextSequence()
  if (!Number.isSafeInteger(sequence) || sequence < 1) {
    throw new Error("Identity peer route sequence must be a positive safe integer")
  }
  return sequence
}

async function waitForAccept<T>(pending: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return pending
  if (signal.aborted) throw abortError()
  let listener: (() => void) | undefined
  const cancelled = new Promise<never>((_resolve, reject) => {
    listener = () => reject(abortError())
    signal.addEventListener("abort", listener, { once: true })
  })
  try { return await Promise.race([pending, cancelled]) }
  finally { if (listener) signal.removeEventListener("abort", listener) }
}

function parseAddress(value: string): BrowserAddress {
  let parsed: unknown
  try { parsed = JSON.parse(value) } catch { throw new Error("Identity peer route has no browser address hint") }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Invalid Identity peer address hint")
  const address = parsed as Partial<BrowserAddress>
  if (address.kind !== "mesh-browser-endpoint-address" || address.version !== 1 ||
      typeof address.endpointId !== "string" || !address.endpointId || address.endpointId.length > 128 ||
      typeof address.relayUrl !== "string" || address.relayUrl.length > 2048 ||
      Object.keys(parsed).sort().join(",") !== "endpointId,kind,relayUrl,version") {
    throw new Error("Invalid Identity peer address hint")
  }
  let url: URL
  try { url = new URL(address.relayUrl) } catch { throw new Error("Invalid Identity peer relay address") }
  const localHttp = url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
  if ((url.protocol !== "https:" && !localHttp) || url.username || url.password || url.hash) {
    throw new Error("Invalid Identity peer relay address")
  }
  return address as BrowserAddress
}

function encodeFrame(value: unknown): Uint8Array {
  const bytes = new TextEncoder().encode(JSON.stringify(value))
  if (bytes.byteLength === 0 || bytes.byteLength > maximumReconnectFrameBytes) {
    throw new Error("Identity reconnect frame exceeds size limit")
  }
  return bytes
}

function decodeEnvelope<T extends { payload: { kind: string; version: number }; signerKeyId: string; signature: string }>(
  bytes: Uint8Array, expectedKind: string): SignedEnvelope<T["payload"]> {
  if (bytes.byteLength === 0 || bytes.byteLength > maximumReconnectFrameBytes) throw new Error("Identity reconnect frame exceeds size limit")
  let value: unknown
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) }
  catch { throw new Error("Invalid Identity reconnect frame") }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid Identity reconnect frame")
  const envelope = value as Partial<SignedEnvelope<T["payload"]>>
  if (!envelope.payload || envelope.payload.kind !== expectedKind || envelope.payload.version !== 1 ||
      typeof envelope.signerKeyId !== "string" || typeof envelope.signature !== "string" ||
      Object.keys(envelope.payload).sort().join(",") !== "challenge,kind,route,version" ||
      Object.keys(envelope).sort().join(",") !== "payload,signature,signerKeyId") {
    throw new Error("Invalid Identity reconnect frame")
  }
  return envelope as SignedEnvelope<T["payload"]>
}

function assertTransportSeed(seed: Uint8Array): void {
  if (!(seed instanceof Uint8Array) || seed.byteLength !== 32) throw new Error("Identity transport seed must contain 32 bytes")
}

function contactKey(personId: string, deviceId: string): string { return `${personId}\0${deviceId}` }

function withDeadline<T>(promise: Promise<T>, message: string, signal?: AbortSignal, onCancel?: () => void | Promise<void>): Promise<T> {
  if (signal?.aborted) return Promise.reject(abortError())
  return new Promise<T>((resolve, reject) => {
    let done = false
    const finish = (callback: () => void) => {
      if (done) return
      done = true
      clearTimeout(timer)
      signal?.removeEventListener("abort", onAbort)
      callback()
    }
    const timer = setTimeout(() => {
      void onCancel?.()
      finish(() => reject(new Error(message)))
    }, reconnectTimeoutMs)
    const onAbort = () => {
      void onCancel?.()
      finish(() => reject(abortError()))
    }
    signal?.addEventListener("abort", onAbort, { once: true })
    promise.then(value => finish(() => resolve(value)), error => finish(() => reject(error)))
  })
}

function abortError(): Error {
  return typeof DOMException === "undefined" ? new Error("Identity peer operation cancelled") :
    new DOMException("Identity peer operation cancelled", "AbortError")
}
