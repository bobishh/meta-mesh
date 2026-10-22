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

/** Accept authenticated reconnects from already enrolled devices. Caller owns contact persistence and sync. */
export async function startBrowserIdentityPeerHost(options: {
  profile: LocalProfile
  certificates: readonly DeviceCertificate[]
  contacts: readonly IdentityPeerContact[]
  transportSeed: Uint8Array
  nextSequence(): number | Promise<number>
  onConnected(peer: IdentityPeerHostConnection): void | Promise<void>
  signal?: AbortSignal
}): Promise<BrowserIdentityPeerHost> {
  await assertLocalProfile(options.profile, options.certificates)
  assertTransportSeed(options.transportSeed)
  if (options.signal?.aborted) throw abortError()
  const contacts = new Map<string, IdentityPeerContact>()
  for (const contact of options.contacts) {
    assertContactShape(contact, options.profile.identity.personId)
    const key = contactKey(contact.personId, contact.deviceId)
    if (contacts.has(key)) throw new Error("Duplicate Identity peer contact")
    contacts.set(key, structuredClone(contact))
  }

  const transport = await initializeBrowserIdentityRuntime()
  const node = await transport.BrowserNode.start(new Uint8Array(options.transportSeed))
  const activeConnections = new Set<IrohConnection>()
  let acceptor: Awaited<ReturnType<IrohNode["accept"]>> | undefined
  let closed = false
  const instanceId = crypto.randomUUID()
  let closePromise: Promise<void> | undefined

  const close = async (): Promise<void> => {
    if (closePromise) return closePromise
    closed = true
    closePromise = (async () => {
      options.signal?.removeEventListener("abort", abortListener)
      await Promise.all(Array.from(activeConnections, connection => connection.close().catch(() => undefined)))
      await node.close("Identity peer host closed").catch(() => undefined)
    })()
    return closePromise
  }
  const abortListener = () => { void close() }
  options.signal?.addEventListener("abort", abortListener, { once: true })

  let relayUrl: string
  try {
    relayUrl = await waitForRelayUrl(node, { timeoutMs: 10_000, signal: options.signal })
    acceptor = await withDeadline(node.accept(), "Identity peer listener timed out", options.signal, close)
  } catch (error) {
    await close()
    throw error
  }

  const done = (async () => {
    while (!closed) {
      let rawConnection: IrohConnection | undefined
      let handedOff = false
      try {
        rawConnection = await waitForAccept(acceptor!.accept(), options.signal)
        if (!rawConnection) continue
        activeConnections.add(rawConnection)
        const peer = await acceptPeerConnection(options, contacts, rawConnection, node.endpointId, relayUrl,
          instanceId, transport, activeConnections)
        await options.onConnected(peer)
        handedOff = true
      } catch (error) {
        if (closed || options.signal?.aborted) return
        // Unknown, stale, and malformed peers never reach the caller's sync or persistence callbacks.
      } finally {
        if (rawConnection && (!handedOff || closed)) {
          activeConnections.delete(rawConnection)
          await rawConnection.close().catch(() => undefined)
        }
      }
    }
  })()

  return { endpointId: node.endpointId, relayUrl, instanceId, done, close }
}

/** Dial one saved address hint, then require a fresh signed challenge response before returning a connection. */
export async function connectBrowserIdentityPeer(options: {
  profile: LocalProfile
  certificates: readonly DeviceCertificate[]
  contact: IdentityPeerContact
  transportSeed: Uint8Array
  nextSequence(): number | Promise<number>
  signal?: AbortSignal
}): Promise<ConnectedIdentityPeer> {
  await assertLocalProfile(options.profile, options.certificates)
  assertTransportSeed(options.transportSeed)
  assertContactShape(options.contact, options.profile.identity.personId)
  if (options.contact.deviceId === options.profile.device.deviceId) throw new Error("Cannot reconnect to this Identity device")
  if (options.signal?.aborted) throw abortError()

  const transport = await initializeBrowserIdentityRuntime()
  const remoteKey = await verifyDeviceCertificateChain(options.profile.identity, options.contact.deviceId,
    Array.from(options.certificates))
  const hint = await verifyContactAddressHint(options.contact, remoteKey)
  const node = await transport.BrowserNode.start(new Uint8Array(options.transportSeed))
  let rawConnection: IrohConnection | undefined
  let closed = false
  const close = async () => {
    if (closed) return
    closed = true
    await rawConnection?.close().catch(() => undefined)
    await node.close("Identity peer connection closed").catch(() => undefined)
  }
  const abortListener = () => { void close() }
  options.signal?.addEventListener("abort", abortListener, { once: true })
  try {
    const relayUrl = await waitForRelayUrl(node, { timeoutMs: 10_000, signal: options.signal })
    rawConnection = await withDeadline(node.dialRelay(hint.endpointId, hint.relayUrl),
      "Identity peer dial timed out", options.signal, close)
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
    options.signal?.removeEventListener("abort", abortListener)
    return {
      connection,
      remoteContact: makeContact(remoteRoute),
      localContact: makeContact(localRoute),
      close,
    }
  } catch (error) {
    options.signal?.removeEventListener("abort", abortListener)
    await close()
    throw error
  }
}

async function acceptPeerConnection(options: Parameters<typeof startBrowserIdentityPeerHost>[0],
  contacts: ReadonlyMap<string, IdentityPeerContact>, rawConnection: IrohConnection,
  endpointId: string, relayUrl: string, instanceId: string,
  transport: Awaited<ReturnType<typeof initializeBrowserIdentityRuntime>>,
  activeConnections: Set<IrohConnection>): Promise<IdentityPeerHostConnection> {
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
  return {
    connection,
    remoteContact: makeContact(freshRemoteRoute),
    localContact: makeContact(localRoute),
    close: async () => {
      activeConnections.delete(rawConnection)
      await connection.close()
    },
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
