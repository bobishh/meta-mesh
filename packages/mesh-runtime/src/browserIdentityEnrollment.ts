import {
  createIdentityDeviceEnrollmentRequest,
  identityRequestAllowsRecoveryTransfer,
  issueIdentityDeviceEnrollment,
  verifyDeviceCertificateChain,
  verifyIdentityDeviceEnrollmentRequest,
  type DeviceCertificate,
  type IdentityDeviceEnrollmentRequest,
  type IdentityProfileRecoveryFile,
  type IdentityRecoveryEnvelope,
  type LocalProfile,
  type PublicIdentity,
} from "@meta-uber/mesh-identity"
import {
  createDeviceEnrollmentInvite,
  createPairingSecret,
  installPairingCodec,
  invitationUrl,
  parseInvitation,
  type DeviceEnrollmentInvitation,
} from "@meta-uber/mesh-pairing"
import { createSignedDeviceRoute, verifySignedDeviceRoute, type DeviceRoute, type SignedDeviceRoute } from "@meta-uber/mesh-replication"
import { enrollmentRouteTimestamps } from "./enrollmentRouteTimes"
import type { WasmPairingCodec } from "@meta-uber/mesh-transport/transport-wasm"
import { meshNetworkConnection, waitForRelayUrl, type IrohConnection, type MeshConnection } from "@meta-uber/mesh-transport"
import { createIdentityEnrollmentDevice } from "@meta-uber/mesh-identity"
import type * as Automerge from "@automerge/automerge"
import { createPersonalIdentityAdapter, PersonalIdentityMeshSync,
  type PersonalIdentityDocument, type PersonalIdentitySyncConnection,
  type PersonalIdentitySyncStream } from "@meta-uber/mesh-replication/identity-mesh"
import { installMeshRustRuntime } from "@meta-uber/mesh-replication/runtime"
import initializePolicyWasm, { WasmAutomergeDeviceSyncFlow, WasmAutomergeSyncEngine, WasmDeviceRouteCatalog,
  WasmGossipLifecycleState, WasmIngressBudgetProfile, WasmLiveWorkspaceSession,
  WasmMeshAuthenticatedSessions, WasmMeshBatchDeliveryFlow, WasmMeshHandshakeFlow,
  WasmMeshLifecycleState, WasmMeshRuntimeState, WasmMeshScopeRuntime, WasmMeshSessionLifecycle,
  WasmStateCore } from "@meta-uber/mesh-transport/wasm"
import { z } from "zod"

const MAX_ENROLLMENT_FRAME_BYTES = 3 * 1024 * 1024

export type IdentityEnrollmentRecovery = {
  recoveryKey: string
  recoveryEnvelope: IdentityRecoveryEnvelope
  file: IdentityProfileRecoveryFile
}

export type BrowserIdentityEnrollmentApproval = {
  identity: PublicIdentity
  certificates: DeviceCertificate[]
  connection: MeshConnection
  remoteEndpointId: string
  remoteRoute: DeviceRoute
  recovery?: IdentityEnrollmentRecovery
}

export type PendingIdentityEnrollment = {
  request: IdentityDeviceEnrollmentRequest
  approve(options?: {
    fullRecoveryConsent?: true
    recovery?: IdentityEnrollmentRecovery
    persist?: (identity: PublicIdentity, certificates: DeviceCertificate[]) => Promise<void>
    ensureCurrent?: () => void | Promise<void>
  }): Promise<BrowserIdentityEnrollmentApproval>
  reject(): Promise<void>
}

export type BrowserIdentityEnrollmentHost = {
  endpointId: string
  invitation: DeviceEnrollmentInvitation
  inviteUrl: string
  waitForEnrollment(signal?: AbortSignal): Promise<PendingIdentityEnrollment>
  close(): Promise<void>
}

export type ConnectedIdentityEnrollment = BrowserIdentityEnrollmentApproval & { profile: LocalProfile; close(): Promise<void> }

export type IdentityProfileSyncOptions = {
  profile: LocalProfile
  certificates: readonly DeviceCertificate[]
  connection: MeshConnection
  current(): Promise<Automerge.Doc<PersonalIdentityDocument>>
  commit(document: Automerge.Doc<PersonalIdentityDocument>, expectedProfileRevision: string): void | Promise<void>
  authorizePeer?: (remoteDeviceId: string, direction: "send" | "receive") => boolean | Promise<boolean>
}

/** Exchange the current personal Identity document with one already enrolled peer. */
export async function syncProfileState(options: IdentityProfileSyncOptions & {
  route: DeviceRoute
  targetDeviceId: string
  signal?: AbortSignal
}): Promise<{ rounds: number; routeInstanceIds: string[] }> {
  const adapter = createPersonalIdentityAdapter({ identity: options.profile.identity,
    current: options.current, commit: options.commit, authorizePeer: options.authorizePeer })
  const sync = new PersonalIdentityMeshSync({ profile: options.profile, adapter })
  return sync.sync(identitySyncConnection(options.connection), options.route, options.targetDeviceId, options.signal)
}

/** Keep accepting authenticated device-sync streams until stopped or the connection closes. */
export function serveIdentityProfileSync(options: IdentityProfileSyncOptions & {
  remoteDeviceId: string
  onAcceptedChanges?: (acceptedChanges: number) => void | Promise<void>
}): { done: Promise<void>; close(): Promise<void> } {
  const adapter = createPersonalIdentityAdapter({ identity: options.profile.identity,
    current: options.current, commit: options.commit, authorizePeer: options.authorizePeer })
  const sync = new PersonalIdentityMeshSync({ profile: options.profile, adapter })
  let stopped = false
  let closing: Promise<void> | undefined
  const done = (async () => {
    while (!stopped) {
      const result = await sync.receiveNext(identitySyncConnection(options.connection), options.remoteDeviceId)
      if (result.acceptedChanges > 0) await options.onAcceptedChanges?.(result.acceptedChanges)
    }
  })()
  return {
    done,
    async close() {
      if (stopped) return closing
      stopped = true
      closing = options.connection.close()
      await closing
    },
  }
}

function identitySyncConnection(connection: MeshConnection): PersonalIdentitySyncConnection {
  return {
    openStream: async () => identitySyncStream(await connection.openStream()),
    acceptStream: async () => identitySyncStream(await connection.acceptStream()),
  }
}

function identitySyncStream(stream: Awaited<ReturnType<MeshConnection["openStream"]>>): PersonalIdentitySyncStream {
  if (!stream.readRaw) throw new Error("Identity sync requires raw stream reads")
  return {
    send: bytes => stream.send(bytes),
    readRaw: () => stream.readRaw!(),
    closeSend: () => stream.closeSend(),
  }
}

type BrowserPairingModule = typeof import("@meta-uber/mesh-transport/transport-wasm")

async function enrollmentFramePhase<T>(streamPhase: string, frameKind: string, encryptedByteLength: number | null,
  operation: () => Promise<T>): Promise<T> {
  try { return await operation() }
  catch (error) {
    if (typeof location !== "undefined" && (location.hostname === "localhost" || location.hostname === "127.0.0.1")) {
      console.warn("Identity enrollment frame failed", {
        streamPhase,
        frameKind,
        encryptedByteLength,
        ingressCap: MAX_ENROLLMENT_FRAME_BYTES,
      })
    }
    throw error
  }
}

let transportReady: Promise<void> | undefined
function initializePairing(transport: BrowserPairingModule): Promise<void> {
  if (!transportReady) {
    transportReady = (async () => {
      await transport.default()
      await initializePolicyWasm()
      installMeshRustRuntime({
        state: WasmStateCore,
        createDeviceRouteCatalog: () => new WasmDeviceRouteCatalog(),
        createAutomergeSyncEngine: (localDeviceId, maximumFrameBytes) => new WasmAutomergeSyncEngine(localDeviceId, maximumFrameBytes),
        createAutomergeDeviceSyncFlow: (targetDeviceId, documentId, maximumRounds) =>
          new WasmAutomergeDeviceSyncFlow(targetDeviceId, documentId, maximumRounds),
        decodeAutomergeDeviceSyncRequest: (request, expectedRemoteDeviceId) => z.object({
          frame: z.unknown(),
          batch: z.object({ protocolVersion: z.literal(1), scopeId: z.string(), documentId: z.string(), batchId: z.string(),
            changes: z.array(z.object({ hash: z.string(), bytes: z.union([z.instanceof(Uint8Array),
              z.array(z.number().int().min(0).max(255))]) })) }),
        }).parse(WasmAutomergeDeviceSyncFlow.decodeIncomingRequest(request, expectedRemoteDeviceId)),
        encodeAutomergeDeviceSyncResponse: (batchId, ack, frame) => WasmAutomergeDeviceSyncFlow.encodeResponse(batchId, ack, frame),
        createBatchDeliveryFlow: (targetDeviceId, routeInstanceIds, fallbackDelayMs, retryDelaysMs) =>
          new WasmMeshBatchDeliveryFlow(targetDeviceId, routeInstanceIds, fallbackDelayMs, retryDelaysMs),
        createMeshRuntimeState: () => new WasmMeshRuntimeState(),
        createGossipLifecycleState: topicPrefix => new WasmGossipLifecycleState(topicPrefix),
        createMeshLifecycleState: () => new WasmMeshLifecycleState(),
        createMeshSessionLifecycleState: stableAfterMs => new WasmMeshSessionLifecycle(stableAfterMs),
        createLiveWorkspaceSession: (workspaceId, secret) => new WasmLiveWorkspaceSession(workspaceId, secret),
        createMeshScopeRuntime: (workspaceId, secret) => new WasmMeshScopeRuntime(workspaceId, secret),
        createMeshHandshakeFlow: direction => new WasmMeshHandshakeFlow(direction),
        createMeshAuthenticatedSessions: () => new WasmMeshAuthenticatedSessions(),
      })
      pairingCodec = new transport.WasmPairingCodec()
      installPairingCodec(pairingCodec)
    })().catch(error => {
      transportReady = undefined
      throw error
    })
  }
  return transportReady
}

/** Initialize shared browser MetaMesh runtime modules before an explicit device connection. */
export async function initializeBrowserIdentityRuntime(): Promise<BrowserPairingModule> {
  const transport = await import("@meta-uber/mesh-transport/transport-wasm")
  await initializePairing(transport)
  return transport
}

/** Host a one-use, invitation-bound request for a full Identity device. */
export async function createBrowserIdentityEnrollmentHost(options: {
  profile: LocalProfile
  certificates: readonly DeviceCertificate[]
  transportSeed: Uint8Array
  origin: string
  signal?: AbortSignal
}): Promise<BrowserIdentityEnrollmentHost> {
  const origin = new URL(options.origin)
  if (options.transportSeed.byteLength !== 32) throw new Error("Identity transport seed must be 32 bytes")
  if (origin.origin !== options.origin || (origin.protocol !== "https:" && origin.hostname !== "localhost" && origin.hostname !== "127.0.0.1")) {
    throw new Error("Identity enrollment requires an exact HTTPS or local origin")
  }
  const transport = await import("@meta-uber/mesh-transport/transport-wasm")
  await initializePairing(transport as BrowserPairingModule)
  const node = await transport.BrowserNode.start(new Uint8Array(options.transportSeed))
  let relayUrl: string
  try { relayUrl = await waitForRelayUrl(node, { signal: options.signal }) }
  catch (error) { await node.close("Identity relay address unavailable").catch(() => undefined); throw error }
  const invitation = createDeviceEnrollmentInvite(node.endpointId, createPairingSecret(), options.profile,
    Date.now(), relayUrl)
  const inviteUrl = invitationUrl(origin.origin, invitation)
  let closed = false
  let consumed = false
  let acceptor: { accept(): Promise<IrohConnection | undefined>; close?(): Promise<void> } | undefined
  let activeConnection: IrohConnection | undefined

  const close = async () => {
    if (closed) return
    closed = true
    await activeConnection?.close().catch(() => undefined)
    await acceptor?.close?.().catch(() => undefined)
    await node.close("Identity enrollment closed").catch(() => undefined)
  }

  return {
    endpointId: node.endpointId,
    invitation,
    inviteUrl,
    async waitForEnrollment(signal) {
      if (closed) throw new Error("Identity enrollment host is closed")
      if (consumed) throw new Error("This Identity enrollment invitation has already been used")
      if (signal?.aborted) throw abortError()
      acceptor ??= await node.accept()
      while (!closed) {
        if (signal?.aborted) throw abortError()
        const connection = await raceAbort(acceptor.accept(), signal, close)
        if (!connection) continue
        activeConnection = connection
        try {
          const stream = await connection.acceptStream()
          const frame = await stream.readPairingFrame(MAX_ENROLLMENT_FRAME_BYTES)
          const payload = parseFrame(requireCodec().decode(frame, "enroll-request", invitation.secret)) as EnrollmentRequestFrame
          assertRequestFrame(payload)
          await verifyIdentityDeviceEnrollmentRequest(payload.request, invitation)
          const route = await verifyRouteForDevice(payload.route, payload.request.payload.devicePublicKey,
            invitation.issuerPersonId, payload.request.payload.deviceId)
          if (connection.remoteEndpointId && parseBrowserEndpointAddress(route.endpoint).endpointId !== connection.remoteEndpointId) {
            throw new Error("Enrollment request route does not match its transport connection")
          }
          consumed = true
          return createPendingEnrollment({
            profile: options.profile,
            certificates: Array.from(options.certificates),
            invitation,
            connection,
            stream,
            request: payload.request,
            requestRoute: route,
            endpointId: node.endpointId,
            relayUrl,
            onClose: close,
          })
        } catch (error) {
          await connection.close().catch(() => undefined)
          activeConnection = undefined
          if (signal?.aborted || closed) throw error
          // Invalid, foreign, or replayed requests do not consume the one-use invitation.
        }
      }
      throw new Error("Identity enrollment host is closed")
    },
    close,
  }
}

/** Join an Identity invitation with a new device key. The invite issuer selects the person. */
export async function connectBrowserIdentityEnrollment(options: {
  inviteUrl: string
  device?: Awaited<ReturnType<typeof createIdentityEnrollmentDevice>>
  transportSeed: Uint8Array
  deviceLabel: string
  fullRecoveryConsent?: true
  acknowledgeRecovery?: (recovery: IdentityEnrollmentRecovery, identity: PublicIdentity, signal?: AbortSignal) => void | Promise<void>
  signal?: AbortSignal
}): Promise<ConnectedIdentityEnrollment> {
  const invitation = parseInvitation(options.inviteUrl)
  if (invitation.kind !== "device-enrollment") throw new Error("This is not an Identity device invitation")
  if (!invitation.issuerRelayUrl) {
    throw new Error("This invite is missing a relay address. Create a new invite from the trusted Identity device.")
  }
  const device = options.device ?? await createIdentityEnrollmentDevice(options.deviceLabel)
  const deviceLabel = options.deviceLabel.trim()
  if (options.transportSeed.byteLength !== 32) throw new Error("Identity transport seed must be 32 bytes")
  if (!deviceLabel || deviceLabel.length > 128) throw new Error("Enter a device name up to 128 characters")
  if (options.signal?.aborted) throw abortError()
  const request = await enrollmentPhase("device request signing", () =>
    createIdentityDeviceEnrollmentRequest(device, invitation, {
      displayName: deviceLabel,
      fullRecoveryConsent: options.fullRecoveryConsent === true,
    }))
  await enrollmentPhase("transport initialization", async () =>
    initializePairing(await import("@meta-uber/mesh-transport/transport-wasm")))
  const transport = await import("@meta-uber/mesh-transport/transport-wasm")
  const node = await enrollmentPhase("device transport start", () =>
    transport.BrowserNode.start(new Uint8Array(options.transportSeed)))
  let rawConnection: IrohConnection | undefined
  const closeOnAbort = async () => {
    await rawConnection?.close().catch(() => undefined)
    await node.close("Identity enrollment cancelled").catch(() => undefined)
  }
  const awaitSignal = <T>(promise: Promise<T>) => raceAbort(promise, options.signal, closeOnAbort)
  const abortListener = () => { void closeOnAbort() }
  options.signal?.addEventListener("abort", abortListener, { once: true })
  try {
    const relayUrl = await awaitSignal(waitForRelayUrl(node, { signal: options.signal }))
    rawConnection = await awaitSignal(enrollmentPhase("invitation relay connection", () =>
      node.dialRelay(invitation.issuerEndpoint, invitation.issuerRelayUrl!)))
    const stream = await awaitSignal(rawConnection.openStream())
    const route = await enrollmentPhase("signed device route creation", () => createRouteForEnrollment(request.payload.personId,
      request.payload.deviceId, invitation.issuerPersonId, node.endpointId, relayUrl,
      request.payload.devicePublicKey, device.privateKey))
    await awaitSignal(stream.send(requireCodec().encode("enroll-request", invitation.secret,
      encodeFrame({ request, route }, MAX_ENROLLMENT_FRAME_BYTES))))
    await awaitSignal(stream.closeSend())
    const frame = await awaitSignal(stream.readPairingFrame(MAX_ENROLLMENT_FRAME_BYTES))
    const response = requireCodec().inspect(frame) as { frame_type?: unknown }
    if (response?.frame_type === "enroll-rejected") {
      const rejection = JSON.parse(new TextDecoder().decode(requireCodec().decode(frame, "enroll-rejected", invitation.secret))) as RejectionFrame
      throw new Error(rejection.message || "Identity device request was declined")
    }
    const approval = parseFrame(requireCodec().decode(frame, "enroll-approved", invitation.secret)) as EnrollmentApprovalFrame
    assertApprovalFrame(approval, request, invitation)
    if (approval.recovery && options.fullRecoveryConsent !== true) {
      throw new Error("This device did not consent to receive full Identity recovery capability")
    }
    await verifyDeviceCertificateChain(approval.identity, request.payload.deviceId, approval.certificates)
    const leaf = approval.certificates.find(certificate => certificate.payload.deviceId === request.payload.deviceId)
    if (!leaf || leaf.payload.devicePublicKey !== request.payload.devicePublicKey || !leaf.payload.canEnrollDevices) {
      throw new Error("Identity device approval does not match this device")
    }
    const issuerCertificate = approval.certificates.find(certificate => certificate.payload.deviceId === invitation.issuerDeviceId)
    if (!issuerCertificate) throw new Error("Identity approval is missing the issuer device certificate")
    const remoteRoute = await verifyRouteForDevice(approval.remoteRoute, issuerCertificate.payload.devicePublicKey,
      approval.identity.personId, invitation.issuerDeviceId)
    if (parseBrowserEndpointAddress(remoteRoute.endpoint).endpointId !== invitation.issuerEndpoint) {
      throw new Error("Identity approval route does not match this invitation")
    }
    if (approval.recovery) {
      if (!options.acknowledgeRecovery) throw new Error("Recovery transfer requires an explicit words-and-file acknowledgment")
      await awaitSignal(Promise.resolve(options.acknowledgeRecovery(structuredClone(approval.recovery),
        structuredClone(approval.identity), options.signal)))
    }
    const signedAck = { kind: "mesh-identity-device-enrollment-ack", version: 1, requestId: request.payload.requestId,
      deviceId: request.payload.deviceId, invitationId: invitation.invitationId }
    const acknowledgementStream = await awaitSignal(rawConnection.openStream())
    await awaitSignal(acknowledgementStream.send(requireCodec().encode("enroll-ack", invitation.secret,
      encodeFrame(signedAck, MAX_ENROLLMENT_FRAME_BYTES))))
    await awaitSignal(acknowledgementStream.closeSend())
    const completeFrame = await awaitSignal(acknowledgementStream.readPairingFrame(MAX_ENROLLMENT_FRAME_BYTES))
    const complete = parseFrame(requireCodec().decode(completeFrame, "enroll-complete", invitation.secret)) as CompleteFrame
    if (complete.kind !== "mesh-identity-device-enrollment-complete" || complete.version !== 1 || complete.requestId !== request.payload.requestId) {
      throw new Error("Identity enrollment completion did not match this request")
    }
    options.signal?.removeEventListener("abort", abortListener)
    const connection = meshNetworkConnection(rawConnection, new WasmIngressBudgetProfile())
    const profile: LocalProfile = {
      identity: structuredClone(approval.identity),
      device: { ...structuredClone(device.device), displayName: deviceLabel },
      certificate: structuredClone(leaf),
      privateKeys: { devicePrivateKey: device.privateKey },
    }
    return {
      profile,
      identity: structuredClone(approval.identity),
      certificates: structuredClone(approval.certificates),
      connection,
      remoteEndpointId: parseBrowserEndpointAddress(remoteRoute.endpoint).endpointId,
      remoteRoute,
      close: async () => {
        await rawConnection?.close().catch(() => undefined)
        await node.close("Identity device connection closed").catch(() => undefined)
      },
      ...(approval.recovery ? { recovery: approval.recovery } : {}),
    }
  } catch (error) {
    options.signal?.removeEventListener("abort", abortListener)
    await rawConnection?.close().catch(() => undefined)
    await node.close("Identity enrollment failed").catch(() => undefined)
    throw error
  }
}

function createPendingEnrollment(options: {
  profile: LocalProfile
  certificates: DeviceCertificate[]
  invitation: DeviceEnrollmentInvitation
  connection: IrohConnection
  stream: Awaited<ReturnType<IrohConnection["openStream"]>>
  request: IdentityDeviceEnrollmentRequest
  requestRoute: DeviceRoute
  endpointId: string
  relayUrl: string
  onClose(): Promise<void>
}): PendingIdentityEnrollment {
  let completed = false
  return {
    request: structuredClone(options.request),
    async approve(approvalOptions = {}) {
      if (completed) throw new Error("Identity enrollment request has already been completed")
      if (approvalOptions.recovery && (approvalOptions.fullRecoveryConsent !== true ||
        !identityRequestAllowsRecoveryTransfer(options.request))) {
        throw new Error("Full Identity recovery transfer requires explicit consent")
      }
      await approvalOptions.ensureCurrent?.()
      const certificate = await issueIdentityDeviceEnrollment(options.profile, options.request, options.invitation,
        options.certificates, { ensureCurrent: approvalOptions.ensureCurrent })
      const certificates = [...structuredClone(options.certificates), certificate]
      await verifyDeviceCertificateChain(options.profile.identity, options.request.payload.deviceId, certificates)
      const { issuedAt, expiresAt } = enrollmentRouteTimestamps()
      const remoteRoute = await createSignedDeviceRoute(options.profile, {
        scopeId: `mesh-identity:${options.profile.identity.personId}`,
        instanceId: crypto.randomUUID(),
        endpoint: encodeBrowserEndpointAddress(options.endpointId, options.relayUrl),
        sequence: 1,
        issuedAt,
        expiresAt,
      })
      const response: EnrollmentApprovalFrame = {
        kind: "mesh-identity-device-enrollment-approved", version: 1,
        requestId: options.request.payload.requestId,
        identity: structuredClone(options.profile.identity),
        certificates,
        remoteRoute,
        ...(approvalOptions.recovery ? { recovery: structuredClone(approvalOptions.recovery) } : {}),
      }
      if (approvalOptions.recovery && approvalOptions.recovery.file.personId !== options.profile.identity.personId) {
        throw new Error("Recovery package belongs to a different Identity")
      }
      const encodedResponse = encodeFrame(response, MAX_ENROLLMENT_FRAME_BYTES)
      await approvalOptions.ensureCurrent?.()
      const approvalFrame = requireCodec().encode("enroll-approved", options.invitation.secret, encodedResponse)
      await enrollmentFramePhase("send-approved", "enroll-approved", approvalFrame.byteLength,
        () => options.stream.send(approvalFrame))
      await options.stream.closeSend()
      const acknowledgementStream = await enrollmentFramePhase("accept-ack-stream", "enroll-ack", null,
        () => options.connection.acceptStream())
      const ackFrame = await enrollmentFramePhase("read-ack", "enroll-ack", null,
        () => acknowledgementStream.readPairingFrame(MAX_ENROLLMENT_FRAME_BYTES))
      const acknowledgement = await enrollmentFramePhase("decode-ack", "enroll-ack", ackFrame.byteLength, async () =>
        parseFrame(requireCodec().decode(ackFrame, "enroll-ack", options.invitation.secret)) as AckFrame)
      if (acknowledgement.kind !== "mesh-identity-device-enrollment-ack" || acknowledgement.version !== 1 ||
        acknowledgement.requestId !== options.request.payload.requestId || acknowledgement.deviceId !== options.request.payload.deviceId) {
        throw new Error("Identity enrollment acknowledgment did not match this request")
      }
      await approvalOptions.ensureCurrent?.()
      await approvalOptions.persist?.(structuredClone(options.profile.identity), structuredClone(certificates))
      const complete: CompleteFrame = { kind: "mesh-identity-device-enrollment-complete", version: 1,
        requestId: options.request.payload.requestId }
      const completeFrame = requireCodec().encode("enroll-complete", options.invitation.secret,
        encodeFrame(complete, MAX_ENROLLMENT_FRAME_BYTES))
      await enrollmentFramePhase("send-complete", "enroll-complete", completeFrame.byteLength,
        () => acknowledgementStream.send(completeFrame))
      await acknowledgementStream.closeSend()
      completed = true
      const connection = meshNetworkConnection(options.connection, new WasmIngressBudgetProfile())
      return {
        identity: structuredClone(options.profile.identity), certificates,
        connection,
        remoteEndpointId: options.requestRoute.endpoint,
        remoteRoute: options.requestRoute,
        ...(approvalOptions.recovery ? { recovery: structuredClone(approvalOptions.recovery) } : {}),
      }
    },
    async reject() {
      if (completed) return
      completed = true
      const frame: RejectionFrame = { kind: "mesh-identity-device-enrollment-rejected", version: 1,
        requestId: options.request.payload.requestId, message: "This device request was declined." }
      await options.stream.send(requireCodec().encode("enroll-rejected", options.invitation.secret,
        encodeFrame(frame, MAX_ENROLLMENT_FRAME_BYTES))).catch(() => undefined)
      await options.stream.closeSend().catch(() => undefined)
      await options.connection.close().catch(() => undefined)
      await options.onClose()
    },
  }
}

type EnrollmentRequestFrame = { request: IdentityDeviceEnrollmentRequest; route: SignedDeviceRoute }
type EnrollmentApprovalFrame = {
  kind: "mesh-identity-device-enrollment-approved"
  version: 1
  requestId: string
  identity: PublicIdentity
  certificates: DeviceCertificate[]
  remoteRoute: SignedDeviceRoute
  recovery?: IdentityEnrollmentRecovery
}
type RejectionFrame = { kind: "mesh-identity-device-enrollment-rejected"; version: 1; requestId: string; message: string }
type AckFrame = { kind: "mesh-identity-device-enrollment-ack"; version: 1; requestId: string; deviceId: string; invitationId: string }
type CompleteFrame = { kind: "mesh-identity-device-enrollment-complete"; version: 1; requestId: string }

function assertRequestFrame(value: EnrollmentRequestFrame): void {
  if (!value || typeof value !== "object" || !value.request || !value.route) throw new Error("Invalid Identity device request")
}

function assertApprovalFrame(value: EnrollmentApprovalFrame, request: IdentityDeviceEnrollmentRequest,
  invitation: DeviceEnrollmentInvitation): void {
  if (!value || value.kind !== "mesh-identity-device-enrollment-approved" || value.version !== 1 ||
    value.requestId !== request.payload.requestId || !value.identity || !Array.isArray(value.certificates) ||
    value.identity.personId !== invitation.issuerPersonId) throw new Error("Identity approval does not match this invitation")
}

async function createRouteForEnrollment(personId: string, deviceId: string, scopePersonId: string, endpointId: string,
  relayUrl: string, publicKey: string, privateKey: CryptoKey): Promise<SignedDeviceRoute> {
  const { issuedAt, expiresAt } = enrollmentRouteTimestamps()
  const temporaryProfile: LocalProfile = {
    identity: { personId: scopePersonId, publicKey, displayName: "Enrollment device" },
    device: { deviceId, publicKey, displayName: "Enrollment device" },
    certificate: {} as DeviceCertificate,
    privateKeys: { devicePrivateKey: privateKey },
  }
  const route = await createSignedDeviceRoute(temporaryProfile, {
    scopeId: `mesh-identity:${personId}`,
    instanceId: crypto.randomUUID(),
    endpoint: encodeBrowserEndpointAddress(endpointId, relayUrl),
    sequence: 1,
    issuedAt,
    expiresAt,
  })
  return route
}

async function verifyRouteForDevice(route: SignedDeviceRoute, publicKey: string, personId: string, deviceId: string): Promise<DeviceRoute> {
  const verified = await verifySignedDeviceRoute(route, publicKey) as DeviceRoute
  parseBrowserEndpointAddress(verified.endpoint)
  if (verified.kind !== "mesh-device-route" || verified.personId !== personId || verified.deviceId !== deviceId ||
    verified.scopeId !== `mesh-identity:${personId}` || Date.parse(verified.expiresAt) <= Date.now() ||
    Date.parse(verified.issuedAt) > Date.now() + 60_000) throw new Error("Invalid Identity device route")
  return verified
}

type BrowserEndpointAddress = { kind: "mesh-browser-endpoint-address"; version: 1; endpointId: string; relayUrl: string }

function encodeBrowserEndpointAddress(endpointId: string, relayUrl: string): string {
  if (!endpointId || endpointId.length > 128 || !isValidRelayUrl(relayUrl)) {
    throw new Error("Invalid browser transport address")
  }
  const endpoint = JSON.stringify({ kind: "mesh-browser-endpoint-address", version: 1, endpointId, relayUrl })
  if (endpoint.length > 2048) throw new Error("Browser transport address exceeds the signed route limit")
  return endpoint
}

function parseBrowserEndpointAddress(value: string): BrowserEndpointAddress {
  let decoded: unknown
  try { decoded = JSON.parse(value) }
  catch { throw new Error("Signed device route is missing its browser transport address") }
  if (!decoded || typeof decoded !== "object") throw new Error("Invalid browser transport address")
  const address = decoded as Partial<BrowserEndpointAddress>
  if (address.kind !== "mesh-browser-endpoint-address" || address.version !== 1 ||
    typeof address.endpointId !== "string" || !address.endpointId || address.endpointId.length > 128 ||
    typeof address.relayUrl !== "string" || !isValidRelayUrl(address.relayUrl) ||
    Object.keys(decoded).sort().join(",") !== "endpointId,kind,relayUrl,version") {
    throw new Error("Invalid browser transport address")
  }
  return address as BrowserEndpointAddress
}

function isValidRelayUrl(value: string): boolean {
  if (!value || value.length > 2048) return false
  try {
    const url = new URL(value)
    const localHttp = url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname)
    return (url.protocol === "https:" || localHttp) && !url.username && !url.password && !url.hash
  } catch { return false }
}

function encodeFrame(value: unknown, maximumBytes: number): Uint8Array {
  const bytes = new TextEncoder().encode(JSON.stringify(value))
  if (bytes.byteLength > maximumBytes) throw new Error("Identity enrollment request is too large")
  return bytes
}

function parseFrame(bytes: Uint8Array): unknown {
  try { return JSON.parse(new TextDecoder().decode(bytes)) }
  catch { throw new Error("Invalid Identity enrollment frame") }
}

function requireCodec(): WasmPairingCodec {
  // The pairing module uses this codec for the bounded, invitation-secret frame envelope.
  const current = pairingCodec
  if (!current) throw new Error("Identity pairing codec is unavailable")
  return current
}

async function raceAbort<T>(promise: Promise<T>, signal?: AbortSignal, cancel?: () => Promise<void>): Promise<T> {
  if (!signal) return promise
  if (signal.aborted) {
    await cancel?.()
    throw abortError()
  }
  let onAbort: (() => void) | undefined
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => {
      void cancel?.()
      reject(abortError())
    }
    signal.addEventListener("abort", onAbort, { once: true })
  })
  try { return await Promise.race([promise, aborted]) }
  finally { if (onAbort) signal.removeEventListener("abort", onAbort) }
}

let pairingCodec: WasmPairingCodec | undefined
function abortError(): DOMException { return new DOMException("Identity enrollment was cancelled", "AbortError") }

async function enrollmentPhase<T>(name: string, operation: () => Promise<T>): Promise<T> {
  try { return await operation() }
  catch (cause) {
    const errorLike = cause as { message?: unknown; stack?: unknown; name?: unknown }
    const detail = cause instanceof Error ? cause.message
      : typeof errorLike?.message === "string" ? errorLike.message
        : typeof errorLike?.stack === "string" ? `${String(errorLike.name ?? "runtime error")}: ${errorLike.stack}`
          : typeof cause === "string" ? cause : Object.prototype.toString.call(cause)
    throw new Error(`Identity ${name} failed: ${detail}`, { cause })
  }
}
