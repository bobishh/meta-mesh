import { authorizeIdentityDataDevice, fromBase64Url, toBase64Url, verifyIdentityAuthorityView,
  canonicalizeJson, sha256Base64Url, type IdentityAuthorityView, type LocalProfile, type VerifiedIdentityAuthorityView } from "@meta-uber/mesh-identity"
import { createOwnerReconnectInvite, createPairingSecret, encodePairingFrame, decodePairingFrame, invitationUrl,
  type OwnerReconnectInvitation } from "@meta-uber/mesh-pairing"
import { meshNetworkConnection, waitForRelayUrl, type IrohConnection, type IrohNode, type MeshConnection, type MeshStream } from "@meta-uber/mesh-transport"
import {
  assertOwnerReconnectSourceState, createOwnerReconnectApproval, createOwnerReconnectChallenge, createOwnerReconnectHello, createOwnerReconnectHistoryRequest,
  createOwnerReconnectHistoryResponse, createOwnerReconnectOffer, createOwnerReconnectReceipt,
  encodeOwnerReconnectMessage, ownerReconnectApprovalIntent, ownerReconnectAuthenticatedPeer, verifyOwnerReconnectHistoryRequest,
  verifyOwnerReconnectHistoryResponse, verifyOwnerReconnectOffer, verifyOwnerReconnectReceipt,
  type OwnerReconnectApproval, type OwnerReconnectChallenge, type OwnerReconnectHistoryOperation,
  type OwnerReconnectHistoryReader, type OwnerReconnectHistoryRequest, type OwnerReconnectHistoryResponse,
  type OwnerReconnectAuthenticatedPeer,
  type OwnerReconnectOffer, type OwnerReconnectReceipt,
  type OwnerReconnectSession, type OwnerReconnectSourceState, type VerifiedOwnerReconnectWorkspace,
} from "@meta-uber/mesh-workspace"
import { initializeBrowserIdentityRuntime } from "./browserIdentityEnrollment"

const frameType = "mesh-owner-reconnect-v1"
const domain = "MESH-OWNER-RECONNECT/1"
const maxContentBytes = 256 * 1024 * 1024
const maxWireFrameBytes = 16 * 1024 * 1024
const chunkBytes = 4 * 1024 * 1024
const maxBaselineBytes = 384 * 1024
const maxDocumentPartBytes = 256 * 1024
const maxPageBytes = 64 * 1024
const maxPartBytes = 256 * 1024
const encoder = new TextEncoder()
const decoder = new TextDecoder("utf-8", { fatal: true })

type AcceptingConnection = MeshConnection & { remoteEndpointId?: string }
type Acceptor = { accept(): Promise<IrohConnection | undefined>; close(): Promise<void> }
type WireHeader = { kind: "owner-reconnect-offer"; envelope: OwnerReconnectOffer["envelope"]; transferId: string; chunkCount: number; byteLength: number }
type WireChunk = { kind: "owner-reconnect-content-chunk"; transferId: string; index: number; chunkCount: number; bytes: string }
type WireHistoryRequest = OwnerReconnectHistoryRequest
type WireHistoryResponse = OwnerReconnectHistoryResponse

export type BrowserOwnerReconnectHost = {
  invitation: OwnerReconnectInvitation
  inviteUrl: string
  done: Promise<void>
  close(): Promise<void>
}

export type StartBrowserOwnerReconnectHostOptions = {
  profile: LocalProfile
  authorityView: IdentityAuthorityView
  origin: string
  workspaceId: string
  /** Current owner identity from the already-known workspace credential; checked before reading board state. */
  expectedOwner: { personId: string; publicKey: string }
  readSource(peer: OwnerReconnectAuthenticatedPeer): OwnerReconnectSourceState | Promise<OwnerReconnectSourceState>
  ensureCurrent?(): void | Promise<void>
  signal?: AbortSignal
}

export type ConnectBrowserOwnerReconnectOptions = {
  invitation: OwnerReconnectInvitation
  profile: LocalProfile
  authorityView: IdentityAuthorityView
  approve(request: { workspaceId: string; scopeId: string; ownerPersonId: string; sourcePersonId: string;
    sourceRole: "editor" | "visitor"; expiresAt: string }): boolean | Promise<boolean>
  commit(workspace: VerifiedOwnerReconnectWorkspace, history: OwnerReconnectHistoryReader): void | Promise<void>
  knownWorkspaceAuthority?: unknown
  ensureCurrent?(): void | Promise<void>
  signal?: AbortSignal
}

/** Host one exact workspace for its verified current owner. Workspace data remains behind approval. */
export async function startBrowserOwnerReconnectHost(options: StartBrowserOwnerReconnectHostOptions): Promise<BrowserOwnerReconnectHost> {
  validateOrigin(options.origin)
  if (!options.workspaceId || !options.expectedOwner.personId || !options.expectedOwner.publicKey) {
    throw new Error("Owner reconnect requires one workspace and its current owner")
  }
  await ensureCurrent(options.ensureCurrent, options.signal)
  const authority = await currentView(options.profile, options.authorityView)
  await authorizeIdentityDataDevice(authority, options.profile.device.deviceId)
  const transport = await initializeBrowserIdentityRuntime()
  const node = await transport.BrowserNode.start(randomBytes(32))
  let relayUrl: string
  let acceptor: Acceptor
  try {
    relayUrl = await waitForRelayUrl(node, { timeoutMs: 10_000, signal: options.signal })
    acceptor = await abortable(node.accept(), options.signal, () => node.close("Owner reconnect host cancelled"))
  } catch (error) {
    await node.close("Owner reconnect host failed to start").catch(() => undefined)
    throw error
  }
  const secret = createPairingSecret()
  const invitation = createOwnerReconnectInvite(node.endpointId, secret, options.profile, options.workspaceId, { relayUrl })
  const session = sessionFromInvitation(invitation)
  let closed = false
  let activeRaw: IrohConnection | undefined
  let closePromise: Promise<void> | undefined
  const close = async () => {
    if (closePromise) return closePromise
    closed = true
    closePromise = (async () => {
      await acceptor.close().catch(() => undefined)
      await activeRaw?.close().catch(() => undefined)
      await node.close("Owner reconnect host closed").catch(() => undefined)
    })()
    return closePromise
  }
  const done = serveOwnerReconnectHost({ options, node, acceptor, session, secret, setActive: raw => { activeRaw = raw }, isClosed: () => closed })
    .finally(() => { void close() })
  void done.catch(() => undefined)
  if (options.signal) {
    const abort = () => { void close() }
    options.signal.addEventListener("abort", abort, { once: true })
    void done.finally(() => options.signal?.removeEventListener("abort", abort)).catch(() => undefined)
  }
  return { invitation, inviteUrl: invitationUrl(options.origin, invitation), done, close }
}

/** Prove current Identity ownership before reading a scope offer; commit owns durable workspace admission. */
export async function connectBrowserOwnerReconnect(options: ConnectBrowserOwnerReconnectOptions): Promise<{ workspaceId: string; offerDigest: string }> {
  const invitation = options.invitation
  if (!invitation || invitation.kind !== "owner-reconnect" || Date.parse(invitation.expiresAt) <= Date.now()) {
    throw new Error("Invalid or expired owner reconnect invitation")
  }
  await ensureCurrent(options.ensureCurrent, options.signal)
  const ownerView = await currentView(options.profile, options.authorityView)
  const transport = await initializeBrowserIdentityRuntime()
  const node = await transport.BrowserNode.start(randomBytes(32))
  let raw: IrohConnection | undefined
  try {
    const relay = await waitForRelayUrl(node, { timeoutMs: 10_000, signal: options.signal })
    raw = await abortable(node.dialRelay(invitation.issuerEndpoint, invitation.issuerRelayUrl ?? relay), options.signal,
      () => node.close("Owner reconnect dial cancelled"), connection => connection.close())
    if (raw.remoteEndpointId && raw.remoteEndpointId !== invitation.issuerEndpoint) throw new Error("Owner reconnect endpoint changed")
    const connection = meshNetworkConnection(raw, new transport.WasmIngressBudgetProfile(), frameType)
    const session = sessionFromInvitation(invitation)
    const hello = await createOwnerReconnectHello({ session, profile: options.profile, authorityView: ownerView, endpointId: node.endpointId })
    const helloStream = await abortable(connection.openStream(), options.signal, () => raw?.close(), stream => stream.reset?.())
    await sendOnStream(helloStream, invitation.secret, hello, options.signal)
    const challengeValue = await readOnStream(helloStream, invitation.secret, options.signal)
    if (isRejected(challengeValue, sessionFromInvitation(invitation))) {
      await sendOneWay(connection, invitation.secret, { kind: "owner-reconnect-rejection-ack", invitationId: invitation.invitationId }, options.signal)
      throw new Error("This invitation is for a different workspace owner")
    }
    const challenge = challengeValue as OwnerReconnectChallenge
    assertRemoteSourceEndpoint(challenge, raw.remoteEndpointId, invitation.issuerEndpoint)
    const intent = await ownerReconnectApprovalIntent({ session, hello, challenge, profile: options.profile, authorityView: ownerView })
    if (!await abortable(Promise.resolve(options.approve(intent)), options.signal, () => raw?.close())) {
      await sendOneWay(connection, invitation.secret, { kind: "owner-reconnect-declined", invitationId: session.invitationId })
      throw new Error("Owner declined workspace reconnect")
    }
    await ensureCurrent(options.ensureCurrent, options.signal)
    const approval: OwnerReconnectApproval = await createOwnerReconnectApproval({ session, hello, challenge,
      profile: options.profile, authorityView: await currentView(options.profile, options.authorityView) })
    const approvalStream = await abortable(connection.openStream(), options.signal, () => raw?.close(), stream => stream.reset?.())
    await sendOnStream(approvalStream, invitation.secret, approval, options.signal)
    const header = parseOfferHeader(await readOnStream(approvalStream, invitation.secret, options.signal))
    const content = await receiveContent(connection, invitation.secret, header, transferLimits(transport), options.signal, () => raw?.close())
    const offer: OwnerReconnectOffer = { envelope: header.envelope, content }
    const verified = await verifyOwnerReconnectOffer({ session, hello, challenge, approval, offer, profile: options.profile,
      authorityView: await currentView(options.profile, options.authorityView), ownerEndpointId: node.endpointId,
      knownWorkspaceAuthority: options.knownWorkspaceAuthority })
    const history = createHistoryReader({ options, connection, invitation, session, hello, challenge, verified,
      sourceAuthorityView: offer.envelope.payload.sourceAuthorityView })
    await ensureCurrent(options.ensureCurrent, options.signal)
    await options.commit(verified, history)
    await ensureCurrent(options.ensureCurrent, options.signal)
    const receipt: OwnerReconnectReceipt = await createOwnerReconnectReceipt({ session, profile: options.profile,
      authorityView: await currentView(options.profile, options.authorityView), verified })
    const receiptStream = await abortable(connection.openStream(), options.signal, () => raw?.close(), stream => stream.reset?.())
    await sendOnStream(receiptStream, invitation.secret, receipt, options.signal)
    const accepted = parseReceiptAccepted(await readOnStream(receiptStream, invitation.secret, options.signal))
    if (accepted.offerDigest !== verified.offerDigest) throw new Error("Owner reconnect receipt was not accepted")
    return { workspaceId: verified.workspaceId, offerDigest: verified.offerDigest }
  } finally {
    await raw?.close().catch(() => undefined)
    await node.close("Owner reconnect completed").catch(() => undefined)
  }
}

async function serveOwnerReconnectHost(input: {
  options: StartBrowserOwnerReconnectHostOptions; node: IrohNode; acceptor: Acceptor; session: OwnerReconnectSession;
  secret: string; setActive(raw?: IrohConnection): void; isClosed(): boolean
}): Promise<void> {
  const signal = sessionSignal(input.options.signal, input.session.expiresAt)
  const options = { ...input.options, signal }
  while (!input.isClosed()) {
    const raw = await abortable(input.acceptor.accept(), signal, () => input.acceptor.close(), connection => connection?.close())
    if (!raw) throw new Error("Owner reconnect listener closed before a peer connected")
    input.setActive(raw)
    try {
      const transport = await initializeBrowserIdentityRuntime()
      const connection = meshNetworkConnection(raw, new transport.WasmIngressBudgetProfile(), frameType)
      const helloStream = await abortable(connection.acceptStream(), signal, () => raw.close(), stream => stream.reset?.())
      const hello = await readOnStream(helloStream, input.secret, signal) as { payload: { ownerEndpointId: string } }
      if (hello.payload.ownerEndpointId !== raw.remoteEndpointId) throw new Error("Owner reconnect hello endpoint does not match transport")
      const peer = await ownerReconnectAuthenticatedPeer(input.session, hello as never)
      if (peer.personId !== options.expectedOwner.personId ||
          (hello as { payload: { ownerPublicKey?: string } }).payload.ownerPublicKey !== options.expectedOwner.publicKey) {
        await sendOnStream(helloStream, input.secret, { kind: "owner-reconnect-rejected", invitationId: input.session.invitationId,
          reason: "wrong-identity" }, signal)
        try {
          const ackSignal = AbortSignal.any([signal, AbortSignal.timeout(5_000)])
          const ackStream = await abortable(connection.acceptStream(), ackSignal, () => raw.close(), stream => stream.reset?.())
          const ack = await readOnStream(ackStream, input.secret, ackSignal)
          if (!isRejectionAck(ack, input.session)) await ackStream.reset?.()
        } catch (error) {
          if (signal.aborted) throw error
        }
        continue
      }
      const source = await currentSource(options, peer)
      const challenge = await createOwnerReconnectChallenge({ session: input.session, hello: hello as never,
        profile: options.profile, authorityView: await currentView(options.profile, options.authorityView),
        source, sourceEndpointId: input.node.endpointId })
      await sendOnStream(helloStream, input.secret, challenge, signal)

      const approvalStream = await abortable(connection.acceptStream(), signal, () => raw.close(), stream => stream.reset?.())
      const approvalValue = await readOnStream(approvalStream, input.secret, signal)
      if (isDeclined(approvalValue, input.session)) throw new Error("Owner declined workspace reconnect")
      const approval = approvalValue as OwnerReconnectApproval
      const offerSource = await currentSource(options, peer)
      const offer = await createOwnerReconnectOffer({ session: input.session, hello: hello as never, challenge, approval,
        profile: options.profile, authorityView: await currentView(options.profile, options.authorityView),
        source: offerSource, sourceEndpointId: input.node.endpointId })
      const contentBytes = encoder.encode(JSON.stringify(offer.content))
      const limits = transferLimits(transport)
      if (contentBytes.byteLength > limits.maxLogicalBytes) throw new Error("Owner reconnect workspace transfer exceeds its size bound")
      const chunkCount = Math.ceil(contentBytes.byteLength / chunkBytes)
      if (chunkCount > limits.maxPages) throw new Error("Owner reconnect workspace transfer page limit exceeded")
      const transferId = crypto.randomUUID()
      const header: WireHeader = { kind: "owner-reconnect-offer", envelope: offer.envelope,
        transferId, chunkCount, byteLength: contentBytes.byteLength }
      await sendOnStream(approvalStream, input.secret, header, signal)
      await sendContent(connection, input.secret, transferId, contentBytes, chunkCount, signal, () => raw.close())

      const offerDigest = await digestOffer(offer)
      while (!input.isClosed()) {
        const stream = await abortable(connection.acceptStream(), signal, () => raw.close(), value => value.reset?.())
        const value = await readOnStream(stream, input.secret, signal)
        if (isReceipt(value)) {
          await verifyOwnerReconnectReceipt({ session: input.session, hello: hello as never, challenge, offer, receipt: value })
          await sendOnStream(stream, input.secret, { kind: "owner-reconnect-receipt-accepted", offerDigest }, signal)
          return
        }
        const request = value as OwnerReconnectHistoryRequest
        await verifyOwnerReconnectHistoryRequest({ request, session: input.session, hello: hello as never, challenge, offerDigest })
        const response = await handleHistoryRequest({ request, source: await currentSource(options, peer), options,
          profileAuthority: await currentView(options.profile, options.authorityView), session: input.session })
        await sendOnStream(stream, input.secret, response, signal)
      }
      throw new Error("Owner reconnect host closed")
    } finally {
      await raw.close().catch(() => undefined)
      input.setActive(undefined)
    }
  }
  throw new Error("Owner reconnect host closed")
}

async function handleHistoryRequest(input: { request: OwnerReconnectHistoryRequest; source: OwnerReconnectSourceState;
  options: StartBrowserOwnerReconnectHostOptions; profileAuthority: IdentityAuthorityView; session: OwnerReconnectSession }): Promise<OwnerReconnectHistoryResponse> {
  await ensureCurrent(input.options.ensureCurrent, input.options.signal)
  const op = input.request.payload.operation
  let result: OwnerReconnectHistoryResponse["payload"]["result"]
  try {
    if (op.kind === "baseline") {
      const value = await input.source.history.readBaseline(input.session.workspaceId, op.baselineId)
      if (value !== undefined && encoder.encode(JSON.stringify(value)).byteLength > maxBaselineBytes) throw new Error("Peer history baseline descriptor exceeds its size bound")
      result = { kind: "baseline", ...(value === undefined ? {} : { value }) }
    } else if (op.kind === "document") {
      if (!validId(op.baselineId) || !validId(op.documentDigest) || !Number.isSafeInteger(op.offset) || op.offset < 0 ||
          !Number.isSafeInteger(op.length) || op.length < 1 || op.length > maxDocumentPartBytes) throw new Error("Invalid peer history document request")
      const bytes = await input.source.history.readDocument(op)
      if (!(bytes instanceof Uint8Array) || bytes.byteLength !== op.length) throw new Error("Peer history document part is unavailable")
      result = { kind: "bytes", bytes: toBase64Url(bytes) }
    } else {
      if (!validId(op.baselineId) || !validId(op.objectId) || op.binding.workspaceId !== input.session.workspaceId ||
          !validId(op.binding.indexId)) throw new Error("Invalid peer history object request")
      const limit = op.binding.objectKind === "part" ? maxPartBytes : maxPageBytes
      if (!Number.isSafeInteger(op.binding.historyEpoch) || op.binding.historyEpoch < 1 ||
          !Number.isSafeInteger(op.binding.partIndex) || op.binding.partIndex < 0 ||
          !Number.isSafeInteger(op.binding.partCount) || op.binding.partCount < 1 || op.binding.partIndex >= op.binding.partCount) {
        throw new Error("Invalid peer history object binding")
      }
      const bytes = await input.source.history.readObject(op)
      if (!(bytes instanceof Uint8Array) || bytes.byteLength > limit || await sha256Base64Url(bytes) !== op.objectId) {
        throw new Error("Peer history object is unavailable or has the wrong content address")
      }
      result = { kind: "bytes", bytes: toBase64Url(bytes) }
    }
  } catch (error) {
    result = { kind: "error", message: error instanceof Error ? error.message : "Peer history read failed" }
  }
  await ensureCurrent(input.options.ensureCurrent, input.options.signal)
  return createOwnerReconnectHistoryResponse({ profile: input.options.profile, authorityView: input.profileAuthority,
    session: input.session, request: input.request, result })
}

function createHistoryReader(input: { options: ConnectBrowserOwnerReconnectOptions; connection: MeshConnection;
  invitation: OwnerReconnectInvitation; session: OwnerReconnectSession; hello: Awaited<ReturnType<typeof createOwnerReconnectHello>>;
  challenge: OwnerReconnectChallenge; verified: VerifiedOwnerReconnectWorkspace; sourceAuthorityView: IdentityAuthorityView }): OwnerReconnectHistoryReader {
  const call = async (operation: OwnerReconnectHistoryOperation) => {
    await ensureCurrent(input.options.ensureCurrent, input.options.signal)
    const request = await createOwnerReconnectHistoryRequest({ profile: input.options.profile,
      authorityView: await currentView(input.options.profile, input.options.authorityView), session: input.session,
      challenge: input.challenge, verified: input.verified, operation })
    const stream = await input.connection.openStream()
    await sendOnStream(stream, input.invitation.secret, request, input.options.signal)
    const response = await readOnStream(stream, input.invitation.secret, input.options.signal) as OwnerReconnectHistoryResponse
    const result = await verifyOwnerReconnectHistoryResponse({ response, request, session: input.session,
      challenge: input.challenge, sourceAuthorityView: input.sourceAuthorityView })
    await ensureCurrent(input.options.ensureCurrent, input.options.signal)
    return result
  }
  return {
    ensureCurrent: () => ensureCurrent(input.options.ensureCurrent, input.options.signal),
    readBaseline: async (workspaceId, baselineId) => {
      const result = await call({ kind: "baseline", workspaceId, ...(baselineId ? { baselineId } : {}) })
      if (result.kind !== "baseline") throw new Error("Invalid peer history baseline response")
      return result.value
    },
    readDocument: async (descriptor, workspaceId) => {
      if (!Number.isSafeInteger(descriptor.documentLength) || descriptor.documentLength < 1 || descriptor.documentLength > 256 * 1024 * 1024 ||
          !validId(descriptor.baselineId) || !validId(descriptor.documentDigest)) throw new Error("Peer history document descriptor exceeds its bounds")
      const output = new Uint8Array(descriptor.documentLength)
      for (let offset = 0; offset < descriptor.documentLength; offset += maxDocumentPartBytes) {
        const length = Math.min(maxDocumentPartBytes, descriptor.documentLength - offset)
        const result = await call({ kind: "document", workspaceId, baselineId: descriptor.baselineId,
          documentDigest: descriptor.documentDigest, offset, length })
        if (result.kind !== "bytes") throw new Error("Invalid peer history document response")
        const part = fromBase64Url(result.bytes)
        if (part.byteLength !== length) throw new Error("Peer history document part length mismatch")
        output.set(part, offset)
      }
      return output
    },
    read: async (objectId, binding, baselineId) => {
      if (!baselineId) throw new Error("Peer history object read requires its verified baseline")
      const result = await call({ kind: "object", workspaceId: binding.workspaceId, baselineId, objectId, binding })
      if (result.kind !== "bytes") throw new Error("Invalid peer history object response")
      const bytes = fromBase64Url(result.bytes)
      if (await sha256Base64Url(bytes) !== objectId) throw new Error("Peer history object content address mismatch")
      return bytes
    },
  }
}

async function currentSource(options: StartBrowserOwnerReconnectHostOptions, peer: OwnerReconnectAuthenticatedPeer): Promise<OwnerReconnectSourceState> {
  await ensureCurrent(options.ensureCurrent, options.signal)
  const source = await options.readSource(peer)
  if (source.workspace && typeof source.workspace === "object" &&
      (source.workspace as { id?: unknown }).id !== options.workspaceId) throw new Error("Owner reconnect source returned another workspace")
  await assertOwnerReconnectSourceState({ source, profile: options.profile,
    authorityView: await currentView(options.profile, options.authorityView), workspaceId: options.workspaceId })
  return source
}

function sessionFromInvitation(invite: OwnerReconnectInvitation): OwnerReconnectSession {
  return { invitationId: invite.invitationId, workspaceId: invite.workspaceId, issuerPersonId: invite.issuerPersonId,
    issuerDeviceId: invite.issuerDeviceId, issuerPublicKey: invite.issuerPublicKey, issuerEndpoint: invite.issuerEndpoint,
    ...(invite.issuerRelayUrl ? { issuerRelayUrl: invite.issuerRelayUrl } : {}), expiresAt: invite.expiresAt, secret: invite.secret }
}

async function currentView(profile: LocalProfile, value: IdentityAuthorityView): Promise<VerifiedIdentityAuthorityView> {
  const view = await verifyIdentityAuthorityView(value)
  if (view.personId !== profile.identity.personId || view.identityPublicKey !== profile.identity.publicKey ||
      !await authorizeIdentityDataDevice(view, profile.device.deviceId)) throw new Error("Owner reconnect Identity authority is not current")
  return view
}

async function sendContent(connection: MeshConnection, secret: string, transferId: string, bytes: Uint8Array, count: number,
  signal?: AbortSignal, close?: () => void | Promise<void>) {
  for (let index = 0; index < count; index += 1) {
    const stream = await abortable(connection.openStream(), signal, close, value => value.reset?.())
    const part = bytes.subarray(index * chunkBytes, Math.min(bytes.byteLength, (index + 1) * chunkBytes))
    await sendOnStream(stream, secret, { kind: "owner-reconnect-content-chunk", transferId, index, chunkCount: count,
      bytes: toBase64Url(part) }, signal)
  }
}

async function receiveContent(connection: MeshConnection, secret: string, header: WireHeader, limits: TransferLimits,
  signal?: AbortSignal, close?: () => void | Promise<void>) {
  if (!Number.isSafeInteger(header.byteLength) || header.byteLength < 0 || header.byteLength > limits.maxLogicalBytes ||
      !Number.isSafeInteger(header.chunkCount) || header.chunkCount < 0 || header.chunkCount !== Math.ceil(header.byteLength / chunkBytes) ||
      header.chunkCount > limits.maxPages || header.chunkCount > Math.ceil(maxContentBytes / chunkBytes) ||
      header.envelope.payload.kind !== "mesh-owner-reconnect-offer") throw new Error("Invalid owner reconnect content transfer")
  const chunks: Uint8Array[] = []
  let total = 0
  for (let index = 0; index < header.chunkCount; index += 1) {
    const stream = await abortable(connection.acceptStream(), signal, close, value => value.reset?.())
    const raw = await readOnStream(stream, secret, signal)
    const chunk = raw as WireChunk
    if (chunk.kind !== "owner-reconnect-content-chunk" || chunk.transferId !== header.transferId ||
        chunk.index !== index || chunk.chunkCount !== header.chunkCount) throw new Error("Owner reconnect content chunk order mismatch")
    const bytes = fromBase64Url(chunk.bytes)
    if (!bytes.byteLength || bytes.byteLength > chunkBytes || (index + 1 < header.chunkCount && bytes.byteLength !== chunkBytes)) {
      throw new Error("Owner reconnect content chunk size invalid")
    }
    chunks.push(bytes)
    total += bytes.byteLength
  }
  if (total !== header.byteLength) throw new Error("Owner reconnect content transfer length mismatch")
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const part of chunks) { bytes.set(part, offset); offset += part.byteLength }
  return JSON.parse(decoder.decode(bytes)) as OwnerReconnectOffer["content"]
}

async function sendOneWay(connection: MeshConnection, secret: string, value: unknown, signal?: AbortSignal) {
  const stream = await abortable(connection.openStream(), signal, undefined, created => created.reset?.())
  await sendOnStream(stream, secret, value, signal)
}

async function sendOnStream(stream: MeshStream, secret: string, value: unknown, signal?: AbortSignal): Promise<void> {
  const bytes = value && typeof value === "object" && "payload" in value && "signerKeyId" in value
    ? encodeOwnerReconnectMessage(value as never) : encoder.encode(JSON.stringify(value))
  const frame = encodePairingFrame(frameType, secret, bytes)
  if (frame.byteLength > maxWireFrameBytes) throw new Error("Owner reconnect frame exceeds its size bound")
  await abortable(stream.send(frame), signal, () => stream.reset?.())
  await abortable(stream.closeSend(), signal, () => stream.reset?.())
}

async function readOnStream(stream: MeshStream, secret: string, signal?: AbortSignal): Promise<unknown> {
  const frame = await abortable(stream.read(maxWireFrameBytes), signal, () => stream.reset?.())
  const bytes = decodePairingFrame(frame, frameType, secret)
  try { return JSON.parse(decoder.decode(bytes)) as unknown }
  catch { throw new Error("Invalid owner reconnect transport message") }
}

function parseOfferHeader(value: unknown): WireHeader {
  if (!value || typeof value !== "object" || (value as WireHeader).kind !== "owner-reconnect-offer") throw new Error("Owner reconnect offer header missing")
  const header = value as WireHeader
  if (!header.transferId || !Number.isSafeInteger(header.byteLength) || !Number.isSafeInteger(header.chunkCount)) throw new Error("Invalid owner reconnect offer header")
  return header
}

function parseReceiptAccepted(value: unknown): { offerDigest: string } {
  if (!value || typeof value !== "object" || (value as {kind?: unknown}).kind !== "owner-reconnect-receipt-accepted" ||
      typeof (value as {offerDigest?: unknown}).offerDigest !== "string") throw new Error("Owner reconnect receipt was not acknowledged")
  return value as { offerDigest: string }
}

function isReceipt(value: unknown): value is OwnerReconnectReceipt {
  return Boolean(value && typeof value === "object" && (value as OwnerReconnectReceipt).payload?.kind === "mesh-owner-reconnect-receipt")
}

function isDeclined(value: unknown, session: OwnerReconnectSession): boolean {
  const item = value as {kind?: unknown; invitationId?: unknown}
  return item?.kind === "owner-reconnect-declined" && item.invitationId === session.invitationId
}

function isRejected(value: unknown, session: OwnerReconnectSession): boolean {
  const item = value as { kind?: unknown; invitationId?: unknown; reason?: unknown }
  return item?.kind === "owner-reconnect-rejected" && item.invitationId === session.invitationId && item.reason === "wrong-identity"
}

function isRejectionAck(value: unknown, session: OwnerReconnectSession): boolean {
  const item = value as { kind?: unknown; invitationId?: unknown }
  return item?.kind === "owner-reconnect-rejection-ack" && item.invitationId === session.invitationId
}

function assertRemoteSourceEndpoint(challenge: OwnerReconnectChallenge, actual: string | undefined, expected: string) {
  if (!challenge.payload || challenge.payload.sourceEndpointId !== expected || (actual && actual !== expected)) {
    throw new Error("Owner reconnect source endpoint does not match the invitation")
  }
}

function validId(value: unknown): value is string { return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value) }
function randomBytes(length: number) { return crypto.getRandomValues(new Uint8Array(length)) }
async function digestOffer(value: OwnerReconnectOffer) { return sha256Base64Url(encoder.encode(canonicalizeJson(value))) }
type TransferLimits = { maxLogicalBytes: number; maxPages: number }
function transferLimits(transport: Awaited<ReturnType<typeof initializeBrowserIdentityRuntime>>): TransferLimits {
  const profile = new transport.WasmIngressBudgetProfile()
  const maxLogicalBytes = Math.min(maxContentBytes, profile.maxLogicalTransferBytes())
  const maxPages = profile.maxTransferPages()
  if (!Number.isSafeInteger(maxLogicalBytes) || maxLogicalBytes < 1 || !Number.isSafeInteger(maxPages) || maxPages < 1) {
    throw new Error("Owner reconnect transfer budget is unavailable")
  }
  return { maxLogicalBytes, maxPages }
}
async function ensureCurrent(ensure: (() => void | Promise<void>) | undefined, signal: AbortSignal | undefined) {
  if (signal?.aborted) throw new Error("Owner reconnect cancelled")
  await ensure?.()
  if (signal?.aborted) throw new Error("Owner reconnect cancelled")
}
function sessionSignal(signal: AbortSignal | undefined, expiresAt: string): AbortSignal {
  const remaining = Date.parse(expiresAt) - Date.now()
  if (!Number.isFinite(remaining) || remaining <= 0) throw new Error("Owner reconnect invitation expired")
  const deadline = AbortSignal.timeout(remaining)
  return signal ? AbortSignal.any([signal, deadline]) : deadline
}
function validateOrigin(value: string) {
  const origin = new URL(value)
  if (origin.origin !== value || (origin.protocol !== "https:" && origin.hostname !== "localhost" && origin.hostname !== "127.0.0.1")) {
    throw new Error("Owner reconnect requires an exact HTTPS or local origin")
  }
}
function abortable<T>(promise: Promise<T>, signal?: AbortSignal, close?: () => void | Promise<void>,
  disposeLate?: (value: T) => void | Promise<void>): Promise<T> {
  if (!signal) return promise
  if (signal.aborted) {
    void Promise.resolve(close?.()).catch(() => undefined)
    void promise.then(value => Promise.resolve(disposeLate?.(value)).catch(() => undefined), () => undefined)
    return Promise.reject(new Error("Owner reconnect cancelled"))
  }
  return new Promise<T>((resolve, reject) => {
    let settled = false
    const abort = () => {
      if (settled) return
      settled = true
      signal.removeEventListener("abort", abort)
      void Promise.resolve(close?.()).catch(() => undefined)
      reject(new Error("Owner reconnect cancelled"))
    }
    signal.addEventListener("abort", abort, { once: true })
    promise.then(value => {
      if (settled) { void Promise.resolve(disposeLate?.(value)).catch(() => undefined); return }
      settled = true
      signal.removeEventListener("abort", abort)
      resolve(value)
    }, error => {
      if (settled) return
      settled = true
      signal.removeEventListener("abort", abort)
      reject(error)
    })
  })
}
