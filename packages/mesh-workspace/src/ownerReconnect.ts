import {
  authorizeIdentityDataDevice,
  canonicalizeJson,
  fromBase64Url,
  sha256Base64Url,
  signEnvelope,
  toBase64Url,
  verifyEnvelope,
  verifyDeviceCertificateChain,
  verifyIdentityAuthorityView,
  type DeviceCertificate,
  type IdentityAuthorityView,
  type LocalProfile,
  type SignedEnvelope,
  type VerifiedIdentityAuthorityView,
} from "@meta-uber/mesh-identity"
import { decodeBlindBytes, type RustyReplicaAccess } from "@meta-uber/mesh-replication/rusty-replica"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
import type { WorkspaceGrant, WorkspaceAuthority } from "./index"

const domain = "MESH-OWNER-RECONNECT/1"
const maxLifetimeMs = 10 * 60 * 1000

export type OwnerReconnectSession = {
  invitationId: string
  workspaceId: string
  issuerPersonId: string
  issuerDeviceId: string
  issuerPublicKey: string
  issuerEndpoint: string
  issuerRelayUrl?: string
  expiresAt: string
  secret: string
}

/** Existing owner-scoped storage fields only. Participant access wrappers never cross this contract. */
export type OwnerReplicaConfig = RustyReplicaAccess & {
  purpose?: "workspace"
  workspaceId: string
  keyEpoch: number
  contentKey: string
  historicalContentKeys?: Record<string, string>
  historicalContentKeyVariants?: Record<string, string[]>
  minimumWriterVersion?: 2
  cursor?: number
  lastUploaded?: string
  preferenceRevision?: string
  removalPending?: boolean
}

export type OwnerReconnectAuthority = {
  genesisOwner: WorkspaceAuthority
  genesisEpoch: number
  currentOwner: WorkspaceAuthority
  currentEpoch: number
  ownershipTransfers: unknown[]
  successionClaims: unknown[]
  revocations: unknown[]
  deviceRevocations: unknown[]
  departures: unknown[]
}

export type OwnerReconnectWorkspaceProof = {
  version: 1 | 2
  records?: unknown[]
  pages?: unknown[][]
  authority: OwnerReconnectAuthority
}

export type OwnerReconnectWorkspaceAccessSnapshot = {
  workspaceId: string
  genesisOwner: WorkspaceAuthority
  genesisEpoch: number
  expectedCurrentOwner: WorkspaceAuthority
  document: Uint8Array
  ownershipTransfers: unknown[]
  successionClaims: unknown[]
  revocations: unknown[]
  deviceRevocations: unknown[]
  departures: unknown[]
}

/** Existing DurableMesh invitation payload, carried intact to restore normal workspace connectivity. */
export type OwnerReconnectMeshEnvelope = {
  version: 1
  workspaceId: string
  ownerPersonId: string
  ownerPublicKey: string
  ownerCertificates: DeviceCertificate[]
  transportSecret: string
  epoch: number
  peers: unknown[]
  departures?: unknown[]
  deviceRevocations?: unknown[]
  revocations?: unknown[]
  ownerHistory?: unknown[]
  ownershipTransfers?: unknown[]
  successionPolicy?: unknown
  successionVotes?: unknown[]
  successionClaims?: unknown[]
  scopeAuthoritySnapshot?: unknown
}

export type OwnerReconnectSourceState = {
  /** Workspace-set entry: { id, bytes, authorization?, chat?, mesh?, historyBaseline? }. */
  workspace: unknown
  workspaceAuthority: OwnerReconnectWorkspaceProof
  /** Native WorkspaceWriteAuthorizationSnapshot, including the local document bytes. */
  workspaceAccessSnapshot: OwnerReconnectWorkspaceAccessSnapshot
  scopeAuthoritySnapshot: unknown
  grant: WorkspaceGrant
  /** Existing durable workspace mesh invitation. Its own source route must be persistent, not this session route. */
  meshEnvelope: OwnerReconnectMeshEnvelope
  replicaConfig?: OwnerReplicaConfig
  /** Original current-owner signature binding workspace and Rusty connection, retained for offline verification. */
  ownerStorageProof?: OwnerReconnectOwnerStorageProof
  history: OwnerReconnectHistorySource
}

export type OwnerReconnectOwnerStorageProof = {
  authorization: SignedEnvelope<Record<string, unknown> & { kind: "workspace-rusty-access"; version: 1 | 2 }>
  certificates: DeviceCertificate[]
}

export type PeerHistoryObjectBinding = {
  workspaceId: string; historyEpoch: number; indexId: string
  objectKind: "page" | "record" | "part"; partIndex: number; partCount: number
}
export type OwnerReconnectHistorySource = {
  readBaseline(workspaceId: string, baselineId?: string): Promise<unknown | undefined>
  readDocument(request: { workspaceId: string; baselineId: string; documentDigest: string; offset: number; length: number }): Promise<Uint8Array | undefined>
  readObject(request: { workspaceId: string; baselineId: string; objectId: string; binding: PeerHistoryObjectBinding }): Promise<Uint8Array | undefined>
}
export type OwnerReconnectHistoryReader = {
  ensureCurrent(): void | Promise<void>
  readBaseline(workspaceId: string, baselineId?: string): Promise<unknown | undefined>
  readDocument(descriptor: { baselineId: string; documentDigest: string; documentLength: number }, workspaceId: string): Promise<Uint8Array>
  read(objectId: string, binding: PeerHistoryObjectBinding, baselineId?: string): Promise<Uint8Array>
}
export type OwnerReconnectHistoryOperation =
  | { kind: "baseline"; workspaceId: string; baselineId?: string }
  | { kind: "document"; workspaceId: string; baselineId: string; documentDigest: string; offset: number; length: number }
  | { kind: "object"; workspaceId: string; baselineId: string; objectId: string; binding: PeerHistoryObjectBinding }
export type OwnerReconnectHistoryRequest = SignedEnvelope<{
  kind: "mesh-owner-reconnect-history-read"
  version: 1
  invitationId: string
  workspaceId: string
  ownerPersonId: string
  ownerDeviceId: string
  challengeDigest: string
  offerDigest: string
  requestId: string
  operation: OwnerReconnectHistoryOperation
}>
export type OwnerReconnectHistoryResponse = SignedEnvelope<{
  kind: "mesh-owner-reconnect-history-response"
  version: 1
  invitationId: string
  workspaceId: string
  ownerPersonId: string
  sourcePersonId: string
  requestId: string
  offerDigest: string
  result: { kind: "baseline"; value?: unknown } | { kind: "bytes"; bytes: string } | { kind: "error"; message: string }
}>
export type OwnerReconnectApprovalIntent = {
  workspaceId: string
  scopeId: string
  ownerPersonId: string
  sourcePersonId: string
  sourceRole: "editor" | "visitor"
  expiresAt: string
}
export type OwnerReconnectAuthenticatedPeer = { workspaceId: string; personId: string; deviceId: string }

export type OwnerReconnectHello = SignedEnvelope<{
  kind: "mesh-owner-reconnect-hello"
  version: 1
  invitationId: string
  workspaceId: string
  ownerPersonId: string
  ownerPublicKey: string
  ownerDeviceId: string
  ownerDevicePublicKey: string
  ownerEndpointId: string
  ownerAuthorityView: IdentityAuthorityView
  nonce: string
  issuedAt: string
  expiresAt: string
}>

export type OwnerReconnectChallenge = SignedEnvelope<{
  kind: "mesh-owner-reconnect-challenge"
  version: 1
  invitationId: string
  workspaceId: string
  scopeId: string
  ownerPersonId: string
  ownerPublicKey: string
  ownerDeviceId: string
  ownerDevicePublicKey: string
  ownerEndpointId: string
  sourceEndpointId: string
  sourcePersonId: string
  sourceDeviceId: string
  sourcePublicKey: string
  sourceDevicePublicKey: string
  sourceAuthorityView: IdentityAuthorityView
  sourceWorkspaceAccessProof: { grant: WorkspaceGrant; workspaceAuthority: OwnerReconnectAuthority }
  scopeAuthoritySnapshot: unknown
  helloDigest: string
  nonce: string
  issuedAt: string
  expiresAt: string
}>

export type OwnerReconnectApproval = SignedEnvelope<{
  kind: "mesh-owner-reconnect-approval"
  version: 1
  invitationId: string
  workspaceId: string
  scopeId: string
  ownerPersonId: string
  ownerDeviceId: string
  challengeDigest: string
  ownerAuthorityView: IdentityAuthorityView
  approvedAt: string
}>

export type OwnerReconnectOffer = {
  envelope: SignedEnvelope<{
    kind: "mesh-owner-reconnect-offer"
    version: 1
    invitationId: string
    workspaceId: string
    scopeId: string
    ownerPersonId: string
    ownerDeviceId: string
    ownerEndpointId: string
    sourceEndpointId: string
    sourcePersonId: string
    sourceDeviceId: string
    challengeDigest: string
    approvalDigest: string
    sourceAuthorityView: IdentityAuthorityView
    contentDigest: string
    issuedAt: string
    expiresAt: string
  }>
  content: {
    workspace: unknown
    workspaceAuthority: OwnerReconnectWorkspaceProof
    workspaceAccessSnapshot: unknown
    scopeAuthoritySnapshot: unknown
    grant: WorkspaceGrant
    meshEnvelope: OwnerReconnectMeshEnvelope
    replicaConfig?: OwnerReplicaConfig
    ownerStorageProof?: OwnerReconnectOwnerStorageProof
  }
}

export type VerifiedOwnerReconnectWorkspace = {
  workspaceId: string
  workspace: unknown
  workspaceAuthority: OwnerReconnectWorkspaceProof
  workspaceAccessSnapshot: unknown
  scopeAuthoritySnapshot: unknown
  grant: WorkspaceGrant
  meshEnvelope: OwnerReconnectMeshEnvelope
  replicaConfig?: OwnerReplicaConfig
  ownerStorageProof?: OwnerReconnectOwnerStorageProof
  sourcePersonId: string
  sourceDeviceId: string
  sourceRole: "editor" | "visitor"
  offerDigest: string
}

export type OwnerReconnectReceipt = SignedEnvelope<{
  kind: "mesh-owner-reconnect-receipt"
  version: 1
  invitationId: string
  workspaceId: string
  ownerPersonId: string
  sourcePersonId: string
  offerDigest: string
  committedAt: string
}>

export type OwnerReconnectMessage = OwnerReconnectHello | OwnerReconnectChallenge | OwnerReconnectApproval |
  OwnerReconnectOffer | OwnerReconnectReceipt

export function encodeOwnerReconnectMessage(value: OwnerReconnectMessage): Uint8Array {
  const captured = captureJson(value)
  return new TextEncoder().encode(JSON.stringify(captured))
}

export function decodeOwnerReconnectMessage(bytes: Uint8Array): OwnerReconnectMessage {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0 || bytes.byteLength > 16 * 1024 * 1024) {
    throw new Error("Invalid owner reconnect message size")
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as OwnerReconnectMessage
  } catch {
    throw new Error("Invalid owner reconnect message")
  }
}

export async function createOwnerReconnectHello(input: {
  session: OwnerReconnectSession
  profile: LocalProfile
  authorityView: IdentityAuthorityView
  endpointId: string
  now?: number
}): Promise<OwnerReconnectHello> {
  const now = input.now ?? Date.now()
  const session = validateSession(input.session, now)
  if (!input.endpointId) throw new Error("Owner reconnect endpoint is required")
  const authorityView = await currentIdentityView(input.profile, input.authorityView)
  const ownerDevicePublicKey = await authorizeIdentityDataDevice(authorityView, input.profile.device.deviceId)
  if (ownerDevicePublicKey !== input.profile.device.publicKey) throw new Error("Owner reconnect device is not active")
  const issuedAt = new Date(now).toISOString()
  const expiresAt = earlierTime(Date.parse(session.expiresAt), now + maxLifetimeMs)
  return signEnvelope(input.profile.privateKeys.devicePrivateKey, {
    kind: "mesh-owner-reconnect-hello", version: 1,
    invitationId: session.invitationId, workspaceId: session.workspaceId,
    ownerPersonId: input.profile.identity.personId, ownerPublicKey: input.profile.identity.publicKey,
    ownerDeviceId: input.profile.device.deviceId, ownerDevicePublicKey,
    ownerEndpointId: input.endpointId,
    ownerAuthorityView: authorityView, nonce: randomNonce(), issuedAt, expiresAt,
  }, input.profile.device.deviceId, domain) as Promise<OwnerReconnectHello>
}

export async function createOwnerReconnectChallenge(input: {
  session: OwnerReconnectSession
  hello: OwnerReconnectHello
  profile: LocalProfile
  authorityView: IdentityAuthorityView
  source: OwnerReconnectSourceState
  sourceEndpointId: string
  now?: number
}): Promise<OwnerReconnectChallenge> {
  const now = input.now ?? Date.now()
  const session = validateSession(input.session, now)
  if (!input.sourceEndpointId) throw new Error("Owner reconnect source endpoint is required")
  const sourceView = await currentIdentityView(input.profile, input.authorityView)
  const sourceKey = await authorizeIdentityDataDevice(sourceView, input.profile.device.deviceId)
  if (sourceKey !== input.profile.device.publicKey) throw new Error("Owner reconnect source device is not active")
  await verifyHelloForSession(input.hello, session, now)
  const ownerScope = validateCurrentScope(input.source.scopeAuthoritySnapshot, session.workspaceId, now)
  const ownerAuthority = input.source.workspaceAuthority.authority.currentOwner
  if (ownerScope.controller.personId !== ownerAuthority.personId || ownerScope.controller.publicKey !== ownerAuthority.publicKey) {
    throw new Error("Rusty scope controller differs from current workspace owner")
  }
  if (input.profile.identity.personId === ownerAuthority.personId ||
      input.hello.payload.ownerPersonId !== ownerAuthority.personId ||
      input.hello.payload.ownerPublicKey !== ownerAuthority.publicKey) {
    throw new Error("Owner reconnect request does not match the current workspace owner")
  }
  const sourceRole = await verifySourceReadAccess(input.source, input.profile, sourceView, session.workspaceId, now,
    input.sourceEndpointId)
  const storage = ownerReconnectStorage(input.source)
  const expiresAt = earlierTime(Date.parse(session.expiresAt), Date.parse(input.hello.payload.expiresAt), now + maxLifetimeMs)
  return signEnvelope(input.profile.privateKeys.devicePrivateKey, {
    kind: "mesh-owner-reconnect-challenge", version: 1,
    invitationId: session.invitationId, workspaceId: session.workspaceId,
    scopeId: storage?.replicaConfig.scopeId ?? session.workspaceId,
    ownerPersonId: ownerAuthority.personId, ownerPublicKey: ownerAuthority.publicKey,
    ownerDeviceId: input.hello.payload.ownerDeviceId,
    ownerDevicePublicKey: input.hello.payload.ownerDevicePublicKey,
    ownerEndpointId: input.hello.payload.ownerEndpointId,
    sourceEndpointId: input.sourceEndpointId,
    sourcePersonId: input.profile.identity.personId, sourceDeviceId: input.profile.device.deviceId,
    sourcePublicKey: input.profile.identity.publicKey, sourceDevicePublicKey: sourceKey, sourceAuthorityView: sourceView,
    sourceWorkspaceAccessProof: { grant: input.source.grant, workspaceAuthority: input.source.workspaceAuthority.authority },
    scopeAuthoritySnapshot: input.source.scopeAuthoritySnapshot,
    helloDigest: await digest(input.hello), nonce: randomNonce(),
    issuedAt: new Date(now).toISOString(), expiresAt,
  }, input.profile.device.deviceId, domain) as Promise<OwnerReconnectChallenge>
}

export async function createOwnerReconnectApproval(input: {
  session: OwnerReconnectSession
  hello: OwnerReconnectHello
  challenge: OwnerReconnectChallenge
  profile: LocalProfile
  authorityView: IdentityAuthorityView
  now?: number
}): Promise<OwnerReconnectApproval> {
  const now = input.now ?? Date.now()
  const session = validateSession(input.session, now)
  const authorityView = await currentIdentityView(input.profile, input.authorityView)
  await verifyHelloForSession(input.hello, session, now)
  await verifyChallengeForSession(input.challenge, session, input.hello, now)
  const ownerKey = await authorizeIdentityDataDevice(authorityView, input.profile.device.deviceId)
  if (ownerKey !== input.profile.device.publicKey || input.profile.identity.personId !== input.challenge.payload.ownerPersonId ||
      input.profile.identity.publicKey !== input.challenge.payload.ownerPublicKey ||
      input.profile.device.deviceId !== input.challenge.payload.ownerDeviceId) {
    throw new Error("Owner reconnect challenge is for another current Identity device")
  }
  return signEnvelope(input.profile.privateKeys.devicePrivateKey, {
    kind: "mesh-owner-reconnect-approval", version: 1,
    invitationId: session.invitationId, workspaceId: session.workspaceId,
    scopeId: input.challenge.payload.scopeId,
    ownerPersonId: input.profile.identity.personId, ownerDeviceId: input.profile.device.deviceId,
    challengeDigest: await digest(input.challenge), ownerAuthorityView: authorityView,
    approvedAt: new Date(now).toISOString(),
  }, input.profile.device.deviceId, domain) as Promise<OwnerReconnectApproval>
}

export async function ownerReconnectApprovalIntent(input: { session: OwnerReconnectSession; hello: OwnerReconnectHello;
  challenge: OwnerReconnectChallenge; profile: LocalProfile; authorityView: IdentityAuthorityView; now?: number }): Promise<OwnerReconnectApprovalIntent> {
  const now = input.now ?? Date.now()
  const session = validateSession(input.session, now)
  const view = await currentIdentityView(input.profile, input.authorityView)
  await verifyHelloForSession(input.hello, session, now)
  await verifyChallengeForSession(input.challenge, session, input.hello, now)
  const ownerKey = await authorizeIdentityDataDevice(view, input.profile.device.deviceId)
  if (ownerKey !== input.profile.device.publicKey || input.profile.identity.personId !== input.challenge.payload.ownerPersonId ||
      input.profile.device.deviceId !== input.challenge.payload.ownerDeviceId) {
    throw new Error("Owner reconnect challenge is for another current Identity device")
  }
  return {
    workspaceId: input.challenge.payload.workspaceId,
    scopeId: input.challenge.payload.scopeId,
    ownerPersonId: input.challenge.payload.ownerPersonId,
    sourcePersonId: input.challenge.payload.sourcePersonId,
    sourceRole: input.challenge.payload.sourceWorkspaceAccessProof.grant.payload.role as "editor" | "visitor",
    expiresAt: input.challenge.payload.expiresAt,
  }
}

export async function ownerReconnectAuthenticatedPeer(sessionValue: OwnerReconnectSession,
  hello: OwnerReconnectHello, now = Date.now()): Promise<OwnerReconnectAuthenticatedPeer> {
  const session = validateSession(sessionValue, now)
  await verifyHelloForSession(hello, session, now)
  return { workspaceId: session.workspaceId, personId: hello.payload.ownerPersonId, deviceId: hello.payload.ownerDeviceId }
}

export async function assertOwnerReconnectSourceState(input: { source: OwnerReconnectSourceState; profile: LocalProfile;
  authorityView: IdentityAuthorityView; workspaceId: string; now?: number }): Promise<"editor" | "visitor"> {
  const now = input.now ?? Date.now()
  const sessionProfile = await currentIdentityView(input.profile, input.authorityView)
  return verifySourceReadAccess(input.source, input.profile, sessionProfile, input.workspaceId, now)
}

export async function createOwnerReconnectOffer(input: {
  session: OwnerReconnectSession
  hello: OwnerReconnectHello
  challenge: OwnerReconnectChallenge
  approval: OwnerReconnectApproval
  profile: LocalProfile
  authorityView: IdentityAuthorityView
  source: OwnerReconnectSourceState
  sourceEndpointId: string
  now?: number
}): Promise<OwnerReconnectOffer> {
  const now = input.now ?? Date.now()
  const session = validateSession(input.session, now)
  if (!input.sourceEndpointId) throw new Error("Owner reconnect source endpoint is required")
  await verifyHelloForSession(input.hello, session, now)
  await verifyChallengeForSession(input.challenge, session, input.hello, now)
  await verifyApprovalForChallenge(input.approval, input.challenge, now)
  const sourceView = await currentIdentityView(input.profile, input.authorityView)
  const sourceKey = await authorizeIdentityDataDevice(sourceView, input.profile.device.deviceId)
  if (sourceKey !== input.profile.device.publicKey || input.challenge.payload.sourcePersonId !== input.profile.identity.personId ||
      input.challenge.payload.sourceDeviceId !== input.profile.device.deviceId ||
      input.challenge.payload.sourceEndpointId !== input.sourceEndpointId ||
      canonicalizeJson(sourceView) !== canonicalizeJson(input.challenge.payload.sourceAuthorityView)) {
    throw new Error("Owner reconnect source does not match the invitation")
  }
  await verifySourceReadAccess(input.source, input.profile, sourceView, session.workspaceId, now, input.sourceEndpointId)
  if (canonicalizeJson(input.source.scopeAuthoritySnapshot) !== canonicalizeJson(input.challenge.payload.scopeAuthoritySnapshot) ||
      canonicalizeJson(input.source.workspaceAuthority.authority.currentOwner) !==
      canonicalizeJson(input.challenge.payload.sourceWorkspaceAccessProof.workspaceAuthority.currentOwner) ||
      canonicalizeJson(input.source.grant) !== canonicalizeJson(input.challenge.payload.sourceWorkspaceAccessProof.grant)) {
    throw new Error("Owner reconnect source authority changed after challenge")
  }
  const storage = ownerReconnectStorage(input.source)
  if (storage) {
    validateReplicaConfig(storage.replicaConfig, session.workspaceId, input.challenge.payload.scopeId)
  } else if (input.challenge.payload.scopeId !== session.workspaceId) {
    throw new Error("Owner reconnect challenge has an unexpected storage scope")
  }
  const content = captureJson({
    workspace: input.source.workspace,
    workspaceAuthority: input.source.workspaceAuthority,
    workspaceAccessSnapshot: captureAccessSnapshot(input.source.workspaceAccessSnapshot),
    scopeAuthoritySnapshot: input.source.scopeAuthoritySnapshot,
    grant: input.source.grant,
    meshEnvelope: input.source.meshEnvelope,
    ...(storage ? {
      replicaConfig: normalizeOwnerReplicaConfig(storage.replicaConfig),
      ownerStorageProof: storage.ownerStorageProof,
    } : {}),
  })
  const contentDigest = await digest(content)
  const expiresAt = earlierTime(Date.parse(session.expiresAt), Date.parse(input.challenge.payload.expiresAt))
  const envelope = await signEnvelope(input.profile.privateKeys.devicePrivateKey, {
    kind: "mesh-owner-reconnect-offer", version: 1,
    invitationId: session.invitationId, workspaceId: session.workspaceId,
    scopeId: input.challenge.payload.scopeId,
    ownerPersonId: input.challenge.payload.ownerPersonId,
    ownerDeviceId: input.challenge.payload.ownerDeviceId,
    sourcePersonId: input.profile.identity.personId, sourceDeviceId: input.profile.device.deviceId,
    ownerEndpointId: input.challenge.payload.ownerEndpointId, sourceEndpointId: input.sourceEndpointId,
    challengeDigest: await digest(input.challenge), approvalDigest: await digest(input.approval),
    sourceAuthorityView: sourceView, contentDigest,
    issuedAt: new Date(now).toISOString(), expiresAt,
  }, input.profile.device.deviceId, domain)
  return { envelope: envelope as OwnerReconnectOffer["envelope"], content }
}

export async function verifyOwnerReconnectOffer(input: {
  session: OwnerReconnectSession
  hello: OwnerReconnectHello
  challenge: OwnerReconnectChallenge
  approval: OwnerReconnectApproval
  offer: OwnerReconnectOffer
  profile: LocalProfile
  authorityView: IdentityAuthorityView
  knownWorkspaceAuthority?: unknown
  ownerEndpointId: string
  now?: number
}): Promise<VerifiedOwnerReconnectWorkspace> {
  const now = input.now ?? Date.now()
  const session = validateSession(input.session, now)
  const ownerView = await currentIdentityView(input.profile, input.authorityView)
  const ownerKey = await authorizeIdentityDataDevice(ownerView, input.profile.device.deviceId)
  if (ownerKey !== input.profile.device.publicKey) throw new Error("Owner reconnect device is not active")
  await verifyHelloForSession(input.hello, session, now)
  await verifyChallengeForSession(input.challenge, session, input.hello, now)
  await verifyApprovalForChallenge(input.approval, input.challenge, now)
  const payload = input.offer.envelope?.payload
  if (!payload || payload.kind !== "mesh-owner-reconnect-offer" || payload.version !== 1 ||
      payload.invitationId !== session.invitationId || payload.workspaceId !== session.workspaceId ||
      payload.scopeId !== input.challenge.payload.scopeId || payload.ownerPersonId !== input.profile.identity.personId ||
      payload.ownerDeviceId !== input.profile.device.deviceId ||
      payload.ownerEndpointId !== input.ownerEndpointId ||
      payload.sourceEndpointId !== input.challenge.payload.sourceEndpointId ||
      payload.sourcePersonId !== input.challenge.payload.sourcePersonId ||
      payload.sourceDeviceId !== input.challenge.payload.sourceDeviceId ||
      canonicalizeJson(payload.sourceAuthorityView) !== canonicalizeJson(input.challenge.payload.sourceAuthorityView) ||
      payload.challengeDigest !== await digest(input.challenge) || payload.approvalDigest !== await digest(input.approval) ||
      !Number.isFinite(Date.parse(payload.expiresAt)) || !Number.isFinite(Date.parse(payload.issuedAt)) ||
      Date.parse(payload.expiresAt) <= now || Date.parse(payload.issuedAt) > now + 5 * 60 * 1000) {
    throw new Error("Owner reconnect offer does not match the approved challenge")
  }
  const sourceView = await verifyIdentityAuthorityView(payload.sourceAuthorityView)
  const sourceKey = await authorizeIdentityDataDevice(sourceView, payload.sourceDeviceId)
  if (sourceView.personId !== payload.sourcePersonId || sourceKey !== (await publicKeyForDevice(sourceView, payload.sourceDeviceId)) ||
      input.offer.envelope.signerKeyId !== payload.sourceDeviceId ||
      !await verifyEnvelope(input.offer.envelope, sourceKey, domain)) {
    throw new Error("Owner reconnect offer is not signed by the active source device")
  }
  const content = captureJson(input.offer.content)
  if (await digest(content) !== payload.contentDigest) throw new Error("Owner reconnect offer content changed")
  const source: OwnerReconnectSourceState = {
    ...content,
    workspace: content.workspace,
    workspaceAuthority: content.workspaceAuthority,
    workspaceAccessSnapshot: restoreAccessSnapshot(content.workspaceAccessSnapshot),
    scopeAuthoritySnapshot: content.scopeAuthoritySnapshot,
    grant: content.grant,
    meshEnvelope: content.meshEnvelope,
    ...(Object.hasOwn(content, "replicaConfig") ? { replicaConfig: content.replicaConfig } : {}),
    ...(Object.hasOwn(content, "ownerStorageProof") ? { ownerStorageProof: content.ownerStorageProof } : {}),
    history: unavailableHistorySource(),
  } as OwnerReconnectSourceState
  await verifySourceReadAccess(source, { identity: { personId: payload.sourcePersonId, publicKey: sourceView.identityPublicKey },
    device: { deviceId: payload.sourceDeviceId, publicKey: sourceKey } } as LocalProfile, sourceView, session.workspaceId, now,
    payload.sourceEndpointId)
  const scope = validateCurrentScope(source.scopeAuthoritySnapshot, session.workspaceId, now)
  if (scope.scopeId !== session.workspaceId || scope.controller.personId !== input.profile.identity.personId ||
      scope.controller.publicKey !== input.profile.identity.publicKey) {
    throw new Error("Owner reconnect scope is not controlled by this Identity")
  }
  const authority = source.workspaceAuthority.authority
  if (authority.currentOwner.personId !== scope.controller.personId || authority.currentOwner.publicKey !== scope.controller.publicKey) {
    throw new Error("Owner reconnect workspace history differs from the current scope controller")
  }
  validateOwnerWorkspace(source.workspace, session.workspaceId, scope.controller.personId)
  const storage = ownerReconnectStorage(source)
  if (storage) {
    validateReplicaConfig(storage.replicaConfig, session.workspaceId, payload.scopeId)
  } else if (payload.scopeId !== session.workspaceId) {
    throw new Error("Owner reconnect offer has an unexpected storage scope")
  }
  validateCausalWorkspace(source.workspace, source.workspaceAuthority, source.workspaceAccessSnapshot,
    input.knownWorkspaceAuthority, session.workspaceId, now)
  return {
    workspaceId: session.workspaceId, workspace: source.workspace, workspaceAuthority: source.workspaceAuthority,
    workspaceAccessSnapshot: source.workspaceAccessSnapshot, scopeAuthoritySnapshot: source.scopeAuthoritySnapshot,
    grant: source.grant, meshEnvelope: source.meshEnvelope,
    ...(storage ? { replicaConfig: storage.replicaConfig, ownerStorageProof: storage.ownerStorageProof } : {}),
    sourcePersonId: payload.sourcePersonId,
    sourceDeviceId: payload.sourceDeviceId, sourceRole: source.grant.payload.role as "editor" | "visitor",
    offerDigest: await digest(input.offer),
  }
}

export async function createOwnerReconnectReceipt(input: {
  profile: LocalProfile
  authorityView: IdentityAuthorityView
  session: OwnerReconnectSession
  verified: VerifiedOwnerReconnectWorkspace
  now?: number
}): Promise<OwnerReconnectReceipt> {
  const now = input.now ?? Date.now()
  const session = validateSession(input.session, now)
  const view = await currentIdentityView(input.profile, input.authorityView)
  const publicKey = await authorizeIdentityDataDevice(view, input.profile.device.deviceId)
  if (publicKey !== input.profile.device.publicKey || input.verified.workspaceId !== session.workspaceId) {
    throw new Error("Owner reconnect receipt identity changed")
  }
  return signEnvelope(input.profile.privateKeys.devicePrivateKey, {
    kind: "mesh-owner-reconnect-receipt", version: 1,
    invitationId: session.invitationId, workspaceId: session.workspaceId,
    ownerPersonId: input.profile.identity.personId, sourcePersonId: input.verified.sourcePersonId,
    offerDigest: input.verified.offerDigest, committedAt: new Date(now).toISOString(),
  }, input.profile.device.deviceId, domain) as Promise<OwnerReconnectReceipt>
}

export async function createOwnerReconnectHistoryRequest(input: {
  profile: LocalProfile; authorityView: IdentityAuthorityView; session: OwnerReconnectSession
  challenge: OwnerReconnectChallenge; verified: VerifiedOwnerReconnectWorkspace; operation: OwnerReconnectHistoryOperation
}): Promise<OwnerReconnectHistoryRequest> {
  const session = validateSession(input.session, Date.now())
  const view = await currentIdentityView(input.profile, input.authorityView)
  const key = await authorizeIdentityDataDevice(view, input.profile.device.deviceId)
  if (key !== input.profile.device.publicKey || input.profile.identity.personId !== input.challenge.payload.ownerPersonId ||
      input.verified.workspaceId !== session.workspaceId || input.operation.workspaceId !== session.workspaceId) {
    throw new Error("Owner reconnect history request identity changed")
  }
  return signEnvelope(input.profile.privateKeys.devicePrivateKey, {
    kind: "mesh-owner-reconnect-history-read", version: 1, invitationId: session.invitationId,
    workspaceId: session.workspaceId, ownerPersonId: input.profile.identity.personId,
    ownerDeviceId: input.profile.device.deviceId, challengeDigest: await digest(input.challenge),
    offerDigest: input.verified.offerDigest, requestId: crypto.randomUUID(), operation: input.operation,
  }, input.profile.device.deviceId, domain) as Promise<OwnerReconnectHistoryRequest>
}

export async function verifyOwnerReconnectHistoryRequest(input: {
  request: OwnerReconnectHistoryRequest; session: OwnerReconnectSession; hello: OwnerReconnectHello; challenge: OwnerReconnectChallenge;
  offerDigest: string; now?: number
}): Promise<void> {
  const now = input.now ?? Date.now()
  const payload = input.request?.payload
  if (!payload || payload.kind !== "mesh-owner-reconnect-history-read" || payload.version !== 1 ||
      payload.invitationId !== input.session.invitationId || payload.workspaceId !== input.session.workspaceId ||
      payload.ownerPersonId !== input.challenge.payload.ownerPersonId || payload.ownerDeviceId !== input.challenge.payload.ownerDeviceId ||
      payload.challengeDigest !== await digest(input.challenge) || payload.offerDigest !== input.offerDigest ||
      payload.operation?.workspaceId !== input.session.workspaceId || Date.parse(input.session.expiresAt) <= now) {
    throw new Error("Owner reconnect history request does not match the approved session")
  }
  const view = await verifyIdentityAuthorityView(input.hello.payload.ownerAuthorityView)
  const key = await authorizeIdentityDataDevice(view, payload.ownerDeviceId)
  if (input.request.signerKeyId !== payload.ownerDeviceId || key !== input.challenge.payload.ownerDevicePublicKey ||
      !await verifyEnvelope(input.request, key, domain)) throw new Error("Owner reconnect history request has no active owner proof")
}

export async function createOwnerReconnectHistoryResponse(input: {
  profile: LocalProfile; authorityView: IdentityAuthorityView; session: OwnerReconnectSession;
  request: OwnerReconnectHistoryRequest; result: OwnerReconnectHistoryResponse["payload"]["result"]
}): Promise<OwnerReconnectHistoryResponse> {
  const view = await currentIdentityView(input.profile, input.authorityView)
  const key = await authorizeIdentityDataDevice(view, input.profile.device.deviceId)
  if (key !== input.profile.device.publicKey || input.request.payload.workspaceId !== input.session.workspaceId) {
    throw new Error("Owner reconnect history source identity changed")
  }
  return signEnvelope(input.profile.privateKeys.devicePrivateKey, {
    kind: "mesh-owner-reconnect-history-response", version: 1, invitationId: input.session.invitationId,
    workspaceId: input.session.workspaceId, ownerPersonId: input.request.payload.ownerPersonId,
    sourcePersonId: input.profile.identity.personId, requestId: input.request.payload.requestId,
    offerDigest: input.request.payload.offerDigest, result: input.result,
  }, input.profile.device.deviceId, domain) as Promise<OwnerReconnectHistoryResponse>
}

export async function verifyOwnerReconnectHistoryResponse(input: {
  response: OwnerReconnectHistoryResponse; request: OwnerReconnectHistoryRequest;
  session: OwnerReconnectSession; challenge: OwnerReconnectChallenge; sourceAuthorityView: IdentityAuthorityView
}): Promise<OwnerReconnectHistoryResponse["payload"]["result"]> {
  const payload = input.response?.payload
  if (!payload || payload.kind !== "mesh-owner-reconnect-history-response" || payload.version !== 1 ||
      payload.invitationId !== input.session.invitationId || payload.workspaceId !== input.session.workspaceId ||
      payload.ownerPersonId !== input.challenge.payload.ownerPersonId || payload.sourcePersonId !== input.challenge.payload.sourcePersonId ||
      payload.requestId !== input.request.payload.requestId || payload.offerDigest !== input.request.payload.offerDigest) {
    throw new Error("Owner reconnect history response does not match the request")
  }
  const view = await verifyIdentityAuthorityView(input.sourceAuthorityView)
  const key = await authorizeIdentityDataDevice(view, input.response.signerKeyId)
  if (input.response.signerKeyId !== input.challenge.payload.sourceDeviceId ||
      key !== input.challenge.payload.sourceDevicePublicKey || !await verifyEnvelope(input.response, key, domain)) {
    throw new Error("Owner reconnect history response has no active source proof")
  }
  if (payload.result.kind === "error") throw new Error(payload.result.message)
  return payload.result
}

export async function verifyOwnerReconnectReceipt(input: {
  session: OwnerReconnectSession
  hello: OwnerReconnectHello
  challenge: OwnerReconnectChallenge
  offer: OwnerReconnectOffer
  receipt: OwnerReconnectReceipt
  now?: number
}): Promise<void> {
  const now = input.now ?? Date.now()
  const session = validateSession(input.session, now)
  const payload = input.receipt?.payload
  if (!payload || payload.kind !== "mesh-owner-reconnect-receipt" || payload.version !== 1 ||
      payload.invitationId !== session.invitationId || payload.workspaceId !== session.workspaceId ||
      payload.ownerPersonId !== input.challenge.payload.ownerPersonId ||
      payload.sourcePersonId !== input.offer.envelope.payload.sourcePersonId ||
      payload.offerDigest !== await digest(input.offer)) {
    throw new Error("Owner reconnect receipt does not match the committed offer")
  }
  const view = await verifyIdentityAuthorityView(input.hello.payload.ownerAuthorityView)
  const key = await authorizeIdentityDataDevice(view, input.receipt.signerKeyId)
  if (input.receipt.signerKeyId !== input.challenge.payload.ownerDeviceId ||
      key !== input.challenge.payload.ownerDevicePublicKey || !await verifyEnvelope(input.receipt, key, domain)) {
    throw new Error("Owner reconnect receipt is not signed by the approved owner device")
  }
}

async function verifyHelloForSession(hello: OwnerReconnectHello, session: OwnerReconnectSession, now: number): Promise<void> {
  const payload = hello?.payload
  if (!payload || payload.kind !== "mesh-owner-reconnect-hello" || payload.version !== 1 ||
      payload.invitationId !== session.invitationId || payload.workspaceId !== session.workspaceId ||
      payload.ownerPersonId !== await keyId(payload.ownerPublicKey) ||
      !payload.ownerEndpointId ||
      payload.ownerDeviceId !== hello.signerKeyId || Date.parse(payload.expiresAt) <= now ||
      !Number.isFinite(Date.parse(payload.expiresAt)) || !Number.isFinite(Date.parse(payload.issuedAt)) ||
      Date.parse(payload.issuedAt) > now + 5 * 60 * 1000 || Date.parse(payload.expiresAt) > Date.parse(session.expiresAt)) {
    throw new Error("Invalid or expired owner reconnect hello")
  }
  const view = await verifyIdentityAuthorityView(payload.ownerAuthorityView)
  const key = await authorizeIdentityDataDevice(view, payload.ownerDeviceId)
  if (view.personId !== payload.ownerPersonId || key !== payload.ownerDevicePublicKey ||
      !await verifyEnvelope(hello, key, domain)) throw new Error("Owner reconnect hello has no active Identity device proof")
}

async function verifyChallengeForSession(challenge: OwnerReconnectChallenge, session: OwnerReconnectSession,
  hello: OwnerReconnectHello, now: number): Promise<void> {
  const payload = challenge?.payload
  if (!payload || payload.kind !== "mesh-owner-reconnect-challenge" || payload.version !== 1 ||
      payload.invitationId !== session.invitationId || payload.workspaceId !== session.workspaceId ||
      payload.ownerPersonId !== hello.payload.ownerPersonId || payload.ownerPublicKey !== hello.payload.ownerPublicKey ||
      payload.ownerDeviceId !== hello.payload.ownerDeviceId || payload.helloDigest !== await digest(hello) ||
      payload.ownerEndpointId !== hello.payload.ownerEndpointId || payload.sourceEndpointId !== session.issuerEndpoint ||
      payload.sourcePersonId !== session.issuerPersonId || payload.sourceDeviceId !== session.issuerDeviceId ||
      Date.parse(payload.expiresAt) <= now ||
      !Number.isFinite(Date.parse(payload.expiresAt)) || !Number.isFinite(Date.parse(payload.issuedAt)) ||
      Date.parse(payload.issuedAt) > now + 5 * 60 * 1000 || Date.parse(payload.expiresAt) > Date.parse(session.expiresAt)) {
    throw new Error("Invalid or expired owner reconnect challenge")
  }
  const sourceView = await verifyIdentityAuthorityView(payload.sourceAuthorityView)
  const sourceKey = await authorizeIdentityDataDevice(sourceView, payload.sourceDeviceId)
  if (sourceView.personId !== payload.sourcePersonId || sourceView.identityPublicKey !== payload.sourcePublicKey ||
      sourceKey !== payload.sourceDevicePublicKey || sourceKey !== session.issuerPublicKey ||
      challenge.signerKeyId !== payload.sourceDeviceId || !await verifyEnvelope(challenge, sourceKey, domain)) {
    throw new Error("Owner reconnect challenge has no active source device proof")
  }
  const scope = validateCurrentScope(payload.scopeAuthoritySnapshot, session.workspaceId, now)
  if (scope.scopeId !== session.workspaceId || scope.controller.personId !== payload.ownerPersonId ||
      scope.controller.publicKey !== payload.ownerPublicKey) {
    throw new Error("Owner reconnect challenge names a different scope controller")
  }
  verifyOwnerMembershipProof(payload.sourceWorkspaceAccessProof.workspaceAuthority, payload.sourceWorkspaceAccessProof.grant,
    payload.sourcePersonId, payload.sourceDeviceId, session.workspaceId, scope.controller, now)
}

async function verifyApprovalForChallenge(approval: OwnerReconnectApproval, challenge: OwnerReconnectChallenge, now: number): Promise<void> {
  const payload = approval?.payload
  const expectedChallenge = await digest(challenge)
  if (!payload || payload.kind !== "mesh-owner-reconnect-approval" || payload.version !== 1 ||
      payload.invitationId !== challenge.payload.invitationId || payload.workspaceId !== challenge.payload.workspaceId ||
      payload.scopeId !== challenge.payload.scopeId || payload.ownerPersonId !== challenge.payload.ownerPersonId ||
      payload.ownerDeviceId !== challenge.payload.ownerDeviceId || payload.challengeDigest !== expectedChallenge ||
      !Number.isFinite(Date.parse(payload.approvedAt)) ||
      Date.parse(payload.approvedAt) > now + 5 * 60 * 1000) {
    throw new Error("Owner reconnect approval does not match the challenge")
  }
  const view = await verifyIdentityAuthorityView(payload.ownerAuthorityView)
  const key = await authorizeIdentityDataDevice(view, payload.ownerDeviceId)
  if (view.personId !== payload.ownerPersonId || key !== challenge.payload.ownerDevicePublicKey ||
      approval.signerKeyId !== payload.ownerDeviceId || !await verifyEnvelope(approval, key, domain)) {
    throw new Error("Owner reconnect approval has no active owner device proof")
  }
}

async function verifySourceReadAccess(source: OwnerReconnectSourceState, profile: LocalProfile,
  identityView: IdentityAuthorityView, workspaceId: string, now: number, ephemeralEndpointId?: string): Promise<"editor" | "visitor"> {
  validateOwnerWorkspace(source.workspace, workspaceId, source.workspaceAuthority.authority.currentOwner.personId)
  const storage = ownerReconnectStorage(source)
  if (storage && storage.replicaConfig.workspaceId !== workspaceId) throw new Error("Owner reconnect source workspace config mismatch")
  const owner = source.workspaceAuthority.authority.currentOwner
  const scope = validateCurrentScope(source.scopeAuthoritySnapshot, workspaceId, now)
  if (scope.scopeId !== workspaceId || scope.controller.personId !== owner.personId || scope.controller.publicKey !== owner.publicKey) {
    throw new Error("Rusty scope controller differs from current workspace owner")
  }
  await verifyOwnerReconnectMeshEnvelope(source.meshEnvelope, source.grant, source.workspaceAuthority.authority,
    source.scopeAuthoritySnapshot, workspaceId, profile.identity.personId, profile.device.deviceId, ephemeralEndpointId, now)
  if (storage) {
    validateReplicaConfig(storage.replicaConfig, workspaceId, storage.replicaConfig.scopeId)
    await verifyOwnerStorageProof(storage.ownerStorageProof, storage.replicaConfig, source.scopeAuthoritySnapshot,
      source.workspaceAuthority.authority, workspaceId, owner)
  }
  const grant = source.grant
  if (!grant || grant.payload.workspaceId !== workspaceId || grant.payload.personId !== profile.identity.personId ||
      (grant.payload.role !== "editor" && grant.payload.role !== "visitor")) {
    throw new Error("Owner reconnect source has no current read grant")
  }
  const authority = source.workspaceAuthority.authority
  const grantEpoch = grant.payload.accessEpoch ?? 1
  const hasActiveDeparture = authority.departures.some((entry: any) => entry?.record?.payload?.personId === profile.identity.personId &&
    Number.isSafeInteger(entry.record.payload.accessEpoch) && entry.record.payload.accessEpoch >= grantEpoch)
  const hasActiveRevocation = authority.revocations.some((entry: any) => entry?.payload?.personId === profile.identity.personId &&
    Number.isSafeInteger(entry.payload.epoch) && entry.payload.epoch >= grantEpoch)
  const hasActiveDeviceRevocation = authority.deviceRevocations.some((entry: any) => {
    const payload = entry?.record?.payload ?? entry?.payload
    return payload?.personId === profile.identity.personId && payload?.deviceId === profile.device.deviceId
  })
  if (hasActiveDeparture || hasActiveRevocation || hasActiveDeviceRevocation) {
    throw new Error("Owner reconnect source workspace access is revoked")
  }
  const role = meshRustRuntime().state.decideWorkspaceAccess({ snapshot: source.workspaceAccessSnapshot,
    identity: { personId: profile.identity.personId, publicKey: profile.identity.publicKey, certificates: identityView.certificates },
    deviceId: profile.device.deviceId, grant,
    departures: (source.workspaceAuthority.authority.departures ?? []) as unknown[] }, now)
  if (role !== grant.payload.role) throw new Error("Owner reconnect source has no current workspace read access")
  return role
}

async function verifyOwnerReconnectMeshEnvelope(envelope: OwnerReconnectMeshEnvelope, grant: WorkspaceGrant,
  authority: OwnerReconnectAuthority, scopeAuthoritySnapshot: unknown, workspaceId: string, sourcePersonId: string,
  sourceDeviceId: string, ephemeralEndpointId: string | undefined, now: number): Promise<void> {
  const state = meshRustRuntime().state
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) ||
      envelope.workspaceId !== workspaceId || envelope.ownerPersonId !== authority.currentOwner.personId ||
      envelope.ownerPublicKey !== authority.currentOwner.publicKey ||
      canonicalizeJson(envelope.scopeAuthoritySnapshot) !== canonicalizeJson(scopeAuthoritySnapshot) ||
      !state.isWorkspaceEnvelope(envelope, now)) {
    throw new Error("Owner reconnect source has no current durable mesh invitation")
  }
  state.planInvitationCredential({ workspaceId, envelope, previousCredential: null, previousAuthority: null,
    localPersonId: sourcePersonId, localGrant: grant, updatedAt: new Date(now).toISOString() })

  const peers = envelope.peers.filter((value: unknown) => {
    const payload = value && typeof value === "object" && !Array.isArray(value)
      ? (value as { advertisement?: { payload?: unknown }; signed?: { payload?: unknown }; payload?: unknown }).advertisement?.payload ??
        (value as { signed?: { payload?: unknown }; payload?: unknown }).signed?.payload ??
        (value as { payload?: unknown }).payload
      : undefined
    return payload && typeof payload === "object" && !Array.isArray(payload) &&
      (payload as { workspaceId?: unknown }).workspaceId === workspaceId &&
      (payload as { personId?: unknown }).personId === sourcePersonId &&
      (payload as { deviceId?: unknown }).deviceId === sourceDeviceId
  })
  if (!peers.length) throw new Error("Owner reconnect source has no persistent workspace route")

  let hasPersistentSourceRoute = false
  for (const peer of peers) {
    const verified = state.verifyWorkspaceMemberBundle(peer, {
      workspaceId, ownerPersonId: authority.currentOwner.personId,
      ownerPublicKey: authority.currentOwner.publicKey,
      ownerCertificates: envelope.ownerCertificates,
      ownerHistory: (envelope.ownerHistory ?? [authority.currentOwner]) as unknown[],
      allowStaleRoute: false,
    }, now) as { payload?: { personId?: string; deviceId?: string; endpoint?: string; instanceId?: string };
      grant?: WorkspaceGrant; role?: string }
    if (verified.payload?.personId !== sourcePersonId || verified.payload.deviceId !== sourceDeviceId ||
        canonicalizeJson(verified.grant) !== canonicalizeJson(grant) || verified.role !== grant.payload.role) continue
    if (typeof verified.payload.endpoint === "string" && verified.payload.endpoint.length > 0 &&
        typeof verified.payload.instanceId === "string" && verified.payload.instanceId.length > 0 &&
        (!ephemeralEndpointId || verified.payload.endpoint !== ephemeralEndpointId)) {
      hasPersistentSourceRoute = true
    }
  }
  if (!hasPersistentSourceRoute) throw new Error("Owner reconnect source has no persistent workspace route")
}

function ownerReconnectStorage(source: { replicaConfig?: unknown; ownerStorageProof?: unknown }):
  { replicaConfig: OwnerReplicaConfig; ownerStorageProof: OwnerReconnectOwnerStorageProof } | undefined {
  const hasConfig = Object.hasOwn(source, "replicaConfig")
  const hasProof = Object.hasOwn(source, "ownerStorageProof")
  if (hasConfig !== hasProof) {
    throw new Error("Owner reconnect replica config and storage proof must be supplied together")
  }
  if (!hasConfig) return undefined

  const replicaConfig = source.replicaConfig
  const ownerStorageProof = source.ownerStorageProof
  if (!replicaConfig || typeof replicaConfig !== "object" || Array.isArray(replicaConfig) ||
      !ownerStorageProof || typeof ownerStorageProof !== "object" || Array.isArray(ownerStorageProof)) {
    throw new Error("Invalid owner reconnect storage payload")
  }
  return { replicaConfig: replicaConfig as OwnerReplicaConfig, ownerStorageProof: ownerStorageProof as OwnerReconnectOwnerStorageProof }
}

function verifyOwnerMembershipProof(authority: OwnerReconnectAuthority, grant: WorkspaceGrant,
  personId: string, deviceId: string, workspaceId: string, currentOwner: { personId: string; publicKey: string }, now: number): void {
  if (grant.payload.workspaceId !== workspaceId || grant.payload.personId !== personId ||
      (grant.payload.role !== "editor" && grant.payload.role !== "visitor")) {
    throw new Error("Owner reconnect source grant is not read-authorized")
  }
  const owners = [authority.currentOwner, ...authority.ownershipTransfers.flatMap((record: any) => {
    const payload = record?.payload
    return payload ? [{ personId: payload.fromOwnerPersonId, publicKey: payload.fromOwnerPublicKey,
      certificates: payload.fromOwnerCertificates ?? [] }, { personId: payload.toOwnerPersonId,
      publicKey: payload.toOwnerPublicKey, certificates: payload.toOwnerCertificates ?? [] }] : []
  }), authority.genesisOwner]
  const verified = owners.some(owner => owner.personId && owner.publicKey &&
    (() => { try { return meshRustRuntime().state.verifyWorkspaceGrant(grant, workspaceId, personId, owner) === grant.payload.role }
      catch { return false } })())
  if (!verified || authority.currentOwner.personId !== currentOwner.personId ||
      authority.currentOwner.publicKey !== currentOwner.publicKey) throw new Error("Owner reconnect source grant failed owner-history verification")
  const grantEpoch = grant.payload.accessEpoch ?? 1
  const hasActiveDeparture = authority.departures.some((entry: any) => entry?.record?.payload?.personId === personId &&
    Number.isSafeInteger(entry.record.payload.accessEpoch) && entry.record.payload.accessEpoch >= grantEpoch)
  const hasActiveRevocation = authority.revocations.some((entry: any) => entry?.payload?.personId === personId &&
    Number.isSafeInteger(entry.payload.epoch) && entry.payload.epoch >= grantEpoch)
  const hasDeviceRevocation = authority.deviceRevocations.some((entry: any) => {
    const payload = entry?.record?.payload ?? entry?.payload
    return payload?.personId === personId && payload?.deviceId === deviceId
  })
  if (hasActiveDeparture || hasActiveRevocation || hasDeviceRevocation) throw new Error("Owner reconnect source workspace access is revoked")
  void now
}

function validateCurrentScope(snapshot: unknown, workspaceId: string, now: number): {
  scopeId: string; controller: { personId: string; publicKey: string }
} {
  const scope = meshRustRuntime().state.validateScopeAuthority(snapshot, now) as {
    scopeId: string; controller: { personId: string; publicKey: string }
  }
  if (!scope || scope.scopeId !== workspaceId || !scope.controller?.personId || !scope.controller.publicKey) {
    throw new Error("Invalid owner reconnect Rusty scope authority")
  }
  return scope
}

async function verifyOwnerStorageProof(proof: OwnerReconnectOwnerStorageProof, config: OwnerReplicaConfig,
  scopeAuthoritySnapshot: unknown, authority: OwnerReconnectAuthority, workspaceId: string,
  owner: WorkspaceAuthority): Promise<void> {
  const envelope = proof?.authorization
  const payload = envelope?.payload
  const commonKeys = ["kind", "version", "ownerPersonId", "workspaceId", "connection"]
  const allowedKeys = [...commonKeys, "readTokenHash", "writeTokenHash", "subjectPersonId", "subjectPublicKey", "grantId",
    "policyEpoch", "actions", "workspaceGrant", "scopeAuthority"]
  if (!payload || !proof || !Array.isArray(proof.certificates) || proof.certificates.length < 1 || proof.certificates.length > 32 ||
      payload.kind !== "workspace-rusty-access" || (payload.version !== 1 && payload.version !== 2) ||
      Object.keys(payload).some(key => !allowedKeys.includes(key)) ||
      commonKeys.some(key => !Object.hasOwn(payload, key)) ||
      payload.ownerPersonId !== owner.personId || payload.workspaceId !== workspaceId ||
      canonicalizeJson(payload.connection) !== canonicalizeJson(ownerStorageConnection(config))) {
    throw new Error("Owner reconnect storage proof does not bind the existing Rusty connection")
  }
  if (payload.version === 1) {
    if (Object.keys(payload).some(key => ![...commonKeys, "writeTokenHash"].includes(key)) || typeof payload.writeTokenHash !== "string") {
      throw new Error("Invalid legacy owner reconnect storage proof")
    }
  } else if (payload.readTokenHash === undefined || payload.workspaceGrant === undefined || payload.scopeAuthority === undefined ||
      payload.subjectPersonId === undefined || payload.subjectPublicKey === undefined || payload.grantId === undefined ||
      payload.policyEpoch === undefined || payload.actions === undefined ||
      canonicalizeJson(payload.scopeAuthority) !== canonicalizeJson(scopeAuthoritySnapshot)) {
    throw new Error("Invalid owner reconnect storage proof")
  }
  if (typeof payload.writeTokenHash !== "string" ||
      payload.writeTokenHash !== await sha256Base64Url(new TextEncoder().encode(config.writeToken))) {
    throw new Error("Owner reconnect storage proof does not bind the owner write token")
  }
  const signerKey = await verifyDeviceCertificateChain({ personId: owner.personId, publicKey: owner.publicKey, displayName: "" },
    envelope.signerKeyId, proof.certificates)
  if (authority.deviceRevocations.some(entry => {
    const record = entry as { payload?: { personId?: string; deviceId?: string }; record?: { payload?: { personId?: string; deviceId?: string } } }
    const revoked = record.record?.payload ?? record.payload
    return revoked?.personId === owner.personId && revoked.deviceId === envelope.signerKeyId
  }) || !await verifyEnvelope(envelope, signerKey)) {
    throw new Error("Owner reconnect storage proof is not signed by a current owner device")
  }
}

function ownerStorageConnection(config: OwnerReplicaConfig): Record<string, unknown> {
  const localOrPrivate = new Set(["writeToken", "cursor", "lastUploaded", "preferenceRevision", "boardAccess"])
  return Object.fromEntries(Object.entries(config).filter(([key]) => !localOrPrivate.has(key)))
}

function normalizeOwnerReplicaConfig(config: OwnerReplicaConfig): OwnerReplicaConfig {
  const localFields = new Set(["cursor", "lastUploaded", "preferenceRevision", "removalPending", "boardAccess"])
  return Object.fromEntries(Object.entries(config).filter(([key]) => !localFields.has(key))) as OwnerReplicaConfig
}

function validateOwnerWorkspace(workspace: unknown, workspaceId: string, ownerPersonId: string): void {
  if (!workspace || typeof workspace !== "object" || Array.isArray(workspace)) throw new Error("Invalid owner reconnect workspace")
  const value = workspace as Record<string, unknown>
  if (value.id !== workspaceId || typeof value.bytes !== "string" || !value.bytes || !ownerPersonId) {
    throw new Error("Owner reconnect workspace binding mismatch")
  }
}

function validateReplicaConfig(config: OwnerReplicaConfig, workspaceId: string, scopeId: string): void {
  const allowed = new Set(["origin", "scopeId", "servicePublicKey", "readToken", "writeToken", "policyRevision", "client", "clientBuild",
    "purpose", "workspaceId", "keyEpoch", "contentKey", "historicalContentKeys", "historicalContentKeyVariants", "minimumWriterVersion",
    "cursor", "lastUploaded", "preferenceRevision", "removalPending"])
  if (!config || typeof config !== "object" || Array.isArray(config) || Object.keys(config).some(key => !allowed.has(key)) ||
      Object.hasOwn(config as object, "boardAccess") || (config as Record<string, unknown>).workspaceId !== workspaceId ||
      (config as Record<string, unknown>).scopeId !== scopeId || !config.origin || !config.servicePublicKey ||
      (config.purpose !== undefined && config.purpose !== "workspace") || config.removalPending === true ||
      (config.cursor !== undefined && (!Number.isSafeInteger(config.cursor) || config.cursor < 0)) ||
      (config.lastUploaded !== undefined && typeof config.lastUploaded !== "string") ||
      !config.readToken || !config.writeToken || typeof config.readToken !== "string" || typeof config.writeToken !== "string" ||
      !Number.isSafeInteger(config.policyRevision) || config.policyRevision < 1 ||
      !Number.isSafeInteger(config.keyEpoch) || config.keyEpoch < 1) {
    throw new Error("Invalid existing owner Rusty replica config")
  }
  if (decodeBlindBytes(config.contentKey).byteLength !== 32) throw new Error("Invalid owner replica content key")
}

function validateCausalWorkspace(workspace: unknown, proof: OwnerReconnectWorkspaceProof, snapshotValue: unknown,
  known: unknown, workspaceId: string, now: number): void {
  validateOwnerWorkspace(workspace, workspaceId, proof.authority.currentOwner.personId)
  const bundle = proof as OwnerReconnectWorkspaceProof & { authority: OwnerReconnectAuthority; records?: unknown[]; pages?: unknown[][] }
  const records = bundle.version === 1 ? bundle.records ?? [] : (bundle.pages ?? []).flat()
  const snapshot = snapshotValue as Record<string, unknown>
  if (!snapshot || snapshot.workspaceId !== workspaceId) throw new Error("Owner reconnect causal snapshot mismatch")
  const workspaceBytes = fromBase64Url((workspace as { bytes: string }).bytes)
  const accessBytes = snapshot.document instanceof Uint8Array ? snapshot.document
    : typeof snapshot.document === "string" ? fromBase64Url(snapshot.document)
      : Uint8Array.from(snapshot.document as number[])
  if (toBase64Url(workspaceBytes) !== toBase64Url(accessBytes)) throw new Error("Owner reconnect document differs from its causal proof")
  const existing = known as { genesisOwner?: WorkspaceAuthority; currentOwner?: WorkspaceAuthority } | undefined
  if (existing?.genesisOwner && canonicalizeJson(existing.genesisOwner) !== canonicalizeJson(bundle.authority.genesisOwner)) {
    throw new Error("Owner reconnect conflicts with known workspace genesis")
  }
  const decisions = meshRustRuntime().state.evaluateCausalAdmission({ records,
    snapshot: { ...snapshot, ownershipTransfers: bundle.authority.ownershipTransfers,
      successionClaims: bundle.authority.successionClaims, revocations: bundle.authority.revocations,
      deviceRevocations: bundle.authority.deviceRevocations, departures: bundle.authority.departures }, nowMs: now }) as {
    decisions: Array<{ status: { type: string } }>
  }
  if (decisions.decisions.some(decision => decision.status.type !== "admitted")) {
    throw new Error("Owner reconnect workspace history is not fully admitted")
  }
}

function captureAccessSnapshot(value: unknown): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid owner reconnect causal snapshot")
  const snapshot = value as Record<string, unknown>
  const document = snapshot.document
  const bytes = document instanceof Uint8Array ? document
    : Array.isArray(document) && document.every(item => Number.isInteger(item) && item >= 0 && item <= 255)
      ? Uint8Array.from(document as number[])
      : undefined
  if (!bytes) throw new Error("Owner reconnect causal snapshot has no document bytes")
  return { ...snapshot, document: toBase64Url(bytes) }
}

function restoreAccessSnapshot(value: unknown): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid owner reconnect causal snapshot")
  const snapshot = value as Record<string, unknown>
  if (typeof snapshot.document !== "string") throw new Error("Owner reconnect causal snapshot has no document bytes")
  return { ...snapshot, document: fromBase64Url(snapshot.document) }
}

async function currentIdentityView(profile: LocalProfile, view: IdentityAuthorityView): Promise<VerifiedIdentityAuthorityView> {
  const verified = await verifyIdentityAuthorityView(view)
  if (verified.personId !== profile.identity.personId || verified.identityPublicKey !== profile.identity.publicKey) {
    throw new Error("Owner reconnect Identity authority does not match the current profile")
  }
  return verified
}

function unavailableHistorySource(): OwnerReconnectHistorySource {
  const unavailable = async (): Promise<never> => { throw new Error("Owner reconnect source history reader is unavailable") }
  return { readBaseline: unavailable, readDocument: unavailable, readObject: unavailable }
}

async function publicKeyForDevice(view: VerifiedIdentityAuthorityView, deviceId: string): Promise<string> {
  return authorizeIdentityDataDevice(view, deviceId)
}

async function keyId(publicKey: string): Promise<string> {
  const { publicKeyId } = await import("@meta-uber/mesh-identity")
  return publicKeyId(publicKey)
}

async function digest(value: unknown): Promise<string> {
  return sha256Base64Url(new TextEncoder().encode(canonicalizeJson(value)))
}

function validateSession(session: OwnerReconnectSession, now: number): OwnerReconnectSession {
  if (!session || !session.invitationId || !session.workspaceId || !session.issuerPersonId || !session.issuerDeviceId ||
      !session.issuerPublicKey || !session.issuerEndpoint || !session.secret || !Number.isFinite(now) ||
      !Number.isFinite(Date.parse(session.expiresAt)) || Date.parse(session.expiresAt) <= now) {
    throw new Error("Invalid or expired owner reconnect invitation")
  }
  return session
}

function earlierTime(...times: number[]): string {
  const value = Math.min(...times)
  if (!Number.isFinite(value)) throw new Error("Invalid owner reconnect expiry")
  return new Date(value).toISOString()
}

function randomNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return toBase64Url(bytes)
}

function captureJson<T>(value: T): T {
  try {
    const serialized = JSON.stringify(value)
    if (serialized === undefined) throw new Error("Invalid owner reconnect data")
    return JSON.parse(serialized) as T
  } catch {
    throw new Error("Owner reconnect data must be JSON serializable")
  }
}
