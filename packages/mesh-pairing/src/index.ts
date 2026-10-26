export const pairingVersion = "0.0.1"
export const protocolVersion = 1

export type PairingInvite = {
  version: string
  endpoint: string
  secret: string
}

export type DeviceEnrollmentInvitation = {
  version: 1
  kind: "device-enrollment"
  invitationId: string
  issuerPersonId: string
  issuerDeviceId: string
  issuerPublicKey: string
  issuerEndpoint: string
  issuerRelayUrl?: string
  createdAt: string
  expiresAt: string
  secret: string
}

export type WorkspaceItem = {
  id: string
  title: string
}

export type WorkspaceJoinInvitation = {
  version: 1
  kind: "workspace-join"
  invitationId: string
  issuerPersonId: string
  issuerDeviceId: string
  issuerPublicKey: string
  issuerEndpoint: string
  workspaceId: string
  workspaceTitle: string
  workspaces: WorkspaceItem[]
  role: "editor" | "visitor"
  createdAt: string
  expiresAt: string
  secret: string
}

/** Rendezvous only. Workspace access and content are exchanged only after owner proof. */
export type OwnerReconnectInvitation = {
  version: 1
  kind: "owner-reconnect"
  invitationId: string
  issuerPersonId: string
  issuerDeviceId: string
  issuerPublicKey: string
  issuerEndpoint: string
  issuerRelayUrl?: string
  workspaceId: string
  createdAt: string
  expiresAt: string
  secret: string
}

export type ScopedInvitation = DeviceEnrollmentInvitation | WorkspaceJoinInvitation | OwnerReconnectInvitation

const pairingFrameTypes = [
  "sync-request", "sync-response", "sync-ack", "sync-update", "sync-heartbeat", "sync-heartbeat-ack",
  "enroll-request", "enroll-approved", "enroll-rejected", "enroll-rejected-ack", "enroll-ack", "enroll-complete",
  "workspace-join-request", "workspace-join-response", "workspace-join-rejected-ack",
  "mesh-handshake-request", "mesh-handshake-response", "mesh-handoff-request", "mesh-handoff-ready", "mesh-handoff-confirmed",
  "mesh-automerge-sync", "mesh-control-sync", "mesh-owner-workspace-offer", "mesh-owner-reconnect-v1",
  "mesh-iroh-gossip", "mesh-durable-batch", "mesh-durable-ack",
  "mesh-blob-request-v1", "mesh-blob-response-v1", "mesh-blob-error-v1",
  "mesh-proof-request-v1", "mesh-proof-page-v1",
] as const

export type PairingFrameType = typeof pairingFrameTypes[number]

export class PairingError extends Error {}

export type PairingCodec = {
  encode(type: string, secret: string, bytes: Uint8Array): Uint8Array
  inspect(frame: Uint8Array): unknown
  decode(frame: Uint8Array, expectedType: string, expectedSecret: string): Uint8Array
}

let pairingCodec: PairingCodec | undefined

export function installPairingCodec(codec: PairingCodec | undefined): () => void {
  const previous = pairingCodec
  pairingCodec = codec
  return () => { pairingCodec = previous }
}

function pairingCodecError(error: unknown): PairingError {
  const message = (error instanceof Error ? error.message : String(error)).replace(/^Error:\s*/, "")
  return new PairingError(message)
}

function requiredPairingCodec(): PairingCodec {
  if (!pairingCodec) throw new PairingError("Rust pairing codec is not installed")
  return pairingCodec
}

export function encodeBase64Url(bytes: Uint8Array) {
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")
}

export function createPairingSecret(random = crypto.getRandomValues.bind(crypto)) {
  const bytes = new Uint8Array(32)
  random(bytes)
  return encodeBase64Url(bytes)
}

export function createPairingInvite(endpoint: string, secret: string): PairingInvite {
  return { version: pairingVersion, endpoint, secret }
}

export function pairingInviteUrl(origin: string, invite: PairingInvite) {
  const url = new URL("/pair", origin)
  url.hash = new URLSearchParams({ v: invite.version, endpoint: invite.endpoint, secret: invite.secret }).toString()
  return url.toString()
}

export function parsePairingInvite(raw: string): PairingInvite {
  let url: URL
  try {
    url = new URL(raw.trim())
  } catch {
    throw new PairingError("Invalid pairing link")
  }

  const params = url.protocol === "match:" && url.hostname === "pair"
    ? url.searchParams
    : url.pathname.replace(/\/$/, "") === "/pair" && url.hash
      ? new URLSearchParams(url.hash.slice(1))
      : undefined

  if (!params) throw new PairingError("Invalid pairing link")
  const version = params.get("v") ?? ""
  const endpoint = params.get("endpoint") ?? ""
  const secret = params.get("secret") ?? ""
  if (version !== pairingVersion || !endpoint || !secret) throw new PairingError("Invalid pairing link")
  return { version, endpoint, secret }
}

export function createDeviceEnrollmentInvite(
  endpoint: string,
  secret: string,
  profile: { identity: { personId: string }; device: { deviceId: string; publicKey: string } },
  now = Date.now(),
  issuerRelayUrl?: string,
): DeviceEnrollmentInvitation {
  if (issuerRelayUrl !== undefined) validateRelayUrl(issuerRelayUrl)
  return {
    version: 1,
    kind: "device-enrollment",
    invitationId: crypto.randomUUID(),
    issuerPersonId: profile.identity.personId,
    issuerDeviceId: profile.device.deviceId,
    issuerPublicKey: profile.device.publicKey,
    issuerEndpoint: endpoint,
    ...(issuerRelayUrl ? { issuerRelayUrl } : {}),
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 10 * 60 * 1000).toISOString(),
    secret,
  }
}

export function createWorkspaceJoinInvite(
  endpoint: string,
  secret: string,
  profile: { identity: { personId: string }; device: { deviceId: string; publicKey: string } },
  workspaces: WorkspaceItem[],
  options: { now?: number; role?: WorkspaceJoinInvitation["role"] } = {},
): WorkspaceJoinInvitation {
  if (workspaces.length === 0) {
    throw new PairingError("At least one workspace must be selected")
  }

  const effectiveNow = options.now ?? Date.now()
  const primaryWs = workspaces[0]

  return {
    version: 1,
    kind: "workspace-join",
    invitationId: crypto.randomUUID(),
    issuerPersonId: profile.identity.personId,
    issuerDeviceId: profile.device.deviceId,
    issuerPublicKey: profile.device.publicKey,
    issuerEndpoint: endpoint,
    workspaceId: primaryWs.id,
    workspaceTitle: primaryWs.title,
    workspaces,
    role: options.role ?? "visitor",
    createdAt: new Date(effectiveNow).toISOString(),
    expiresAt: new Date(effectiveNow + 10 * 60 * 1000).toISOString(),
    secret,
  }
}

export function createOwnerReconnectInvite(
  endpoint: string,
  secret: string,
  profile: { identity: { personId: string }; device: { deviceId: string; publicKey: string } },
  workspaceId: string,
  options: { now?: number; lifetimeMs?: number; relayUrl?: string } = {},
): OwnerReconnectInvitation {
  if (options.relayUrl !== undefined) validateRelayUrl(options.relayUrl)
  const effectiveNow = options.now ?? Date.now()
  const lifetimeMs = options.lifetimeMs ?? 10 * 60 * 1000
  if (!endpoint || !secret || !workspaceId || !Number.isSafeInteger(effectiveNow) ||
      !Number.isSafeInteger(lifetimeMs) || lifetimeMs <= 0 || lifetimeMs > 60 * 60 * 1000) {
    throw new PairingError("Invalid owner reconnect invitation")
  }
  return {
    version: 1,
    kind: "owner-reconnect",
    invitationId: crypto.randomUUID(),
    issuerPersonId: profile.identity.personId,
    issuerDeviceId: profile.device.deviceId,
    issuerPublicKey: profile.device.publicKey,
    issuerEndpoint: endpoint,
    ...(options.relayUrl ? { issuerRelayUrl: options.relayUrl } : {}),
    workspaceId,
    createdAt: new Date(effectiveNow).toISOString(),
    expiresAt: new Date(effectiveNow + lifetimeMs).toISOString(),
    secret,
  }
}

export function invitationUrl(origin: string, invite: ScopedInvitation): string {
  const url = new URL("/pair", origin)
  const params = new URLSearchParams()
  params.set("v", "1")
  params.set("kind", invite.kind)
  params.set("invitationId", invite.invitationId)
  params.set("issuerPersonId", invite.issuerPersonId)
  params.set("issuerDeviceId", invite.issuerDeviceId)
  params.set("issuerPublicKey", invite.issuerPublicKey)
  params.set("endpoint", invite.issuerEndpoint)
  if (invite.kind === "device-enrollment" && invite.issuerRelayUrl) {
    params.set("issuerRelayUrl", invite.issuerRelayUrl)
  }
  params.set("createdAt", invite.createdAt)
  params.set("expiresAt", invite.expiresAt)
  params.set("secret", invite.secret)
  if (invite.kind === "workspace-join") {
    params.set("workspaceId", invite.workspaceId)
    params.set("workspaceTitle", invite.workspaceTitle)
    params.set("role", invite.role)
    if (invite.workspaces && invite.workspaces.length > 0) {
      params.set("workspaceIds", invite.workspaces.map((w) => w.id).join(","))
      params.set("workspaceTitles", invite.workspaces.map((w) => encodeURIComponent(w.title)).join(","))
    }
  } else if (invite.kind === "owner-reconnect") {
    if (invite.issuerRelayUrl) params.set("issuerRelayUrl", invite.issuerRelayUrl)
    params.set("workspaceId", invite.workspaceId)
  }
  url.hash = params.toString()
  return url.toString()
}

type InvitationEnvelope = {
  version: 1
  invitationId: string
  issuerPersonId: string
  issuerDeviceId: string
  issuerPublicKey: string
  issuerEndpoint: string
  issuerRelayUrl?: string
  createdAt: string
  expiresAt: string
  secret: string
}

type InvitationDecoder = (params: URLSearchParams, envelope: InvitationEnvelope) => ScopedInvitation

const invitationDecoders = new Map<string, InvitationDecoder>([
  ["device-enrollment", decodeDeviceEnrollment],
  ["workspace-join", decodeWorkspaceJoin],
  ["owner-reconnect", decodeOwnerReconnect],
])

export function parseInvitation(raw: string, now = Date.now()): ScopedInvitation {
  const params = invitationParams(raw)
  validateInvitationVersion(params)
  const envelope = readInvitationEnvelope(params, now)
  const kind = params.get("kind") ?? ""
  const decoder = invitationDecoders.get(kind)
  if (!decoder) throw new PairingError("Invalid pairing link")
  return decoder(params, envelope)
}

function invitationParams(raw: string) {
  let url: URL
  try {
    url = new URL(raw.trim(), "http://localhost")
  } catch {
    throw new PairingError("Invalid pairing link")
  }

  const params = new URLSearchParams(url.hash.startsWith("#") ? url.hash.slice(1) : url.hash)
  const singularFields = ["v", "kind", "invitationId", "issuerPersonId", "issuerDeviceId", "issuerPublicKey", "endpoint", "issuerRelayUrl", "createdAt", "expiresAt", "secret", "workspaceId", "workspaceTitle", "workspaceIds", "workspaceTitles", "role"]
  if (singularFields.some(field => params.getAll(field).length > 1)) throw new PairingError("Invalid pairing link")
  return params
}

function validateInvitationVersion(params: URLSearchParams) {
  const v = params.get("v")
  if (!params.get("secret")) {
    throw new PairingError("This pairing link is invalid.")
  }
  if (v === "0.0.1" || !params.has("kind")) {
    throw new PairingError("This sync link was created by an older version of Match. Please create a new invitation.")
  }
  if (v !== "1") throw new PairingError("Invalid pairing link")
}

function readInvitationEnvelope(params: URLSearchParams, now: number): InvitationEnvelope {
  const invitationId = params.get("invitationId") || ""
  const secret = params.get("secret") || ""
  const endpoint = params.get("endpoint") || ""
  const issuerPersonId = params.get("issuerPersonId") || ""
  const issuerDeviceId = params.get("issuerDeviceId") || ""
  const issuerPublicKey = params.get("issuerPublicKey") || ""
  const issuerRelayUrl = params.get("issuerRelayUrl") || undefined
  if (!invitationId || !endpoint || !issuerPersonId || !issuerDeviceId || !issuerPublicKey) {
    throw new PairingError("Invalid pairing link")
  }
  if (issuerRelayUrl !== undefined) validateRelayUrl(issuerRelayUrl)

  const createdAt = params.get("createdAt") || ""
  const expiresAt = params.get("expiresAt") || ""
  const createdTime = Date.parse(createdAt)
  const expiryTime = Date.parse(expiresAt)
  if (Number.isNaN(createdTime) || Number.isNaN(expiryTime) || expiryTime <= createdTime) {
    throw new PairingError("Invalid pairing link")
  }
  if (expiryTime <= now) throw new PairingError("This invitation has expired.")

  return {
    version: 1,
    invitationId,
    issuerPersonId,
    issuerDeviceId,
    issuerPublicKey,
    issuerEndpoint: endpoint,
    ...(issuerRelayUrl ? { issuerRelayUrl } : {}),
    createdAt,
    expiresAt,
    secret,
  }
}

function decodeDeviceEnrollment(params: URLSearchParams, envelope: InvitationEnvelope): DeviceEnrollmentInvitation {
  const workspaceFields = ["workspaceId", "workspaceTitle", "workspaceIds", "workspaceTitles", "role"]
  if (workspaceFields.some(field => params.has(field)) || params.has("issuerLocalCustomAddr")) {
    throw new PairingError("Invalid invitation: wrong-kind fields present on device-enrollment")
  }
  return { ...envelope, kind: "device-enrollment" }
}

function decodeWorkspaceJoin(params: URLSearchParams, envelope: InvitationEnvelope): WorkspaceJoinInvitation {
  if (params.has("issuerRelayUrl") || params.has("issuerLocalCustomAddr")) {
    throw new PairingError("Invalid invitation: wrong-kind fields present on workspace-join")
  }
  const workspaceId = params.get("workspaceId") ?? ""
  const role = params.get("role")
  if (!workspaceId || (role !== "editor" && role !== "visitor")) {
    throw new PairingError("Invalid invitation: missing workspace or valid role on workspace-join")
  }

  const workspaceTitle = params.get("workspaceTitle") || "Workspace"
  const workspaces = readWorkspaceList(params, workspaceId, workspaceTitle)
  return {
    ...envelope,
    kind: "workspace-join",
    workspaceId: workspaces[0].id,
    workspaceTitle: workspaces[0].title,
    workspaces,
    role,
  }
}

function decodeOwnerReconnect(params: URLSearchParams, envelope: InvitationEnvelope): OwnerReconnectInvitation {
  const allowed = new Set(["v", "kind", "invitationId", "issuerPersonId", "issuerDeviceId", "issuerPublicKey",
    "endpoint", "createdAt", "expiresAt", "secret", "workspaceId", "issuerRelayUrl"])
  if ([...params.keys()].some(key => !allowed.has(key)) ||
      ["workspaceTitle", "workspaceIds", "workspaceTitles", "role", "issuerLocalCustomAddr"]
        .some(key => params.has(key))) {
    throw new PairingError("Invalid invitation: wrong-kind fields present on owner-reconnect")
  }
  const workspaceId = params.get("workspaceId") ?? ""
  if (!workspaceId) throw new PairingError("Invalid invitation: missing workspace on owner-reconnect")
  const issuerRelayUrl = params.get("issuerRelayUrl") || undefined
  if (issuerRelayUrl !== undefined) validateRelayUrl(issuerRelayUrl)
  return { ...envelope, ...(issuerRelayUrl ? { issuerRelayUrl } : {}), kind: "owner-reconnect", workspaceId }
}

function validateRelayUrl(value: string): void {
  let url: URL
  try { url = new URL(value) }
  catch { throw new PairingError("Invalid browser relay address") }
  const localHttp = url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname)
  if (value.length > 2048 || (url.protocol !== "https:" && !localHttp) || url.username || url.password || url.hash) {
    throw new PairingError("Invalid browser relay address")
  }
}

function readWorkspaceList(params: URLSearchParams, primaryId: string, primaryTitle: string): WorkspaceItem[] {
  if (!params.has("workspaceIds")) {
    if (params.has("workspaceTitles")) throw new PairingError("Invalid pairing link")
    return [{ id: primaryId, title: primaryTitle }]
  }

  const rawIds = params.get("workspaceIds") ?? ""
  const ids = rawIds.split(",").map(id => id.trim())
  if (ids.some(id => !id) || ids[0] !== primaryId || new Set(ids).size !== ids.length) {
    throw new PairingError("Invalid pairing link")
  }
  const titles = decodeWorkspaceTitles(params.get("workspaceTitles"))
  if (params.has("workspaceTitles") && titles.length !== ids.length) {
    throw new PairingError("Invalid pairing link")
  }
  const workspaces = ids.map((id, index) => ({
    id,
    title: titles[index] || (id === primaryId ? primaryTitle : "Workspace"),
  }))
  return workspaces.length ? workspaces : [{ id: primaryId, title: primaryTitle }]
}

function decodeWorkspaceTitles(rawTitles: string | null): string[] {
  if (!rawTitles) return []
  try {
    return rawTitles.split(",").map(title => decodeURIComponent(title.trim()))
  } catch {
    throw new PairingError("Invalid pairing link")
  }
}

export function encodePairingFrame(type: PairingFrameType, secret: string, bytes: Uint8Array) {
  try { return requiredPairingCodec().encode(type, secret, bytes) }
  catch (error) { throw pairingCodecError(error) }
}

export function inspectPairingFrame(frame: Uint8Array): { type: PairingFrameType; secret: string } {
  try {
    const header = requiredPairingCodec().inspect(frame) as { type?: string; secret?: string }
    if (!header || !pairingFrameTypes.includes((header.type ?? "") as PairingFrameType) || !header.secret) {
      throw new PairingError("Pairing frame invalid")
    }
    return { type: header.type as PairingFrameType, secret: header.secret }
  } catch (error) { throw pairingCodecError(error) }
}

export function decodePairingFrame(frame: Uint8Array, expectedType: PairingFrameType, expectedSecret: string) {
  try { return requiredPairingCodec().decode(frame, expectedType, expectedSecret) }
  catch (error) { throw pairingCodecError(error) }
}
