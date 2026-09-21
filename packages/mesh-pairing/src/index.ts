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

export type ScopedInvitation = DeviceEnrollmentInvitation | WorkspaceJoinInvitation

const pairingFrameTypes = [
  "sync-request", "sync-response", "sync-ack", "sync-update", "sync-heartbeat", "sync-heartbeat-ack",
  "enroll-request", "enroll-approved", "enroll-ack", "enroll-complete",
  "workspace-join-request", "workspace-join-response",
  "mesh-handshake-request", "mesh-handshake-response", "mesh-handoff-request", "mesh-handoff-ready", "mesh-handoff-confirmed",
  "mesh-automerge-sync", "mesh-control-sync", "mesh-gossip", "mesh-iroh-gossip", "mesh-durable-batch", "mesh-durable-ack",
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
  now = Date.now()
): DeviceEnrollmentInvitation {
  return {
    version: 1,
    kind: "device-enrollment",
    invitationId: crypto.randomUUID(),
    issuerPersonId: profile.identity.personId,
    issuerDeviceId: profile.device.deviceId,
    issuerPublicKey: profile.device.publicKey,
    issuerEndpoint: endpoint,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 10 * 60 * 1000).toISOString(),
    secret,
  }
}

export function createWorkspaceJoinInvite(
  endpoint: string,
  secret: string,
  profile: { identity: { personId: string }; device: { deviceId: string; publicKey: string } },
  workspaceOrWorkspaces: string | WorkspaceItem[] | WorkspaceItem,
  workspaceTitleOrNow?: string | number,
  now = Date.now()
): WorkspaceJoinInvitation {
  let workspaces: WorkspaceItem[] = []
  let effectiveNow = now

  if (typeof workspaceOrWorkspaces === "string") {
    const title = typeof workspaceTitleOrNow === "string" ? workspaceTitleOrNow : "Workspace"
    workspaces = [{ id: workspaceOrWorkspaces, title }]
  } else if (Array.isArray(workspaceOrWorkspaces)) {
    workspaces = workspaceOrWorkspaces
    if (typeof workspaceTitleOrNow === "number") {
      effectiveNow = workspaceTitleOrNow
    }
  } else if (workspaceOrWorkspaces && typeof workspaceOrWorkspaces === "object") {
    workspaces = [workspaceOrWorkspaces]
    if (typeof workspaceTitleOrNow === "number") {
      effectiveNow = workspaceTitleOrNow
    }
  }

  if (workspaces.length === 0) {
    throw new PairingError("At least one workspace must be selected")
  }

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
    role: "visitor",
    createdAt: new Date(effectiveNow).toISOString(),
    expiresAt: new Date(effectiveNow + 10 * 60 * 1000).toISOString(),
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
  }
  url.hash = params.toString()
  return url.toString()
}

export function parseInvitation(raw: string, now = Date.now()): ScopedInvitation {
  let url: URL
  try {
    url = new URL(raw.trim(), "http://localhost")
  } catch {
    throw new PairingError("Invalid pairing link")
  }

  const hashContent = url.hash.startsWith("#") ? url.hash.slice(1) : url.hash
  const params = new URLSearchParams(hashContent)

  const v = params.get("v")
  const secret = params.get("secret") || ""
  if (!secret) {
    throw new PairingError("This pairing link is invalid.")
  }

  if (v === "0.0.1" || !params.has("kind")) {
    throw new PairingError("This sync link was created by an older version of Match. Please create a new invitation.")
  }
  if (v !== "1") {
    throw new PairingError("Invalid pairing link")
  }

  const kind = params.get("kind")
  const invitationId = params.get("invitationId") || ""
  const issuerPersonId = params.get("issuerPersonId") || ""
  const issuerDeviceId = params.get("issuerDeviceId") || ""
  const issuerPublicKey = params.get("issuerPublicKey") || ""
  const endpoint = params.get("endpoint") || ""
  const createdAt = params.get("createdAt") || ""
  const expiresAt = params.get("expiresAt") || ""

  if (!invitationId || !secret || !endpoint) {
    throw new PairingError("Invalid pairing link")
  }

  if (expiresAt) {
    const expiryTime = Date.parse(expiresAt)
    if (!Number.isNaN(expiryTime) && expiryTime <= now) {
      throw new PairingError("This invitation has expired.")
    }
  }

  if (kind === "device-enrollment") {
    if (params.has("workspaceId") || params.has("role") || params.has("workspaceTitle")) {
      throw new PairingError("Invalid invitation: wrong-kind fields present on device-enrollment")
    }
    return {
      version: 1,
      kind: "device-enrollment",
      invitationId,
      issuerPersonId,
      issuerDeviceId,
      issuerPublicKey,
      issuerEndpoint: endpoint,
      createdAt,
      expiresAt,
      secret,
    }
  }

  if (kind === "workspace-join") {
    const workspaceId = params.get("workspaceId")
    const workspaceTitle = params.get("workspaceTitle") || "Workspace"
    const role = params.get("role")
    if (!workspaceId || (role !== "editor" && role !== "visitor")) {
      throw new PairingError("Invalid invitation: missing workspace or valid role on workspace-join")
    }

    const rawIds = params.get("workspaceIds")
    const rawTitles = params.get("workspaceTitles")
    let workspaces: WorkspaceItem[] = []
    if (rawIds) {
      const ids = rawIds.split(",").map((s) => s.trim()).filter(Boolean)
      const titles = rawTitles ? rawTitles.split(",").map((t) => decodeURIComponent(t.trim())) : []
      workspaces = ids.map((id, index) => ({
        id,
        title: titles[index] || (id === workspaceId ? workspaceTitle : "Workspace"),
      }))
    }
    if (workspaces.length === 0) {
      workspaces = [{ id: workspaceId, title: workspaceTitle }]
    }

    return {
      version: 1,
      kind: "workspace-join",
      invitationId,
      issuerPersonId,
      issuerDeviceId,
      issuerPublicKey,
      issuerEndpoint: endpoint,
      workspaceId: workspaces[0].id,
      workspaceTitle: workspaces[0].title,
      workspaces,
      role,
      createdAt,
      expiresAt,
      secret,
    }
  }

  throw new PairingError("Invalid pairing link")
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
