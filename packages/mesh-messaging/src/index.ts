import * as Automerge from "@automerge/automerge"
import {
  canonicalizeJson,
  signEnvelope,
  verifyDeviceCertificateChain,
  verifyEnvelope,
  type DeviceCertificate,
  type LocalProfile,
  type PublicIdentity,
  type SignedEnvelope,
} from "../../mesh-identity/src/index"

export const MESSAGING_SIGNATURE_DOMAIN = "MESH-MESSAGING/1"
export const MAX_MESSAGE_LENGTH = 4_000

export type ConversationRole = "member" | "admin"

export type ConversationGrantPayload = {
  kind: "conversation-grant"
  version: 1
  conversationId: string
  issuerPersonId: string
  issuerDeviceId: string
  memberPersonId: string
  role: ConversationRole
  createdAt: string
}

export type ConversationGrant = SignedEnvelope<ConversationGrantPayload>

export type ConversationParticipant = {
  identity: PublicIdentity
  certificates: DeviceCertificate[]
  grant: ConversationGrant | null
}

export type MessagePayload = {
  kind: "message"
  version: 1
  conversationId: string
  messageId: string
  authorPersonId: string
  authorDeviceId: string
  body: string
  createdAt: string
}

export type Message = SignedEnvelope<MessagePayload>

export type ConversationDocument = {
  kind: "conversation"
  version: 1
  roomKind: "direct" | "group"
  conversationId: string
  title: string
  creatorPersonId: string
  participants: Record<string, ConversationParticipant>
  messages: Record<string, Message>
}

export type Conversation = Automerge.Doc<ConversationDocument>

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

function normalizeTitle(value: string): string {
  const title = value.trim().replace(/\s+/g, " ")
  if (!title || [...title].length > 120) throw new Error("Conversation title must contain 1–120 characters")
  return title
}

function normalizeBody(value: string): string {
  const body = value.trim()
  if (!body || [...body].length > MAX_MESSAGE_LENGTH) {
    throw new Error(`Message must contain 1–${MAX_MESSAGE_LENGTH.toLocaleString()} characters`)
  }
  return body
}

function profileParticipant(profile: LocalProfile, grant: ConversationGrant | null): ConversationParticipant {
  return { identity: clone(profile.identity), certificates: [clone(profile.certificate)], grant: clone(grant) }
}

export function createConversation(
  profile: LocalProfile,
  title: string,
  conversationId: string = crypto.randomUUID(),
  roomKind: "direct" | "group" = "group",
): Conversation {
  let doc = Automerge.init<ConversationDocument>()
  doc = Automerge.change(doc, { message: "Create conversation" }, draft => {
    draft.kind = "conversation"
    draft.version = 1
    draft.roomKind = roomKind
    draft.conversationId = conversationId
    draft.title = normalizeTitle(title)
    draft.creatorPersonId = profile.identity.personId
    draft.participants = { [profile.identity.personId]: profileParticipant(profile, null) }
    draft.messages = {}
  })
  return doc
}

export async function addParticipantDeviceCertificate(
  doc: Conversation,
  profile: LocalProfile,
): Promise<Conversation> {
  const participant = doc.participants[profile.identity.personId]
  if (!participant) throw new Error("Device owner is not a participant")
  if (participant.identity.publicKey !== profile.identity.publicKey) throw new Error("Participant identity does not match")
  await verifyDeviceCertificateChain(profile.identity, profile.device.deviceId, [profile.certificate])
  if (participant.certificates.some(value => value.payload.deviceId === profile.device.deviceId)) return doc
  return Automerge.change(doc, { message: "Add participant device" }, draft => {
    draft.participants[profile.identity.personId].certificates.push(clone(profile.certificate))
  })
}

export async function createConversationGrant(
  issuer: LocalProfile,
  conversationId: string,
  memberPersonId: string,
  role: ConversationRole = "member",
  now = Date.now(),
): Promise<ConversationGrant> {
  return signEnvelope(issuer.privateKeys.devicePrivateKey, {
    kind: "conversation-grant",
    version: 1,
    conversationId,
    issuerPersonId: issuer.identity.personId,
    issuerDeviceId: issuer.device.deviceId,
    memberPersonId,
    role,
    createdAt: new Date(now).toISOString(),
  }, issuer.device.deviceId, MESSAGING_SIGNATURE_DOMAIN)
}

async function verifyGrant(doc: ConversationDocument, participant: ConversationParticipant): Promise<void> {
  const grant = participant.grant
  if (!grant) throw new Error("Participant grant missing")
  const payload = grant.payload
  if (payload.kind !== "conversation-grant" || payload.version !== 1 ||
    payload.conversationId !== doc.conversationId || payload.memberPersonId !== participant.identity.personId ||
    grant.signerKeyId !== payload.issuerDeviceId || !["member", "admin"].includes(payload.role)) {
    throw new Error("Invalid participant grant")
  }
  const issuer = doc.participants[payload.issuerPersonId]
  if (!issuer || (payload.issuerPersonId !== doc.creatorPersonId && issuer.grant?.payload.role !== "admin")) {
    throw new Error("Participant grant issuer is not an admin")
  }
  const key = await verifyDeviceCertificateChain(issuer.identity, payload.issuerDeviceId, issuer.certificates)
  if (!await verifyEnvelope(grant, key, MESSAGING_SIGNATURE_DOMAIN)) throw new Error("Invalid participant grant signature")
}

export async function addConversationParticipant(
  doc: Conversation,
  participant: Omit<ConversationParticipant, "grant">,
  grant: ConversationGrant,
): Promise<Conversation> {
  const record: ConversationParticipant = { ...clone(participant), grant: clone(grant) }
  const probe = clone(doc) as ConversationDocument
  probe.participants[participant.identity.personId] = record
  await verifyGrant(probe, record)
  return Automerge.change(doc, { message: "Add conversation participant" }, draft => {
    draft.participants[participant.identity.personId] = record
  })
}

export async function createMessage(
  profile: LocalProfile,
  conversationId: string,
  body: string,
  options: { now?: number; messageId?: string } = {},
): Promise<Message> {
  return signEnvelope(profile.privateKeys.devicePrivateKey, {
    kind: "message",
    version: 1,
    conversationId,
    messageId: options.messageId ?? crypto.randomUUID(),
    authorPersonId: profile.identity.personId,
    authorDeviceId: profile.device.deviceId,
    body: normalizeBody(body),
    createdAt: new Date(options.now ?? Date.now()).toISOString(),
  }, profile.device.deviceId, MESSAGING_SIGNATURE_DOMAIN)
}

async function verifyMessage(doc: ConversationDocument, message: Message, now: number): Promise<void> {
  const payload = message?.payload
  if (!payload || payload.kind !== "message" || payload.version !== 1 ||
    payload.conversationId !== doc.conversationId || !payload.messageId ||
    message.signerKeyId !== payload.authorDeviceId || normalizeBody(payload.body) !== payload.body) {
    throw new Error("Invalid message")
  }
  const timestamp = Date.parse(payload.createdAt)
  if (!Number.isFinite(timestamp) || timestamp > now + 5 * 60 * 1000) throw new Error("Invalid message timestamp")
  const author = doc.participants[payload.authorPersonId]
  if (!author) throw new Error("Message author is not a participant")
  const key = await verifyDeviceCertificateChain(author.identity, payload.authorDeviceId, author.certificates)
  if (!await verifyEnvelope(message, key, MESSAGING_SIGNATURE_DOMAIN)) throw new Error("Invalid message signature")
}

export async function appendMessage(doc: Conversation, message: Message, now = Date.now()): Promise<Conversation> {
  await verifyConversation(doc, now)
  await verifyMessage(doc, message, now)
  const existing = doc.messages[message.payload.messageId]
  if (existing) {
    if (canonicalizeJson(existing) !== canonicalizeJson(message)) throw new Error("Message id already exists")
    return doc
  }
  return Automerge.change(doc, { message: "Append message" }, draft => {
    draft.messages[message.payload.messageId] = clone(message)
  })
}

export async function verifyConversation(doc: Conversation, now = Date.now()): Promise<Conversation> {
  if (!doc || doc.kind !== "conversation" || doc.version !== 1 ||
    !["direct", "group"].includes(doc.roomKind) || !doc.conversationId ||
    normalizeTitle(doc.title) !== doc.title || !doc.participants || !doc.messages) throw new Error("Invalid conversation")
  const creator = doc.participants[doc.creatorPersonId]
  if (!creator || creator.grant !== null) throw new Error("Invalid conversation creator")
  await verifyDeviceCertificateChain(creator.identity, creator.certificates[0]?.payload.deviceId, creator.certificates)
  for (const [personId, participant] of Object.entries(doc.participants)) {
    if (participant.identity.personId !== personId) throw new Error("Invalid participant id")
    if (personId !== doc.creatorPersonId) await verifyGrant(doc, participant)
  }
  for (const [messageId, message] of Object.entries(doc.messages)) {
    if (message.payload.messageId !== messageId) throw new Error("Invalid message id")
    await verifyMessage(doc, message, now)
  }
  return doc
}

export async function mergeConversations(local: Conversation, remoteBytes: Uint8Array, now = Date.now()): Promise<Conversation> {
  const remote = Automerge.load<ConversationDocument>(remoteBytes)
  if (remote.conversationId !== local.conversationId || remote.creatorPersonId !== local.creatorPersonId) {
    throw new Error("Conversation does not match")
  }
  const candidate = Automerge.merge(Automerge.clone(local), remote)
  await verifyConversation(candidate, now)
  return candidate
}

export const saveConversation = (doc: Conversation) => Automerge.save(doc)
export const loadConversation = (bytes: Uint8Array) => Automerge.load<ConversationDocument>(bytes)

export function conversationMessages(doc: Conversation): Message[] {
  return Object.values(doc.messages).sort((a, b) =>
    a.payload.createdAt.localeCompare(b.payload.createdAt) || a.payload.messageId.localeCompare(b.payload.messageId))
}
