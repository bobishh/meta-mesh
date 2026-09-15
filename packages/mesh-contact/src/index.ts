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
import * as Automerge from "@automerge/automerge"

export const CONTACT_SIGNATURE_DOMAIN = "META-MESH/1"
export const MAX_CONTACT_MESSAGE_LENGTH = 2_000
export const MAX_CONTACT_RECORD_BYTES = 24 * 1024
export const MAX_CONTACT_AGE_MS = 60 * 60 * 1000
export const MAX_FUTURE_TOLERANCE_MS = 5 * 60 * 1000

export type ContactRequestPayload = {
  kind: "contact-request"
  version: 1
  requestId: string
  personId: string
  deviceId: string
  displayName: string
  firstMessage: string
  createdAt: string
}

export type ContactRequest = {
  signed: SignedEnvelope<ContactRequestPayload>
  identity: PublicIdentity
  certificates: DeviceCertificate[]
}

export type ContactDecisionPayload = {
  kind: "contact-decision"
  version: 1
  requestId: string
  visitorPersonId: string
  ownerPersonId: string
  ownerDeviceId: string
  accepted: boolean
  channelId?: string
  channelSecret?: string
  createdAt: string
}

export type ContactDecision = {
  signed: SignedEnvelope<ContactDecisionPayload>
  identity: PublicIdentity
  certificates: DeviceCertificate[]
}

export type ContactMessagePayload = {
  kind: "contact-message"
  version: 1
  channelId: string
  messageId: string
  authorPersonId: string
  authorDeviceId: string
  body: string
  createdAt: string
}

export type ContactMessage = SignedEnvelope<ContactMessagePayload>

export type ContactChannelDocument = {
  kind: "contact-channel"
  version: 1
  channelId: string
  ownerPersonId: string
  visitorPersonId: string
  request: ContactRequest
  decision: ContactDecision
  ownerCertificates?: DeviceCertificate[]
  visitorCertificates?: DeviceCertificate[]
  messages: Record<string, ContactMessage>
}

export type ContactChannel = Automerge.Doc<ContactChannelDocument>

export type CreateContactRequestInput = {
  firstMessage: string
  displayName?: string
  now?: number
  requestId?: string
  certificates?: DeviceCertificate[]
}

function byteLength(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength
}

export function normalizeMessage(value: string): string {
  const message = value.trim()
  if (!message || [...message].length > MAX_CONTACT_MESSAGE_LENGTH) {
    throw new Error(`Message must contain 1–${MAX_CONTACT_MESSAGE_LENGTH.toLocaleString()} characters`)
  }
  return message
}

function normalizeName(value: string): string {
  const name = value.trim().replace(/\s+/g, " ")
  if (!name || [...name].length > 80) throw new Error("Name must contain 1–80 characters")
  return name
}

export async function verifyDevice(
  identity: PublicIdentity,
  deviceId: string,
  certificates: DeviceCertificate[],
): Promise<string> {
  return verifyDeviceCertificateChain(identity, deviceId, certificates)
}

function validateTimestamp(value: string, now: number) {
  const timestamp = Date.parse(value)
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error("Invalid request timestamp")
  }
  if (timestamp > now + MAX_FUTURE_TOLERANCE_MS) throw new Error("Request timestamp is in the future")
  if (timestamp < now - MAX_CONTACT_AGE_MS) throw new Error("Contact request has expired")
}

export async function createContactRequest(
  profile: LocalProfile,
  input: CreateContactRequestInput,
): Promise<ContactRequest> {
  const common = {
    kind: "contact-request",
    requestId: input.requestId ?? crypto.randomUUID(),
    personId: profile.identity.personId,
    deviceId: profile.device.deviceId,
    displayName: normalizeName(input.displayName ?? profile.identity.displayName),
    firstMessage: normalizeMessage(input.firstMessage),
    createdAt: new Date(input.now ?? Date.now()).toISOString(),
  } as const
  const payload: ContactRequestPayload = { ...common, version: 1 }
  return {
    signed: await signEnvelope(
      profile.privateKeys.devicePrivateKey,
      payload,
      profile.device.deviceId,
      CONTACT_SIGNATURE_DOMAIN,
    ),
    identity: profile.identity,
    certificates: input.certificates ?? [profile.certificate],
  }
}

export async function verifyContactRequest(value: unknown, now = Date.now()): Promise<ContactRequest> {
  if (byteLength(value) > MAX_CONTACT_RECORD_BYTES) throw new Error("Contact request too large")
  const request = value as ContactRequest
  const payload = request?.signed?.payload
  if (!payload || payload.kind !== "contact-request" || payload.version !== 1 ||
    typeof payload.requestId !== "string" || !payload.requestId || payload.requestId.length > 128 ||
    typeof payload.personId !== "string" || typeof payload.deviceId !== "string" ||
    typeof payload.displayName !== "string" || normalizeName(payload.displayName) !== payload.displayName ||
    typeof payload.firstMessage !== "string" || normalizeMessage(payload.firstMessage) !== payload.firstMessage ||
    request.signed.signerKeyId !== payload.deviceId ||
    request.identity?.personId !== payload.personId) throw new Error("Invalid contact request")
  validateTimestamp(payload.createdAt, now)
  const deviceKey = await verifyDevice(request.identity, payload.deviceId, request.certificates)
  if (!await verifyEnvelope(request.signed, deviceKey, CONTACT_SIGNATURE_DOMAIN)) {
    throw new Error("Invalid contact request signature")
  }
  return request
}

export async function createContactDecision(
  profile: LocalProfile,
  request: ContactRequest,
  accepted: boolean,
  options: { now?: number; channelId?: string; channelSecret?: string; certificates?: DeviceCertificate[] } = {},
): Promise<ContactDecision> {
  const payload: ContactDecisionPayload = {
    kind: "contact-decision",
    version: 1,
    requestId: request.signed.payload.requestId,
    visitorPersonId: request.signed.payload.personId,
    ownerPersonId: profile.identity.personId,
    ownerDeviceId: profile.device.deviceId,
    accepted,
    channelId: accepted ? options.channelId ?? crypto.randomUUID() : undefined,
    channelSecret: accepted ? options.channelSecret : undefined,
    createdAt: new Date(options.now ?? Date.now()).toISOString(),
  }
  if (accepted && !payload.channelSecret) throw new Error("Accepted contact needs a channel secret")
  return {
    signed: await signEnvelope(
      profile.privateKeys.devicePrivateKey,
      payload,
      profile.device.deviceId,
      CONTACT_SIGNATURE_DOMAIN,
    ),
    identity: profile.identity,
    certificates: options.certificates ?? [profile.certificate],
  }
}

export async function verifyContactDecision(
  value: unknown,
  request: ContactRequest,
  now = Date.now(),
): Promise<ContactDecision> {
  if (byteLength(value) > MAX_CONTACT_RECORD_BYTES) throw new Error("Contact decision too large")
  const decision = value as ContactDecision
  const payload = decision?.signed?.payload
  if (!payload || payload.kind !== "contact-decision" || payload.version !== 1 ||
    payload.requestId !== request.signed.payload.requestId ||
    payload.visitorPersonId !== request.signed.payload.personId ||
    typeof payload.ownerPersonId !== "string" || typeof payload.ownerDeviceId !== "string" ||
    typeof payload.accepted !== "boolean" ||
    (payload.accepted && (!payload.channelId || !payload.channelSecret)) ||
    (!payload.accepted && (payload.channelId !== undefined || payload.channelSecret !== undefined)) ||
    decision.signed.signerKeyId !== payload.ownerDeviceId ||
    decision.identity?.personId !== payload.ownerPersonId) throw new Error("Invalid contact decision")
  validateTimestamp(payload.createdAt, now)
  const deviceKey = await verifyDevice(decision.identity, payload.ownerDeviceId, decision.certificates)
  if (!await verifyEnvelope(decision.signed, deviceKey, CONTACT_SIGNATURE_DOMAIN)) {
    throw new Error("Invalid contact decision signature")
  }
  return decision
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

export async function createContactMessage(
  profile: LocalProfile,
  channelId: string,
  body: string,
  options: { now?: number; messageId?: string } = {},
): Promise<ContactMessage> {
  const payload: ContactMessagePayload = {
    kind: "contact-message",
    version: 1,
    channelId,
    messageId: options.messageId ?? crypto.randomUUID(),
    authorPersonId: profile.identity.personId,
    authorDeviceId: profile.device.deviceId,
    body: normalizeMessage(body),
    createdAt: new Date(options.now ?? Date.now()).toISOString(),
  }
  return signEnvelope(
    profile.privateKeys.devicePrivateKey,
    payload,
    profile.device.deviceId,
    CONTACT_SIGNATURE_DOMAIN,
  )
}

async function verifyContactMessage(
  message: ContactMessage,
  channel: Pick<ContactChannelDocument,
    "channelId" | "ownerPersonId" | "visitorPersonId" | "request" | "decision" |
    "ownerCertificates" | "visitorCertificates">,
  now: number,
): Promise<void> {
  const payload = message?.payload
  if (!payload || payload.kind !== "contact-message" || payload.version !== 1 ||
    payload.channelId !== channel.channelId ||
    typeof payload.messageId !== "string" || !payload.messageId || payload.messageId.length > 128 ||
    (payload.authorPersonId !== channel.ownerPersonId && payload.authorPersonId !== channel.visitorPersonId) ||
    typeof payload.authorDeviceId !== "string" || message.signerKeyId !== payload.authorDeviceId ||
    typeof payload.body !== "string" || normalizeMessage(payload.body) !== payload.body) {
    throw new Error("Invalid contact message")
  }
  const timestamp = Date.parse(payload.createdAt)
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== payload.createdAt ||
    timestamp > now + MAX_FUTURE_TOLERANCE_MS) throw new Error("Invalid message timestamp")

  const owner = payload.authorPersonId === channel.ownerPersonId
  const party = owner ? channel.decision : channel.request
  const certificates = owner
    ? [...party.certificates, ...(channel.ownerCertificates ?? [])]
    : [...party.certificates, ...(channel.visitorCertificates ?? [])]
  const deviceKey = await verifyDevice(party.identity, payload.authorDeviceId, certificates)
  if (!await verifyEnvelope(message, deviceKey, CONTACT_SIGNATURE_DOMAIN)) {
    throw new Error("Invalid contact message signature")
  }
}

export async function createContactChannel(
  requestValue: ContactRequest,
  decisionValue: ContactDecision,
  now = Date.now(),
): Promise<ContactChannel> {
  const request = await verifyContactRequest(requestValue, now)
  const decision = await verifyContactDecision(decisionValue, request, now)
  if (!decision.signed.payload.accepted || !decision.signed.payload.channelId) {
    throw new Error("Only an accepted request can create a channel")
  }
  let doc = Automerge.init<ContactChannelDocument>()
  doc = Automerge.change(doc, { message: "Create contact channel" }, draft => {
    draft.kind = "contact-channel"
    draft.version = 1
    draft.channelId = decision.signed.payload.channelId!
    draft.ownerPersonId = decision.signed.payload.ownerPersonId
    draft.visitorPersonId = request.signed.payload.personId
    draft.request = clone(request)
    draft.decision = clone(decision)
    draft.ownerCertificates = clone(decision.certificates)
    draft.visitorCertificates = clone(request.certificates)
    draft.messages = {}
  })
  return doc
}

export async function addContactParticipantDeviceCertificate(
  doc: ContactChannel,
  identity: PublicIdentity,
  certificate: DeviceCertificate,
): Promise<ContactChannel> {
  const owner = identity.personId === doc.ownerPersonId
  const visitor = identity.personId === doc.visitorPersonId
  if (!owner && !visitor) throw new Error("Certificate owner is not a channel participant")
  const party = owner ? doc.decision : doc.request
  if (party.identity.publicKey !== identity.publicKey) throw new Error("Channel identity does not match")
  await verifyDeviceCertificateChain(identity, certificate.payload.deviceId, [certificate])
  const certificates = owner
    ? [...party.certificates, ...(doc.ownerCertificates ?? [])]
    : [...party.certificates, ...(doc.visitorCertificates ?? [])]
  if (certificates.some(value => value.payload.deviceId === certificate.payload.deviceId)) return doc
  return Automerge.change(doc, { message: "Add participant device" }, draft => {
    const key = owner ? "ownerCertificates" : "visitorCertificates"
    if (!draft[key]) draft[key] = []
    draft[key]!.push(clone(certificate))
  })
}

export async function appendContactMessage(
  doc: ContactChannel,
  message: ContactMessage,
  now = Date.now(),
): Promise<ContactChannel> {
  await verifyContactChannel(doc, now)
  await verifyContactMessage(message, doc, now)
  if (message.payload.messageId in doc.messages) {
    if (canonicalizeJson(doc.messages[message.payload.messageId]) !== canonicalizeJson(message)) {
      throw new Error("Message id already exists")
    }
    return doc
  }
  return Automerge.change(doc, { message: "Append contact message" }, draft => {
    draft.messages[message.payload.messageId] = clone(message)
  })
}

export async function verifyContactChannel(doc: ContactChannel, now = Date.now()): Promise<ContactChannel> {
  if (!doc || doc.kind !== "contact-channel" || doc.version !== 1 ||
    typeof doc.channelId !== "string" || !doc.channelId ||
    typeof doc.ownerPersonId !== "string" || typeof doc.visitorPersonId !== "string" ||
    !doc.request || !doc.decision || !doc.messages || Array.isArray(doc.messages)) {
    throw new Error("Invalid contact channel")
  }
  const requestTime = Date.parse(doc.request.signed.payload.createdAt)
  const decisionTime = Date.parse(doc.decision.signed.payload.createdAt)
  const request = await verifyContactRequest(doc.request, requestTime)
  const decision = await verifyContactDecision(doc.decision, request, decisionTime)
  if (!decision.signed.payload.accepted || decision.signed.payload.channelId !== doc.channelId ||
    decision.signed.payload.ownerPersonId !== doc.ownerPersonId ||
    request.signed.payload.personId !== doc.visitorPersonId) throw new Error("Invalid contact channel binding")
  for (const certificate of doc.ownerCertificates ?? []) {
    await verifyDeviceCertificateChain(decision.identity, certificate.payload.deviceId, [certificate])
  }
  for (const certificate of doc.visitorCertificates ?? []) {
    await verifyDeviceCertificateChain(request.identity, certificate.payload.deviceId, [certificate])
  }
  const entries = Object.entries(doc.messages)
  if (entries.length > 10_000) throw new Error("Contact channel has too many messages")
  for (const [id, message] of entries) {
    if (id !== message.payload.messageId) throw new Error("Invalid contact message id")
    await verifyContactMessage(message, doc, now)
  }
  return doc
}

export async function mergeContactChannels(
  local: ContactChannel,
  remoteBytes: Uint8Array,
  now = Date.now(),
): Promise<ContactChannel> {
  const remote = Automerge.load<ContactChannelDocument>(remoteBytes)
  if (remote.channelId !== local.channelId || remote.ownerPersonId !== local.ownerPersonId ||
    remote.visitorPersonId !== local.visitorPersonId) throw new Error("Contact channel does not match")
  const candidate = Automerge.merge(Automerge.clone(local), remote)
  await verifyContactChannel(candidate, now)
  return candidate
}

export function saveContactChannel(doc: ContactChannel): Uint8Array {
  return Automerge.save(doc)
}

export function loadContactChannel(bytes: Uint8Array): ContactChannel {
  return Automerge.load<ContactChannelDocument>(bytes)
}

export type ContactTimelineEntry = {
  id: string
  authorPersonId: string
  body: string
  createdAt: string
  isJoinRequest: boolean
}

export function contactTimeline(doc: ContactChannel): ContactTimelineEntry[] {
  const first = doc.request.signed.payload
  return [{
    id: first.requestId,
    authorPersonId: first.personId,
    body: first.firstMessage,
    createdAt: first.createdAt,
    isJoinRequest: true,
  }, ...Object.values(doc.messages).map(message => ({
    id: message.payload.messageId,
    authorPersonId: message.payload.authorPersonId,
    body: message.payload.body,
    createdAt: message.payload.createdAt,
    isJoinRequest: false,
  }))].sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id))
}
