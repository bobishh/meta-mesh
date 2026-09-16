import * as Automerge from "@automerge/automerge"
import {
  fromBase64Url,
  signEnvelope,
  toBase64Url,
  verifyDeviceCertificateChain,
  verifyEnvelope,
  type DeviceCertificate,
  type LocalProfile,
  type PublicIdentity,
  type SignedEnvelope,
} from "../../mesh-identity/src/index"
import {
  createSignedDeviceRoute,
  verifySignedDeviceRoute,
  MAX_DEVICE_ROUTE_LIFETIME_MS,
  type SignedDeviceRoute,
} from "../../mesh-replication/src/protocol"

export const CONTACT_CARD_SIGNATURE_DOMAIN = "TWANG-CONTACT-CARD/1"
export const CONTACT_LOCATOR_SIGNATURE_DOMAIN = "TWANG-CONTACT-LOCATOR/1"

export type ContactState = "incoming" | "outgoing" | "accepted" | "blocked"
export type RoomKind = "direct" | "group"

export type Contact = {
  personId: string
  identity: PublicIdentity
  certificates: DeviceCertificate[]
  alias: string
  endpoints: Array<{ deviceId: string; endpoint: string }>
  state: ContactState
  createdAt: string
  updatedAt: string
}

export type LegacyContactCard = {
  kind: "twang-contact"
  version: 1
  identity: PublicIdentity
  certificates: DeviceCertificate[]
  deviceId: string
  endpoint: string
  signed: SignedEnvelope<{
    kind: "contact-card"
    version: 1
    personId: string
    deviceId: string
    endpoint: string
    createdAt: string
  }>
}

export type ContactRouteCard = {
  kind: "twang-contact"
  version: 2
  identity: PublicIdentity
  certificates: DeviceCertificate[]
  deviceId: string
  instanceId: string
  endpoint: string
  sequence: number
  issuedAt: string
  expiresAt: string
  signed: SignedDeviceRoute
}

export type ContactLocatorPayload = {
  kind: "contact-locator"
  version: 1
  personId: string
  deviceId: string
  rendezvousEndpoint: string
  publishedAt: string
}

export type ContactLocatorCard = {
  kind: "twang-contact"
  version: 3
  identity: PublicIdentity
  certificates: DeviceCertificate[]
  deviceId: string
  rendezvousEndpoint: string
  publishedAt: string
  signed: SignedEnvelope<ContactLocatorPayload>
}

export type ContactCard = LegacyContactCard | ContactRouteCard | ContactLocatorCard

export type RoomReference = {
  roomId: string
  kind: RoomKind
  title: string
  participantPersonIds: string[]
  updatedAt: string
}

export type DirectoryDocument = {
  kind: "directory"
  version: 1
  ownerPersonId: string
  contacts: Record<string, Contact>
  rooms: Record<string, RoomReference>
}

export type Directory = Automerge.Doc<DirectoryDocument>

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

function cleanLabel(value: string, fallback: string, maximum = 120): string {
  const label = value.trim().replace(/\s+/g, " ") || fallback
  if ([...label].length > maximum) throw new Error(`Label must contain at most ${maximum} characters`)
  return label
}

function iso(now: number): string {
  const value = new Date(now).toISOString()
  if (!Number.isFinite(Date.parse(value))) throw new Error("Invalid timestamp")
  return value
}

export function createDirectory(profile: LocalProfile): Directory {
  let doc = Automerge.init<DirectoryDocument>()
  doc = Automerge.change(doc, { message: "Create directory" }, draft => {
    draft.kind = "directory"
    draft.version = 1
    draft.ownerPersonId = profile.identity.personId
    draft.contacts = {}
    draft.rooms = {}
  })
  return doc
}

export async function putContact(
  doc: Directory,
  input: {
    identity: PublicIdentity
    certificates: DeviceCertificate[]
    endpoint: string
    alias?: string
    state: ContactState
    now?: number
  },
): Promise<Directory> {
  if (input.identity.personId === doc.ownerPersonId) throw new Error("Cannot add yourself as a contact")
  if (!input.endpoint.trim()) throw new Error("Contact endpoint is empty")
  await verifyDeviceCertificateChain(
    input.identity,
    input.certificates[0]?.payload.deviceId,
    input.certificates,
  )
  const previous = doc.contacts[input.identity.personId]
  const deviceId = input.certificates[0]?.payload.deviceId
  if (!deviceId) throw new Error("Contact device is missing")
  const updatedAt = iso(input.now ?? Date.now())
  const endpoints = [
    ...clone(previous?.endpoints ?? []).filter(value => value.deviceId !== deviceId),
    { deviceId, endpoint: input.endpoint.trim() },
  ].sort((a, b) => a.deviceId.localeCompare(b.deviceId))
  const certificates = [
    ...clone(previous?.certificates ?? []).filter(value => value.payload.deviceId !== deviceId),
    ...clone(input.certificates),
  ]
  const contact: Contact = {
    personId: input.identity.personId,
    identity: clone(input.identity),
    certificates,
    alias: cleanLabel(input.alias ?? "", input.identity.displayName),
    endpoints,
    state: input.state,
    createdAt: previous?.createdAt ?? updatedAt,
    updatedAt,
  }
  return Automerge.change(doc, { message: "Put contact" }, draft => {
    draft.contacts[contact.personId] = contact
  })
}

export function renameContact(doc: Directory, personId: string, alias: string, now = Date.now()): Directory {
  if (!doc.contacts[personId]) throw new Error("Contact not found")
  return Automerge.change(doc, { message: "Rename contact" }, draft => {
    draft.contacts[personId].alias = cleanLabel(alias, draft.contacts[personId].identity.displayName)
    draft.contacts[personId].updatedAt = iso(now)
  })
}

export function removeContact(doc: Directory, personId: string): Directory {
  if (!doc.contacts[personId]) return doc
  return Automerge.change(doc, { message: "Remove contact" }, draft => {
    delete draft.contacts[personId]
  })
}

export function putRoom(doc: Directory, room: Omit<RoomReference, "updatedAt">, now = Date.now()): Directory {
  const participantPersonIds = [...new Set(room.participantPersonIds)].sort()
  if (!participantPersonIds.includes(doc.ownerPersonId)) throw new Error("Directory owner must belong to room")
  if (room.kind === "direct" && participantPersonIds.length !== 2) throw new Error("Direct room needs two participants")
  if (room.kind === "group" && participantPersonIds.length < 2) throw new Error("Group room needs at least two participants")
  const value: RoomReference = {
    roomId: room.roomId,
    kind: room.kind,
    title: cleanLabel(room.title, room.kind === "group" ? "Untitled group" : "Direct"),
    participantPersonIds,
    updatedAt: iso(now),
  }
  return Automerge.change(doc, { message: "Put room" }, draft => {
    draft.rooms[value.roomId] = value
  })
}

export async function verifyDirectory(doc: Directory): Promise<Directory> {
  if (!doc || doc.kind !== "directory" || doc.version !== 1 || !doc.ownerPersonId || !doc.contacts || !doc.rooms) {
    throw new Error("Invalid directory")
  }
  for (const [personId, contact] of Object.entries(doc.contacts)) {
    if (personId !== contact.personId || personId !== contact.identity.personId || personId === doc.ownerPersonId) {
      throw new Error("Invalid contact identity")
    }
    await verifyDeviceCertificateChain(contact.identity, contact.certificates[0]?.payload.deviceId, contact.certificates)
    for (const endpoint of contact.endpoints) {
      if (!endpoint.endpoint || !contact.certificates.some(value => value.payload.deviceId === endpoint.deviceId)) {
        throw new Error("Invalid contact endpoint")
      }
    }
  }
  for (const [roomId, room] of Object.entries(doc.rooms)) {
    if (roomId !== room.roomId || !room.participantPersonIds.includes(doc.ownerPersonId)) throw new Error("Invalid room reference")
    if (room.kind === "direct" && room.participantPersonIds.length !== 2) throw new Error("Invalid direct room")
    if (room.kind === "group" && room.participantPersonIds.length < 2) throw new Error("Invalid group room")
  }
  return doc
}

export async function mergeDirectories(local: Directory, remoteBytes: Uint8Array): Promise<Directory> {
  const remote = Automerge.load<DirectoryDocument>(remoteBytes)
  if (remote.ownerPersonId !== local.ownerPersonId) throw new Error("Directory owner does not match")
  const candidate = Automerge.merge(Automerge.clone(local), remote)
  return verifyDirectory(candidate)
}

export const saveDirectory = (doc: Directory): Uint8Array => Automerge.save(doc)
export const loadDirectory = (bytes: Uint8Array): Directory => Automerge.load<DirectoryDocument>(bytes)
export const contacts = (doc: Directory): Contact[] => Object.values(doc.contacts)
  .sort((a, b) => a.alias.localeCompare(b.alias) || a.personId.localeCompare(b.personId))
export const rooms = (doc: Directory): RoomReference[] => Object.values(doc.rooms)
  .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt) || a.roomId.localeCompare(b.roomId))

export function encodeContactCard(card: ContactCard): string {
  return `twang:${toBase64Url(new TextEncoder().encode(JSON.stringify(card)))}`
}

export async function createContactLocator(
  profile: LocalProfile,
  rendezvousEndpoint: string,
  options: { now?: number } = {},
): Promise<ContactLocatorCard> {
  const value = rendezvousEndpoint.trim()
  if (!value || value.length > 2_048) throw new Error("Invalid contact rendezvous endpoint")
  const now = options.now ?? Date.now()
  const publishedAt = new Date(now).toISOString()
  const payload: ContactLocatorPayload = {
    kind: "contact-locator",
    version: 1,
    personId: profile.identity.personId,
    deviceId: profile.device.deviceId,
    rendezvousEndpoint: value,
    publishedAt,
  }
  const signed = await signEnvelope(
    profile.privateKeys.devicePrivateKey,
    payload,
    profile.device.deviceId,
    CONTACT_LOCATOR_SIGNATURE_DOMAIN,
  )
  return {
    kind: "twang-contact",
    version: 3,
    identity: clone(profile.identity),
    certificates: [clone(profile.certificate)],
    deviceId: profile.device.deviceId,
    rendezvousEndpoint: value,
    publishedAt,
    signed,
  }
}

export async function createContactCard(profile: LocalProfile, endpoint: string, now?: number): Promise<LegacyContactCard>
export async function createContactCard(profile: LocalProfile, endpoint: string, options: {
  instanceId: string; sequence: number; now?: number; lifetimeMs?: number
}): Promise<ContactRouteCard>
export async function createContactCard(profile: LocalProfile, endpoint: string, options: number | {
  instanceId: string; sequence: number; now?: number; lifetimeMs?: number
} = Date.now()): Promise<ContactCard> {
  const value = endpoint.trim()
  if (!value || value.length > 2_048) throw new Error("Invalid contact endpoint")
  if (typeof options === "object") {
    const now = options.now ?? Date.now()
    const issuedAt = new Date(now).toISOString()
    const expiresAt = new Date(now + (options.lifetimeMs ?? 10 * 60_000)).toISOString()
    const signed = await createSignedDeviceRoute(profile, {
      scopeId: `twang:contact:${profile.identity.personId}`,
      instanceId: options.instanceId,
      endpoint: value,
      sequence: options.sequence,
      issuedAt,
      expiresAt,
    })
    return {
      kind: "twang-contact", version: 2, identity: clone(profile.identity), certificates: [clone(profile.certificate)],
      deviceId: profile.device.deviceId, instanceId: options.instanceId, endpoint: value,
      sequence: options.sequence, issuedAt, expiresAt, signed,
    }
  }
  const now = options
  return {
    kind: "twang-contact",
    version: 1,
    identity: clone(profile.identity),
    certificates: [clone(profile.certificate)],
    deviceId: profile.device.deviceId,
    endpoint: value,
    signed: await signEnvelope(profile.privateKeys.devicePrivateKey, {
      kind: "contact-card",
      version: 1,
      personId: profile.identity.personId,
      deviceId: profile.device.deviceId,
      endpoint: value,
      createdAt: new Date(now).toISOString(),
    }, profile.device.deviceId, CONTACT_CARD_SIGNATURE_DOMAIN),
  }
}

export async function decodeContactCard(
  value: string,
  options: { now?: number; allowExpired?: boolean } = {},
): Promise<ContactCard> {
  const encoded = value.trim().replace(/^twang:/, "")
  let card: ContactCard
  try {
    card = JSON.parse(new TextDecoder().decode(fromBase64Url(encoded))) as ContactCard
  } catch {
    throw new Error("Invalid contact card")
  }
  if (card?.kind !== "twang-contact" || ![1, 2, 3].includes(card.version) ||
    card.identity?.personId === undefined || !Array.isArray(card.certificates) ||
    !card.certificates.some(value => value.payload.deviceId === card.deviceId)) {
    throw new Error("Invalid contact card")
  }
  const deviceKey = await verifyDeviceCertificateChain(card.identity, card.deviceId, card.certificates)
  if (card.version === 3) {
    const publishedTime = Date.parse(card.publishedAt)
    if (!Number.isFinite(publishedTime) || new Date(publishedTime).toISOString() !== card.publishedAt ||
      publishedTime > (options.now ?? Date.now()) + 5 * 60_000) {
      throw new Error("Invalid contact locator card")
    }
    if (!card.rendezvousEndpoint ||
      card.signed?.payload?.kind !== "contact-locator" || card.signed.payload.version !== 1 ||
      card.signed.payload.personId !== card.identity.personId || card.signed.payload.deviceId !== card.deviceId ||
      card.signed.payload.rendezvousEndpoint !== card.rendezvousEndpoint ||
      card.signed.payload.publishedAt !== card.publishedAt ||
      card.signed.signerKeyId !== card.deviceId ||
      !await verifyEnvelope(card.signed, deviceKey, CONTACT_LOCATOR_SIGNATURE_DOMAIN)) {
      throw new Error("Invalid contact locator card")
    }
  } else if (card.version === 2) {
    if (!card.endpoint) throw new Error("Invalid contact card")
    if (!card.instanceId || card.signed.payload.scopeId !== `twang:contact:${card.identity.personId}` ||
      card.signed.payload.personId !== card.identity.personId || card.signed.payload.deviceId !== card.deviceId ||
      card.signed.payload.instanceId !== card.instanceId || card.signed.payload.endpoint !== card.endpoint ||
      card.signed.payload.sequence !== card.sequence || card.signed.payload.issuedAt !== card.issuedAt ||
      card.signed.payload.expiresAt !== card.expiresAt) throw new Error("Invalid contact route card")
    await verifySignedDeviceRoute(card.signed, deviceKey, options)
  } else {
    if (!card.endpoint) throw new Error("Invalid contact card")
    if (card.signed?.payload?.kind !== "contact-card" || card.signed.payload.version !== 1 ||
      card.signed.payload.personId !== card.identity.personId || card.signed.payload.deviceId !== card.deviceId ||
      card.signed.payload.endpoint !== card.endpoint || card.signed.signerKeyId !== card.deviceId ||
      !await verifyEnvelope(card.signed, deviceKey, CONTACT_CARD_SIGNATURE_DOMAIN)) {
      throw new Error("Invalid contact card signature")
    }
    const createdAt = Date.parse(card.signed.payload.createdAt)
    if (Number.isFinite(createdAt) && (options.now ?? Date.now()) - createdAt > MAX_DEVICE_ROUTE_LIFETIME_MS) {
      throw new Error("Device route expired")
    }
  }
  return card
}

export async function decodeContactLink(value: string, now = Date.now()): Promise<ContactCard> {
  try {
    return await decodeContactCard(value, { now })
  } catch (error) {
    if (error instanceof Error && (error.message === "Device route expired" || error.message === "Link expired")) {
      throw new Error("Link expired")
    }
    throw error
  }
}

export async function deriveContactRendezvousSeed(identitySeed: Uint8Array, rotationIndex = 0): Promise<Uint8Array> {
  const ikm = await crypto.subtle.importKey("raw", identitySeed, "HKDF", false, ["deriveBits"])
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode("meta-mesh/contact-rendezvous/v1"),
      info: new TextEncoder().encode(`contact-rendezvous-seed:${rotationIndex}`),
    },
    ikm,
    256,
  )
  return new Uint8Array(bits)
}

export async function contactRendezvousSeedFromProfile(profile: LocalProfile, rotationIndex = 0): Promise<Uint8Array> {
  if (!profile.privateKeys.identityPrivateKey) throw new Error("Identity private key is unavailable")
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", profile.privateKeys.identityPrivateKey))
  const identitySeed = pkcs8.slice(16, 48)
  return deriveContactRendezvousSeed(identitySeed, rotationIndex)
}
