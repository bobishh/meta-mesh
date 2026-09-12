import * as Automerge from "@automerge/automerge"
import {
  fromBase64Url,
  toBase64Url,
  verifyDeviceCertificateChain,
  type DeviceCertificate,
  type LocalProfile,
  type PublicIdentity,
} from "../../mesh-identity/src/index"

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

export type ContactCard = {
  kind: "twang-contact"
  version: 1
  identity: PublicIdentity
  certificates: DeviceCertificate[]
  deviceId: string
  endpoint: string
}

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
    ...(previous?.endpoints ?? []).filter(value => value.deviceId !== deviceId),
    { deviceId, endpoint: input.endpoint.trim() },
  ].sort((a, b) => a.deviceId.localeCompare(b.deviceId))
  const certificates = [
    ...(previous?.certificates ?? []).filter(value => value.payload.deviceId !== deviceId),
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

export async function decodeContactCard(value: string): Promise<ContactCard> {
  const encoded = value.trim().replace(/^twang:/, "")
  let card: ContactCard
  try {
    card = JSON.parse(new TextDecoder().decode(fromBase64Url(encoded))) as ContactCard
  } catch {
    throw new Error("Invalid contact card")
  }
  if (card?.kind !== "twang-contact" || card.version !== 1 || !card.endpoint ||
    card.identity?.personId === undefined || !Array.isArray(card.certificates) ||
    !card.certificates.some(value => value.payload.deviceId === card.deviceId)) {
    throw new Error("Invalid contact card")
  }
  await verifyDeviceCertificateChain(card.identity, card.deviceId, card.certificates)
  return card
}
