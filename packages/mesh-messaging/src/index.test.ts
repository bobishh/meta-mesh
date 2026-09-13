import { beforeEach, describe, expect, it } from "vitest"
import * as Automerge from "@automerge/automerge"
import { BrowserIdentityStore, createRecoverableIdentity, openIdentityRecoveryEnvelope } from "../../mesh-identity/src/index"
import {
  addConversationParticipant,
  addParticipantDeviceCertificate,
  appendMessage,
  conversationMessages,
  createConversation,
  createConversationGrant,
  createMessage,
  mergeConversations,
  saveConversation,
} from "./index"

describe("mesh messaging", () => {
  let alice: Awaited<ReturnType<BrowserIdentityStore["bootstrap"]>>
  let bob: Awaited<ReturnType<BrowserIdentityStore["bootstrap"]>>
  let eve: Awaited<ReturnType<BrowserIdentityStore["bootstrap"]>>

  beforeEach(async () => {
    alice = await new BrowserIdentityStore({ storageKey: crypto.randomUUID() }).bootstrap("Alice")
    bob = await new BrowserIdentityStore({ storageKey: crypto.randomUUID() }).bootstrap("Bob")
    eve = await new BrowserIdentityStore({ storageKey: crypto.randomUUID() }).bootstrap("Eve")
  })

  it("Given two members, when each writes, then both signed messages share one CRDT", async () => {
    const now = 1_800_000_000_000
    let chat = createConversation(alice, "Alice and Bob", "chat-1")
    const grant = await createConversationGrant(alice, "chat-1", bob.identity.personId, "member", now)
    chat = await addConversationParticipant(chat, { identity: bob.identity, certificates: [bob.certificate] }, grant)
    chat = await appendMessage(chat, await createMessage(alice, "chat-1", "Hi", { now, messageId: "m1" }), now)
    chat = await appendMessage(chat, await createMessage(bob, "chat-1", "Hello", { now, messageId: "m2" }), now)

    expect(conversationMessages(chat).map(message => message.payload.body)).toEqual(["Hi", "Hello"])
  })

  it("Given a conversation, when an outsider writes, then the message is rejected", async () => {
    const chat = createConversation(alice, "Private", "chat-2")
    const message = await createMessage(eve, "chat-2", "Let me in")

    await expect(appendMessage(chat, message)).rejects.toThrow("not a participant")
  })

  it("Given a replicated conversation, when a signed body is forged, then merge rejects it", async () => {
    const now = 1_800_000_000_000
    const local = createConversation(alice, "Private", "chat-3")
    let remote = await appendMessage(local, await createMessage(alice, "chat-3", "Original", { now, messageId: "m1" }), now)
    remote = Automerge.change(remote, draft => { draft.messages.m1.payload.body = "Forged" })

    await expect(mergeConversations(local, saveConversation(remote), now)).rejects.toThrow("signature")
  })

  it("Given the same person on another device, when it joins a room, then its messages verify", async () => {
    const created = await createRecoverableIdentity("better", "Alice", new Uint8Array(32).fill(1))
    const firstDevice = created.profile
    const secondDevice = await openIdentityRecoveryEnvelope(
      created.recoveryEnvelope,
      created.recoveryKey,
      "Alice",
      new Uint8Array(32).fill(2),
    )
    let room = createConversation(firstDevice, "Devices", "room-devices")
    room = await addParticipantDeviceCertificate(room, secondDevice)
    room = await appendMessage(room, await createMessage(secondDevice, room.conversationId, "Other device"))

    expect(conversationMessages(room).map(message => message.payload.body)).toEqual(["Other device"])
  })
})
