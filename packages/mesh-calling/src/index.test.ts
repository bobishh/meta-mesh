import { beforeEach, describe, expect, it } from "vitest"
import { BrowserIdentityStore } from "../../mesh-identity/src/index"
import {
  addConversationParticipant,
  createConversation,
  createConversationGrant,
} from "../../mesh-messaging/src/index"
import { CallSession, createCallSignal, verifyCallSignal } from "./index"

describe("mesh calling", () => {
  let alice: Awaited<ReturnType<BrowserIdentityStore["bootstrap"]>>
  let bob: Awaited<ReturnType<BrowserIdentityStore["bootstrap"]>>
  let eve: Awaited<ReturnType<BrowserIdentityStore["bootstrap"]>>

  beforeEach(async () => {
    alice = await new BrowserIdentityStore({ storageKey: crypto.randomUUID() }).bootstrap("Alice")
    bob = await new BrowserIdentityStore({ storageKey: crypto.randomUUID() }).bootstrap("Bob")
    eve = await new BrowserIdentityStore({ storageKey: crypto.randomUUID() }).bootstrap("Eve")
  })

  it("Given two direct-room members, when one offers video, then the other verifies it", async () => {
    const now = 1_800_000_000_000
    let room = createConversation(alice, "Direct", "room-call", "direct")
    room = await addConversationParticipant(room, {
      identity: bob.identity,
      certificates: [bob.certificate],
    }, await createConversationGrant(alice, room.conversationId, bob.identity.personId, "member", now))
    const signal = await createCallSignal(alice, {
      signalKind: "offer",
      callId: "call-1",
      roomId: room.conversationId,
      media: "video",
      targetPersonId: bob.identity.personId,
      data: "offer-sdp",
      now,
    })

    await expect(verifyCallSignal(signal, room, bob.identity.personId, now)).resolves.toEqual(signal)
  })

  it("Given an outsider, when it signals a room, then verification rejects it", async () => {
    const room = createConversation(alice, "Direct", "room-private", "direct")
    const signal = await createCallSignal(eve, {
      signalKind: "offer",
      callId: "call-2",
      roomId: room.conversationId,
      media: "audio",
      targetPersonId: alice.identity.personId,
      data: "offer-sdp",
    })

    await expect(verifyCallSignal(signal, room, alice.identity.personId)).rejects.toThrow("not a room member")
  })

  it("Given an outgoing video call, when media connects and controls change, then lifecycle stays transport-independent", () => {
    const session = new CallSession()
    session.start("call-1", "bob", "video")
    session.connecting()
    session.connected()
    session.setMicrophoneMuted(true)
    session.setCameraDisabled(true)

    expect(session.snapshot()).toEqual({
      state: "active", callId: "call-1", peerId: "bob", media: "video",
      error: "", microphoneMuted: true, cameraDisabled: true,
    })
    session.end()
    expect(session.snapshot().state).toBe("idle")
  })

  it("Given a busy or failed session, when another offer or failure arrives, then state is explicit", () => {
    const session = new CallSession()
    session.ring("call-1", "alice", "audio")
    expect(() => session.ring("call-2", "eve", "video")).toThrow("Call session is busy")
    session.fail("ICE failed")
    expect(session.snapshot()).toEqual(expect.objectContaining({ state: "failed", error: "ICE failed" }))
  })
})
