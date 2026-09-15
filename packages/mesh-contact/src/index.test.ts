import { beforeEach, describe, expect, it } from "vitest"
import * as Automerge from "@automerge/automerge"
import { BrowserIdentityStore, createRecoverableIdentity, openIdentityRecoveryEnvelope } from "../../mesh-identity/src/index"
import {
  addContactParticipantDeviceCertificate,
  createContactDecision,
  createContactChannel,
  createContactMessage,
  createContactRequest,
  appendContactMessage,
  contactTimeline,
  mergeContactChannels,
  saveContactChannel,
  verifyContactDecision,
  verifyContactRequest,
} from "./index"

describe("contact mesh protocol", () => {
  let visitor: Awaited<ReturnType<BrowserIdentityStore["bootstrap"]>>
  let owner: Awaited<ReturnType<BrowserIdentityStore["bootstrap"]>>

  beforeEach(async () => {
    const visitorStore = new BrowserIdentityStore({ storageKey: crypto.randomUUID() })
    const ownerStore = new BrowserIdentityStore({ storageKey: crypto.randomUUID() })
    visitor = await visitorStore.bootstrap("Visitor")
    owner = await ownerStore.bootstrap("Owner")
  })

  it("Given a visitor identity, when the first message is sent, then the owner can verify it", async () => {
    const request = await createContactRequest(visitor, {
      firstMessage: "Hello from the cliff.",
      now: 1_800_000_000_000,
      requestId: "request-1",
    })

    await expect(verifyContactRequest(request, 1_800_000_000_000)).resolves.toEqual(request)
    expect(request.signed.payload.version).toBe(1)
    expect("endpoint" in request.signed.payload).toBe(false)
  })

  it("Given a signed request, when its first message is altered, then verification fails", async () => {
    const request = await createContactRequest(visitor, {
      firstMessage: "Original",
    })
    request.signed.payload.firstMessage = "Altered"

    await expect(verifyContactRequest(request)).rejects.toThrow("signature")
  })

  it("Given an old request, when received, then it is rejected as expired", async () => {
    const request = await createContactRequest(visitor, {
      firstMessage: "Late hello",
      now: 1_800_000_000_000,
    })

    await expect(verifyContactRequest(request, 1_800_003_600_001)).rejects.toThrow("expired")
  })

  it("Given an approved request, when the visitor verifies it, then the channel is bound to both identities", async () => {
    const request = await createContactRequest(visitor, {
      firstMessage: "Hello",
      now: 1_800_000_000_000,
      requestId: "request-2",
    })
    const decision = await createContactDecision(owner, request, true, {
      now: 1_800_000_000_100,
      channelId: "channel-1",
      channelSecret: "secret-1",
    })

    await expect(verifyContactDecision(decision, request, 1_800_000_000_100)).resolves.toEqual(decision)
  })

  it("Given a declined request, when encoded, then it grants no channel", async () => {
    const request = await createContactRequest(visitor, {
      firstMessage: "Hello",
    })
    const decision = await createContactDecision(owner, request, false)

    expect(decision.signed.payload).toMatchObject({ accepted: false })
    expect(decision.signed.payload.channelId).toBeUndefined()
    expect(decision.signed.payload.channelSecret).toBeUndefined()
  })

  it("Given an accepted request, when both people write, then one CRDT contains the whole chat", async () => {
    const now = 1_800_000_000_000
    const request = await createContactRequest(visitor, {
      firstMessage: "Can we talk?", now, requestId: "request-chat",
    })
    const decision = await createContactDecision(owner, request, true, {
      now: now + 1, channelId: "channel-chat", channelSecret: "secret-chat",
    })
    let channel = await createContactChannel(request, decision, now + 1)
    channel = await appendContactMessage(channel,
      await createContactMessage(owner, "channel-chat", "Yes.", { now: now + 2, messageId: "owner-1" }), now + 2)
    channel = await appendContactMessage(channel,
      await createContactMessage(visitor, "channel-chat", "Excellent.", { now: now + 3, messageId: "visitor-1" }), now + 3)

    expect(contactTimeline(channel).map(item => item.body)).toEqual(["Can we talk?", "Yes.", "Excellent."])
  })

  it("Given one visitor on a second device, when its certificate joins, then its message verifies", async () => {
    const now = 1_800_000_000_000
    const created = await createRecoverableIdentity("better", "Visitor", new Uint8Array(32).fill(1))
    const firstDevice = created.profile
    const secondDevice = await openIdentityRecoveryEnvelope(
      created.recoveryEnvelope,
      created.recoveryKey,
      "Visitor",
      new Uint8Array(32).fill(2),
    )
    const request = await createContactRequest(firstDevice, {
      firstMessage: "First device", now, requestId: "request-devices",
    })
    const decision = await createContactDecision(owner, request, true, {
      now, channelId: "channel-devices", channelSecret: "secret-devices",
    })
    let channel = await createContactChannel(request, decision, now)
    channel = await addContactParticipantDeviceCertificate(channel, secondDevice.identity, secondDevice.certificate)
    channel = await appendContactMessage(channel,
      await createContactMessage(secondDevice, channel.channelId, "Second device", { now: now + 1, messageId: "device-2" }), now + 1)

    expect(contactTimeline(channel).map(item => item.body)).toEqual(["First device", "Second device"])
  })

  it("Given separate contacts, when one channel is merged, then another channel cannot leak into it", async () => {
    const now = 1_800_000_000_000
    const firstRequest = await createContactRequest(visitor, {
      firstMessage: "First", now, requestId: "request-first",
    })
    const firstDecision = await createContactDecision(owner, firstRequest, true, {
      now, channelId: "channel-first", channelSecret: "secret-first",
    })
    const first = await createContactChannel(firstRequest, firstDecision, now)
    const secondRequest = await createContactRequest(visitor, {
      firstMessage: "Second", now, requestId: "request-second",
    })
    const secondDecision = await createContactDecision(owner, secondRequest, true, {
      now, channelId: "channel-second", channelSecret: "secret-second",
    })
    const second = await createContactChannel(secondRequest, secondDecision, now)

    await expect(mergeContactChannels(first, saveContactChannel(second), now)).rejects.toThrow()
  })

  it("Given a valid CRDT, when a message body is changed without its key, then merge rejects it", async () => {
    const now = 1_800_000_000_000
    const request = await createContactRequest(visitor, {
      firstMessage: "Hello", now, requestId: "request-tamper",
    })
    const decision = await createContactDecision(owner, request, true, {
      now, channelId: "channel-tamper", channelSecret: "secret-tamper",
    })
    const local = await createContactChannel(request, decision, now)
    let remote = await appendContactMessage(local,
      await createContactMessage(visitor, "channel-tamper", "Original", { now, messageId: "message-tamper" }), now)
    remote = Automerge.change(remote, draft => { draft.messages["message-tamper"].payload.body = "Forged" })

    await expect(mergeContactChannels(local, saveContactChannel(remote), now)).rejects.toThrow("signature")
  })
})
