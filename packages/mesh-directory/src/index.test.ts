import { beforeEach, describe, expect, it } from "vitest"
import { BrowserIdentityStore } from "../../mesh-identity/src/index"
import {
  contacts,
  createDirectory,
  decodeContactCard,
  encodeContactCard,
  mergeDirectories,
  putContact,
  putRoom,
  saveDirectory,
} from "./index"

describe("mesh directory", () => {
  let alice: Awaited<ReturnType<BrowserIdentityStore["bootstrap"]>>
  let bob: Awaited<ReturnType<BrowserIdentityStore["bootstrap"]>>

  beforeEach(async () => {
    alice = await new BrowserIdentityStore({ storageKey: crypto.randomUUID() }).bootstrap("Alice")
    bob = await new BrowserIdentityStore({ storageKey: crypto.randomUUID() }).bootstrap("Bob")
  })

  it("Given a verified peer, when accepted, then the contact becomes available", async () => {
    let directory = createDirectory(alice)
    directory = await putContact(directory, {
      identity: bob.identity,
      certificates: [bob.certificate],
      endpoint: "bob-endpoint",
      state: "accepted",
      now: 1_800_000_000_000,
    })

    expect(contacts(directory).map(contact => contact.alias)).toEqual(["Bob"])
  })

  it("Given contacts, when a group is created, then it records all members", async () => {
    let directory = createDirectory(alice)
    directory = putRoom(directory, {
      roomId: "room-1",
      kind: "group",
      title: "Garden people",
      participantPersonIds: [bob.identity.personId, alice.identity.personId],
    }, 1_800_000_000_000)

    expect(directory.rooms["room-1"].participantPersonIds).toEqual(
      [alice.identity.personId, bob.identity.personId].sort(),
    )
  })

  it("Given another identity directory, when merged, then ownership is rejected", async () => {
    const local = createDirectory(alice)
    const remote = createDirectory(bob)

    await expect(mergeDirectories(local, saveDirectory(remote))).rejects.toThrow("owner")
  })

  it("Given a public contact card, when shared, then identity and endpoint verify without its secret", async () => {
    const encoded = encodeContactCard({
      kind: "twang-contact",
      version: 1,
      identity: bob.identity,
      certificates: [bob.certificate],
      deviceId: bob.device.deviceId,
      endpoint: "bob-endpoint",
    })

    await expect(decodeContactCard(encoded)).resolves.toMatchObject({
      identity: { personId: bob.identity.personId },
      endpoint: "bob-endpoint",
    })
    expect(encoded).not.toContain("private")
  })
})
