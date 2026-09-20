import { beforeEach, describe, expect, it } from "vitest"
import {
  BrowserIdentityStore,
  createRecoverableIdentity,
  openIdentityRecoveryEnvelope,
} from "../../mesh-identity/src/index"
import {
  contacts,
  createDirectory,
  createContactCard,
  createContactLocator,
  createWakeTargetCard,
  contactRendezvousSeedFromProfile,
  decodeContactCard,
  decodeContactLink,
  encodeContactCard,
  mergeDirectories,
  putContact,
  putRoom,
  saveDirectory,
  verifyWakeTargetCard,
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

  it("Given an accepted contact, when it shares a targeted wake capability, then only its intended peer can store it", async () => {
    const wake = await createWakeTargetCard(bob, alice.identity.personId, {
      serviceUrl: "https://push.tw.example",
      capabilityId: "capability-123456789012",
      secret: "wake-secret-123456789",
    }, 1_800_000_000_000)

    await expect(verifyWakeTargetCard(wake, alice.identity.personId, 1_800_000_000_001))
      .resolves.toMatchObject({ signed: { payload: { personId: bob.identity.personId } } })
    await expect(verifyWakeTargetCard(wake, "some-other-person", 1_800_000_000_001))
      .rejects.toThrow("target")

    const directory = await putContact(createDirectory(alice), {
      identity: bob.identity,
      certificates: [bob.certificate],
      endpoint: "bob-endpoint",
      wake,
      state: "accepted",
      now: 1_800_000_000_001,
    })
    expect(directory.contacts[bob.identity.personId].wake).toEqual(wake)
  })

  it("Given a stored wake capability, when another route arrives without one, then the capability survives", async () => {
    const wake = await createWakeTargetCard(bob, alice.identity.personId, {
      serviceUrl: "https://push.tw.example",
      capabilityId: "capability-123456789012",
      secret: "wake-secret-123456789",
    })
    let directory = await putContact(createDirectory(alice), {
      identity: bob.identity, certificates: [bob.certificate], endpoint: "bob-a", wake, state: "accepted",
    })
    directory = await putContact(directory, {
      identity: bob.identity, certificates: [bob.certificate], endpoint: "bob-b", state: "accepted",
    })

    expect(directory.contacts[bob.identity.personId].wake).toEqual(wake)
  })

  it("Given one contact on two devices, when its second route arrives, then both endpoints remain usable", async () => {
    const created = await createRecoverableIdentity("better", "Bob", new Uint8Array(32).fill(1))
    const desktop = created.profile
    const phone = await openIdentityRecoveryEnvelope(
      created.recoveryEnvelope,
      created.recoveryKey,
      "Bob",
      new Uint8Array(32).fill(2),
    )
    let directory = await putContact(createDirectory(alice), {
      identity: desktop.identity,
      certificates: [desktop.certificate],
      endpoint: "bob-desktop",
      state: "accepted",
    })

    directory = await putContact(directory, {
      identity: phone.identity,
      certificates: [phone.certificate],
      endpoint: "bob-phone",
      state: "accepted",
    })

    expect(directory.contacts[desktop.identity.personId].endpoints.map(value => value.endpoint).sort())
      .toEqual(["bob-desktop", "bob-phone"])
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
    const encoded = encodeContactCard(await createContactCard(bob, "bob-endpoint"))

    await expect(decodeContactCard(encoded)).resolves.toMatchObject({
      identity: { personId: bob.identity.personId },
      endpoint: "bob-endpoint",
    })
    expect(encoded).not.toContain("private")
  })

  it("Given two tabs share one device, when they publish contact routes, then each signed instance remains distinct", async () => {
    const now = Date.now()
    const first = await createContactCard(bob, "bob-tab-a", { instanceId: "tab-a", sequence: 1,
      now })
    const second = await createContactCard(bob, "bob-tab-b", { instanceId: "tab-b", sequence: 1,
      now })

    await expect(decodeContactCard(encodeContactCard(first))).resolves.toMatchObject({ version: 2, instanceId: "tab-a" })
    await expect(decodeContactCard(encodeContactCard(second))).resolves.toMatchObject({ version: 2, instanceId: "tab-b" })
  })

  it("Given an expired public contact link, when opened, then it fails before contact state is created", async () => {
    const card = await createContactCard(bob, "bob-endpoint", {
      instanceId: "tab-a",
      sequence: 1,
      now: 1_000,
      lifetimeMs: 10 * 60_000,
    })

    await expect(decodeContactLink(encodeContactCard(card), 1_000 + 10 * 60_000))
      .rejects.toThrow("Link expired")
  })

  it("Given a durable contact locator, when created, then it verifies and remains valid beyond device route TTL", async () => {
    const now = 1_000_000
    const locator = await createContactLocator(bob, "bob-rendezvous-endpoint-12345678901234567890123456789012", { now })
    const encoded = encodeContactCard(locator)

    const decoded = await decodeContactCard(encoded, { now: now + 30 * 24 * 3600 * 1000 })
    expect(decoded).toMatchObject({
      kind: "twang-contact",
      version: 3,
      deviceId: bob.device.deviceId,
      rendezvousEndpoint: "bob-rendezvous-endpoint-12345678901234567890123456789012",
      identity: { personId: bob.identity.personId },
    })

    await expect(decodeContactLink(encoded, now + 30 * 24 * 3600 * 1000)).resolves.toMatchObject({
      version: 3,
      rendezvousEndpoint: "bob-rendezvous-endpoint-12345678901234567890123456789012",
    })
  })

  it("Given a tampered contact locator, when decoded, then verification fails", async () => {
    const locator = await createContactLocator(bob, "bob-rendezvous-endpoint-12345678901234567890123456789012")
    const tampered = { ...locator, rendezvousEndpoint: "eve-intercept-endpoint" }
    const encoded = encodeContactCard(tampered as unknown as typeof locator)

    await expect(decodeContactCard(encoded)).rejects.toThrow("Invalid contact locator card")
  })

  it("Given an old version 1 contact card older than route TTL, when decoded, then it throws Link expired", async () => {
    const oldCard = await createContactCard(bob, "bob-endpoint", 1_000)
    await expect(decodeContactLink(encodeContactCard(oldCard), 1_000 + 11 * 60_000))
      .rejects.toThrow("Link expired")
  })

  it("Given a local profile, when deriving contact rendezvous seed, then it is deterministic and rotates with index", async () => {
    const seed1 = await contactRendezvousSeedFromProfile(bob, 0)
    const seed2 = await contactRendezvousSeedFromProfile(bob, 0)
    const rotated = await contactRendezvousSeedFromProfile(bob, 1)

    expect(seed1).toHaveLength(32)
    expect(seed1).toEqual(seed2)
    expect(seed1).not.toEqual(rotated)
  })

  it("Given a contact locator published too far in the future, when decoded, then verification fails", async () => {
    const now = 1_000_000
    const locator = await createContactLocator(bob, "bob-rendezvous-endpoint-12345678901234567890123456789012", { now: now + 10 * 60_000 })
    const encoded = encodeContactCard(locator)

    await expect(decodeContactCard(encoded, { now })).rejects.toThrow("Invalid contact locator card")
  })
})
