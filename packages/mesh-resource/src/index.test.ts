import { describe, expect, it } from "vitest"
import { profileFromIdentitySeedForDevice, sha256Base64Url } from "@meta-uber/mesh-identity"
import { ResourceProvider, ResourceClient, type ResourceState, type ResourceStore } from "./index"

function store(): ResourceStore {
  const rows = new Map<string, ResourceState>()
  return {
    async read(key) { return structuredClone(rows.get(key)) },
    async compareAndSwap(key, expectedVersion, next) {
      if ((rows.get(key)?.version ?? null) !== expectedVersion) return false
      rows.set(key, structuredClone(next)); return true
    },
  }
}
async function setup() {
  const owner = await profileFromIdentitySeedForDevice(new Uint8Array(32).fill(11), "Owner", new Uint8Array(32).fill(12))
  const node = await profileFromIdentitySeedForDevice(new Uint8Array(32).fill(21), "Automation", new Uint8Array(32).fill(22))
  let now = 1_800_000_000_000
  let approvals = 0
  let allow = true
  const durable = store()
  const provider = new ResourceProvider({ profile: owner, store: durable, now: () => now,
    approve: async request => { approvals++; return allow ? { actions: request.actions, expiresAt: now + 60_000 } : null } })
  const resource = await provider.addResource({ id: "board-a", title: "Board A", audience: "https://board.example",
    actions: ["read", "create", "update"], readScope: "Entire Board A" })
  const client = new ResourceClient({ profile: node, now: () => now, transport: message => provider.handleConnection(message) })
  return { owner, node, provider, client, resource, durable, now: () => now, advance: (ms: number) => { now += ms },
    approvals: () => approvals, deny: () => { allow = false } }
}
const digest = () => sha256Base64Url(new TextEncoder().encode("bounded request body"))

describe("resource connection and authorization", () => {
  it("Given an independently initialized service identity, when its owner approves Connect board, then return a subject-bound grant and authorize only approved actions", async () => {
    const f = await setup()
    const connection = await f.client.connectResource({ resource: f.resource, actions: ["read", "create"] })
    expect(f.approvals()).toBe(1)
    expect(connection.grant.payload).toMatchObject({ resourceId: "board-a", subjectPersonId: f.node.identity.personId,
      issuerPersonId: f.owner.identity.personId, actions: ["read", "create"], audience: "https://board.example" })
    const proof = await f.client.signOperation(connection.grant, { action: "create", bodyDigest: await digest() })
    await expect(f.provider.authorize({ grant: connection.grant, proof, resourceId: "board-a", action: "create", bodyDigest: await digest() })).resolves.toMatchObject({ subjectPersonId: f.node.identity.personId })
    const denied = await f.client.signOperation(connection.grant, { action: "update", bodyDigest: await digest() })
    await expect(f.provider.authorize({ grant: connection.grant, proof: denied, resourceId: "board-a", action: "update", bodyDigest: await digest() })).rejects.toThrow()
  })

  it("Given a denied approval, when connecting, then return no grant and retain the node identity", async () => {
    const f = await setup(); f.deny()
    await expect(f.client.connectResource({ resource: f.resource, actions: ["read"] })).rejects.toThrow(/denied/i)
    expect(f.client.identity.personId).toBe(f.node.identity.personId)
  })

  it("Given a signed grant, when a resource, audience, body or signer is changed, then deny before an operation", async () => {
    const f = await setup()
    const { grant } = await f.client.connectResource({ resource: f.resource, actions: ["read"] })
    const proof = await f.client.signOperation(grant, { action: "read", bodyDigest: await digest() })
    for (const change of [{ resourceId: "other" }, { bodyDigest: "different" }]) {
      await expect(f.provider.authorize({ grant, proof, resourceId: "board-a", action: "read", bodyDigest: await digest(), ...change })).rejects.toThrow()
    }
    const altered = structuredClone(grant); altered.payload.audience = "https://attacker.example"
    await expect(f.provider.authorize({ grant: altered, proof, resourceId: "board-a", action: "read", bodyDigest: await digest() })).rejects.toThrow()
    const other = new ResourceClient({ profile: f.owner, now: f.now, transport: message => f.provider.handleConnection(message) })
    const foreignProof = await other.signOperation(grant, { action: "read", bodyDigest: await digest() })
    await expect(f.provider.authorize({ grant, proof: foreignProof, resourceId: "board-a", action: "read", bodyDigest: await digest() })).rejects.toThrow()
  })

  it("Given expiry, revocation or a replayed operation, when authorizing, then fail closed against current durable authority", async () => {
    const f = await setup()
    const { grant } = await f.client.connectResource({ resource: f.resource, actions: ["read"] })
    const input = { grant, proof: await f.client.signOperation(grant, { action: "read", bodyDigest: await digest() }), resourceId: "board-a", action: "read", bodyDigest: await digest() }
    await f.provider.authorize(input)
    await expect(f.provider.authorize(input)).rejects.toThrow(/replay/i)
    await f.provider.revokeGrant("board-a", grant.payload.grantId)
    const next = await f.client.signOperation(grant, { action: "read", bodyDigest: await digest() })
    await expect(f.provider.authorize({ ...input, proof: next })).rejects.toThrow(/revok/i)
    f.advance(61_000)
    await expect(f.provider.authorize({ ...input, proof: next })).rejects.toThrow()
  })

  it("Given a code bound to an existing node, when CLI initialization redeems it, then preserve identity, never expose owner keys, and reject a second redemption", async () => {
    const f = await setup()
    const code = await f.provider.createInvitation({ resourceId: "board-a", subjectPersonId: f.node.identity.personId,
      actions: ["read"], expiresAt: f.now() + 60_000 })
    const connection = await f.client.redeemInvitation(code, f.resource)
    expect(connection.grant.payload.subjectPersonId).toBe(f.node.identity.personId)
    expect(JSON.stringify(connection)).not.toMatch(/privateKey|contentKey|identitySeed/)
    await expect(f.client.redeemInvitation(code, f.resource)).rejects.toThrow()
  })

  it("Given concurrent requests after a lost response, when retrying the exact connection, then consent and grant issuance occur once", async () => {
    const f = await setup()
    const messages: unknown[] = []
    const client = new ResourceClient({ profile: f.node, now: f.now, transport: async message => {
      messages.push(structuredClone(message))
      const result = await f.provider.handleConnection(message)
      if (messages.length === 2) throw new Error("Response lost")
      return result
    } })
    const pending = { resource: f.resource, actions: ["read"], requestId: "retained-connection" }
    await expect(client.connectResource(pending)).rejects.toThrow(/Response lost/)
    const connected = await client.connectResource(pending)
    expect(connected.grant.payload.subjectPersonId).toBe(f.node.identity.personId)
    expect(f.approvals()).toBe(1)
  })
})

it("Given an owner approval waiting across provider restart, when the owner decides later, then resume the exact pending connection", async () => {
  const f = await setup(), durable = store()
  let provider = new ResourceProvider({ profile: f.owner, store: durable, now: f.now })
  const resource = await provider.addResource({ id: "restart-board", title: "Restart board", audience: "https://board.example", actions: ["read"], readScope: "Whole board" })
  let lost = true
  const client = new ResourceClient({ profile: f.node, now: f.now, transport: async message => {
    const response = await provider.handleConnection(message)
    if (response.kind === "pending" && lost) { lost = false; throw new Error("Tab closed while waiting") }
    return response
  } })
  await expect(client.connectResource({ resource, actions: ["read"], requestId: "pending-owner-decision" })).rejects.toThrow(/Tab closed/)
  provider = new ResourceProvider({ profile: f.owner, store: durable, now: f.now })
  const requests = await provider.listPendingRequests(resource.id)
  expect(requests).toHaveLength(1)
  expect(requests[0]!.subject.personId).toBe(f.node.identity.personId)
  await provider.approveConnection(resource.id, requests[0]!.requestId, { actions: ["read"], expiresAt: f.now() + 60_000 })
  const connected = await client.connectResource({ resource, actions: ["read"], requestId: "pending-owner-decision" })
  expect(connected.grant.payload.subjectPersonId).toBe(f.node.identity.personId)
})

it("Given a resource epoch update, when an old grant is used, then reject it without changing either identity", async () => {
  const f = await setup()
  const { grant } = await f.client.connectResource({ resource: f.resource, actions: ["read"] })
  const current = await f.provider.updateResource({ id: f.resource.id, title: "Renamed board", audience: f.resource.audience,
    actions: ["read"], readScope: f.resource.readScope })
  expect(current.epoch).toBe(2)
  const proof = await f.client.signOperation(grant, { action: "read", bodyDigest: await digest() })
  await expect(f.provider.authorize({ grant, proof, resourceId: current.id, action: "read", bodyDigest: await digest() })).rejects.toThrow()
  expect(f.client.identity.personId).toBe(f.node.identity.personId)
})

it("Given a subject-bound connection code, when a different identity redeems it, then issue no grant", async () => {
  const f = await setup()
  const code = await f.provider.createInvitation({ resourceId: f.resource.id, subjectPersonId: f.node.identity.personId, actions: ["read"], expiresAt: f.now()+60_000 })
  const thief = new ResourceClient({ profile: f.owner, now: f.now, transport: message => f.provider.handleConnection(message) })
  await expect(thief.redeemInvitation(code, f.resource)).rejects.toThrow()
  await expect(f.client.redeemInvitation(code, f.resource)).resolves.toHaveProperty("grant")
})

it("Given the HTTP SDK and an exact origin policy, when connecting through Requests and Responses, then complete real signed approval and reject an unapproved origin", async () => {
  const { createHttpResourceTransport, createResourceConnectionHandler } = await import("./http")
  const f = await setup(), handler = createResourceConnectionHandler(f.provider, ["https://automation.example"])
  const transport = createHttpResourceTransport("https://board.example/connect", async (url, init) => {
    const headers = new Headers(init?.headers)
    headers.set("Origin", "https://automation.example")
    return handler(new Request(url, { ...init, headers }))
  })
  const client = new ResourceClient({ profile: f.node, now: f.now, transport })
  await expect(client.connectResource({ resource: f.resource, actions: ["read"] })).resolves.toHaveProperty("grant")
  const denied = await handler(new Request("https://board.example/connect", { method: "POST", headers: { Origin: "https://foreign.example", "Content-Type": "application/json" }, body: "{}" }))
  expect(denied.status).toBe(403)
})

it("Given a registered resource, when the same issuer changes its display name, then registration retains existing authority and epoch", async () => {
  const f = await setup(), durable = store()
  const input = { id: "stable-board", title: "Stable board", audience: "https://board.example", actions: ["read"], readScope: "Whole board" }
  const first = new ResourceProvider({ profile: f.owner, store: durable, now: f.now })
  const registered = await first.addResource(input)
  const renamed = { ...f.owner, identity: { ...f.owner.identity, displayName: "New display name" } }
  const second = new ResourceProvider({ profile: renamed, store: durable, now: f.now })
  await expect(second.addResource(input)).resolves.toEqual(registered)
  await expect(second.addResource({ ...input, actions: ["read", "write"] })).rejects.toThrow(/different authority/)
})

it("Given full device revocation storage, when repeating an existing revocation, then succeed without admitting another device", async () => {
  const f = await setup(), durable = store()
  const provider = new ResourceProvider({ profile: f.owner, store: durable, now: f.now })
  await provider.addResource({ id: "revocations", title: "Revocations", audience: "https://board.example", actions: ["read"], readScope: "Whole board" })
  const key = `mesh-resource:${f.owner.identity.personId}:revocations`
  const row = (await durable.read(key))!
  row.revokedDevices = Array.from({ length: 256 }, (_, index) => fixtureDeviceId(index))
  await durable.compareAndSwap(key, row.version, { ...row, version: row.version + 1 })
  await expect(provider.revokeDevice("revocations", row.revokedDevices[0]!)).resolves.toBeUndefined()
  await expect(provider.revokeDevice("revocations", f.node.device.deviceId)).rejects.toThrow(/capacity/)
})

function fixtureDeviceId(index: number): string {
  return index.toString(16).padStart(43, "A")
}

it("Given revoked grants whose lifetime ended, when another connection starts, then retire obsolete revocations and retain current ones", async () => {
  const f = await setup()
  const first = await f.client.connectResource({ resource: f.resource, actions: ["read"] })
  await f.provider.revokeGrant(f.resource.id, first.grant.payload.grantId)
  f.advance(30_000)
  const second = await f.client.connectResource({ resource: f.resource, actions: ["read"] })
  await f.provider.revokeGrant(f.resource.id, second.grant.payload.grantId)
  f.advance(31_000)
  await f.client.connectResource({ resource: f.resource, actions: ["read"] })
  const row = await f.durable.read(`mesh-resource:${f.owner.identity.personId}:${f.resource.id}`)
  expect(row!.revokedGrants).toEqual([second.grant.payload.grantId])
  const proof = await f.client.signOperation(second.grant, { action: "read", bodyDigest: await digest() })
  await expect(f.provider.authorize({ resourceId: f.resource.id, action: "read", bodyDigest: await digest(), grant: second.grant, proof })).rejects.toThrow(/revok/i)
})

it("Given an issued invitation grant whose response was lost, when the client restarts after code expiry, then recover the exact grant without redeeming again", async () => {
  const f = await setup()
  const rows = new Map<string, import("./index").PendingConnection>()
  const pending = { load: async (key: string) => structuredClone(rows.get(key)),
    save: async (key: string, value: import("./index").PendingConnection) => { rows.set(key, structuredClone(value)) },
    remove: async (key: string) => { rows.delete(key) } }
  const code = await f.provider.createInvitation({ resourceId: f.resource.id, subjectPersonId: f.node.identity.personId,
    actions: ["read"], expiresAt: f.now() + 1_000, grantExpiresAt: f.now() + 60_000 })
  let issued: unknown
  const first = new ResourceClient({ profile: f.node, now: f.now, store: pending, transport: async message => {
    const result = await f.provider.handleConnection(message)
    if (result.kind === "connected") { issued = result.grant; throw new Error("Response lost") }
    return result
  } })
  await expect(first.redeemInvitation(code, f.resource)).rejects.toThrow(/Response lost/)
  f.advance(2_000)
  const resumed = new ResourceClient({ profile: f.node, now: f.now, store: pending, transport: message => f.provider.handleConnection(message) })
  await expect(resumed.redeemInvitation(code, f.resource)).resolves.toHaveProperty("grant", issued)
  await expect(resumed.redeemInvitation(code, f.resource)).rejects.toThrow()
})
