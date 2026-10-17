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
  const provider = new ResourceProvider({ profile: owner, store: store(), now: () => now,
    approve: async request => { approvals++; return allow ? { actions: request.actions, expiresAt: now + 60_000 } : null } })
  const resource = await provider.addResource({ id: "board-a", title: "Board A", audience: "https://board.example",
    actions: ["read", "create", "update"], readScope: "Entire Board A" })
  const client = new ResourceClient({ profile: node, now: () => now, transport: message => provider.handleConnection(message) })
  return { owner, node, provider, client, resource, now: () => now, advance: (ms: number) => { now += ms },
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
