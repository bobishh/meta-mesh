import * as Automerge from "@automerge/automerge"
import { describe, expect, it } from "vitest"
import { BrowserIdentityStore, canonicalizeJson, sha256Base64Url, signEnvelope, type LocalProfile } from "@meta-uber/mesh-identity"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
import { createWorkspaceGrant, createWorkspaceRevocation } from "./index"

type Status = { type: "admitted"; role: string } | { type: "quarantined" | "pending"; reason: string }
type Plan = { decisions: Array<{ hash: string; status: Status }>; authorizedDocument: number[] }
type Board = { id: string; ownerPersonId: string; title: string }
const authority = (person: LocalProfile) => ({ personId: person.identity.personId,
  publicKey: person.identity.publicKey, certificates: [person.certificate] })

async function fixtures() {
  const alice = await new BrowserIdentityStore({ storageKey: crypto.randomUUID(), signatureDomain: "MATCH/1" }).bootstrap("Alice")
  const bob = await new BrowserIdentityStore({ storageKey: crypto.randomUUID(), signatureDomain: "MATCH/1" }).bootstrap("Bob")
  const base = Automerge.from<Board>({ id: "causal-board", ownerPersonId: alice.identity.personId, title: "Original" })
  const grant = await createWorkspaceGrant(alice, base.id, bob.identity.personId, "editor", 1)
  const grantHash = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(grant)))
  const edited = Automerge.change(Automerge.clone(base), { message: JSON.stringify({
    kind: "workspace-change-metadata", version: 1, personId: bob.identity.personId, deviceId: bob.device.deviceId, authorityGrantHash: grantHash,
  }), time: 8_640_000_000_000 }, draft => { draft.title = "Offline draft" })
  const editHash = Automerge.decodeChange(Automerge.getLastLocalChange(edited)!).hash
  const baseHash = Automerge.getHeads(base)[0]
  async function proof(person: LocalProfile, hash: string, attachedGrant?: typeof grant) {
    return { signed: await signEnvelope(person.privateKeys.devicePrivateKey, {
      kind: "workspace-changes", version: 1, workspaceId: base.id, hashes: [hash],
      personId: person.identity.personId, deviceId: person.device.deviceId,
    }, person.device.deviceId), publicKey: person.identity.publicKey, certificates: [person.certificate],
    ...(attachedGrant ? { grant: attachedGrant } : {}) }
  }
  const genesisProof = await proof(alice, baseHash)
  const editorProof = await proof(bob, editHash, grant)
  const snapshot = { workspaceId: base.id, genesisOwner: authority(alice), genesisEpoch: 1,
    expectedCurrentOwner: authority(alice), document: Array.from(Automerge.save(edited)),
    ownershipTransfers: [], successionClaims: [], revocations: [], deviceRevocations: [], departures: [] }
  return { alice, bob, base, edited, editHash, grant, proof, genesisProof, editorProof, snapshot }
}

describe("causal admission through actual WASM", () => {
  it("Given a far-future admitted edit, when owner writes a causal successor, then timestamp cannot lock the title", async () => {
    const f = await fixtures()
    const next = Automerge.change(Automerge.clone(f.edited), { time: -10_000, message: JSON.stringify({
      kind: "workspace-change-metadata", version: 1, personId: f.alice.identity.personId, deviceId: f.alice.device.deviceId,
    }) }, draft => { draft.title = "Later authorized title" })
    const hash = Automerge.decodeChange(Automerge.getLastLocalChange(next)!).hash
    const plan = meshRustRuntime().state.evaluateCausalAdmission({
      records: [f.genesisProof, f.editorProof, await f.proof(f.alice, hash)],
      snapshot: { ...f.snapshot, document: Array.from(Automerge.save(next)) }, nowMs: 0,
    }) as Plan
    expect(plan.decisions.every(d => d.status.type === "admitted")).toBe(true)
    expect(Automerge.load<Board>(new Uint8Array(plan.authorizedDocument)).title).toBe("Later authorized title")
  })

  it("Given previously accepted edit, when revocation arrives, then view retracts edit while raw bytes stay", async () => {
    const f = await fixtures()
    const evaluate = (revocations: unknown[], nowMs = Date.now()) => meshRustRuntime().state.evaluateCausalAdmission({
      records: [f.genesisProof, f.editorProof], snapshot: { ...f.snapshot, revocations }, nowMs,
    }) as Plan
    const before = evaluate([])
    expect(before.decisions.find(d => d.hash === f.editHash)?.status.type).toBe("admitted")
    const revocation = await createWorkspaceRevocation(f.alice, f.base.id, f.bob.identity.personId, 2, Automerge.getHeads(f.base))
    const after = evaluate([revocation])
    expect(after.decisions.find(d => d.hash === f.editHash)?.status.type).toBe("quarantined")
    const view = Automerge.load<Board>(new Uint8Array(after.authorizedDocument))
    expect(view.title).toBe("Original")
    expect(f.edited.title).toBe("Offline draft")
    expect(evaluate([revocation], 0).decisions).toEqual(evaluate([revocation], 9_999_999_999_999).decisions)
    expect(() => meshRustRuntime().state.evaluateCausalAdmission({
      records: [f.genesisProof], snapshot: f.snapshot, nowMs: Date.now(), unexpected: true,
    })).toThrow(/unknown field/i)
  })

  it("Given a new grant, when attached to old bytes, then hash-bound provenance refuses retroactive approval", async () => {
    const f = await fixtures()
    const revocation = await createWorkspaceRevocation(f.alice, f.base.id, f.bob.identity.personId, 2, Automerge.getHeads(f.base))
    const newer = await createWorkspaceGrant(f.alice, f.base.id, f.bob.identity.personId, "editor", 3)
    const borrowedGrant = await f.proof(f.bob, f.editHash, newer)
    const plan = meshRustRuntime().state.evaluateCausalAdmission({ records: [f.genesisProof, borrowedGrant],
      snapshot: { ...f.snapshot, revocations: [revocation] }, nowMs: Date.now() }) as Plan
    expect(plan.decisions.find(d => d.hash === f.editHash)?.status.type).toBe("quarantined")
    const dependent = Automerge.change(Automerge.clone(f.edited), { message: JSON.stringify({
      kind: "workspace-change-metadata", version: 1, personId: f.alice.identity.personId, deviceId: f.alice.device.deviceId,
    }) }, draft => { draft.title = "Owner descendant" })
    const bytes = Automerge.getLastLocalChange(dependent)!
    const hash = Automerge.decodeChange(bytes).hash
    const dependentProof = await f.proof(f.alice, hash)
    const missing = meshRustRuntime().state.evaluateCausalAdmission({
      records: [f.genesisProof, dependentProof], snapshot: { ...f.snapshot, document: Array.from(Automerge.save(f.base)) },
      pendingChangeBytes: [Array.from(bytes)], nowMs: Date.now(),
    }) as Plan
    expect(missing.decisions.find(d => d.hash === hash)?.status.type).toBe("pending")
  })
})
