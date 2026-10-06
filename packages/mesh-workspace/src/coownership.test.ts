import { describe, expect, it } from "vitest"
import { BrowserIdentityStore, createRecoverableIdentity, openIdentityRecoveryEnvelope, type LocalProfile } from "@meta-uber/mesh-identity"
import {
  approveCoownershipPayload, coownerIdentity, createCoownershipLedger, forkCoownershipLedger,
  mergeCoownershipLedgers, planCoownershipResolution, planCoownershipTransition,
  validateCoownershipLedger, type CoownedTransitionPayload, type CoownershipLedger,
} from "./coownership"

async function profile(name: string) {
  return new BrowserIdentityStore({ storageKey: crypto.randomUUID(), signatureDomain: "MATCH/1" }).bootstrap(name)
}

async function transition(ledger: CoownershipLedger, payload: CoownedTransitionPayload, people: LocalProfile[]) {
  const approvals = await Promise.all(people.map(person => approveCoownershipPayload(person, payload)))
  return { ...ledger, transitions: [...ledger.transitions, { payload, approvals }] }
}

async function twoOwners() {
  const alice = await profile("Alice")
  const bob = await profile("Bob")
  const genesis = await createCoownershipLedger(alice, "board-alpha")
  const payload = planCoownershipTransition(genesis, [coownerIdentity(bob), coownerIdentity(alice)], "majority")
  const ledger = await transition(genesis, payload, [alice])
  expect(validateCoownershipLedger(ledger).status.status).toBe("authorized")
  return { alice, bob, ledger }
}

describe("opt-in co-ownership through real WASM and browser signatures", () => {
  it("Given restored identity on a new device, when approving, then same owner vote works but quorum still applies", async () => {
    const recovery = await createRecoverableIdentity("better", "Alice")
    const alice = recovery.profile
    const bob = await profile("Bob")
    let ledger = await createCoownershipLedger(alice, "recovery-board")
    ledger = await transition(ledger, planCoownershipTransition(ledger,
      [coownerIdentity(alice), coownerIdentity(bob)], "majority"), [alice])
    const restored = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey)
    expect(restored.identity.personId).toBe(alice.identity.personId)
    expect(restored.device.deviceId).not.toBe(alice.device.deviceId)
    const payload = planCoownershipTransition(ledger, [coownerIdentity(bob)], "majority")
    expect(() => validateCoownershipLedger({ ...ledger, transitions: [...ledger.transitions,
      { payload, approvals: [] }] })).toThrow()
    const oneVote = await transition(ledger, payload, [restored])
    expect(() => validateCoownershipLedger(oneVote)).toThrow(/insufficient distinct/i)
    const bothVotes = await transition(ledger, payload, [restored, bob])
    expect(validateCoownershipLedger(bothVotes).status.status).toBe("authorized")
    const afterRemoval = planCoownershipTransition(bothVotes, [coownerIdentity(restored), coownerIdentity(bob)], "majority")
    const removedVote = await transition(bothVotes, afterRemoval, [restored])
    expect(() => validateCoownershipLedger(removedVote)).toThrow(/invalid co-ownership signer/i)
  })
  it("Given two owners, when one tries removal, then quorum rejects; both signatures authorize", async () => {
    const { alice, bob, ledger } = await twoOwners()
    const payload = planCoownershipTransition(ledger, [coownerIdentity(alice)], "majority")
    const insufficient = await transition(ledger, payload, [alice])
    expect(() => validateCoownershipLedger(insufficient)).toThrow(/insufficient distinct co-owner approvals/i)
    const accepted = await transition(ledger, payload, [alice, bob])
    const state = validateCoownershipLedger(accepted).status
    expect(state.status).toBe("authorized")
    if (state.status === "authorized") expect(state.value.owners.map(owner => owner.personId)).toEqual([alice.identity.personId])
    const malformed = structuredClone(accepted)
    ;(malformed.transitions[1].payload as unknown as Record<string, unknown>).extra = true
    expect(() => validateCoownershipLedger(malformed)).toThrow(/unknown field/i)
    expect(() => mergeCoownershipLedgers(malformed, accepted)).toThrow(/unknown field/i)
    expect(() => mergeCoownershipLedgers(accepted, malformed)).toThrow(/unknown field/i)
    const oversizedEpoch = structuredClone(accepted)
    oversizedEpoch.transitions[1].payload.epoch = Number.MAX_SAFE_INTEGER + 1
    expect(() => validateCoownershipLedger(oversizedEpoch)).toThrow()
  })

  it("Given offline conflicting changes, when merged and resolved, then evidence survives; late change reopens", async () => {
    const { alice, bob, ledger } = await twoOwners()
    const left = await transition(ledger, planCoownershipTransition(ledger, [coownerIdentity(alice)], "majority"), [alice, bob])
    const right = await transition(ledger, planCoownershipTransition(ledger, [coownerIdentity(bob)], "majority"), [alice, bob])
    const merged = mergeCoownershipLedgers(left, right)
    const status = validateCoownershipLedger(merged).status
    expect(status.status).toBe("ambiguous")
    expect(() => planCoownershipTransition(merged, [coownerIdentity(alice)], "unanimous")).toThrow(/ambiguous/i)
    if (status.status !== "ambiguous") throw new Error("Expected conflict")
    const payload = planCoownershipResolution(merged, status.value.conflicts[0].parentCertificateHash,
      [coownerIdentity(alice), coownerIdentity(bob)], "unanimous")
    const approvals = await Promise.all([alice, bob].map(person => approveCoownershipPayload(person, payload)))
    const resolved = mergeCoownershipLedgers(merged, { ...merged, resolutions: [{ payload, approvals }] })
    expect(validateCoownershipLedger(resolved).status.status).toBe("authorized")
    expect(resolved.transitions).toHaveLength(3)
    expect(resolved.resolutions).toHaveLength(1)
    const late = await transition(ledger, planCoownershipTransition(ledger,
      [coownerIdentity(alice), coownerIdentity(bob)], "unanimous"), [alice, bob])
    const reopened = mergeCoownershipLedgers(resolved, late)
    expect(validateCoownershipLedger(reopened).status.status).toBe("ambiguous")
    expect(reopened.transitions).toHaveLength(4)
    expect(reopened.resolutions).toHaveLength(1)
    expect(mergeCoownershipLedgers(reopened, late)).toEqual(reopened)
  })

  it("Given unavailable agreement, when forked, then fresh scope has caller only and source stays intact", async () => {
    const { alice, bob, ledger } = await twoOwners()
    const left = await transition(ledger, planCoownershipTransition(ledger, [coownerIdentity(alice)], "majority"), [alice, bob])
    const right = await transition(ledger, planCoownershipTransition(ledger, [coownerIdentity(bob)], "majority"), [alice, bob])
    const source = mergeCoownershipLedgers(left, right)
    const before = structuredClone(source)
    await expect(forkCoownershipLedger(source, alice, "board-alpha")).rejects.toThrow(/different|new scope/i)
    const fork = await forkCoownershipLedger(source, alice, "board-fork")
    const status = validateCoownershipLedger(fork).status
    expect(status.status).toBe("authorized")
    if (status.status === "authorized") {
      expect(status.value.scopeId).toBe("board-fork")
      expect(status.value.epoch).toBe(1)
      expect(status.value.owners.map(owner => owner.personId)).toEqual([alice.identity.personId])
    }
    expect(fork.transitions).toEqual([])
    expect(fork.resolutions).toEqual([])
    expect(source).toEqual(before)
    expect(validateCoownershipLedger(source).status.status).toBe("ambiguous")
  })
})
