import { describe, expect, it, vi } from "vitest"
import { BrowserMeshAuthority, BrowserMeshRecovery } from "./browserAuthority"

describe("BrowserMeshAuthority", () => {
  it("publishes a signed revocation before disconnecting its target", async () => {
    const credential = { workspaceId: "workspace", ownerPersonId: "owner", epoch: 3 }
    const mergeRevocations = vi.fn(async () => {})
    const publishAll = vi.fn(async () => {})
    const createRevocation = vi.fn(async () => ({ signed: "revocation" }))
    const authority = new BrowserMeshAuthority({
      profile: async () => ({ personId: "owner" }), credential: async () => credential,
      createRevocation, nextAccessEpoch: async () => 9,
      mergeRevocations, refreshSuccessionPolicy: vi.fn(async () => {}), publishAll, notify: vi.fn(async () => {}), leave: vi.fn(async () => {}),
    })

    await authority.revokePerson("workspace", "member")

    expect(createRevocation).toHaveBeenCalledWith({ personId: "owner" }, "workspace", "member", 9)
    expect(mergeRevocations).toHaveBeenNthCalledWith(1, credential, [{ signed: "revocation" }], false)
    expect(publishAll.mock.invocationCallOrder[0]).toBeLessThan(mergeRevocations.mock.invocationCallOrder[1]!)
    expect(mergeRevocations).toHaveBeenNthCalledWith(2, credential, [{ signed: "revocation" }], true)
  })
})

describe("BrowserMeshRecovery", () => {
  it("records one editor vote and publishes it", async () => {
    const merge = vi.fn(async () => {})
    const publishAll = vi.fn(async () => {})
    const recovery = new BrowserMeshRecovery({
      profile: async () => ({ personId: "editor" }),
      credential: async () => ({ workspaceId: "workspace", ownerPersonId: "owner" }),
      policy: () => ({ payload: { successorPersonId: null, eligibleEditorPersonIds: ["editor"] } }),
      grant: () => ({ payload: { personId: "editor", role: "editor" } }),
      votes: () => [], certificates: async () => ["certificate"],
      createVote: async () => ({ signed: { payload: { voterPersonId: "editor", candidatePersonId: "candidate" } } }),
      createClaim: async () => ({ claim: true }), merge,
      notify: vi.fn(async () => {}), publishAll,
    })

    await recovery.vote("workspace", "candidate")

    expect(merge).toHaveBeenCalledOnce()
    expect(publishAll).toHaveBeenCalledOnce()
  })
})
