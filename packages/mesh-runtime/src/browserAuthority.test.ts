import { describe, expect, it, vi } from "vitest"
import { BrowserMeshAuthority } from "./browserAuthority"

describe("BrowserMeshAuthority", () => {
  it("publishes a signed revocation before disconnecting its target", async () => {
    const credential = { workspaceId: "workspace", ownerPersonId: "owner", epoch: 3 }
    const mergeRevocations = vi.fn(async () => {})
    const publishAll = vi.fn(async () => {})
    const authority = new BrowserMeshAuthority({
      profile: async () => ({ personId: "owner" }), credential: async () => credential,
      createRevocation: async () => ({ signed: "revocation" }), epoch: item => item.epoch,
      mergeRevocations, refreshSuccessionPolicy: vi.fn(async () => {}), publishAll, notify: vi.fn(async () => {}), leave: vi.fn(async () => {}),
    })

    await authority.revokePerson("workspace", "member")

    expect(mergeRevocations).toHaveBeenNthCalledWith(1, credential, [{ signed: "revocation" }], false)
    expect(publishAll.mock.invocationCallOrder[0]).toBeLessThan(mergeRevocations.mock.invocationCallOrder[1]!)
    expect(mergeRevocations).toHaveBeenNthCalledWith(2, credential, [{ signed: "revocation" }], true)
  })
})
