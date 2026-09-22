import { describe, expect, it, vi } from "vitest"
import { BrowserMeshOwnershipTransfer } from "./browserOwnership"

describe("BrowserMeshOwnershipTransfer", () => {
  it("persists one signed proposal before confirmed delivery and merge", async () => {
    const order: string[] = []
    const credential = { workspaceId: "workspace", ownerPersonId: "owner", epoch: 1 }
    const transfer = { payload: { epoch: 2, fromOwnerPersonId: "owner", toOwnerPersonId: "member" } }
    const runtime = new BrowserMeshOwnershipTransfer({
      profile: async () => ({ personId: "owner" }), credential: async () => credential,
      peers: async () => [{ personId: "member", deviceId: "device", advertisement: "signed" }],
      online: () => true, confirmationSessions: () => ["session"],
      advertisement: peer => (peer as { advertisement: string }).advertisement,
      verifyTarget: async () => ({ personId: "member" }), transfers: () => [],
      createTransfer: async () => transfer,
      persistProposal: async () => { order.push("persist") },
      confirmDelivery: async () => { order.push("deliver") },
      merge: async () => { order.push("merge") },
      notify: vi.fn(async () => {}), publishAll: vi.fn(async () => {}),
    })

    await runtime.transfer("workspace", "member")

    expect(order).toEqual(["persist", "deliver", "merge"])
  })
})
