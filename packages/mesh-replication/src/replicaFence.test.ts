import { expect, it } from "vitest"
import { ReplicaEngine, emptyReplicaState, parseReplicaState, type ReplicaState } from "./replicaEngine"

function fixture() {
  let state = { ...emptyReplicaState<string>("storage"), cursor: 7 }
  let fail = true
  const uploads: unknown[][] = []
  const ports = {
    repository: { read: async () => structuredClone(state), commit: async (_: number, next: ReplicaState<string>) => { state = structuredClone(next) } },
    content: { revision: async () => "revision", capture: async () => ({ hash: "hash", bytes: 1, payload: "original" }), seal: async (value: string) => value },
    transport: { inventory: async () => ({ objects: [], cursor: 19, hasMore: false }), download: async () => "remote",
      upload: async (...args: unknown[]) => { uploads.push(args); if (fail) throw new Error("Lost response"); return "receipt" } },
    admit: async () => ({ hash: "remote" }), verifyReceipt: async () => {}, guard: async () => {},
  }
  return { engine: () => new ReplicaEngine("storage", ports), uploads, state: () => structuredClone(state),
    resume: () => { fail = false; state = { ...state, cursor: 19 } } }
}

it("Given a pending snapshot prepared at sequence seven, when restart observes a newer checkpoint, then retry retains original fence, ciphertext and request", async () => {
  const f = fixture()
  await expect(f.engine().push()).rejects.toThrow("Lost response")
  expect(f.state().pending).toMatchObject({ observedSequence: 7, object: "original" })
  f.resume()
  await f.engine().push()
  expect(f.uploads[0]?.[2]).toBe(7)
  expect(f.uploads[1]).toEqual(f.uploads[0])
})

it("Given legacy pending ciphertext without an observed sequence, when restarting at a newer cursor, then upload keeps the legacy zero fence", async () => {
  const f = fixture()
  await expect(f.engine().push()).rejects.toThrow("Lost response")
  const legacy = f.state()
  delete (legacy.pending as { observedSequence?: number }).observedSequence
  const uploads: unknown[][] = []
  const state = parseReplicaState<string>(legacy, "storage")
  const engine = new ReplicaEngine("storage", {
    repository: { read: async () => ({ ...state, cursor: 19 }), commit: async () => {} },
    content: { revision: async () => "revision", capture: async () => { throw new Error("Do not replace pending ciphertext") }, seal: async () => "" },
    transport: { inventory: async () => ({ objects: [], cursor: 19, hasMore: false }), download: async () => "",
      upload: async (...args: unknown[]) => { uploads.push(args); return "receipt" } },
    admit: async () => ({ hash: "remote" }), verifyReceipt: async () => {}, guard: async () => {},
  })
  await engine.push()
  expect(uploads[0]?.[2]).toBe(0)
})

it("Given an outbox sequence outside admitted progress, when loading it, then reject without upload", () => {
  for (const observedSequence of [-1, 1.5, NaN, 8]) {
    expect(() => parseReplicaState({ ...emptyReplicaState("storage"), cursor: 7,
      pending: { requestId: "request", hash: "hash", bytes: 1, object: "bytes", observedSequence } }, "storage")).toThrow()
  }
})
