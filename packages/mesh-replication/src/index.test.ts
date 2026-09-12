import { describe, expect, it } from "vitest"
import { reconcileReplicaSet, type ReplicaSet } from "./index"

type Label = { text: string }

const at = (seconds: number) => new Date(seconds * 1_000).toISOString()

describe("mesh replication", () => {
  it("Given a chat exists on one device, when devices reconcile, then both can receive it", () => {
    const computer: ReplicaSet<Label> = {
      records: [{ id: "chat-1", updatedAt: at(1), value: { text: "Recruiter" } }],
      tombstones: [],
    }

    expect(reconcileReplicaSet(computer, { records: [], tombstones: [] }).records).toEqual(computer.records)
  })

  it("Given both devices renamed a chat, when devices reconcile, then the latest label wins", () => {
    const computer: ReplicaSet<Label> = {
      records: [{ id: "chat-1", updatedAt: at(1), value: { text: "Old" } }],
      tombstones: [],
    }
    const mobile: ReplicaSet<Label> = {
      records: [{ id: "chat-1", updatedAt: at(2), value: { text: "New" } }],
      tombstones: [],
    }

    expect(reconcileReplicaSet(computer, mobile).records[0].value.text).toBe("New")
  })

  it("Given one device deleted a pending request, when stale state returns, then it stays deleted", () => {
    const computer: ReplicaSet<Label> = {
      records: [{ id: "request-1", updatedAt: at(1), value: { text: "Hello" } }],
      tombstones: [],
    }
    const mobile: ReplicaSet<Label> = {
      records: [],
      tombstones: [{ id: "request-1", deletedAt: at(2) }],
    }

    const merged = reconcileReplicaSet(computer, mobile)
    expect(merged.records).toEqual([])
    expect(reconcileReplicaSet(merged, computer).records).toEqual([])
  })

  it("Given malformed replication data, when reconciled, then it is rejected", () => {
    const malformed: ReplicaSet<Label> = {
      records: [{ id: "chat-1", updatedAt: "tomorrowish", value: { text: "No" } }],
      tombstones: [],
    }

    expect(() => reconcileReplicaSet(malformed, { records: [], tombstones: [] })).toThrow("timestamp")
  })
})
