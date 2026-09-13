import { describe, expect, it } from "vitest"
import {
  acquireMeshInstanceLease,
  deriveMeshInstanceSeed,
  tryAcquireMeshLeaderLease,
  type MeshInstanceLocks,
} from "./index"

class FakeLocks implements MeshInstanceLocks {
  private readonly held = new Set<string>()

  async request(name: string, _options: { mode: "exclusive"; ifAvailable: true }, callback: (lock: unknown | null) => Promise<void>) {
    if (this.held.has(name)) return callback(null)
    this.held.add(name)
    try { await callback({ name }) } finally { this.held.delete(name) }
  }
}

describe("mesh runtime instance", () => {
  it("Given two tabs in one app, when both acquire a lease, then live instance ids differ and released slots are reused", async () => {
    const locks = new FakeLocks()
    const first = await acquireMeshInstanceLease({ namespace: "twang", locks })
    const second = await acquireMeshInstanceLease({ namespace: "twang", locks })

    expect(first.instanceId).toBe("slot-0")
    expect(second.instanceId).toBe("slot-1")
    await first.release()
    const replacement = await acquireMeshInstanceLease({ namespace: "twang", locks })
    expect(replacement.instanceId).toBe("slot-0")

    await second.release()
    await replacement.release()
  })

  it("Given one device seed, when two tab ids derive transport seeds, then each endpoint seed is stable and distinct", async () => {
    const base = new Uint8Array(32).fill(7)
    const first = await deriveMeshInstanceSeed(base, "twang", "slot-0")
    const repeated = await deriveMeshInstanceSeed(base, "twang", "slot-0")
    const second = await deriveMeshInstanceSeed(base, "twang", "slot-1")

    expect(first).toEqual(repeated)
    expect(first).not.toEqual(second)
  })

  it("Given separate apps, when both acquire slot zero, then namespaces prevent lock collisions", async () => {
    const locks = new FakeLocks()
    const twang = await acquireMeshInstanceLease({ namespace: "twang", locks })
    const match = await acquireMeshInstanceLease({ namespace: "match", locks })
    expect(twang.instanceId).toBe("slot-0")
    expect(match.instanceId).toBe("slot-0")
    await twang.release()
    await match.release()
  })

  it("Given two tabs of one identity, when both request leadership, then only one owns the rendezvous", async () => {
    const locks = new FakeLocks()
    const first = await tryAcquireMeshLeaderLease({ namespace: "twang", name: "identity", locks })
    const second = await tryAcquireMeshLeaderLease({ namespace: "twang", name: "identity", locks })
    expect(first).not.toBeNull()
    expect(second).toBeNull()
    await first!.release()
    expect(await tryAcquireMeshLeaderLease({ namespace: "twang", name: "identity", locks })).not.toBeNull()
  })
})
