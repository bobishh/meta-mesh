import { describe, expect, it, vi } from "vitest"
import { memoizeIdentityEnrollmentPeerRuntimePromotion } from "./browserIdentityEnrollment"
import type { BrowserIdentityPeerRuntime } from "./browserIdentityReconnect"

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  const promise = new Promise<T>(res => { resolve = res })
  return { promise, resolve }
}

describe("Identity enrollment peer runtime promotion", () => {
  it("Given concurrent promotion and close during module loading, when adoption resumes, then it rejects without adopting a closed node", async () => {
    let closed = false
    const loaded = deferred<() => BrowserIdentityPeerRuntime>()
    const adopt = vi.fn(() => ({ startHost: vi.fn(), connect: vi.fn(), close: vi.fn(async () => undefined) }))
    const promote = memoizeIdentityEnrollmentPeerRuntimePromotion({
      isClosed: () => closed,
      validate: vi.fn(),
      loadAdopter: vi.fn(() => loaded.promise),
    })
    const first = promote()
    const concurrent = promote()
    expect(concurrent).toBe(first)
    closed = true
    loaded.resolve(adopt as unknown as () => BrowserIdentityPeerRuntime)

    await expect(first).rejects.toThrow("closed before peer runtime promotion")
    expect(adopt).not.toHaveBeenCalled()
    await expect(promote()).rejects.toThrow("Identity enrollment is closed")
  })

  it("Given concurrent promotion requests, when the loader completes, then both receive one runtime adoption", async () => {
    const runtime = { startHost: vi.fn(), connect: vi.fn(), close: vi.fn(async () => undefined) }
    const adopt = vi.fn(() => runtime)
    const promote = memoizeIdentityEnrollmentPeerRuntimePromotion({
      isClosed: () => false,
      validate: vi.fn(),
      loadAdopter: async () => adopt,
    })

    const [first, second] = await Promise.all([promote(), promote()])
    expect(first).toBe(runtime)
    expect(second).toBe(runtime)
    expect(adopt).toHaveBeenCalledOnce()
  })
})
