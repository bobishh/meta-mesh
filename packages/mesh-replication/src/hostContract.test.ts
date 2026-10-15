import { describe, expect, it } from "vitest"
import { ReplicaEngine, emptyReplicaState } from "./replicaEngine"
import type { ReplicaInventory } from "./replicaEngine"

type Payload = { text: string }
type Ciphertext = { ciphertext: string }
type Pending = { requestId: string; revision?: string; hash: string; bytes: number; object: Ciphertext; identity?: string }
type State = {
  version: 1
  binding: string
  generation: number
  cursor: number
  lastUploaded: string
  uploadedRevision?: string
  contentIdentity?: string
  pending?: Pending
}

function fixture(options: {
  revision?: string
  payload?: Payload
  inventory?: Array<{ objectId: string; sequence: number }>
  inventoryResponse?: (cursor: number) => ReplicaInventory
  admissionError?: Error
  receiptError?: Error
  commitError?: Error
  commitErrorAt?: number
  beforeUpload?: () => void | Promise<void>
  beforeVerify?: () => void | Promise<void>
  beforeCommit?: (attempt: number) => void | Promise<void>
  mutateUploadArgument?: boolean
  initialState?: Partial<State>
  guard?: () => void | Promise<void>
  beforeCapture?: () => void | Promise<void>
} = {}) {
  let state: State = { ...(emptyReplicaState<Payload>("workspace-a") as State), ...options.initialState }
  let revision = options.revision ?? "revision-1"
  let payload = options.payload ?? { text: "snapshot-1" }
  const inventoryObjects = options.inventory ?? []
  const calls = {
    captures: 0,
    seals: 0,
    uploads: [] as Array<{ object: Ciphertext; requestId: string }>,
    admissions: [] as Array<{ object: Ciphertext; sequence: number }>,
    commits: [] as Array<{ expected: number; next: State }>,
    verifies: [] as Array<{ object: string; requestId: string }>,
    guards: 0,
    revisions: 0,
    inventories: 0,
  }
  let lostReceiptOnce = false
  let commitAttempt = 0
  let activeReceiptError = options.receiptError
  let activeCommitError = options.commitError

  const ports = {
    repository: {
      read: async () => structuredClone(state),
      commit: async (expectedGeneration: number, next: State) => {
        commitAttempt += 1
        calls.commits.push({ expected: expectedGeneration, next: structuredClone(next) })
        await options.beforeCommit?.(commitAttempt)
        if (activeCommitError && commitAttempt === (options.commitErrorAt ?? 1)) throw activeCommitError
        if (state.generation !== expectedGeneration) throw new Error("CAS conflict")
        state = structuredClone({ ...next, generation: expectedGeneration + 1 })
      },
    },
    content: {
      revision: async () => { calls.revisions += 1; return revision },
      capture: async () => {
        calls.captures += 1
        await options.beforeCapture?.()
        const bytes = new TextEncoder().encode(payload.text)
        return { hash: `hash:${payload.text}`, bytes: bytes.byteLength, payload: structuredClone(payload), identity: `identity:${revision}` }
      },
      seal: async (value: Payload) => {
        calls.seals += 1
        return { ciphertext: `sealed:${value.text}` }
      },
    },
    transport: {
      inventory: async (cursor: number) => {
        calls.inventories += 1
        return options.inventoryResponse?.(cursor) ?? ({ objects: inventoryObjects.filter(object => object.sequence > cursor),
          cursor: inventoryObjects.filter(object => object.sequence > cursor).at(-1)?.sequence ?? cursor, hasMore: false })
      },
      download: async (id: string): Promise<Ciphertext> => ({ ciphertext: `downloaded:${id}` }),
      upload: async (object: Ciphertext, requestId: string) => {
        const ciphertext = object.ciphertext
        calls.uploads.push({ object: structuredClone(object), requestId })
        await options.beforeUpload?.()
        if (options.mutateUploadArgument) object.ciphertext = "mutated-by-transport"
        return { object: ciphertext, requestId, valid: true }
      },
    },
    admit: async (object: Ciphertext, sequence: number) => {
      calls.admissions.push({ object, sequence })
      if (options.admissionError) throw options.admissionError
      return { hash: `admitted:${object.ciphertext}`, identity: `remote:${sequence}` }
    },
    verifyReceipt: async (receipt: { object: string; requestId: string; valid: boolean }, object: Ciphertext, requestId: string) => {
      calls.verifies.push({ object: object.ciphertext, requestId })
      await options.beforeVerify?.()
      if (activeReceiptError || !receipt.valid || receipt.object !== object.ciphertext || receipt.requestId !== requestId) {
        throw activeReceiptError ?? new Error("invalid receipt")
      }
      if (lostReceiptOnce) {
        lostReceiptOnce = false
        throw new Error("receipt persistence interrupted")
      }
    },
    guard: async () => {
      calls.guards += 1
      await options.guard?.()
    },
  }
  const engine = () => new ReplicaEngine("workspace-a", ports)
  return {
    engine,
    calls,
    read: () => structuredClone(state),
    setRevision: (next: string) => { revision = next },
    setPayload: (next: Payload) => { payload = next },
    loseNextReceipt: () => { lostReceiptOnce = true },
    clearReceiptError: () => { activeReceiptError = undefined },
    clearCommitError: () => { activeCommitError = undefined },
  }
}

describe("shared replica host contract", () => {
  it("Given an uncertain old-basis upload, when sync receives a compact basis, then acknowledge the exact old request before attempting incoming admission", async () => {
    const pending: Pending = { requestId: "old-request", hash: "old-hash", bytes: 10,
      object: { ciphertext: "exact-original-ciphertext" }, revision: "revision-1" }
    const f = fixture({ initialState: { pending }, inventory: [{ objectId: "new-basis", sequence: 1 }],
      admissionError: new Error("Basis awaits local-head coverage"), inventoryResponse: cursor => {
        expect(f.read().pending).toBeUndefined()
        expect(f.read().lastUploaded).toBe(pending.hash)
        return { objects: [{ objectId: "new-basis", sequence: 1 }], cursor: 1, hasMore: false }
      } })
    await expect(f.engine().sync()).resolves.toBe(false)
    expect(f.calls.inventories).toBe(0)
    await expect(f.engine().sync()).rejects.toThrow("Basis awaits local-head coverage")
    expect(f.calls.uploads).toEqual([{ requestId: pending.requestId, object: pending.object }])
    expect(f.calls.captures).toBe(0)
    expect(f.calls.seals).toBe(0)
    expect(f.read()).toMatchObject({ cursor: 0, lastUploaded: pending.hash })
  })

  it("Given the old outbox has no verified receipt, when sync retries, then preserve original ciphertext and skip incoming basis admission", async () => {
    const pending: Pending = { requestId: "old-request", hash: "old-hash", bytes: 10,
      object: { ciphertext: "exact-original-ciphertext" }, revision: "revision-1" }
    const f = fixture({ initialState: { pending }, receiptError: new Error("Reply unavailable") })
    await expect(f.engine().sync()).rejects.toThrow("Reply unavailable")
    expect(f.read().pending).toEqual(pending)
    expect(f.calls.inventories).toBe(0)
    expect(f.calls.admissions).toEqual([])
    expect(f.calls.captures).toBe(0)
    f.clearReceiptError()
    await f.engine().sync()
    expect(f.calls.uploads).toEqual([{ requestId: pending.requestId, object: pending.object },
      { requestId: pending.requestId, object: pending.object }])
    expect(f.calls.captures).toBe(0)
  })

  it("Given an acknowledged snapshot, when push runs again in this engine or after restart, then unchanged revision skips capture, sealing, and upload", async () => {
    const f = fixture()
    const first = f.engine()
    await first.push()
    const before = { ...f.calls, uploads: [...f.calls.uploads] }

    await first.push()
    await f.engine().push()

    expect(f.calls.captures).toBe(before.captures)
    expect(f.calls.seals).toBe(before.seals)
    expect(f.calls.uploads).toEqual(before.uploads)
  })

  it("Given upload preparation, when transport starts, then pending ciphertext and request ID are durable first", async () => {
    const f = fixture()
    const portsEngine = f.engine()
    await portsEngine.push()

    expect(f.calls.commits.length).toBeGreaterThanOrEqual(2)
    expect(f.calls.commits[0]?.next.pending).toMatchObject({ object: { ciphertext: "sealed:snapshot-1" }, hash: "hash:snapshot-1" })
    expect(f.calls.commits[0]?.next.pending?.requestId).toBe(f.calls.uploads[0]?.requestId)
    expect(f.calls.uploads[0]?.object).toEqual({ ciphertext: "sealed:snapshot-1" })
  })

  it("Given upload committed remotely but receipt handling failed, when a new engine retries, then exact ciphertext and request ID are reused", async () => {
    const f = fixture()
    f.loseNextReceipt()
    await expect(f.engine().push()).rejects.toThrow("receipt persistence interrupted")
    const durablePending = f.read().pending

    await f.engine().push()

    expect(f.calls.uploads).toHaveLength(2)
    expect(f.calls.uploads[1]).toEqual({ object: durablePending?.object, requestId: durablePending?.requestId })
    expect(f.calls.seals).toBe(1)
  })

  it("Given receipt verification rejects, when upload returns, then uploaded acknowledgement is not committed and pending remains", async () => {
    const f = fixture({ receiptError: new Error("signature rejected") })

    await expect(f.engine().push()).rejects.toThrow("signature rejected")

    expect(f.read().pending).toMatchObject({ object: { ciphertext: "sealed:snapshot-1" } })
    expect(f.read().lastUploaded).toBe("")
    expect(f.read().uploadedRevision).toBeUndefined()
  })

  it("Given durable acknowledgement write fails, when receipt verifies, then pending ciphertext remains retryable", async () => {
    const f = fixture({ commitError: new Error("ack write failed"), commitErrorAt: 2 })

    await expect(f.engine().push()).rejects.toThrow("ack write failed")

    expect(f.read().pending).toMatchObject({ object: { ciphertext: "sealed:snapshot-1" } })
    expect(f.read().lastUploaded).toBe("")
  })

  it("Given remote admission fails, when pull processes an object, then cursor does not advance", async () => {
    const f = fixture({ inventory: [{ objectId: "object-1", sequence: 1 }], admissionError: new Error("admission denied") })

    await expect(f.engine().pull()).rejects.toThrow("admission denied")

    expect(f.read().cursor).toBe(0)
    expect(f.read().generation).toBe(0)
  })

  it("Given admission succeeds but cursor commit fails, when poll retries, then same object is admitted again from unchanged cursor", async () => {
    const f = fixture({ inventory: [{ objectId: "object-1", sequence: 1 }], commitError: new Error("cursor write failed"), commitErrorAt: 1 })

    await expect(f.engine().pull()).rejects.toThrow("cursor write failed")

    expect(f.read().cursor).toBe(0)
    expect(f.calls.admissions).toEqual([{ object: { ciphertext: "downloaded:object-1" }, sequence: 1 }])
  })

  it("Given a live guard changes while snapshot capture awaits, when push resumes, then it rejects without uploading", async () => {
    let blocked = false
    let releaseCapture!: () => void
    let captured!: () => void
    const captureStarted = new Promise<void>(resolve => { captured = resolve })
    const captureGate = new Promise<void>(resolve => { releaseCapture = resolve })
    const f = fixture({
      beforeCapture: async () => { captured(); await captureGate },
      guard: () => { if (blocked) throw new Error("binding revoked") },
    })
    const pushing = f.engine().push()
    await captureStarted
    blocked = true
    releaseCapture()

    await expect(pushing).rejects.toThrow("binding revoked")
    expect(f.calls.uploads).toEqual([])
  })

  it("Given authorization is revoked during upload, when transport returns, then receipt verification and acknowledgment stop", async () => {
    let blocked = false
    let releaseUpload!: () => void
    let uploadStarted!: () => void
    const started = new Promise<void>(resolve => { uploadStarted = resolve })
    const gate = new Promise<void>(resolve => { releaseUpload = resolve })
    const f = fixture({
      beforeUpload: async () => { uploadStarted(); await gate },
      guard: () => { if (blocked) throw new Error("binding revoked") },
    })
    const pushing = f.engine().push()
    await started
    blocked = true
    releaseUpload()

    await expect(pushing).rejects.toThrow("binding revoked")
    expect(f.calls.verifies).toEqual([])
    expect(f.read().pending).toMatchObject({ object: { ciphertext: "sealed:snapshot-1" } })
    expect(f.read().lastUploaded).toBe("")
  })

  it("Given authorization is revoked during receipt verification, when verification returns, then acknowledgment is blocked", async () => {
    let blocked = false
    let releaseVerification!: () => void
    let verificationStarted!: () => void
    const started = new Promise<void>(resolve => { verificationStarted = resolve })
    const gate = new Promise<void>(resolve => { releaseVerification = resolve })
    const f = fixture({
      beforeVerify: async () => { verificationStarted(); await gate },
      guard: () => { if (blocked) throw new Error("binding revoked") },
    })
    const pushing = f.engine().push()
    await started
    blocked = true
    releaseVerification()

    await expect(pushing).rejects.toThrow("binding revoked")
    expect(f.read().pending).toMatchObject({ object: { ciphertext: "sealed:snapshot-1" } })
    expect(f.read().lastUploaded).toBe("")
  })

  it("Given malformed or replayed inventory sequences, when pulling, then reject without admission or cursor movement", async () => {
    const malformed = fixture({ inventoryResponse: cursor => ({ objects: [
      { objectId: "object-1", sequence: cursor + 1 }, { objectId: "object-2", sequence: cursor + 1 },
    ], cursor: cursor + 1, hasMore: false }) })
    await expect(malformed.engine().pull()).rejects.toThrow(/inventory sequence/i)
    expect(malformed.calls.admissions).toEqual([])
    expect(malformed.read().cursor).toBe(0)

    const replayed = fixture({ initialState: { cursor: 1 }, inventoryResponse: () => ({
      objects: [{ objectId: "replayed-object", sequence: 1 }], cursor: 1, hasMore: false,
    }) })
    await expect(replayed.engine().pull()).rejects.toThrow(/inventory sequence/i)
    expect(replayed.calls.admissions).toEqual([])
    expect(replayed.read().cursor).toBe(1)
  })

  it("Given two engines race a compare-and-swap, when both commit from one generation, then only one commit wins", async () => {
    let commitsStarted = 0
    let signalBothStarted!: () => void
    let releaseCommits!: () => void
    const bothStarted = new Promise<void>(resolve => { signalBothStarted = resolve })
    const commitsGate = new Promise<void>(resolve => { releaseCommits = resolve })
    const f = fixture({ beforeCommit: async attempt => {
      if (attempt > 2) return
      commitsStarted += 1
      if (commitsStarted === 2) signalBothStarted()
      await commitsGate
    } })
    const first = f.engine().push()
    const second = f.engine().push()
    await bothStarted
    releaseCommits()
    const results = await Promise.allSettled([first, second])

    expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1)
    expect(results.filter(result => result.status === "rejected")).toHaveLength(1)
    expect(f.calls.commits.slice(0, 2).map(commit => commit.expected)).toEqual([0, 0])
    expect(f.read().generation).toBe(2)
  })

  it("Given an uploaded revision without an uploaded hash, when pushing, then do not trust the forged acknowledgment", async () => {
    const f = fixture({ initialState: { uploadedRevision: "revision-1", lastUploaded: "" } })

    await f.engine().push()

    expect(f.calls.captures).toBe(1)
    expect(f.calls.uploads).toHaveLength(1)
    expect(f.read().lastUploaded).toBe("hash:snapshot-1")
  })

  it("Given a mutable sealed object, when transport mutates its argument, then durable pending bytes remain exact", async () => {
    const f = fixture({ mutateUploadArgument: true })
    f.loseNextReceipt()
    await expect(f.engine().push()).rejects.toThrow("receipt persistence interrupted")

    expect(f.read().pending?.object).toEqual({ ciphertext: "sealed:snapshot-1" })
    await f.engine().push()

    expect(f.calls.uploads).toHaveLength(2)
    expect(f.calls.uploads[0]?.object).toEqual({ ciphertext: "sealed:snapshot-1" })
    expect(f.calls.uploads[1]?.object).toEqual({ ciphertext: "sealed:snapshot-1" })
    expect(f.calls.uploads[1]?.requestId).toBe(f.calls.uploads[0]?.requestId)
    expect(f.calls.seals).toBe(1)
  })

  it("Given revision changes during capture, when upload commits, then do not store the earlier revision as stable", async () => {
    let f!: ReturnType<typeof fixture>
    f = fixture({ beforeCapture: () => { f.setRevision("revision-2") } })

    await f.engine().push()

    expect(f.calls.commits[0]?.next.pending?.revision).toBeUndefined()
    expect(f.read().uploadedRevision).toBeUndefined()
  })

  it("Given a newer local edit arrives with an older pending upload, when push retries, then old pending snapshot is completed before new content is captured", async () => {
    const f = fixture()
    f.loseNextReceipt()
    await expect(f.engine().push()).rejects.toThrow("receipt persistence interrupted")
    const oldPending = f.read().pending
    f.setRevision("revision-2")
    f.setPayload({ text: "snapshot-2" })

    await f.engine().push()

    expect(f.calls.uploads[1]).toEqual({ object: oldPending?.object, requestId: oldPending?.requestId })
    expect(f.calls.seals).toBe(1)
    expect(f.read().pending).toBeUndefined()
    expect(f.read().lastUploaded).toBe("hash:snapshot-1")
  })

  it("Given no durable upload is pending, when drainPending runs, then it performs no content or remote work", async () => {
    const f = fixture()

    await expect(f.engine().drainPending()).resolves.toBe(true)

    expect(f.calls.revisions).toBe(0)
    expect(f.calls.captures).toBe(0)
    expect(f.calls.seals).toBe(0)
    expect(f.calls.inventories).toBe(0)
    expect(f.calls.admissions).toEqual([])
    expect(f.calls.uploads).toEqual([])
    expect(f.calls.commits).toEqual([])
  })

  it("Given newer local content and an older durable upload, when draining, then upload only the saved request once", async () => {
    const pending: Pending = { requestId: "saved-request", revision: "revision-1", hash: "saved-hash", bytes: 12,
      object: { ciphertext: "sealed:old-snapshot" }, identity: "identity:revision-1" }
    const f = fixture({ revision: "revision-2", payload: { text: "newer-local-snapshot" }, initialState: { pending } })
    const engine = f.engine()

    await expect(engine.drainPending()).resolves.toBe(true)
    await expect(engine.drainPending()).resolves.toBe(true)

    expect(f.calls.uploads).toEqual([{ object: pending.object, requestId: pending.requestId }])
    expect(f.calls.revisions).toBe(0)
    expect(f.calls.captures).toBe(0)
    expect(f.calls.seals).toBe(0)
    expect(f.calls.inventories).toBe(0)
    expect(f.read().pending).toBeUndefined()
    expect(f.read().lastUploaded).toBe(pending.hash)
    expect(f.read().uploadedRevision).toBe(pending.revision)
  })

  it.each(["receipt verification", "acknowledgment commit"] as const)(
    "Given %s fails while draining, when a new engine retries, then retain and deliver the exact saved request", async failure => {
      const pending: Pending = { requestId: "saved-request", revision: "revision-1", hash: "saved-hash", bytes: 12,
        object: { ciphertext: "sealed:old-snapshot" }, identity: "identity:revision-1" }
      const f = fixture({ initialState: { pending },
        ...(failure === "receipt verification" ? { receiptError: new Error("receipt signature rejected") }
          : { commitError: new Error("acknowledgment write failed") }) })
      const original = f.read().pending

      await expect(f.engine().drainPending()).rejects.toThrow(failure === "receipt verification" ? "receipt signature rejected" : "acknowledgment write failed")
      expect(f.read().pending).toEqual(original)
      f.clearReceiptError()
      f.clearCommitError()

      await expect(f.engine().drainPending()).resolves.toBe(true)

      expect(f.calls.uploads).toEqual([
        { object: pending.object, requestId: pending.requestId },
        { object: pending.object, requestId: pending.requestId },
      ])
      expect(f.calls.captures).toBe(0)
      expect(f.calls.seals).toBe(0)
      expect(f.read().pending).toBeUndefined()
      expect(f.read().lastUploaded).toBe(pending.hash)
    }
  )

  it("Given authorization is revoked during a pending upload, when transport returns, then do not verify or acknowledge it", async () => {
    const pending: Pending = { requestId: "saved-request", revision: "revision-1", hash: "saved-hash", bytes: 12,
      object: { ciphertext: "sealed:old-snapshot" }, identity: "identity:revision-1" }
    let revoked = false
    let releaseUpload!: () => void
    let uploadStarted!: () => void
    const started = new Promise<void>(resolve => { uploadStarted = resolve })
    const gate = new Promise<void>(resolve => { releaseUpload = resolve })
    const f = fixture({ initialState: { pending }, beforeUpload: async () => { uploadStarted(); await gate },
      guard: () => { if (revoked) throw new Error("binding revoked") } })
    const draining = f.engine().drainPending()
    await started
    revoked = true
    releaseUpload()

    await expect(draining).rejects.toThrow("binding revoked")

    expect(f.calls.verifies).toEqual([])
    expect(f.calls.commits).toEqual([])
    expect(f.read().pending).toEqual(pending)
  })
})
