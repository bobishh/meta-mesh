import * as Automerge from "@automerge/automerge"
import { describe, expect, it, vi } from "vitest"
import {
  AutomergeAntiEntropy,
  AutomergeDocumentCache,
  AutomergeSyncScheduler,
  receiveAutomergeDeviceSync,
  syncAutomergeDocumentToDevice,
  type AutomergeAdmission,
  type AutomergeDocumentAdapter,
  type AutomergeSyncFrame,
} from "./automerge"

describe("Automerge document lifecycle", () => {
  it("Given one stored document, when UI snapshots read it repeatedly, then WASM loads it once and releases it on shutdown", () => {
    const document = { room: "one" } as unknown as Automerge.Doc<Chat>
    const runtime = {
      load: vi.fn(() => document),
      free: vi.fn(),
    } as unknown as Pick<typeof Automerge, "load" | "free">
    const cache = new AutomergeDocumentCache<Chat>(runtime)
    const bytes = new Uint8Array([1, 2, 3])

    expect(cache.getOrLoad("room-1", bytes)).toBe(document)
    expect(cache.getOrLoad("room-1", bytes)).toBe(document)
    expect(runtime.load).toHaveBeenCalledOnce()

    cache.clear()
    expect(runtime.free).toHaveBeenCalledOnce()
  })

  it("Given an independently loaded replacement, when remembered, then the previous WASM document is released", () => {
    const first = { room: "first" } as unknown as Automerge.Doc<Chat>
    const second = { room: "second" } as unknown as Automerge.Doc<Chat>
    const runtime = {
      load: vi.fn(() => first),
      free: vi.fn(),
    } as unknown as Pick<typeof Automerge, "load" | "free">
    const cache = new AutomergeDocumentCache<Chat>(runtime)

    cache.getOrLoad("room-1", new Uint8Array([1]))
    cache.remember("room-1", second, { independent: true })

    expect(runtime.free).toHaveBeenCalledWith(first)
    cache.clear()
    expect(runtime.free).toHaveBeenLastCalledWith(second)
  })
})
import { createRecoverableIdentity, verifyDeviceCertificateChain } from "@meta-uber/mesh-identity"
import { verifySignedDurableBatchAck, type DeviceRoute } from "./protocol"

type Chat = { messages: string[] }

class MemoryAdapter implements AutomergeDocumentAdapter<Chat> {
  readonly scopeId = "room-1"
  readonly documentId = "chat-1"
  commits = 0
  publications = 0
  authorized = true

  constructor(public document: Automerge.Doc<Chat>) {}
  async current() { return this.document }
  async authorize() { return this.authorized }
  async validateCandidate(_admission: AutomergeAdmission<Chat>) {}
  async commit(admission: AutomergeAdmission<Chat>) { this.document = admission.candidate; this.commits += 1 }
  async publish() { this.publications += 1 }
}

async function exchange(
  left: AutomergeAntiEntropy,
  leftAdapter: MemoryAdapter,
  right: AutomergeAntiEntropy,
  rightAdapter: MemoryAdapter,
  first?: AutomergeSyncFrame | null,
): Promise<void> {
  let frame = first === undefined ? await left.generate(leftAdapter, "right") : first
  for (let count = 0; frame && count < 1_000; count += 1) {
    const receiver = frame.toDeviceId === "right" ? right : left
    const adapter = frame.toDeviceId === "right" ? rightAdapter : leftAdapter
    const remote = frame.fromDeviceId
    frame = (await receiver.receive(adapter, remote, frame)).response
  }
  if (frame) throw new Error("Sync exchange exceeded bound")
}

describe("Automerge anti-entropy", () => {
  it("Given one device has a document, when a fresh remote session bootstraps, then both replicas reach equal heads", async () => {
    const base = Automerge.from<Chat>({ messages: [] })
    const leftAdapter = new MemoryAdapter(Automerge.change(base, doc => { doc.messages.push("hello") }))
    const rightAdapter = new MemoryAdapter(Automerge.clone(base))
    const left = new AutomergeAntiEntropy("left", Automerge)
    const right = new AutomergeAntiEntropy("right", Automerge)

    await exchange(left, leftAdapter, right, rightAdapter)

    expect(rightAdapter.document.messages).toEqual(["hello"])
    expect(Automerge.getHeads(rightAdapter.document)).toEqual(Automerge.getHeads(leftAdapter.document))
    expect(rightAdapter.commits).toBeGreaterThan(0)
  })

  it("Given peers already synchronized a large history, when one change occurs, then the next frame is incremental", async () => {
    let base = Automerge.from<Chat>({ messages: [] })
    for (let index = 0; index < 500; index += 1) {
      base = Automerge.change(base, doc => { doc.messages.push(`message-${index}-${"x".repeat(30)}`) })
    }
    const leftAdapter = new MemoryAdapter(base)
    const rightAdapter = new MemoryAdapter(Automerge.init<Chat>())
    const left = new AutomergeAntiEntropy("left", Automerge)
    const right = new AutomergeAntiEntropy("right", Automerge)
    await exchange(left, leftAdapter, right, rightAdapter)
    leftAdapter.document = Automerge.change(leftAdapter.document, doc => { doc.messages.push("increment") })

    const incremental = await left.generate(leftAdapter, "right")
    expect(incremental).not.toBeNull()
    expect(incremental!.message.byteLength).toBeLessThan(Automerge.save(leftAdapter.document).byteLength)
    await exchange(left, leftAdapter, right, rightAdapter, incremental)
    expect(rightAdapter.document.messages.at(-1)).toBe("increment")
  })

  it("Given sync state is discarded and frames were missed, when a new session starts, then partitioned branches still heal", async () => {
    const base = Automerge.from<Chat>({ messages: [] })
    const leftAdapter = new MemoryAdapter(Automerge.change(Automerge.clone(base), doc => { doc.messages.push("left") }))
    const rightAdapter = new MemoryAdapter(Automerge.change(Automerge.clone(base), doc => { doc.messages.push("right") }))
    const left = new AutomergeAntiEntropy("left", Automerge)
    const right = new AutomergeAntiEntropy("right", Automerge)
    const missed = await left.generate(leftAdapter, "right")
    expect(missed).not.toBeNull()
    left.reset("chat-1", "right")
    right.reset("chat-1", "left")

    await exchange(left, leftAdapter, right, rightAdapter)

    expect([...leftAdapter.document.messages].sort()).toEqual(["left", "right"])
    expect([...rightAdapter.document.messages].sort()).toEqual(["left", "right"])
    expect(Automerge.getHeads(leftAdapter.document).sort()).toEqual(Automerge.getHeads(rightAdapter.document).sort())
  })

  it("Given a delayed sync frame is delivered twice, when received, then dependencies arrive and duplicate admission is empty", async () => {
    let source = Automerge.from<Chat>({ messages: [] })
    source = Automerge.change(source, doc => { doc.messages.push("first") })
    source = Automerge.change(source, doc => { doc.messages.push("dependent") })
    const leftAdapter = new MemoryAdapter(source)
    const rightAdapter = new MemoryAdapter(Automerge.init<Chat>())
    const left = new AutomergeAntiEntropy("left", Automerge)
    const right = new AutomergeAntiEntropy("right", Automerge)
    const hello = await left.generate(leftAdapter, "right")
    const request = (await right.receive(rightAdapter, "left", hello!)).response
    const changes = (await left.receive(leftAdapter, "right", request!)).response

    const first = await right.receive(rightAdapter, "left", changes!)
    const duplicate = await right.receive(rightAdapter, "left", changes!)

    expect(rightAdapter.document.messages).toEqual(["first", "dependent"])
    expect(first.acceptedChanges).toBeGreaterThan(0)
    expect(duplicate.acceptedChanges).toBe(0)
  })

  it("Given an oversized or unauthorized frame, when received, then trusted document state does not advance", async () => {
    const adapter = new MemoryAdapter(Automerge.from<Chat>({ messages: [] }))
    const engine = new AutomergeAntiEntropy("right", Automerge, { maximumFrameBytes: 16 })
    const frame: AutomergeSyncFrame = {
      version: 1, scopeId: "room-1", documentId: "chat-1", fromDeviceId: "left", toDeviceId: "right",
      message: new Uint8Array(17),
    }
    await expect(engine.receive(adapter, "left", frame)).rejects.toThrow("size limit")
    adapter.authorized = false
    await expect(engine.receive(adapter, "left", { ...frame, message: new Uint8Array([1]) })).rejects.toThrow("Unauthorized")
    expect(adapter.document.messages).toEqual([])
    expect(adapter.commits).toBe(0)
  })

  it("Given several repair triggers occur together, when scheduled, then one flush retains every reason", async () => {
    const flush = vi.fn()
    const scheduler = new AutomergeSyncScheduler(flush)
    scheduler.trigger("chat-1", "local-commit")
    scheduler.trigger("chat-1", "remote-commit")
    scheduler.trigger("chat-1", "connection")
    scheduler.trigger("chat-1", "scope-discovery")
    scheduler.trigger("chat-1", "scheduled-repair")

    await vi.waitFor(() => expect(flush).toHaveBeenCalledOnce())
    const requests = flush.mock.calls[0][0]
    expect([...requests.get("chat-1")]).toEqual([
      "local-commit", "remote-commit", "connection", "scope-discovery", "scheduled-repair",
    ])
  })

  it("Given one durable device has two routes, when the first route fails, then one native sync reaches the sibling route and returns a signed durable ACK", async () => {
    const leftProfile = (await createRecoverableIdentity("better", "Left")).profile
    const rightProfile = (await createRecoverableIdentity("better", "Right")).profile
    const base = Automerge.from<Chat>({ messages: [] })
    const leftAdapter = new MemoryAdapter(Automerge.change(base, doc => { doc.messages.push("one") }))
    const rightAdapter = new MemoryAdapter(Automerge.clone(base))
    const left = new AutomergeAntiEntropy(leftProfile.device.deviceId, Automerge)
    const right = new AutomergeAntiEntropy(rightProfile.device.deviceId, Automerge)
    const route = (instanceId: string): DeviceRoute => ({
      kind: "mesh-device-route", version: 1, scopeId: "room-1", personId: rightProfile.identity.personId,
      deviceId: rightProfile.device.deviceId, instanceId, endpoint: instanceId, sequence: 1,
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(),
      signerKeyId: rightProfile.device.deviceId, signature: "route-signature",
    })
    const attempted: string[] = []
    const trace: string[] = []

    const result = await syncAutomergeDocumentToDevice({
      engine: left,
      adapter: leftAdapter,
      targetDeviceId: rightProfile.device.deviceId,
      routes: [route("closed-tab"), route("live-tab")],
      fallbackDelayMs: 0,
      retryDelaysMs: [],
      trace: event => trace.push(event),
      send: async (candidate, request) => {
        attempted.push(candidate.instanceId)
        if (candidate.instanceId === "closed-tab") throw new Error("closed")
        return receiveAutomergeDeviceSync({ profile: rightProfile, engine: right, adapter: rightAdapter,
          remoteDeviceId: leftProfile.device.deviceId, request })
      },
      verifyAck: async ack => verifySignedDurableBatchAck(ack,
        await verifyDeviceCertificateChain(rightProfile.identity, rightProfile.device.deviceId, [rightProfile.certificate])),
    })

    expect(attempted).toContain("closed-tab")
    expect(attempted).toContain("live-tab")
    expect(result.routeInstanceIds).toContain("live-tab")
    expect(trace).toContain("delivery.route.failed")
    expect(trace).toContain("delivery.ack.durable")
    expect(trace.at(-1)).toBe("sync.converged")
    expect(rightAdapter.document.messages).toEqual(["one"])
    expect(Automerge.getHeads(rightAdapter.document)).toEqual(Automerge.getHeads(leftAdapter.document))
  })
})
