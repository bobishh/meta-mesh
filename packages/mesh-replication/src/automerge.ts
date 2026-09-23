import type * as Automerge from "@automerge/automerge"
import type { LocalProfile } from "@meta-uber/mesh-identity"
import {
  createSignedDurableBatchAck,
  deliverBatchToDevice,
  type DeviceRoute,
  type DurableBatchAck,
  type SignedDurableBatchAck,
} from "./protocol"
import { meshRustRuntime, type RustAutomergeSyncEngine } from "./runtime"

export type AutomergeRuntime = Pick<typeof Automerge,
  "load" | "save" | "getChanges" | "getHeads" | "clone" | "initSyncState" | "generateSyncMessage" | "receiveSyncMessage">

export type AutomergeDocumentRuntime = Pick<typeof Automerge, "load">

/** Keeps one materialized WASM document per durable document id.
 * Replacements only drop the old reference: active readers may still own it,
 * so FinalizationRegistry performs the safe release after those readers finish.
 */
export class AutomergeDocumentCache<T extends Record<string, unknown>> {
  private readonly documents = new Map<string, Automerge.Doc<T>>()

  constructor(private readonly automerge: AutomergeDocumentRuntime) {}

  getOrLoad(documentId: string, bytes: Uint8Array): Automerge.Doc<T> {
    const existing = this.documents.get(documentId)
    if (existing) return existing
    const document = this.automerge.load<T>(bytes)
    this.documents.set(documentId, document)
    return document
  }

  replaceFromBytes(documentId: string, bytes: Uint8Array): Automerge.Doc<T> {
    const document = this.automerge.load<T>(bytes)
    this.documents.set(documentId, document)
    return document
  }

  clear(): void {
    this.documents.clear()
  }
}

export type AutomergeSyncFrame = {
  version: 1
  scopeId: string
  documentId: string
  fromDeviceId: string
  toDeviceId: string
  message: Uint8Array
  proof?: unknown
}

export type AutomergeAdmission<T extends Record<string, unknown>> = {
  before: Automerge.Doc<T>
  candidate: Automerge.Doc<T>
  changes: Automerge.Change[]
  remoteDeviceId: string
  proof?: unknown
}

export interface AutomergeDocumentAdapter<T extends Record<string, unknown>> {
  readonly scopeId: string
  readonly documentId: string
  current(): Promise<Automerge.Doc<T>>
  authorize(remoteDeviceId: string, proof: unknown, direction: "send" | "receive"): boolean | Promise<boolean>
  validateCandidate(admission: AutomergeAdmission<T>): void | Promise<void>
  commit(admission: AutomergeAdmission<T>): void | Promise<void>
  snapshot?(document: Automerge.Doc<T>, heads: readonly string[]): void | Promise<void>
  publish?(documentId: string, heads: readonly string[], trigger: "remote-commit"): void | Promise<void>
}

export type AutomergeSyncResult = {
  acceptedChanges: number
  heads: string[]
  response: AutomergeSyncFrame | null
}

export type AutomergeDeviceSyncRequest = {
  kind: "mesh-automerge-device-sync"
  version: 1
  batchId: string
  frame: Omit<AutomergeSyncFrame, "message"> & { message: string }
}

export type AutomergeDeviceSyncResponse = {
  kind: "mesh-automerge-device-sync-response"
  version: 1
  batchId: string
  ack: SignedDurableBatchAck
  frame?: Omit<AutomergeSyncFrame, "message"> & { message: string }
}

export async function receiveAutomergeDeviceSync<T extends Record<string, unknown>>(options: {
  profile: LocalProfile
  engine: AutomergeAntiEntropy
  adapter: AutomergeDocumentAdapter<T>
  remoteDeviceId: string
  request: AutomergeDeviceSyncRequest
}): Promise<AutomergeDeviceSyncResponse> {
  const { frame: rawFrame, batch } = meshRustRuntime().decodeAutomergeDeviceSyncRequest(options.request, options.remoteDeviceId)
  const frame = normalizeRustFrame(rawFrame as AutomergeSyncFrame)
  const result = await options.engine.receive(options.adapter, options.remoteDeviceId, frame)
  const ack = await createSignedDurableBatchAck(options.profile, {
    scopeId: batch.scopeId,
    documentId: batch.documentId,
    batchId: batch.batchId,
    acceptedHashes: [batch.changes[0]!.hash],
    acceptedHeads: result.heads,
    committedAt: new Date().toISOString(),
  })
  return meshRustRuntime().encodeAutomergeDeviceSyncResponse(batch.batchId, ack, result.response) as AutomergeDeviceSyncResponse
}

export async function syncAutomergeDocumentToDevice<T extends Record<string, unknown>>(options: {
  engine: AutomergeAntiEntropy
  adapter: AutomergeDocumentAdapter<T>
  targetDeviceId: string
  routes: readonly DeviceRoute[]
  send: (route: DeviceRoute, request: AutomergeDeviceSyncRequest, signal: AbortSignal) => Promise<AutomergeDeviceSyncResponse>
  verifyAck: (ack: SignedDurableBatchAck) => DurableBatchAck | Promise<DurableBatchAck>
  routeHealth?: (route: DeviceRoute) => number
  fallbackDelayMs?: number
  retryDelaysMs?: readonly number[]
  maximumRounds?: number
  trace?: import("./protocol.js").MeshReplicationTrace
  signal?: AbortSignal
}): Promise<{ rounds: number; routeInstanceIds: string[] }> {
  const flow = meshRustRuntime().createAutomergeDeviceSyncFlow(options.targetDeviceId,
    options.adapter.documentId, options.maximumRounds ?? 64)
  try {
    let frame = await options.engine.generate(options.adapter, options.targetDeviceId)
    while (true) {
      const step = flow.nextRound(frame)
      if (step.kind === "converged") {
        options.trace?.("sync.converged", { targetDeviceId: options.targetDeviceId,
          documentId: options.adapter.documentId, rounds: step.value.rounds })
        return step.value
      }
      const plan = step.value
      const batch = { ...plan.batch, changes: plan.batch.changes.map(change => ({ ...change,
        bytes: new Uint8Array(change.bytes) })) }
      const request = plan.request as AutomergeDeviceSyncRequest
      options.trace?.("sync.round", { targetDeviceId: options.targetDeviceId,
        documentId: options.adapter.documentId, round: plan.round, batchId: batch.batchId })
      const selectedRoute = plan.selectedRouteInstanceId
        ? options.routes.find(route => route.instanceId === plan.selectedRouteInstanceId) : undefined
      if (plan.selectedRouteInstanceId && !selectedRoute) throw new Error("Selected Automerge sync route disappeared")
      const responses = new Map<string, AutomergeDeviceSyncResponse>()
      const delivery = await deliverBatchToDevice({
        targetDeviceId: options.targetDeviceId,
        routes: selectedRoute ? [selectedRoute] : options.routes,
        batch,
        fallbackDelayMs: options.fallbackDelayMs,
        retryDelaysMs: options.retryDelaysMs,
        routeHealth: options.routeHealth,
        trace: options.trace,
        signal: options.signal,
        send: async (route, _batch, signal) => {
          const response = await options.send(route, request, signal)
          flow.validateResponse(response)
          responses.set(route.instanceId, response)
          return options.verifyAck(response.ack)
        },
        verifyAck: () => true,
      })
      const response = responses.get(delivery.route.instanceId)
      if (!response) throw new Error("Missing Automerge sync route response")
      const responseFrame = flow.completeRound(delivery.route.instanceId, response) as AutomergeSyncFrame | null
      frame = responseFrame
        ? (await options.engine.receive(options.adapter, options.targetDeviceId, normalizeRustFrame(responseFrame))).response
        : await options.engine.generate(options.adapter, options.targetDeviceId)
    }
  } finally {
    flow.free?.()
  }
}

export class AutomergeAntiEntropy {
  private readonly busy = new Set<string>()
  private readonly documentQueues = new Map<string, Promise<void>>()
  private readonly engine: RustAutomergeSyncEngine

  constructor(
    localDeviceId: string,
    private readonly automerge: AutomergeRuntime,
    private readonly options: {
      maximumFrameBytes?: number
      proof?: (scopeId: string, documentId: string, remoteDeviceId: string) => unknown | Promise<unknown>
    } = {},
  ) {
    this.engine = meshRustRuntime().createAutomergeSyncEngine(localDeviceId, options.maximumFrameBytes)
  }

  private key(documentId: string, remoteDeviceId: string): string {
    return `${documentId}\u0000${remoteDeviceId}`
  }

  reset(documentId: string, remoteDeviceId: string): void {
    this.engine.reset(documentId, remoteDeviceId)
  }

  private async exclusive<T>(key: string, documentId: string, run: () => Promise<T>): Promise<T> {
    if (this.busy.has(key)) throw new Error("Automerge sync backpressure")
    this.busy.add(key)
    const previous = this.documentQueues.get(documentId)
    let release!: () => void
    const current = new Promise<void>(resolve => { release = resolve })
    this.documentQueues.set(documentId, current)
    await previous
    try { return await run() } finally {
      this.busy.delete(key)
      release()
      if (this.documentQueues.get(documentId) === current) this.documentQueues.delete(documentId)
    }
  }

  async generate<T extends Record<string, unknown>>(
    adapter: AutomergeDocumentAdapter<T>,
    remoteDeviceId: string,
  ): Promise<AutomergeSyncFrame | null> {
    const key = this.key(adapter.documentId, remoteDeviceId)
    return this.exclusive(key, adapter.documentId, async () => {
      if (!await adapter.authorize(remoteDeviceId, undefined, "send")) throw new Error("Unauthorized Automerge sync")
      const document = await adapter.current()
      this.engine.loadDocument(adapter.scopeId, adapter.documentId, this.automerge.save(document))
      const proof = await this.options.proof?.(adapter.scopeId, adapter.documentId, remoteDeviceId)
      const frame = this.engine.generate(adapter.documentId, remoteDeviceId, true, proof) as AutomergeSyncFrame | null
      return frame ? normalizeRustFrame(frame) : null
    })
  }

  async receive<T extends Record<string, unknown>>(
    adapter: AutomergeDocumentAdapter<T>,
    remoteDeviceId: string,
    frame: AutomergeSyncFrame,
  ): Promise<AutomergeSyncResult> {
    const key = this.key(adapter.documentId, remoteDeviceId)
    return this.exclusive(key, adapter.documentId, async () => {
      if (!await adapter.authorize(remoteDeviceId, frame.proof, "receive")) throw new Error("Unauthorized Automerge sync")
      const before = await adapter.current()
      this.engine.loadDocument(adapter.scopeId, adapter.documentId, this.automerge.save(before))
      const responseProof = await this.options.proof?.(adapter.scopeId, adapter.documentId, remoteDeviceId)
      const result = this.engine.prepareReceive(remoteDeviceId, frame, true, responseProof) as {
        acceptedChanges: number
        heads: string[]
        document: Uint8Array | number[]
        response?: AutomergeSyncFrame | null
      }
      let rustCommitted = false
      try {
        const candidate = this.automerge.load<T>(new Uint8Array(result.document))
        const changes = this.automerge.getChanges(before, candidate)
        const admission = { before, candidate, changes, remoteDeviceId, proof: frame.proof }
        if (changes.length > 0) await adapter.validateCandidate(admission)
        this.engine.commitPreparedReceive(adapter.documentId, remoteDeviceId)
        rustCommitted = true
        if (changes.length > 0) {
          await adapter.commit(admission)
          await adapter.snapshot?.(candidate, result.heads)
          await adapter.publish?.(adapter.documentId, result.heads, "remote-commit")
        }
        return {
          acceptedChanges: result.acceptedChanges,
          heads: result.heads,
          response: result.response ? normalizeRustFrame(result.response) : null,
        }
      } catch (error) {
        if (rustCommitted) {
          this.engine.reset(adapter.documentId, remoteDeviceId)
          this.engine.loadDocument(adapter.scopeId, adapter.documentId, this.automerge.save(await adapter.current()))
        } else {
          this.engine.abortPreparedReceive(adapter.documentId, remoteDeviceId)
        }
        throw error
      }
    })
  }
}

function normalizeRustFrame(frame: AutomergeSyncFrame): AutomergeSyncFrame {
  return { ...frame, message: new Uint8Array(frame.message) }
}

export function reconcileAutomergePeers<T extends Record<string, unknown>>(
  automerge: AutomergeRuntime,
  initialLeft: Automerge.Doc<T>,
  initialRight: Automerge.Doc<T>,
  maximumMessages = 1_000,
): [Automerge.Doc<T>, Automerge.Doc<T>] {
  let left = initialLeft
  let right = initialRight
  let leftState = automerge.initSyncState()
  let rightState = automerge.initSyncState()
  for (let count = 0; count < maximumMessages; count += 1) {
    let progressed = false
    let message: Automerge.SyncMessage | null
    ;[leftState, message] = automerge.generateSyncMessage(left, leftState)
    if (message) { ;[right, rightState] = automerge.receiveSyncMessage(automerge.clone(right), rightState, message); progressed = true }
    ;[rightState, message] = automerge.generateSyncMessage(right, rightState)
    if (message) { ;[left, leftState] = automerge.receiveSyncMessage(automerge.clone(left), leftState, message); progressed = true }
    if (!progressed) return [left, right]
  }
  throw new Error("Automerge sync exceeded message bound")
}
