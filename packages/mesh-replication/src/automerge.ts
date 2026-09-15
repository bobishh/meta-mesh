import type * as Automerge from "@automerge/automerge"
import { fromBase64Url, sha256Base64Url, toBase64Url, type LocalProfile } from "@meta-uber/mesh-identity"
import {
  createSignedDurableBatchAck,
  deliverBatchToDevice,
  type DeviceBatch,
  type DeviceRoute,
  type DurableBatchAck,
  type SignedDurableBatchAck,
} from "./protocol"

export type AutomergeRuntime = Pick<typeof Automerge,
  "initSyncState" | "generateSyncMessage" | "receiveSyncMessage" | "clone" | "getChanges" | "getHeads">

export type SyncTrigger = "local-commit" | "remote-commit" | "connection" | "scope-discovery" | "scheduled-repair"

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

function encodeFrame(frame: AutomergeSyncFrame): AutomergeDeviceSyncRequest["frame"] {
  return { ...frame, message: toBase64Url(frame.message) }
}

function decodeFrame(frame: AutomergeDeviceSyncRequest["frame"]): AutomergeSyncFrame {
  if (!frame || typeof frame.message !== "string") throw new Error("Invalid Automerge device sync frame")
  return { ...frame, message: fromBase64Url(frame.message) }
}

async function syncBatch(frame: AutomergeSyncFrame, batchId?: string): Promise<DeviceBatch> {
  const hash = await sha256Base64Url(frame.message)
  if (batchId !== undefined && batchId !== hash) throw new Error("Automerge sync batch does not match frame")
  return {
    protocolVersion: 1,
    scopeId: frame.scopeId,
    documentId: frame.documentId,
    batchId: hash,
    changes: [{ hash, bytes: frame.message }],
  }
}

export async function receiveAutomergeDeviceSync<T extends Record<string, unknown>>(options: {
  profile: LocalProfile
  engine: AutomergeAntiEntropy
  adapter: AutomergeDocumentAdapter<T>
  remoteDeviceId: string
  request: AutomergeDeviceSyncRequest
}): Promise<AutomergeDeviceSyncResponse> {
  const request = options.request
  if (request?.kind !== "mesh-automerge-device-sync" || request.version !== 1 || !request.batchId) {
    throw new Error("Invalid Automerge device sync request")
  }
  const frame = decodeFrame(request.frame)
  const batch = await syncBatch(frame, request.batchId)
  const result = await options.engine.receive(options.adapter, options.remoteDeviceId, frame)
  const ack = await createSignedDurableBatchAck(options.profile, {
    scopeId: batch.scopeId,
    documentId: batch.documentId,
    batchId: batch.batchId,
    acceptedHashes: [batch.changes[0]!.hash],
    acceptedHeads: result.heads,
    committedAt: new Date().toISOString(),
  })
  return {
    kind: "mesh-automerge-device-sync-response",
    version: 1,
    batchId: batch.batchId,
    ack,
    ...(result.response ? { frame: encodeFrame(result.response) } : {}),
  }
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
  signal?: AbortSignal
}): Promise<{ rounds: number; routeInstanceIds: string[] }> {
  const maximumRounds = options.maximumRounds ?? 64
  if (!Number.isSafeInteger(maximumRounds) || maximumRounds < 1) throw new Error("Invalid Automerge sync round limit")
  const routeInstanceIds: string[] = []
  let frame = await options.engine.generate(options.adapter, options.targetDeviceId)
  for (let rounds = 0; rounds < maximumRounds; rounds += 1) {
    if (!frame) return { rounds, routeInstanceIds }
    const batch = await syncBatch(frame)
    const request: AutomergeDeviceSyncRequest = {
      kind: "mesh-automerge-device-sync",
      version: 1,
      batchId: batch.batchId,
      frame: encodeFrame(frame),
    }
    const responses = new Map<string, AutomergeDeviceSyncResponse>()
    const delivery = await deliverBatchToDevice({
      targetDeviceId: options.targetDeviceId,
      routes: options.routes,
      batch,
      fallbackDelayMs: options.fallbackDelayMs,
      retryDelaysMs: options.retryDelaysMs,
      routeHealth: options.routeHealth,
      signal: options.signal,
      send: async (route, _batch, signal) => {
        const response = await options.send(route, request, signal)
        if (response?.kind !== "mesh-automerge-device-sync-response" || response.version !== 1 || response.batchId !== batch.batchId) {
          throw new Error("Invalid Automerge device sync response")
        }
        responses.set(route.instanceId, response)
        return options.verifyAck(response.ack)
      },
      verifyAck: () => true,
    })
    routeInstanceIds.push(delivery.route.instanceId)
    const response = responses.get(delivery.route.instanceId)?.frame
    frame = response
      ? (await options.engine.receive(options.adapter, options.targetDeviceId, decodeFrame(response))).response
      : await options.engine.generate(options.adapter, options.targetDeviceId)
  }
  throw new Error("Automerge device sync exceeded round limit")
}

export class AutomergeAntiEntropy {
  private readonly states = new Map<string, Automerge.SyncState>()
  private readonly busy = new Set<string>()

  constructor(
    private readonly localDeviceId: string,
    private readonly automerge: AutomergeRuntime,
    private readonly options: {
      maximumFrameBytes?: number
      proof?: (scopeId: string, documentId: string, remoteDeviceId: string) => unknown | Promise<unknown>
    } = {},
  ) {}

  private key(documentId: string, remoteDeviceId: string): string {
    return `${documentId}\u0000${remoteDeviceId}`
  }

  reset(documentId: string, remoteDeviceId: string): void {
    this.states.delete(this.key(documentId, remoteDeviceId))
  }

  private maximumFrameBytes(): number {
    return this.options.maximumFrameBytes ?? 256 * 1024
  }

  private validateFrame(frame: AutomergeSyncFrame, adapter: AutomergeDocumentAdapter<Record<string, unknown>>, remoteDeviceId: string): void {
    if (frame?.version !== 1 || frame.scopeId !== adapter.scopeId || frame.documentId !== adapter.documentId ||
      frame.fromDeviceId !== remoteDeviceId || frame.toDeviceId !== this.localDeviceId || !(frame.message instanceof Uint8Array)) {
      throw new Error("Invalid Automerge sync frame")
    }
    if (frame.message.byteLength === 0 || frame.message.byteLength > this.maximumFrameBytes()) {
      throw new Error("Automerge sync frame exceeds size limit")
    }
  }

  private async exclusive<T>(key: string, run: () => Promise<T>): Promise<T> {
    if (this.busy.has(key)) throw new Error("Automerge sync backpressure")
    this.busy.add(key)
    try { return await run() } finally { this.busy.delete(key) }
  }

  async generate<T extends Record<string, unknown>>(
    adapter: AutomergeDocumentAdapter<T>,
    remoteDeviceId: string,
  ): Promise<AutomergeSyncFrame | null> {
    const key = this.key(adapter.documentId, remoteDeviceId)
    return this.exclusive(key, async () => {
      if (!await adapter.authorize(remoteDeviceId, undefined, "send")) throw new Error("Unauthorized Automerge sync")
      const document = await adapter.current()
      let state = this.states.get(key) ?? this.automerge.initSyncState()
      let message: Automerge.SyncMessage | null
      ;[state, message] = this.automerge.generateSyncMessage(document, state)
      this.states.set(key, state)
      if (!message) return null
      if (message.byteLength > this.maximumFrameBytes()) throw new Error("Automerge sync frame exceeds size limit")
      return {
        version: 1,
        scopeId: adapter.scopeId,
        documentId: adapter.documentId,
        fromDeviceId: this.localDeviceId,
        toDeviceId: remoteDeviceId,
        message,
        ...(this.options.proof ? { proof: await this.options.proof(adapter.scopeId, adapter.documentId, remoteDeviceId) } : {}),
      }
    })
  }

  async receive<T extends Record<string, unknown>>(
    adapter: AutomergeDocumentAdapter<T>,
    remoteDeviceId: string,
    frame: AutomergeSyncFrame,
  ): Promise<AutomergeSyncResult> {
    const key = this.key(adapter.documentId, remoteDeviceId)
    return this.exclusive(key, async () => {
      this.validateFrame(frame, adapter as AutomergeDocumentAdapter<Record<string, unknown>>, remoteDeviceId)
      if (!await adapter.authorize(remoteDeviceId, frame.proof, "receive")) throw new Error("Unauthorized Automerge sync")
      const before = await adapter.current()
      const writable = this.automerge.clone(before)
      let state = this.states.get(key) ?? this.automerge.initSyncState()
      let candidate: Automerge.Doc<T>
      ;[candidate, state] = this.automerge.receiveSyncMessage(writable, state, frame.message)
      const changes = this.automerge.getChanges(before, candidate)
      if (changes.length > 0) {
        const admission = { before, candidate, changes, remoteDeviceId, proof: frame.proof }
        await adapter.validateCandidate(admission)
        await adapter.commit(admission)
      }
      this.states.set(key, state)
      const current = changes.length > 0 ? candidate : before
      const heads = this.automerge.getHeads(current)
      if (changes.length > 0) {
        await adapter.snapshot?.(current, heads)
        await adapter.publish?.(adapter.documentId, heads, "remote-commit")
      }
      let responseMessage: Automerge.SyncMessage | null
      ;[state, responseMessage] = this.automerge.generateSyncMessage(current, state)
      this.states.set(key, state)
      if (responseMessage && responseMessage.byteLength > this.maximumFrameBytes()) throw new Error("Automerge sync frame exceeds size limit")
      return {
        acceptedChanges: changes.length,
        heads,
        response: responseMessage ? {
          version: 1,
          scopeId: adapter.scopeId,
          documentId: adapter.documentId,
          fromDeviceId: this.localDeviceId,
          toDeviceId: remoteDeviceId,
          message: responseMessage,
          ...(this.options.proof ? { proof: await this.options.proof(adapter.scopeId, adapter.documentId, remoteDeviceId) } : {}),
        } : null,
      }
    })
  }
}

export class AutomergeSyncScheduler {
  private readonly queued = new Map<string, Set<SyncTrigger>>()
  private scheduled = false

  constructor(private readonly flush: (requests: ReadonlyMap<string, ReadonlySet<SyncTrigger>>) => void | Promise<void>) {}

  trigger(documentId: string, trigger: SyncTrigger): void {
    let triggers = this.queued.get(documentId)
    if (!triggers) {
      triggers = new Set()
      this.queued.set(documentId, triggers)
    }
    triggers.add(trigger)
    if (this.scheduled) return
    this.scheduled = true
    queueMicrotask(() => { void this.drain() })
  }

  private async drain(): Promise<void> {
    const requests = new Map([...this.queued].map(([documentId, triggers]) => [documentId, new Set(triggers)]))
    this.queued.clear()
    this.scheduled = false
    await this.flush(requests)
  }
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
