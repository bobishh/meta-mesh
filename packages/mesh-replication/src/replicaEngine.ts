/** Durable host-independent replica progress. This record never travels with a shared document. */
export type ReplicaPending<Object> = {
  requestId: string
  hash: string
  bytes: number
  object: Object
  revision?: string
  identity?: string
}
export type ReplicaState<Object> = {
  version: 1
  binding: string
  generation: number
  cursor: number
  lastUploaded: string
  uploadedRevision?: string
  contentIdentity?: string
  pending?: ReplicaPending<Object>
}
export type ReplicaInventory = {
  objects: Array<{ objectId: string; sequence: number }>
  cursor: number
  hasMore: boolean
  objectCount?: number
  maxSequence?: number
}
export type ReplicaContent<Payload> = { hash: string; bytes: number; payload: Payload; identity?: string }
export type ReplicaPorts<Payload, Object, Receipt> = {
  repository: {
    read: () => Promise<ReplicaState<Object>>
    /** Atomically require expected generation and current credential binding before replacing progress. */
    commit: (expectedGeneration: number, next: ReplicaState<Object>) => Promise<void>
  }
  content: {
    /** Cheap durable revision covering document, proofs, authority, policy and persistent chat. */
    revision: () => Promise<string | undefined>
    capture: () => Promise<ReplicaContent<Payload>>
    seal: (payload: Payload) => Promise<Object>
  }
  transport: {
    inventory: (cursor: number) => Promise<ReplicaInventory>
    download: (objectId: string) => Promise<Object>
    upload: (object: Object, requestId: string) => Promise<Receipt>
  }
  /** Await signed causal admission and durable host storage before returning. Never grants application rights. */
  admit: (object: Object, sequence: number) => Promise<{ hash: string; identity?: string }>
  verifyReceipt: (receipt: Receipt, object: Object, requestId: string) => Promise<void>
  /** Recheck live identity, authorization, credential revision and lifecycle, including on no-op polls. */
  guard: () => Promise<void>
  observe?: (event: string, detail: Record<string, unknown>) => void
}

export function emptyReplicaState<Object>(binding: string, cursor = 0, lastUploaded = ""): ReplicaState<Object> {
  const state: ReplicaState<Object> = { version: 1, binding, generation: 0, cursor, lastUploaded }
  validateState(state, binding)
  return state
}

const clone = <T>(value: T): T => structuredClone(value)
const positiveCounter = (value: unknown) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0
const token = (value: unknown) => typeof value === "string" && value.length > 0 && value.length <= 1024 * 1024
const optionalToken = (value: unknown) => value === undefined || token(value)
const maximumContentBytes = 16 * 1024 * 1024 - 16

export function parseReplicaState<Object>(value: unknown, binding: string): ReplicaState<Object> {
  const state = clone(value) as ReplicaState<Object>
  validateState(state, binding)
  return state
}

function validateState<Object>(state: ReplicaState<Object>, binding: string) {
  if (!state || state.version !== 1 || !token(state.binding) || state.binding !== binding ||
    !positiveCounter(state.generation) || !positiveCounter(state.cursor)) throw new Error("Invalid or changed replica binding")
  if (typeof state.lastUploaded !== "string" || state.lastUploaded.length > 128 ||
    !optionalToken(state.uploadedRevision) || !optionalToken(state.contentIdentity)) throw new Error("Invalid replica acknowledgment")
  if (state.pending) validatePending(state.pending)
}

function validatePending<Object>(pending: ReplicaPending<Object>) {
  if (!token(pending.requestId) || pending.requestId.length > 128 || !token(pending.hash) || pending.hash.length > 128 ||
    !positiveCounter(pending.bytes) || pending.bytes > maximumContentBytes || pending.object === undefined ||
    !optionalToken(pending.revision) || !optionalToken(pending.identity)) throw new Error("Invalid durable replica outbox")
}

function validateInventory(inventory: ReplicaInventory, after: number) {
  if (!inventory || !Array.isArray(inventory.objects) || inventory.objects.length > 128 || typeof inventory.hasMore !== "boolean") {
    throw new Error("Invalid replica inventory")
  }
  let previous = after
  for (const entry of inventory.objects) {
    if (!entry || !token(entry.objectId) || !positiveCounter(entry.sequence) || entry.sequence <= previous) throw new Error("Invalid replica inventory sequence")
    previous = entry.sequence
  }
  if (inventory.cursor !== previous || inventory.hasMore && !inventory.objects.length) throw new Error("Invalid replica inventory cursor")
}

/** One outbox/cursor/receipt algorithm for browser and server hosts. Host adapters own storage, crypto and policy. */
export class ReplicaEngine<Payload, Object, Receipt> {
  private queue: Promise<unknown> = Promise.resolve()
  private received?: { hash: string; identity?: string }
  private inventory?: ReplicaInventory

  constructor(private readonly binding: string, private readonly ports: ReplicaPorts<Payload, Object, Receipt>) {
    if (!token(binding)) throw new Error("Replica binding is required")
  }

  pull(): Promise<boolean> { return this.enqueue(() => this.pullNow()) }
  push(): Promise<boolean> { return this.enqueue(() => this.pushNow()) }
  sync(): Promise<boolean> { return this.enqueue(async () => {
    const caughtUp = await this.pullNow()
    const uploaded = await this.pushNow()
    return caughtUp && uploaded
  }) }
  inventoryStatus(): ReplicaInventory | undefined { return this.inventory ? clone(this.inventory) : undefined }

  private enqueue<T>(run: () => Promise<T>): Promise<T> {
    const next = this.queue.then(run, run)
    this.queue = next.then(() => undefined, () => undefined)
    return next
  }

  private async state(): Promise<ReplicaState<Object>> {
    await this.ports.guard()
    const state = clone(await this.ports.repository.read())
    validateState(state, this.binding)
    await this.ports.guard()
    return state
  }

  private async commit(previous: ReplicaState<Object>, next: ReplicaState<Object>): Promise<ReplicaState<Object>> {
    const changed = { ...clone(next), generation: previous.generation + 1 }
    validateState(changed, this.binding)
    if (changed.cursor < previous.cursor) throw new Error("Replica cursor cannot move backwards")
    await this.ports.guard()
    await this.ports.repository.commit(previous.generation, changed)
    await this.ports.guard()
    return changed
  }

  private async pullNow(): Promise<boolean> {
    let state = await this.state()
    for (let page = 0; page < 8; page += 1) {
      await this.ports.guard()
      const inventory = clone(await this.ports.transport.inventory(state.cursor))
      validateInventory(inventory, state.cursor)
      await this.ports.guard()
      for (const entry of inventory.objects) {
        const object = await this.ports.transport.download(entry.objectId)
        await this.ports.guard()
        const admitted = await this.ports.admit(object, entry.sequence)
        await this.ports.guard()
        state = await this.commit(state, { ...state, cursor: entry.sequence })
        this.received = clone(admitted)
      }
      this.inventory = inventory
      if (!inventory.hasMore) return true
    }
    return false
  }

  private async pushNow(): Promise<boolean> {
    let state = await this.state()
    // Never replace an uncertain upload with newer content. Finish the saved request first, then poll again.
    if (state.pending) return this.deliver(state)
    const revision = await this.ports.content.revision()
    await this.ports.guard()
    if (revision && state.lastUploaded && revision === state.uploadedRevision) { this.observe("unchanged", 0); return true }
    const captured = clone(await this.ports.content.capture())
    await this.ports.guard()
    const stableRevision = revision && await this.ports.content.revision() === revision ? revision : undefined
    if (!token(captured.hash) || captured.hash.length > 128 || !positiveCounter(captured.bytes) || captured.bytes > maximumContentBytes) {
      throw new Error("Replica content exceeds the supported size or hash bounds")
    }
    if (this.alreadyStored(state, captured)) {
      await this.commit(state, { ...state, lastUploaded: captured.hash, uploadedRevision: stableRevision,
        contentIdentity: captured.identity })
      this.observe("already-stored", captured.bytes)
      return stableRevision !== undefined || revision === undefined
    }
    const object = await this.ports.content.seal(clone(captured.payload))
    await this.ports.guard()
    const finalRevision = stableRevision && await this.ports.content.revision() === stableRevision ? stableRevision : undefined
    const pending: ReplicaPending<Object> = { requestId: crypto.randomUUID(), hash: captured.hash, bytes: captured.bytes,
      object: clone(object), revision: finalRevision, identity: captured.identity }
    state = await this.commit(state, { ...state, pending })
    return this.deliver(state)
  }

  private alreadyStored(state: ReplicaState<Object>, content: ReplicaContent<Payload>): boolean {
    return content.hash === state.lastUploaded || content.hash === this.received?.hash ||
      Boolean(content.identity && [state.contentIdentity, this.received?.identity].includes(content.identity))
  }

  private async deliver(state: ReplicaState<Object>): Promise<boolean> {
    const pending = state.pending!
    await this.ports.guard()
    const receipt = await this.ports.transport.upload(clone(pending.object), pending.requestId)
    await this.ports.guard()
    await this.ports.verifyReceipt(receipt, clone(pending.object), pending.requestId)
    await this.ports.guard()
    const { pending: _pending, ...completed } = state
    await this.commit(state, { ...completed, lastUploaded: pending.hash,
      uploadedRevision: pending.revision, contentIdentity: pending.identity })
    this.observe("uploaded", pending.bytes)
    const revision = await this.ports.content.revision()
    await this.ports.guard()
    return revision === undefined || pending.revision === revision
  }

  private observe(phase: string, bytes: number) {
    try { this.ports.observe?.("replica.push", { phase, bytes }) }
    catch { /* Diagnostics never affect durable replication. */ }
  }
}
