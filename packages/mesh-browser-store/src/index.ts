import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"

export type MeshStore = {
  get<T>(store: string, key: string): Promise<T | undefined>
  put<T>(store: string, key: string, value: T): Promise<void>
  delete(store: string, key: string): Promise<void>
  list<T>(store: string): Promise<Array<{ key: string; value: T }>>
  scan<T>(store: string, prefix: string, after: string | undefined, limit: number): Promise<{ entries: Array<{ key: string; value: T }>; nextAfter: string | null }>
  batch(operations: readonly MeshStoreOperation[]): Promise<void>
  compareAndSwap(conditions: readonly MeshStoreCondition[], operations: readonly MeshStoreOperation[], guard?: () => void): Promise<boolean>
  update<T>(store: string, key: string, change: (current: T | undefined) => T | undefined): Promise<T | undefined>
  updateRecords<T>(store: string, keys: readonly string[], change: (values: readonly unknown[]) => { writes: readonly { key: string; value: unknown | undefined }[]; result: T }): Promise<T>
}

type RecordUpdatePlan<T> = { writes: readonly { key: string; value: unknown | undefined }[]; result: T }

function recordUpdateInput<T>(keys: readonly string[], values: readonly unknown[], change: (values: readonly unknown[]) => { writes: readonly { key: string; value: unknown | undefined }[]; result: T }): RecordUpdatePlan<T> {
  const allowed = new Set(keys)
  const input = structuredClone(values)
  const proposed = change(input)
  if (proposed === null || typeof proposed !== "object" || Array.isArray(proposed)) throw new Error("Invalid synchronous record update plan")
  if (typeof (proposed as { then?: unknown }).then === "function") {
    void Promise.resolve(proposed).catch(() => undefined)
    throw new Error("Invalid synchronous record update plan")
  }
  const detached = structuredClone(proposed)
  if (!Array.isArray(detached.writes)) throw new Error("Invalid record update writes")
  const seen = new Set<string>()
  for (const write of detached.writes) {
    if (!write || typeof write !== "object" || typeof write.key !== "string" || !allowed.has(write.key) || seen.has(write.key)) {
      throw new Error("Record update writes must target distinct declared keys")
    }
    seen.add(write.key)
  }
  return detached
}

function recordUpdateKeys(keys: readonly string[]): string[] {
  const snapshot = structuredClone(keys)
  if (!Array.isArray(snapshot) || snapshot.some(key => typeof key !== "string" || !key) || new Set(snapshot).size !== snapshot.length) {
    throw new Error("Record update keys must be distinct non-empty strings")
  }
  return snapshot
}

function prefixScanInput(prefix: string, after: string | undefined, limit: number): void {
  if (typeof prefix !== "string" || prefix.length < 1 || prefix.length > 2048) throw new Error("Invalid scan prefix")
  if (!Number.isInteger(limit) || limit < 1 || limit > 128) throw new Error("Invalid scan limit")
  if (after !== undefined && (typeof after !== "string" || !after.startsWith(prefix))) throw new Error("Invalid scan continuation key")
}

function prefixSuccessor(prefix: string): string | undefined {
  for (let index = prefix.length - 1; index >= 0; index -= 1) {
    const code = prefix.charCodeAt(index)
    if (code < 0xffff) return `${prefix.slice(0, index)}${String.fromCharCode(code + 1)}`
  }
  return undefined
}

export type MeshStoreOperation =
  | { type: "put"; store: string; key: string; value: unknown }
  | { type: "delete"; store: string; key: string }

/** Exact serialized-state conditions; undefined means the record must be absent. */
export type MeshStoreCondition = { store: string; key: string; expected: string | undefined }

function transactionInput(conditions: readonly MeshStoreCondition[], operations: readonly MeshStoreOperation[]) {
  const snapshot = structuredClone({ conditions, operations })
  const seen = new Set<string>()
  for (const condition of snapshot.conditions) {
    const key = JSON.stringify([condition.store, condition.key])
    if (seen.has(key) || (condition.expected !== undefined && typeof condition.expected !== "string")) {
      throw new Error("Invalid atomic store conditions")
    }
    seen.add(key)
  }
  return snapshot
}

export class MemoryMeshStore implements MeshStore {
  private readonly stores = new Map<string, Map<string, unknown>>()

  private store(name: string): Map<string, unknown> {
    let store = this.stores.get(name)
    if (!store) {
      store = new Map()
      this.stores.set(name, store)
    }
    return store
  }

  async get<T>(store: string, key: string): Promise<T | undefined> {
    return structuredClone(this.store(store).get(key)) as T | undefined
  }

  async put<T>(store: string, key: string, value: T): Promise<void> {
    this.store(store).set(key, structuredClone(value))
  }

  async delete(store: string, key: string): Promise<void> {
    this.store(store).delete(key)
  }

  async list<T>(store: string): Promise<Array<{ key: string; value: T }>> {
    return [...this.store(store).entries()].map(([key, value]) => ({
      key,
      value: structuredClone(value) as T,
    }))
  }

  async scan<T>(store: string, prefix: string, after: string | undefined, limit: number): Promise<{ entries: Array<{ key: string; value: T }>; nextAfter: string | null }> {
    prefixScanInput(prefix, after, limit)
    const entries = [...this.store(store).entries()]
      .filter(([key]) => key.startsWith(prefix) && (after === undefined || key > after))
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    return {
      entries: entries.slice(0, limit).map(([key, value]) => ({ key, value: structuredClone(value) as T })),
      nextAfter: entries.length > limit ? entries[limit - 1][0] : null,
    }
  }

  async batch(operations: readonly MeshStoreOperation[]): Promise<void> {
    const next = structuredClone(this.stores)
    for (const operation of operations) {
      let store = next.get(operation.store)
      if (!store) {
        store = new Map()
        next.set(operation.store, store)
      }
      if (operation.type === "put") store.set(operation.key, structuredClone(operation.value))
      else store.delete(operation.key)
    }
    this.stores.clear()
    for (const [name, values] of next) this.stores.set(name, values)
  }

  async update<T>(store: string, key: string, change: (current: T | undefined) => T | undefined): Promise<T | undefined> {
    const values = this.store(store)
    const next = change(structuredClone(values.get(key)) as T | undefined)
    if (next === undefined) values.delete(key)
    else values.set(key, structuredClone(next))
    return structuredClone(next)
  }

  async updateRecords<T>(name: string, keys: readonly string[], change: (values: readonly unknown[]) => { writes: readonly { key: string; value: unknown | undefined }[]; result: T }): Promise<T> {
    const snapshot = recordUpdateKeys(keys)
    const current = this.stores.get(name)
    const values = snapshot.map(key => structuredClone(current?.get(key)))
    const plan = recordUpdateInput(snapshot, values, change)
    const next = new Map(current)
    for (const write of plan.writes) {
      if (write.value === undefined) next.delete(write.key)
      else next.set(write.key, write.value)
    }
    this.stores.set(name, next)
    return plan.result
  }

  async compareAndSwap(conditions: readonly MeshStoreCondition[], operations: readonly MeshStoreOperation[], guard: () => void = () => {}) {
    const snapshot = transactionInput(conditions, operations)
    if (snapshot.conditions.some(condition => this.stores.get(condition.store)?.get(condition.key) !== condition.expected)) return false
    const next = structuredClone(this.stores)
    for (const operation of snapshot.operations) {
      let values = next.get(operation.store)
      if (!values) { values = new Map(); next.set(operation.store, values) }
      if (operation.type === "put") values.set(operation.key, operation.value)
      else values.delete(operation.key)
    }
    guard()
    this.stores.clear()
    for (const [name, values] of next) this.stores.set(name, values)
    return true
  }
}

class IndexedDBUpgradeBlockedError extends Error {
  constructor() {
    super("IndexedDB schema upgrade blocked by another tab")
    this.name = "IndexedDBUpgradeBlockedError"
  }
}

export class BrowserMeshStore implements MeshStore {
  private database?: Promise<IDBDatabase>

  constructor(
    private readonly name: string,
    private readonly stores: string[],
  ) {}

  private open(): Promise<IDBDatabase> {
    if (!this.database) {
      this.database = this.openWithStores().catch(error => {
        // The refused open remains queued in IndexedDB until the other tab closes.
        // Retain its refusal for retries rather than queueing another open behind it.
        if (!(error instanceof IndexedDBUpgradeBlockedError)) this.database = undefined
        throw error
      })
    }
    return this.database
  }

  private requestOpen(version?: number): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = version === undefined ? indexedDB.open(this.name) : indexedDB.open(this.name, version)
      let settled = false
      request.onupgradeneeded = () => {
        if (settled) { request.transaction?.abort(); return }
        for (const store of this.stores) {
          if (!request.result.objectStoreNames.contains(store)) request.result.createObjectStore(store)
        }
      }
      request.onsuccess = () => {
        const database = request.result
        if (settled) { database.close(); this.database = undefined; return }
        settled = true
        const invalidate = () => { this.database = undefined }
        database.onversionchange = () => { database.close(); invalidate() }
        database.onclose = invalidate
        resolve(database)
      }
      request.onerror = () => {
        if (settled) this.database = undefined
        settled = true
        reject(request.error ?? new Error("IndexedDB failed to open"))
      }
      request.onblocked = () => { settled = true; reject(new IndexedDBUpgradeBlockedError()) }
    })
  }

  private async openWithStores(): Promise<IDBDatabase> {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const current = await this.requestOpen()
      const missing = this.stores.filter(store => !current.objectStoreNames.contains(store))
      if (missing.length === 0) return current
      const version = current.version + 1
      current.close()
      try {
        const upgraded = await this.requestOpen(version)
        if (this.stores.every(store => upgraded.objectStoreNames.contains(store))) return upgraded
        upgraded.close()
      } catch (error) {
        if (error instanceof IndexedDBUpgradeBlockedError || attempt === 2) throw error
      }
    }
    throw new Error("IndexedDB schema upgrade failed")
  }

  private async request<T>(store: string, mode: IDBTransactionMode, run: (value: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    if (!this.stores.includes(store)) throw new Error(`Unknown store: ${store}`)
    const database = await this.open()
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(store, mode)
      const request = run(transaction.objectStore(store))
      let result: T
      request.onsuccess = () => { result = request.result }
      request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"))
      transaction.oncomplete = () => resolve(result)
      transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction aborted"))
    })
  }

  async get<T>(store: string, key: string): Promise<T | undefined> {
    return this.request(store, "readonly", value => value.get(key))
  }

  async put<T>(store: string, key: string, value: T): Promise<void> {
    await this.request(store, "readwrite", objectStore => objectStore.put(value, key))
  }

  async delete(store: string, key: string): Promise<void> {
    await this.request(store, "readwrite", objectStore => objectStore.delete(key))
  }

  async list<T>(store: string): Promise<Array<{ key: string; value: T }>> {
    if (!this.stores.includes(store)) throw new Error(`Unknown store: ${store}`)
    const database = await this.open()
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(store, "readonly")
      const objectStore = transaction.objectStore(store)
      const result: Array<{ key: string; value: T }> = []
      const cursor = objectStore.openCursor()
      cursor.onsuccess = () => {
        if (!cursor.result) return
        result.push({ key: String(cursor.result.key), value: cursor.result.value as T })
        cursor.result.continue()
      }
      cursor.onerror = () => reject(cursor.error ?? new Error("IndexedDB cursor failed"))
      transaction.oncomplete = () => resolve(result)
      transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction aborted"))
    })
  }

  async scan<T>(store: string, prefix: string, after: string | undefined, limit: number): Promise<{ entries: Array<{ key: string; value: T }>; nextAfter: string | null }> {
    prefixScanInput(prefix, after, limit)
    if (!this.stores.includes(store)) throw new Error(`Unknown store: ${store}`)
    const database = await this.open()
    const upper = prefixSuccessor(prefix)
    const range = upper === undefined
      ? IDBKeyRange.lowerBound(after === undefined ? prefix : after, after !== undefined)
      : IDBKeyRange.bound(after === undefined ? prefix : after, upper, after !== undefined, true)
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(store, "readonly")
      const cursorRequest = transaction.objectStore(store).openCursor(range)
      const entries: Array<{ key: string; value: T }> = []
      let nextAfter: string | null = null
      let failure: unknown
      cursorRequest.onsuccess = () => {
        const cursor = cursorRequest.result
        if (!cursor) return
        if (typeof cursor.key !== "string" || !cursor.key.startsWith(prefix)) return
        const key = cursor.key
        if (entries.length === limit) {
          nextAfter = entries[entries.length - 1].key
          return
        }
        entries.push({ key, value: cursor.value as T })
        cursor.continue()
      }
      cursorRequest.onerror = () => { failure = cursorRequest.error ?? new Error("IndexedDB scan cursor failed") }
      transaction.oncomplete = () => resolve({ entries, nextAfter })
      transaction.onerror = () => reject(failure ?? transaction.error ?? new Error("IndexedDB scan failed"))
      transaction.onabort = () => reject(failure ?? transaction.error ?? new Error("IndexedDB scan aborted"))
    })
  }

  async batch(operations: readonly MeshStoreOperation[]): Promise<void> {
    const names = [...new Set(operations.map(operation => operation.store))]
    if (names.some(name => !this.stores.includes(name))) throw new Error("Unknown store in batch")
    if (operations.length === 0) return
    const database = await this.open()
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(names, "readwrite")
      for (const operation of operations) {
        const store = transaction.objectStore(operation.store)
        if (operation.type === "put") store.put(operation.value, operation.key)
        else store.delete(operation.key)
      }
      transaction.oncomplete = () => resolve()
      transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB batch failed"))
      transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB batch aborted"))
    })
  }

  async update<T>(store: string, key: string, change: (current: T | undefined) => T | undefined): Promise<T | undefined> {
    if (!this.stores.includes(store)) throw new Error(`Unknown store: ${store}`)
    const database = await this.open()
    return new Promise<T | undefined>((resolve, reject) => {
      const transaction = database.transaction(store, "readwrite")
      const objectStore = transaction.objectStore(store)
      const request = objectStore.get(key)
      let next: T | undefined
      request.onsuccess = () => {
        try {
          next = change(request.result as T | undefined)
          if (next === undefined) objectStore.delete(key)
          else objectStore.put(next, key)
        } catch (error) {
          transaction.abort()
          reject(error)
        }
      }
      request.onerror = () => reject(request.error ?? new Error("IndexedDB update read failed"))
      transaction.oncomplete = () => resolve(next)
      transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB update failed"))
      transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB update aborted"))
    })
  }

  async updateRecords<T>(store: string, keys: readonly string[], change: (values: readonly unknown[]) => { writes: readonly { key: string; value: unknown | undefined }[]; result: T }): Promise<T> {
    if (!this.stores.includes(store)) throw new Error(`Unknown store: ${store}`)
    const snapshot = recordUpdateKeys(keys)
    const database = await this.open()
    return new Promise<T>((resolve, reject) => {
      const transaction = database.transaction(store, "readwrite")
      const objectStore = transaction.objectStore(store)
      const requests: IDBRequest[] = snapshot.map(key => objectStore.get(key))
      let result: T
      let failure: unknown
      let settled = false
      const rejectOnce = (error: unknown) => {
        if (!settled) { settled = true; reject(error) }
      }
      const run = () => {
        try {
          const plan = recordUpdateInput(snapshot, requests.map(request => request.result), change)
          result = plan.result
          for (const write of plan.writes) {
            if (write.value === undefined) objectStore.delete(write.key)
            else objectStore.put(write.value, write.key)
          }
        } catch (error) {
          failure = error
          try { transaction.abort() } catch { rejectOnce(error) }
        }
      }
      if (requests.length === 0) run()
      else {
        let remaining = requests.length
        for (const request of requests) {
          request.onsuccess = () => { remaining -= 1; if (remaining === 0) run() }
          request.onerror = () => { failure = request.error ?? new Error("IndexedDB record update read failed") }
        }
      }
      transaction.oncomplete = () => { if (!settled) { settled = true; resolve(result) } }
      transaction.onerror = () => rejectOnce(failure ?? transaction.error ?? new Error("IndexedDB record update failed"))
      transaction.onabort = () => rejectOnce(failure ?? transaction.error ?? new Error("IndexedDB record update aborted"))
    })
  }

  async compareAndSwap(conditions: readonly MeshStoreCondition[], operations: readonly MeshStoreOperation[], guard: () => void = () => {}) {
    const snapshot = transactionInput(conditions, operations)
    const names = [...new Set([...snapshot.conditions, ...snapshot.operations].map(record => record.store))]
    if (names.some(name => !this.stores.includes(name))) throw new Error("Unknown store in atomic update")
    if (!names.length) { guard(); return true }
    const database = await this.open()
    return new Promise<boolean>((resolve, reject) => {
      const transaction = database.transaction(names, "readwrite")
      let matched = true
      let remaining = snapshot.conditions.length
      const publish = () => {
        if (!matched) return
        try {
          guard()
          for (const operation of snapshot.operations) {
            const values = transaction.objectStore(operation.store)
            if (operation.type === "put") values.put(operation.value, operation.key)
            else values.delete(operation.key)
          }
        } catch (error) { transaction.abort(); reject(error) }
      }
      for (const condition of snapshot.conditions) {
        const request = transaction.objectStore(condition.store).get(condition.key)
        request.onsuccess = () => {
          if (request.result !== condition.expected) matched = false
          remaining -= 1
          if (!remaining) publish()
        }
      }
      transaction.oncomplete = () => resolve(matched)
      transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB atomic update failed"))
      transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB atomic update aborted"))
      if (!remaining) publish()
    })
  }
}

export type StoredDocumentChange = {
  version: 1
  documentId: string
  hash: string
  bytes: Uint8Array
  proof: unknown
  verifiedAt: string
}

export type StoredDocumentSnapshot = {
  version: 1
  documentId: string
  heads: string[]
  bytes: Uint8Array
  createdAt: string
}

export type OutboxClaim = {
  version: 1
  documentId: string
  targetDeviceId: string
  batchId: string
  ownerInstanceId: string
  claimedAt: number
  expiresAt: number
}

export class DurableReplicaStore {
  constructor(
    private readonly store: MeshStore,
    private readonly names = { changes: "replica-changes", snapshots: "replica-snapshots", claims: "replica-claims" },
  ) {}

  private changeKey(documentId: string, hash: string): string {
    return `${documentId}\u0000${hash}`
  }

  private claimKey(documentId: string, targetDeviceId: string, batchId: string): string {
    return `${documentId}\u0000${targetDeviceId}\u0000${batchId}`
  }

  async admitChanges(input: {
    documentId: string
    changes: readonly { hash: string; bytes: Uint8Array; proof: unknown }[]
    verifiedAt?: string
    verify: (change: { hash: string; bytes: Uint8Array; proof: unknown }) => boolean | Promise<boolean>
  }): Promise<{ acceptedHashes: string[]; duplicateHashes: string[] }> {
    const verifiedAt = input.verifiedAt ?? new Date().toISOString()
    const changes: Array<{
      hash: string; bytes: Uint8Array; proof: unknown; verified: boolean; existingBytes?: Uint8Array
    }> = []
    for (const change of input.changes) {
      if (!(change.bytes instanceof Uint8Array)) throw new Error("Document change verification failed")
      const key = this.changeKey(input.documentId, change.hash)
      const existing = await this.store.get<StoredDocumentChange>(this.names.changes, key)
      changes.push({
        hash: change.hash,
        bytes: change.bytes,
        proof: change.proof,
        verified: await input.verify(change),
        existingBytes: existing?.bytes,
      })
    }
    const plan = meshRustRuntime().state.planChangeAdmission(input.documentId, changes, verifiedAt) as {
      acceptedHashes: string[]
      duplicateHashes: string[]
      accepted: StoredDocumentChange[]
    }
    const operations: MeshStoreOperation[] = plan.accepted.map(change => ({
      type: "put", store: this.names.changes, key: this.changeKey(input.documentId, change.hash), value: {
        ...change, bytes: new Uint8Array(change.bytes),
      },
    }))
    await this.store.batch(operations)
    return { acceptedHashes: plan.acceptedHashes, duplicateHashes: plan.duplicateHashes }
  }

  async changes(documentId: string): Promise<StoredDocumentChange[]> {
    return (await this.store.list<StoredDocumentChange>(this.names.changes))
      .filter(entry => entry.key.startsWith(`${documentId}\u0000`))
      .map(entry => entry.value)
      .sort((left, right) => left.hash.localeCompare(right.hash))
  }

  async putSnapshot(snapshot: StoredDocumentSnapshot): Promise<void> {
    if (snapshot.version !== 1 || !snapshot.documentId || snapshot.heads.length === 0 || !(snapshot.bytes instanceof Uint8Array)) {
      throw new Error("Invalid document snapshot")
    }
    await this.store.put(this.names.snapshots, snapshot.documentId, structuredClone(snapshot))
  }

  async snapshot(documentId: string): Promise<StoredDocumentSnapshot | undefined> {
    return this.store.get(this.names.snapshots, documentId)
  }

  async claimOutbox(input: Omit<OutboxClaim, "version" | "claimedAt" | "expiresAt"> & { now: number; ttlMs: number }): Promise<OutboxClaim | undefined> {
    const key = this.claimKey(input.documentId, input.targetDeviceId, input.batchId)
    let acquired = false
    const claim = await this.store.update<OutboxClaim>(this.names.claims, key, current => {
      const transition = meshRustRuntime().state.transitionOutboxClaim(current, input) as {
        claim: OutboxClaim; acquired: boolean
      }
      acquired = transition.acquired
      return transition.claim
    })
    return acquired ? claim : undefined
  }
}

export type ReplicaInvalidation = { version: 1; documentId: string; heads: string[] }

type MessageChannel = {
  postMessage(value: unknown): void
  addEventListener(type: "message", listener: (event: MessageEvent) => void): void
  removeEventListener(type: "message", listener: (event: MessageEvent) => void): void
  close(): void
}

export class BrowserReplicaInvalidation {
  private closed = false
  private readonly onMessage = (event: MessageEvent) => {
    void this.receive(event.data).catch(error => this.reportError(error))
  }

  constructor(
    private readonly channel: MessageChannel,
    private readonly currentHeads: (documentId: string) => Promise<readonly string[]>,
    private readonly reconcile: (documentId: string, announcedHeads: readonly string[]) => Promise<void>,
    private readonly reportError: (error: unknown) => void = () => undefined,
  ) {
    channel.addEventListener("message", this.onMessage)
  }

  publish(documentId: string, heads: readonly string[]): void {
    if (this.closed) return
    this.channel.postMessage({ version: 1, documentId, heads: [...heads] } satisfies ReplicaInvalidation)
  }

  async receive(raw: unknown): Promise<void> {
    if (this.closed) return
    const message = raw as ReplicaInvalidation
    if (message?.version !== 1 || typeof message.documentId !== "string" || !message.documentId ||
      !Array.isArray(message.heads) || message.heads.some(head => typeof head !== "string" || !head)) return
    const current = [...await this.currentHeads(message.documentId)].sort()
    if (this.closed) return
    const announced = [...message.heads].sort()
    if (current.length !== announced.length || current.some((head, index) => head !== announced[index])) {
      await this.reconcile(message.documentId, announced)
    }
  }

  async reconcileOnFocus(documentIds: readonly string[], durableHeads: (documentId: string) => Promise<readonly string[]>): Promise<void> {
    for (const documentId of documentIds) {
      if (this.closed) return
      const heads = await durableHeads(documentId)
      if (this.closed) return
      await this.receive({ version: 1, documentId, heads: [...heads] })
    }
  }

  close(): void {
    if (this.closed) return
    this.closed = true
    this.channel.removeEventListener("message", this.onMessage)
    this.channel.close()
  }
}
