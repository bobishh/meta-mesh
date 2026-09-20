import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"

export type MeshStore = {
  get<T>(store: string, key: string): Promise<T | undefined>
  put<T>(store: string, key: string, value: T): Promise<void>
  delete(store: string, key: string): Promise<void>
  list<T>(store: string): Promise<Array<{ key: string; value: T }>>
  batch(operations: readonly MeshStoreOperation[]): Promise<void>
  update<T>(store: string, key: string, change: (current: T | undefined) => T | undefined): Promise<T | undefined>
}

export type MeshStoreOperation =
  | { type: "put"; store: string; key: string; value: unknown }
  | { type: "delete"; store: string; key: string }

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
        this.database = undefined
        throw error
      })
    }
    return this.database
  }

  private requestOpen(version?: number): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = version === undefined ? indexedDB.open(this.name) : indexedDB.open(this.name, version)
      request.onupgradeneeded = () => {
        for (const store of this.stores) {
          if (!request.result.objectStoreNames.contains(store)) request.result.createObjectStore(store)
        }
      }
      request.onsuccess = () => {
        request.result.onversionchange = () => request.result.close()
        resolve(request.result)
      }
      request.onerror = () => reject(request.error ?? new Error("IndexedDB failed to open"))
      request.onblocked = () => reject(new Error("IndexedDB schema upgrade blocked by another tab"))
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
        return await this.requestOpen(version)
      } catch (error) {
        if (attempt === 2) throw error
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
  private readonly onMessage = (event: MessageEvent) => { void this.receive(event.data) }

  constructor(
    private readonly channel: MessageChannel,
    private readonly currentHeads: (documentId: string) => Promise<readonly string[]>,
    private readonly reconcile: (documentId: string, announcedHeads: readonly string[]) => Promise<void>,
  ) {
    channel.addEventListener("message", this.onMessage)
  }

  publish(documentId: string, heads: readonly string[]): void {
    this.channel.postMessage({ version: 1, documentId, heads: [...heads] } satisfies ReplicaInvalidation)
  }

  async receive(raw: unknown): Promise<void> {
    const message = raw as ReplicaInvalidation
    if (message?.version !== 1 || typeof message.documentId !== "string" || !message.documentId ||
      !Array.isArray(message.heads) || message.heads.some(head => typeof head !== "string" || !head)) return
    const current = [...await this.currentHeads(message.documentId)].sort()
    const announced = [...message.heads].sort()
    if (current.length !== announced.length || current.some((head, index) => head !== announced[index])) {
      await this.reconcile(message.documentId, announced)
    }
  }

  async reconcileOnFocus(documentIds: readonly string[], durableHeads: (documentId: string) => Promise<readonly string[]>): Promise<void> {
    for (const documentId of documentIds) await this.receive({ version: 1, documentId, heads: [...await durableHeads(documentId)] })
  }

  close(): void {
    this.channel.removeEventListener("message", this.onMessage)
    this.channel.close()
  }
}
