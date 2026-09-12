export type MeshStore = {
  get<T>(store: string, key: string): Promise<T | undefined>
  put<T>(store: string, key: string, value: T): Promise<void>
  delete(store: string, key: string): Promise<void>
  list<T>(store: string): Promise<Array<{ key: string; value: T }>>
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
}

export class BrowserMeshStore implements MeshStore {
  private database?: Promise<IDBDatabase>

  constructor(
    private readonly name: string,
    private readonly stores: string[],
  ) {}

  private open(): Promise<IDBDatabase> {
    return this.database ??= new Promise((resolve, reject) => {
      const request = indexedDB.open(this.name, 1)
      request.onupgradeneeded = () => {
        for (const store of this.stores) {
          if (!request.result.objectStoreNames.contains(store)) request.result.createObjectStore(store)
        }
      }
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error ?? new Error("IndexedDB failed to open"))
    })
  }

  private async request<T>(store: string, mode: IDBTransactionMode, run: (value: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    if (!this.stores.includes(store)) throw new Error(`Unknown store: ${store}`)
    const database = await this.open()
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(store, mode)
      const request = run(transaction.objectStore(store))
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"))
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
        if (!cursor.result) return resolve(result)
        result.push({ key: String(cursor.result.key), value: cursor.result.value as T })
        cursor.result.continue()
      }
      cursor.onerror = () => reject(cursor.error ?? new Error("IndexedDB cursor failed"))
    })
  }
}
