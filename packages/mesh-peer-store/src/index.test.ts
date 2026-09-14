import { describe, it, expect, beforeEach, afterEach, vi } from "vitest"
import {
  PeerStore,
  peerStore,
  DEFAULT_PEER_DB_NAME,
  mergePeerRecords,
  validatePeerRecord,
  validateNodeSecret,
  type WorkspacePeerRecord,
  type WorkspaceMeshCredential,
  type PeerRole,
} from "./index"

// Minimal in-memory Mock IndexedDB implementation for Vitest environment
class MockIDBRequest<T> {
  result!: T
  error: Error | null = null
  onsuccess: ((ev: any) => void) | null = null
  onerror: ((ev: any) => void) | null = null
  transaction: any = null

  _fireSuccess(res: T) {
    this.result = res
    if (this.onsuccess) {
      this.onsuccess({ target: this })
    }
  }

  _fireError(err: Error) {
    this.error = err
    if (this.onerror) {
      this.onerror({ target: this })
    }
  }
}

class MockIDBOpenDBRequest extends MockIDBRequest<any> {
  onupgradeneeded: ((ev: any) => void) | null = null
  onblocked: ((ev: any) => void) | null = null
}

class MockIDBIndex {
  constructor(
    public name: string,
    public keyPath: string,
    public options: any,
    private store: MockIDBObjectStore
  ) {}

  getAll(query?: any): MockIDBRequest<any[]> {
    const req = new MockIDBRequest<any[]>()
    req.transaction = this.store.transaction
    this.store.transaction._addRequest(req, () => {
      const all = Array.from(this.store._records.values())
      if (query === undefined) {
        return all
      }
      return all.filter((r) => r[this.keyPath] === query)
    })
    return req
  }

  get(query: any): MockIDBRequest<any> {
    const req = new MockIDBRequest<any>()
    req.transaction = this.store.transaction
    this.store.transaction._addRequest(req, () => {
      const all = Array.from(this.store._records.values())
      return all.find((r) => r[this.keyPath] === query) ?? null
    })
    return req
  }
}

class MockIDBObjectStore {
  indices = new Map<string, MockIDBIndex>()
  _records = new Map<string, any>()

  constructor(
    public name: string,
    public keyPath: string | string[],
    public transaction: MockIDBTransaction
  ) {}

  createIndex(name: string, keyPath: string, options: any = {}): MockIDBIndex {
    const idx = new MockIDBIndex(name, keyPath, options, this)
    this.indices.set(name, idx)
    return idx
  }

  index(name: string): MockIDBIndex {
    const idx = this.indices.get(name)
    if (!idx) throw new Error(`Index not found: ${name}`)
    return idx
  }

  private _getKey(val: any): string {
    if (Array.isArray(this.keyPath)) {
      return this.keyPath.map((k) => String(val[k])).join("|||")
    }
    return String(val[this.keyPath])
  }

  get(key: any): MockIDBRequest<any> {
    const req = new MockIDBRequest<any>()
    req.transaction = this.transaction
    this.transaction._addRequest(req, () => {
      const k = Array.isArray(key) ? key.map(String).join("|||") : String(key)
      return this._records.get(k) ?? null
    })
    return req
  }

  put(value: any, explicitKey?: any): MockIDBRequest<any> {
    const req = new MockIDBRequest<any>()
    req.transaction = this.transaction
    this.transaction._addRequest(req, () => {
      const k = explicitKey !== undefined
        ? (Array.isArray(explicitKey) ? explicitKey.map(String).join("|||") : String(explicitKey))
        : this._getKey(value)
      // Structured clone simulation
      this._records.set(k, structuredClone(value))
      return k
    })
    return req
  }

  delete(key: any): MockIDBRequest<void> {
    const req = new MockIDBRequest<void>()
    req.transaction = this.transaction
    this.transaction._addRequest(req, () => {
      const k = Array.isArray(key) ? key.map(String).join("|||") : String(key)
      this._records.delete(k)
    })
    return req
  }

  clear(): MockIDBRequest<void> {
    const req = new MockIDBRequest<void>()
    req.transaction = this.transaction
    this.transaction._addRequest(req, () => {
      this._records.clear()
    })
    return req
  }

  getAll(query?: any): MockIDBRequest<any[]> {
    const req = new MockIDBRequest<any[]>()
    req.transaction = this.transaction
    this.transaction._addRequest(req, () => {
      return Array.from(this._records.values()).map((v) => structuredClone(v))
    })
    return req
  }
}

class MockIDBTransaction {
  error: Error | null = null
  oncomplete: (() => void) | null = null
  onerror: (() => void) | null = null
  onabort: (() => void) | null = null
  private _pendingCount = 0
  private _aborted = false

  constructor(
    public db: MockIDBDatabase,
    public storeNames: string[],
    public mode: "readonly" | "readwrite"
  ) {}

  objectStore(name: string): MockIDBObjectStore {
    const store = this.db._stores.get(name)
    if (!store) throw new Error(`ObjectStore not found: ${name}`)
    store.transaction = this
    return store
  }

  abort() {
    this._aborted = true
    queueMicrotask(() => {
      if (this.onabort) this.onabort()
    })
  }

  _addRequest<T>(req: MockIDBRequest<T>, exec: () => T) {
    if (this._aborted) return
    this._pendingCount++
    queueMicrotask(() => {
      if (this._aborted) return
      try {
        const result = exec()
        req._fireSuccess(result)
      } catch (err: any) {
        req._fireError(err)
        this.error = err
        if (this.onerror) this.onerror()
        return
      }
      this._pendingCount--
      if (this._pendingCount === 0 && !this._aborted) {
        setTimeout(() => {
          if (!this._aborted && this._pendingCount === 0 && this.oncomplete) {
            this.oncomplete()
          }
        }, 0)
      }
    })
  }
}

class MockIDBDatabase {
  _stores = new Map<string, MockIDBObjectStore>()
  objectStoreNames = {
    contains: (name: string) => this._stores.has(name),
  }
  onversionchange: (() => void) | null = null
  onclose: (() => void) | null = null

  createObjectStore(name: string, options: { keyPath: string | string[] }): MockIDBObjectStore {
    const dummyTx = new MockIDBTransaction(this, [name], "readwrite")
    const store = new MockIDBObjectStore(name, options.keyPath, dummyTx)
    this._stores.set(name, store)
    return store
  }

  transaction(storeNames: string[] | string, mode: "readonly" | "readwrite"): MockIDBTransaction {
    const names = Array.isArray(storeNames) ? storeNames : [storeNames]
    return new MockIDBTransaction(this, names, mode)
  }

  close() {
    if (this.onclose) this.onclose()
  }
}

class MockIDBFactory {
  private dbs = new Map<string, MockIDBDatabase>()

  open(name: string, version: number = 1): MockIDBOpenDBRequest {
    const req = new MockIDBOpenDBRequest()
    queueMicrotask(() => {
      let db = this.dbs.get(name)
      let needsUpgrade = false
      if (!db) {
        db = new MockIDBDatabase()
        this.dbs.set(name, db)
        needsUpgrade = true
      }
      req.result = db
      if (needsUpgrade && req.onupgradeneeded) {
        req.onupgradeneeded({ target: req, oldVersion: 0, newVersion: version })
      }
      if (req.onsuccess) {
        req.onsuccess({ target: req })
      }
    })
    return req
  }

  deleteDatabase(name: string) {
    this.dbs.delete(name)
  }
}

describe("Peer Catalog & Node Secret Module (src/sync/peerStore.ts)", () => {
  let mockIdb: MockIDBFactory

  beforeEach(() => {
    mockIdb = new MockIDBFactory()
    vi.stubGlobal("indexedDB", mockIdb)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe("Outer BDD Integration: Complete peer lifecycle & persistent secret", () => {
    it("Given an existing install upgrades, when slot zero starts, then it keeps the durable endpoint identity", async () => {
      const store = new PeerStore("match-test-peer-instance-migration", mockIdb as any)
      const legacySecret = new Uint8Array(32).fill(19)
      const interimSlotSecret = await store.getOrCreateInstanceNodeSecret("slot-0")
      expect(interimSlotSecret).not.toEqual(legacySecret)
      await store.setNodeSecret(legacySecret)

      expect(await store.getOrCreateInstanceNodeSecret("slot-0")).toEqual(legacySecret)
      expect(await store.getOrCreateInstanceNodeSecret("slot-1")).not.toEqual(legacySecret)
    })

    it("Given two tabs on one device, when both advertise, then both transport instances remain under one device", async () => {
      const store = new PeerStore("match-test-peer-instances", mockIdb as any)
      const base: WorkspacePeerRecord = {
        workspaceId: "ws_tabs", deviceId: "device_a", personId: "person_a",
        endpoint: "endpoint_a", instanceId: "tab_a", transportSecret: "secret", role: "editor",
        lastSeen: "2026-09-11T00:00:00.000Z", advertisement: { tab: "a" },
      }

      await store.upsertPeer(base)
      await store.upsertPeer({ ...base, endpoint: "endpoint_b", instanceId: "tab_b",
        lastSeen: "2026-09-11T00:01:00.000Z", advertisement: { tab: "b" } })

      expect(await store.listPeers("ws_tabs")).toHaveLength(1)
      expect((await store.listPeerInstances("ws_tabs")).map(peer => peer.instanceId)).toEqual(["tab_a", "tab_b"])
    })

    it("Given a legacy endpoint upgrades its signed instance, when the catalog merges it, then the stale endpoint alias disappears", async () => {
      const store = new PeerStore("match-test-peer-instance-upgrade", mockIdb as any)
      const base: WorkspacePeerRecord = {
        workspaceId: "ws_upgrade", deviceId: "device_a", personId: "person_a",
        instanceId: "interim-instance", endpoint: "same_endpoint", transportSecret: "secret", role: "editor",
        lastSeen: "2026-09-11T00:00:00.000Z", advertisement: { version: "legacy" },
      }
      await store.upsertPeer(base)
      await store.upsertPeer({ ...base, instanceId: "slot-0", lastSeen: "2026-09-11T00:01:00.000Z",
        advertisement: { version: "runtime" } })

      const instances = await store.listPeerInstances("ws_upgrade")
      expect(instances).toHaveLength(1)
      expect(instances[0]).toMatchObject({ instanceId: "slot-0", endpoint: "same_endpoint" })
    })

    it("manages node secret and peer catalog end-to-end with zero localStorage usage", async () => {
      const storageSpy = {
        getItem: vi.fn(),
        setItem: vi.fn(),
        removeItem: vi.fn(),
        clear: vi.fn(),
      }
      vi.stubGlobal("localStorage", storageSpy)

      const store = new PeerStore("match-test-peers", mockIdb as any)

      // 1. Persistent 32-byte node secret
      const nodeSecret1 = await store.getOrCreateNodeSecret()
      expect(nodeSecret1).toBeInstanceOf(Uint8Array)
      expect(nodeSecret1.byteLength).toBe(32)

      // Calling again returns the exact same bytes
      const nodeSecret2 = await store.getOrCreateNodeSecret()
      expect(nodeSecret2).toEqual(nodeSecret1)

      const directSecret = await store.getNodeSecret()
      expect(directSecret).toEqual(nodeSecret1)

      // 2. Register peers for a workspace
      const peerA: WorkspacePeerRecord = {
        workspaceId: "ws_alpha",
        deviceId: "dev_laptop",
        personId: "person_alice",
        endpoint: "relay://node-a.local:8000",
        transportSecret: "secret-alice-laptop-123",
        role: "owner",
        lastSeen: "2026-09-11T00:00:00.000Z",
      }

      const peerB: WorkspacePeerRecord = {
        workspaceId: "ws_alpha",
        deviceId: "dev_phone",
        personId: "person_bob",
        endpoint: "relay://node-b.local:8000",
        transportSecret: "secret-bob-phone-456",
        role: "editor",
        lastSeen: "2026-09-11T00:01:00.000Z",
      }

      await store.upsertPeer(peerA)
      await store.upsertPeer(peerB)

      // 3. Query peer records
      const fetchedA = await store.getPeer("ws_alpha", "dev_laptop")
      expect(fetchedA).toEqual(peerA)

      const listAlpha = await store.listPeers("ws_alpha")
      expect(listAlpha).toHaveLength(2)
      expect(listAlpha.map((p) => p.deviceId)).toEqual(["dev_laptop", "dev_phone"])

      // 4. Deterministic upsert / update
      const peerAUpdate: WorkspacePeerRecord = {
        ...peerA,
        endpoint: "relay://node-a-new.local:8000",
        lastSeen: "2026-09-11T00:05:00.000Z",
      }
      const mergedA = await store.upsertPeer(peerAUpdate)
      expect(mergedA.endpoint).toBe("relay://node-a-new.local:8000")
      expect(mergedA.lastSeen).toBe("2026-09-11T00:05:00.000Z")

      // 5. Revocation handling
      const peerBRevoked: WorkspacePeerRecord = {
        ...peerB,
        lastSeen: "2026-09-11T00:06:00.000Z",
        revokedAt: "2026-09-11T00:06:00.000Z",
      }
      await store.upsertPeer(peerBRevoked)
      const fetchedB = await store.getPeer("ws_alpha", "dev_phone")
      expect(fetchedB?.revokedAt).toBe("2026-09-11T00:06:00.000Z")

      // 6. Removal and clearing
      const removed = await store.removePeer("ws_alpha", "dev_laptop")
      expect(removed).toBe(true)
      expect(await store.getPeer("ws_alpha", "dev_laptop")).toBeNull()

      await store.clearPeers("ws_alpha")
      expect(await store.listPeers("ws_alpha")).toEqual([])

      // 7. Verify localStorage was NEVER called
      expect(storageSpy.getItem).not.toHaveBeenCalled()
      expect(storageSpy.setItem).not.toHaveBeenCalled()
      expect(storageSpy.removeItem).not.toHaveBeenCalled()
      expect(storageSpy.clear).not.toHaveBeenCalled()
    })

    it("Given multiple workspace credentials, when one workspace leaves the mesh, then only its peers and credential are removed", async () => {
      const store = new PeerStore("match-test-leave-workspace", mockIdb as any)
      const credential = (workspaceId: string): WorkspaceMeshCredential => ({
        version: 1, workspaceId, ownerPersonId: `owner_${workspaceId}`, ownerPublicKey: `key_${workspaceId}`,
        transportSecret: `secret_${workspaceId}`, epoch: 1, updatedAt: "2026-09-11T00:00:00.000Z", ownerCertificates: [],
      })
      await store.putWorkspaceCredential(credential("ws_alpha"))
      await store.putWorkspaceCredential(credential("ws_beta"))
      await store.upsertPeer({ workspaceId: "ws_alpha", deviceId: "a", personId: "pa", endpoint: "ep-a", transportSecret: "s", role: "editor", lastSeen: "2026-09-11T00:00:00.000Z" })
      await store.upsertPeer({ workspaceId: "ws_beta", deviceId: "b", personId: "pb", endpoint: "ep-b", transportSecret: "s", role: "editor", lastSeen: "2026-09-11T00:00:00.000Z" })

      await store.removeWorkspaceMeshData("ws_alpha")

      expect(await store.getWorkspaceCredential("ws_alpha")).toBeNull()
      expect(await store.listPeers("ws_alpha")).toEqual([])
      expect(await store.getWorkspaceCredential("ws_beta")).toEqual(credential("ws_beta"))
      expect(await store.listPeers("ws_beta")).toHaveLength(1)
    })
  })

  describe("Validation: Strong field & secret constraints", () => {
    it("validates 32-byte node secret strictly", () => {
      const valid = new Uint8Array(32)
      valid.fill(42)
      expect(() => validateNodeSecret(valid)).not.toThrow()

      // Invalid lengths
      expect(() => validateNodeSecret(new Uint8Array(16))).toThrow(/32 bytes/)
      expect(() => validateNodeSecret(new Uint8Array(64))).toThrow(/32 bytes/)
      expect(() => validateNodeSecret(new Uint8Array(0))).toThrow(/32 bytes/)

      // Invalid types
      expect(() => validateNodeSecret("a".repeat(32))).toThrow(/Uint8Array/)
      expect(() => validateNodeSecret(null)).toThrow(/Uint8Array/)
      expect(() => validateNodeSecret([1, 2, 3])).toThrow(/Uint8Array/)
    })

    it("validates peer record fields strictly", () => {
      const base: WorkspacePeerRecord = {
        workspaceId: "ws_1",
        deviceId: "dev_1",
        personId: "person_1",
        endpoint: "relay://localhost:1234",
        transportSecret: "transport-secret-123",
        role: "editor",
        lastSeen: "2026-09-11T00:00:00.000Z",
      }

      expect(() => validatePeerRecord(base)).not.toThrow()

      // Empty or missing workspaceId
      expect(() => validatePeerRecord({ ...base, workspaceId: "" })).toThrow(/workspaceId/)
      expect(() => validatePeerRecord({ ...base, workspaceId: "   " })).toThrow(/workspaceId/)

      // Empty or missing deviceId
      expect(() => validatePeerRecord({ ...base, deviceId: "" })).toThrow(/deviceId/)

      // Empty or missing personId
      expect(() => validatePeerRecord({ ...base, personId: "" })).toThrow(/personId/)

      // Empty or invalid endpoint
      expect(() => validatePeerRecord({ ...base, endpoint: "" })).toThrow(/endpoint/)

      // Invalid transportSecret
      expect(() => validatePeerRecord({ ...base, transportSecret: "" })).toThrow(/transportSecret/)
      expect(() => validatePeerRecord({ ...base, transportSecret: null as any })).toThrow(/transportSecret/)

      // Invalid role
      expect(() => validatePeerRecord({ ...base, role: "admin" as any })).toThrow(/role/)

      // Invalid lastSeen
      expect(() => validatePeerRecord({ ...base, lastSeen: "not-a-date" })).toThrow(/lastSeen/)

      // Invalid revokedAt
      expect(() => validatePeerRecord({ ...base, revokedAt: "invalid-iso" })).toThrow(/revokedAt/)

      // Valid Uint8Array transport secret
      expect(() => validatePeerRecord({ ...base, transportSecret: new Uint8Array(32) })).not.toThrow()
    })
  })

  describe("Deterministic merge / upsert logic", () => {
    const existing: WorkspacePeerRecord = {
      workspaceId: "ws_1",
      deviceId: "dev_1",
      personId: "person_1",
      endpoint: "relay://old-endpoint:1234",
      transportSecret: "secret-old",
      role: "editor",
      lastSeen: "2026-09-11T00:00:00.000Z",
    }

    it("rejects merge across mismatched workspaces or devices", () => {
      const diffWs: WorkspacePeerRecord = { ...existing, workspaceId: "ws_different" }
      expect(() => mergePeerRecords(existing, diffWs)).toThrow(/workspace/i)

      const diffDev: WorkspacePeerRecord = { ...existing, deviceId: "dev_different" }
      expect(() => mergePeerRecords(existing, diffDev)).toThrow(/deviceId/i)
    })

    it("newer incoming record updates endpoint and lastSeen", () => {
      const incoming: WorkspacePeerRecord = {
        ...existing,
        endpoint: "relay://new-endpoint:5678",
        transportSecret: "secret-new",
        lastSeen: "2026-09-11T00:05:00.000Z",
      }

      const merged = mergePeerRecords(existing, incoming)
      expect(merged.endpoint).toBe("relay://new-endpoint:5678")
      expect(merged.transportSecret).toBe("secret-new")
      expect(merged.lastSeen).toBe("2026-09-11T00:05:00.000Z")
    })

    it("stale incoming record does not downgrade lastSeen or endpoint", () => {
      const stale: WorkspacePeerRecord = {
        ...existing,
        endpoint: "relay://stale:1111",
        lastSeen: "2026-09-10T23:50:00.000Z",
      }

      const merged = mergePeerRecords(existing, stale)
      expect(merged.endpoint).toBe(existing.endpoint)
      expect(merged.lastSeen).toBe(existing.lastSeen)
    })

    it("preserves revocation against stale unrevoked sync", () => {
      const revoked: WorkspacePeerRecord = {
        ...existing,
        lastSeen: "2026-09-11T00:05:00.000Z",
        revokedAt: "2026-09-11T00:05:00.000Z",
      }

      const unrevokedStale: WorkspacePeerRecord = {
        ...existing,
        lastSeen: "2026-09-11T00:03:00.000Z",
        revokedAt: undefined,
      }

      const merged = mergePeerRecords(revoked, unrevokedStale)
      expect(merged.revokedAt).toBe("2026-09-11T00:05:00.000Z")
    })

    it("takes earlier revocation timestamp if both have revokedAt", () => {
      const rev1: WorkspacePeerRecord = {
        ...existing,
        lastSeen: "2026-09-11T00:05:00.000Z",
        revokedAt: "2026-09-11T00:04:00.000Z",
      }
      const rev2: WorkspacePeerRecord = {
        ...existing,
        lastSeen: "2026-09-11T00:06:00.000Z",
        revokedAt: "2026-09-11T00:03:00.000Z",
      }

      const merged = mergePeerRecords(rev1, rev2)
      expect(merged.revokedAt).toBe("2026-09-11T00:03:00.000Z")
    })

    it("resolves role conflict deterministically (owner priority on tie)", () => {
      const editor: WorkspacePeerRecord = {
        ...existing,
        role: "editor",
        lastSeen: "2026-09-11T00:00:00.000Z",
      }
      const owner: WorkspacePeerRecord = {
        ...existing,
        role: "owner",
        lastSeen: "2026-09-11T00:00:00.000Z",
      }

      const m1 = mergePeerRecords(editor, owner)
      expect(m1.role).toBe("owner")

      const m2 = mergePeerRecords(owner, editor)
      expect(m2.role).toBe("owner")
    })
  })

  describe("IndexedDB error handling & absence", () => {
    it("rejects immediately when indexedDB is undefined without using localStorage", async () => {
      vi.stubGlobal("indexedDB", undefined)
      const store = new PeerStore()

      await expect(store.getNodeSecret()).rejects.toThrow(/IndexedDB is not available/)
      await expect(store.getOrCreateNodeSecret()).rejects.toThrow(/IndexedDB is not available/)
      await expect(
        store.upsertPeer({
          workspaceId: "ws_1",
          deviceId: "dev_1",
          personId: "p_1",
          endpoint: "ep",
          transportSecret: "ts",
          role: "editor",
          lastSeen: "2026-09-11T00:00:00.000Z",
        })
      ).rejects.toThrow(/IndexedDB is not available/)
    })

    it("exports default peerStore singleton", () => {
      expect(peerStore).toBeInstanceOf(PeerStore)
      expect(DEFAULT_PEER_DB_NAME).toBeDefined()
    })
  })

  describe("Node Secret Persistence and Custom Secret Setting", () => {
    it("allows explicitly setting a 32-byte node secret and persists across instances", async () => {
      const store1 = new PeerStore("test-db-secret", mockIdb as any)
      const customSecret = new Uint8Array(32)
      customSecret.fill(123)

      await store1.setNodeSecret(customSecret)
      const fetched1 = await store1.getNodeSecret()
      expect(fetched1).toEqual(customSecret)

      // Re-instantiate store on same db
      const store2 = new PeerStore("test-db-secret", mockIdb as any)
      const fetched2 = await store2.getNodeSecret()
      expect(fetched2).toEqual(customSecret)
      const orCreated = await store2.getOrCreateNodeSecret()
      expect(orCreated).toEqual(customSecret)
    })

    it("rejects invalid node secrets when setting", async () => {
      const store = new PeerStore("test-db-secret", mockIdb as any)
      await expect(store.setNodeSecret(new Uint8Array(31))).rejects.toThrow(/32 bytes/)
      await expect(store.setNodeSecret(new Uint8Array(33))).rejects.toThrow(/32 bytes/)
      await expect(store.setNodeSecret("not-a-uint8array" as any)).rejects.toThrow(/Uint8Array/)
    })
  })

  describe("Multi-peer operations: mergePeers, binary secrets, unrevoking", () => {
    it("supports mergePeers batch processing", async () => {
      const store = new PeerStore("test-db-batch", mockIdb as any)
      const peers: WorkspacePeerRecord[] = [
        {
          workspaceId: "ws_1",
          deviceId: "dev_1",
          personId: "p_1",
          endpoint: "ep1",
          transportSecret: "sec1",
          role: "owner",
          lastSeen: "2026-09-11T00:00:00.000Z",
        },
        {
          workspaceId: "ws_1",
          deviceId: "dev_2",
          personId: "p_2",
          endpoint: "ep2",
          transportSecret: "sec2",
          role: "editor",
          lastSeen: "2026-09-11T00:01:00.000Z",
        },
        {
          workspaceId: "ws_2",
          deviceId: "dev_3",
          personId: "p_3",
          endpoint: "ep3",
          transportSecret: "sec3",
          role: "editor",
          lastSeen: "2026-09-11T00:02:00.000Z",
        },
      ]

      const merged = await store.mergePeers(peers)
      expect(merged).toHaveLength(3)

      const ws1Peers = await store.listPeers("ws_1")
      expect(ws1Peers).toHaveLength(2)
      expect(ws1Peers.map((p) => p.deviceId)).toEqual(["dev_1", "dev_2"])

      const allPeers = await store.listPeers()
      expect(allPeers).toHaveLength(3)
    })

    it("supports 32-byte Uint8Array binary transport secrets", async () => {
      const store = new PeerStore("test-db-bin", mockIdb as any)
      const binarySecret = new Uint8Array(32)
      binarySecret.fill(99)

      const peer: WorkspacePeerRecord = {
        workspaceId: "ws_bin",
        deviceId: "dev_bin",
        personId: "p_bin",
        endpoint: "relay://binary",
        transportSecret: binarySecret,
        role: "owner",
        lastSeen: "2026-09-11T00:00:00.000Z",
      }

      await store.upsertPeer(peer)
      const fetched = await store.getPeer("ws_bin", "dev_bin")
      expect(fetched).not.toBeNull()
      expect(fetched?.transportSecret).toBeInstanceOf(Uint8Array)
      expect(fetched?.transportSecret).toEqual(binarySecret)
    })

    it("unrevokes a peer when incoming explicitly specifies revokedAt: null with a newer timestamp", () => {
      const revoked: WorkspacePeerRecord = {
        workspaceId: "ws_1",
        deviceId: "dev_1",
        personId: "p_1",
        endpoint: "ep",
        transportSecret: "sec",
        role: "editor",
        lastSeen: "2026-09-11T00:00:00.000Z",
        revokedAt: "2026-09-11T00:00:00.000Z",
      }

      const unrevokeUpdate: WorkspacePeerRecord = {
        ...revoked,
        lastSeen: "2026-09-11T00:10:00.000Z",
        revokedAt: null,
      }

      const merged = mergePeerRecords(revoked, unrevokeUpdate)
      expect(merged.revokedAt).toBeNull()
      expect(merged.lastSeen).toBe("2026-09-11T00:10:00.000Z")
    })

    it("handles clearPeers with and without workspaceId, and clearAll", async () => {
      const store = new PeerStore("test-db-clear", mockIdb as any)
      await store.getOrCreateNodeSecret()

      await store.upsertPeer({
        workspaceId: "ws_A",
        deviceId: "dev_A",
        personId: "p_A",
        endpoint: "epA",
        transportSecret: "secA",
        role: "owner",
        lastSeen: "2026-09-11T00:00:00.000Z",
      })

      await store.upsertPeer({
        workspaceId: "ws_B",
        deviceId: "dev_B",
        personId: "p_B",
        endpoint: "epB",
        transportSecret: "secB",
        role: "editor",
        lastSeen: "2026-09-11T00:00:00.000Z",
      })

      // Clear only ws_A
      await store.clearPeers("ws_A")
      expect(await store.listPeers("ws_A")).toHaveLength(0)
      expect(await store.listPeers("ws_B")).toHaveLength(1)

      // Node secret still intact
      expect(await store.getNodeSecret()).not.toBeNull()

      // clearAll clears everything including node secret
      await store.clearAll()
      expect(await store.listPeers()).toHaveLength(0)
      expect(await store.getNodeSecret()).toBeNull()
    })

    it("Given one instance renews with skewed wall time, when peer routes merge, then sequence selects the new route", () => {
      const peer = (endpoint: string, lastSeen: string, routeSequence: number): WorkspacePeerRecord => ({
        workspaceId: "ws_route", deviceId: "dev_route", personId: "person_route", instanceId: "slot-0",
        endpoint, transportSecret: "secret", role: "editor", lastSeen,
        advertisement: { advertisement: { payload: { routeSequence } } },
      })

      const merged = mergePeerRecords(peer("old-endpoint", "2026-09-14T12:05:00.000Z", 4),
        peer("renewed-endpoint", "2026-09-14T12:00:00.000Z", 5))

      expect(merged.instances).toContainEqual(expect.objectContaining({
        instanceId: "slot-0", endpoint: "renewed-endpoint",
      }))
    })

    it("Given one browser instance, when advertisements renew, then its sequence increases durably", async () => {
      const store = new PeerStore("test-db-route-sequence", mockIdb as any)

      await expect(store.nextInstanceAdvertisementSequence("slot-0")).resolves.toBe(1)
      await expect(store.nextInstanceAdvertisementSequence("slot-0")).resolves.toBe(2)
      await expect(store.nextInstanceAdvertisementSequence("slot-1")).resolves.toBe(1)
    })
  })
})
