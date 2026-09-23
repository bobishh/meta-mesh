/**
 * PeerStore: Robust IndexedDB peer catalog and local node secret storage.
 *
 * Requirements:
 * - Persistent local 32-byte node secret
 * - Workspace peer records keyed by [workspaceId, deviceId]
 * - Endpoint, person/device IDs, per-peer transport secret, role (owner/editor)
 * - Monotonic lastSeen and optional revokedAt
 * - Deterministic merge/upsert with canonical tie-breaking
 * - Strictly IndexedDB: zero secrets or data in localStorage
 * - Strong validation and transactional completion (durability)
 */
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"

export type PeerRole = "owner" | "editor" | "visitor"

export interface PeerTransportInstance {
  instanceId: string
  endpoint: string
  lastSeen: string
  advertisement?: unknown
}

export interface DeviceReplicaRecord {
  scopeId: string
  deviceId: string
  personId: string
  role: PeerRole
  revokedAt?: string | null
  routes: PeerTransportInstance[]
}

export interface WorkspacePeerRecord {
  workspaceId: string
  deviceId: string
  instanceId?: string
  personId: string
  endpoint: string
  transportSecret: string | Uint8Array
  role: PeerRole
  lastSeen: string // ISO 8601 string
  revokedAt?: string | null // optional ISO 8601 string or null
  advertisement?: unknown
  instances?: PeerTransportInstance[]
}

export interface WorkspaceMeshCredential {
  version: 1
  workspaceId: string
  ownerPersonId: string
  ownerPublicKey: string
  transportSecret: string
  epoch: number
  updatedAt: string
  localGrant?: unknown
  ownerCertificates: unknown[]
  ownerHistory?: Array<{
    personId: string
    publicKey: string
    certificates: unknown[]
  }>
  catalog?: unknown
}

/** Durable signed workspace authority. Kept when routes or active mesh membership are removed. */
export interface WorkspaceAuthorityRecord {
  version: 1
  workspaceId: string
  genesisOwnerPersonId?: string
  ownerPersonId: string
  ownerPublicKey: string
  epoch: number
  updatedAt: string
  localGrant?: unknown
  ownerCertificates: unknown[]
  ownerHistory?: Array<{
    personId: string
    publicKey: string
    certificates: unknown[]
  }>
  catalog?: unknown
}

export const DEFAULT_PEER_DB_NAME = "match-peer-catalog-v1"
export const STORE_PEERS = "peers"
export const STORE_NODE = "node"
export const STORE_AUTHORITY = "authority"

export const INDEX_PEERS_WORKSPACE = "by_workspace"
export const INDEX_PEERS_DEVICE = "by_device"
export const INDEX_PEERS_LAST_SEEN = "by_last_seen"

const NODE_SECRET_KEY = "localNodeSecret"
const INSTANCE_SEQUENCE_PREFIX = "instance-sequence:"
const WORKSPACE_CREDENTIAL_PREFIX = "workspace:"

export const MAX_STRING_LENGTH = 256
export const MAX_ENDPOINT_LENGTH = 2048
export const MAX_SECRET_LENGTH = 4096
export const MAX_AUTH_BUNDLE_LENGTH = 131072

export function validateWorkspaceCredential(value: unknown): asserts value is WorkspaceMeshCredential {
  const item = value as WorkspaceMeshCredential
  if (!item || item.version !== 1 || typeof item.workspaceId !== "string" || !item.workspaceId || item.workspaceId.length > MAX_STRING_LENGTH ||
    typeof item.ownerPersonId !== "string" || !item.ownerPersonId || item.ownerPersonId.length > MAX_STRING_LENGTH ||
    typeof item.ownerPublicKey !== "string" || !item.ownerPublicKey || item.ownerPublicKey.length > MAX_SECRET_LENGTH ||
    typeof item.transportSecret !== "string" || !item.transportSecret || item.transportSecret.length > MAX_SECRET_LENGTH ||
    !Number.isSafeInteger(item.epoch) || item.epoch < 1 ||
    typeof item.updatedAt !== "string" || Number.isNaN(Date.parse(item.updatedAt)) ||
    !Array.isArray(item.ownerCertificates) || item.ownerCertificates.length > 32 ||
    (item.ownerHistory !== undefined && (!Array.isArray(item.ownerHistory) || item.ownerHistory.length > 32 || item.ownerHistory.some(owner =>
      !owner || typeof owner.personId !== "string" || !owner.personId || typeof owner.publicKey !== "string" || !owner.publicKey ||
      !Array.isArray(owner.certificates) || owner.certificates.length > 32))) ||
    new TextEncoder().encode(JSON.stringify(item)).byteLength > MAX_AUTH_BUNDLE_LENGTH) {
    throw new Error("Invalid workspace mesh credential")
  }
}

export function validateWorkspaceAuthority(value: unknown): asserts value is WorkspaceAuthorityRecord {
  const item = value as WorkspaceAuthorityRecord
  if (!item || item.version !== 1 || typeof item.workspaceId !== "string" || !item.workspaceId || item.workspaceId.length > MAX_STRING_LENGTH ||
    (item.genesisOwnerPersonId !== undefined && (typeof item.genesisOwnerPersonId !== "string" || !item.genesisOwnerPersonId || item.genesisOwnerPersonId.length > MAX_STRING_LENGTH)) ||
    typeof item.ownerPersonId !== "string" || !item.ownerPersonId || item.ownerPersonId.length > MAX_STRING_LENGTH ||
    typeof item.ownerPublicKey !== "string" || !item.ownerPublicKey || item.ownerPublicKey.length > MAX_SECRET_LENGTH ||
    !Number.isSafeInteger(item.epoch) || item.epoch < 1 ||
    typeof item.updatedAt !== "string" || Number.isNaN(Date.parse(item.updatedAt)) ||
    !Array.isArray(item.ownerCertificates) || item.ownerCertificates.length > 32 ||
    (item.ownerHistory !== undefined && (!Array.isArray(item.ownerHistory) || item.ownerHistory.length > 32 || item.ownerHistory.some(owner =>
      !owner || typeof owner.personId !== "string" || !owner.personId || typeof owner.publicKey !== "string" || !owner.publicKey ||
      !Array.isArray(owner.certificates) || owner.certificates.length > 32))) ||
    new TextEncoder().encode(JSON.stringify(item)).byteLength > MAX_AUTH_BUNDLE_LENGTH) {
    throw new Error("Invalid workspace authority")
  }
}

export function authorityFromCredential(credential: WorkspaceMeshCredential): WorkspaceAuthorityRecord {
  validateWorkspaceCredential(credential)
  const { transportSecret: _transportSecret, ...authority } = credential
  validateWorkspaceAuthority(authority)
  return structuredClone(authority)
}

/**
 * Validates that a node secret is a 32-byte Uint8Array.
 */
export function validateNodeSecret(secret: unknown): asserts secret is Uint8Array {
  const isUint8 =
    secret instanceof Uint8Array ||
    (typeof secret === "object" && secret !== null && (secret as { constructor?: { name?: string } }).constructor?.name === "Uint8Array")

  if (!isUint8) {
    throw new Error("Invalid node secret: must be a Uint8Array of exactly 32 bytes")
  }
  if ((secret as Uint8Array).byteLength !== 32) {
    throw new Error("Invalid node secret: must be a Uint8Array of exactly 32 bytes")
  }
}

/**
 * Validates all fields of a WorkspacePeerRecord.
 */
export function validatePeerRecord(peer: unknown): asserts peer is WorkspacePeerRecord {
  if (typeof peer !== "object" || peer === null) {
    throw new Error("Invalid peer record: must be a non-null object")
  }
  const r = peer as Record<string, unknown>

  if (typeof r.workspaceId !== "string" || r.workspaceId.trim().length === 0 || r.workspaceId.length > MAX_STRING_LENGTH) {
    throw new Error(`Invalid peer record: workspaceId must be a non-empty string <= ${MAX_STRING_LENGTH} characters`)
  }
  if (typeof r.deviceId !== "string" || r.deviceId.trim().length === 0 || r.deviceId.length > MAX_STRING_LENGTH) {
    throw new Error(`Invalid peer record: deviceId must be a non-empty string <= ${MAX_STRING_LENGTH} characters`)
  }
  if (r.instanceId !== undefined && (typeof r.instanceId !== "string" || !r.instanceId || r.instanceId.length > MAX_STRING_LENGTH)) {
    throw new Error(`Invalid peer record: instanceId must be a non-empty string <= ${MAX_STRING_LENGTH} characters`)
  }
  if (r.instances !== undefined && (!Array.isArray(r.instances) || r.instances.length > 32 || r.instances.some(instance =>
    !instance || typeof instance.instanceId !== "string" || !instance.instanceId || instance.instanceId.length > MAX_STRING_LENGTH ||
    typeof instance.endpoint !== "string" || !instance.endpoint || instance.endpoint.length > MAX_ENDPOINT_LENGTH ||
    typeof instance.lastSeen !== "string" || Number.isNaN(Date.parse(instance.lastSeen))))) {
    throw new Error("Invalid peer record transport instances")
  }
  if (typeof r.personId !== "string" || r.personId.trim().length === 0 || r.personId.length > MAX_STRING_LENGTH) {
    throw new Error(`Invalid peer record: personId must be a non-empty string <= ${MAX_STRING_LENGTH} characters`)
  }
  if (typeof r.endpoint !== "string" || r.endpoint.trim().length === 0 || r.endpoint.length > MAX_ENDPOINT_LENGTH) {
    throw new Error(`Invalid peer record: endpoint must be a non-empty string <= ${MAX_ENDPOINT_LENGTH} characters`)
  }

  const isSecretString = typeof r.transportSecret === "string" && r.transportSecret.length > 0 && r.transportSecret.length <= MAX_SECRET_LENGTH
  const isSecretBytes = r.transportSecret instanceof Uint8Array && r.transportSecret.byteLength > 0 && r.transportSecret.byteLength <= MAX_SECRET_LENGTH
  if (!isSecretString && !isSecretBytes) {
    throw new Error(`Invalid peer record: transportSecret must be a non-empty string or Uint8Array <= ${MAX_SECRET_LENGTH} bytes`)
  }

  if (r.role !== "owner" && r.role !== "editor" && r.role !== "visitor") {
    throw new Error("Invalid peer record: role must be 'owner' or 'editor'")
  }

  if (typeof r.lastSeen !== "string" || Number.isNaN(Date.parse(r.lastSeen))) {
    throw new Error("Invalid peer record: lastSeen must be a valid ISO 8601 date string")
  }

  if (r.revokedAt !== undefined && r.revokedAt !== null) {
    if (typeof r.revokedAt !== "string" || Number.isNaN(Date.parse(r.revokedAt))) {
      throw new Error("Invalid peer record: revokedAt must be a valid ISO 8601 date string or null/undefined")
    }
  }
  if (r.advertisement !== undefined && new TextEncoder().encode(JSON.stringify(r.advertisement)).byteLength > MAX_AUTH_BUNDLE_LENGTH) {
    throw new Error("Invalid peer record: advertisement is too large")
  }
}

/**
 * Deterministically serializes a value to canonical JSON.
 */
export function canonicalJson(val: unknown, seen = new Set<unknown>()): string {
  if (val === null) return "null"
  const type = typeof val
  if (type === "boolean" || type === "number" || type === "string") {
    return JSON.stringify(val)
  }
  if (type === "undefined" || type === "symbol" || type === "function") {
    return "null"
  }
  if (type === "bigint") {
    throw new TypeError("BigInt cannot be serialized to canonical JSON")
  }
  if (val instanceof Uint8Array) {
    let bin = ""
    for (let i = 0; i < val.byteLength; i++) {
      bin += String.fromCharCode(val[i])
    }
    return JSON.stringify(btoa(bin))
  }
  if (typeof val === "object") {
    if (seen.has(val)) {
      throw new TypeError("Circular reference detected")
    }
    seen.add(val)
    try {
      if (Array.isArray(val)) {
        const items = val.map((item) => (item === undefined ? "null" : canonicalJson(item, seen)))
        return `[${items.join(",")}]`
      }
      const obj = val as Record<string, unknown>
      const keys = Object.keys(obj).sort()
      const entries: string[] = []
      for (const key of keys) {
        const v = obj[key]
        if (v !== undefined && typeof v !== "function" && typeof v !== "symbol") {
          entries.push(`${JSON.stringify(key)}:${canonicalJson(v, seen)}`)
        }
      }
      return `{${entries.join(",")}}`
    } finally {
      seen.delete(val)
    }
  }
  return "null"
}

/**
 * Deterministically merges an existing peer record with an incoming update.
 *
 * Rules:
 * - workspaceId and deviceId must match
 * - lastSeen: monotonic progression (maximum timestamp)
 * - role: owner priority on tie, otherwise newer timestamp wins
 * - endpoint & transportSecret: newer timestamp wins, or deterministic tie-break
 * - revokedAt: once revoked, stays revoked unless explicitly unrevoked (null).
 *   If both have revokedAt, earliest revocation date is preserved.
 */
export function mergePeerRecords(
  existing: WorkspacePeerRecord,
  incoming: WorkspacePeerRecord
): WorkspacePeerRecord {
  return meshRustRuntime().state.mergePeerRecords(existing, incoming) as WorkspacePeerRecord
}

function promisifyRequest<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error || new Error("IndexedDB request failed"))
  })
}

// Transport timestamps cannot erase verified security records saved by another tab.
function mergeCredentialSecurity(current: WorkspaceMeshCredential, incoming: WorkspaceMeshCredential): WorkspaceMeshCredential {
  const newer = incoming.epoch > current.epoch || (incoming.epoch === current.epoch && incoming.updatedAt >= current.updatedAt)
  const result = structuredClone(newer ? incoming : current)
  const left = (current.catalog ?? {}) as Record<string, unknown>
  const right = (incoming.catalog ?? {}) as Record<string, unknown>
  const catalog = { ...(result.catalog as Record<string, unknown> | undefined) }
  for (const key of ["deviceRevocations", "departures", "revocations"]) {
    if (!Array.isArray(left[key]) && !Array.isArray(right[key])) continue
    const values = [...(Array.isArray(left[key]) ? left[key] : []), ...(Array.isArray(right[key]) ? right[key] : [])]
    const unique = new Map(values.map(value => [JSON.stringify(value), value]))
    if (unique.size > 512) throw new Error("Too many workspace security records")
    catalog[key] = [...unique.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, value]) => value)
  }
  result.catalog = catalog
  type Grant = { payload: { personId: string; accessEpoch?: number } }
  const oldGrant = current.localGrant as Grant | undefined, nextGrant = incoming.localGrant as Grant | undefined
  if (oldGrant && nextGrant && oldGrant.payload.personId === nextGrant.payload.personId) {
    result.localGrant = (oldGrant.payload.accessEpoch ?? 1) > (nextGrant.payload.accessEpoch ?? 1) ? current.localGrant : incoming.localGrant
  }
  result.ownerCertificates = [...new Map([...current.ownerCertificates, ...incoming.ownerCertificates]
    .map(value => [JSON.stringify(value), value])).values()]
  return result
}

async function putAuthorityIfNewer(store: IDBObjectStore, authority: WorkspaceAuthorityRecord): Promise<void> {
  const current = await promisifyRequest<WorkspaceAuthorityRecord | undefined>(store.get(authority.workspaceId))
  if (current) {
    validateWorkspaceAuthority(current)
    if (authority.epoch < current.epoch) return
    if (authority.epoch === current.epoch && authority.updatedAt < current.updatedAt) return
  }
  await promisifyRequest(store.put(structuredClone(authority)))
}

export class PeerStore {
  private readonly dbName: string
  private readonly idbFactory?: IDBFactory
  private dbInstance: IDBDatabase | null = null

  constructor(dbName: string = DEFAULT_PEER_DB_NAME, idbFactory?: IDBFactory) {
    this.dbName = dbName
    this.idbFactory = idbFactory
  }

  private getIdb(): IDBFactory {
    if (this.idbFactory) {
      return this.idbFactory
    }
    if (typeof indexedDB !== "undefined" && indexedDB) {
      return indexedDB
    }
    throw new Error("IndexedDB is not available in this environment")
  }

  private openDb(): Promise<IDBDatabase> {
    const idb = this.getIdb()
    return new Promise((resolve, reject) => {
      const request = idb.open(this.dbName, 2)

      request.onblocked = () => {
        reject(new Error(`IndexedDB open blocked for database ${this.dbName}`))
      }

      request.onerror = () => {
        reject(request.error || new Error(`Failed to open IndexedDB ${this.dbName}`))
      }

      request.onupgradeneeded = () => {
        const db = request.result
        if (!db.objectStoreNames.contains(STORE_PEERS)) {
          const peerStore = db.createObjectStore(STORE_PEERS, {
            keyPath: ["workspaceId", "deviceId"],
          })
          peerStore.createIndex(INDEX_PEERS_WORKSPACE, "workspaceId", { unique: false })
          peerStore.createIndex(INDEX_PEERS_DEVICE, "deviceId", { unique: false })
          peerStore.createIndex(INDEX_PEERS_LAST_SEEN, "lastSeen", { unique: false })
        }
        if (!db.objectStoreNames.contains(STORE_NODE)) {
          db.createObjectStore(STORE_NODE, { keyPath: "key" })
        }
        if (!db.objectStoreNames.contains(STORE_AUTHORITY)) {
          db.createObjectStore(STORE_AUTHORITY, { keyPath: "workspaceId" })
        }
      }

      request.onsuccess = () => {
        const db = request.result
        db.onversionchange = () => {
          try {
            db.close()
          } catch {}
          this.dbInstance = null
        }
        db.onclose = () => {
          this.dbInstance = null
        }
        resolve(db)
      }
    })
  }

  private async getDb(): Promise<IDBDatabase> {
    if (this.dbInstance) {
      return this.dbInstance
    }
    const db = await this.openDb()
    this.dbInstance = db
    return db
  }

  /**
   * Executes an atomic IndexedDB transaction.
   * Resolves only after tx.oncomplete fires (durability guarantee).
   */
  private runTx<T>(
    storeNames: string[],
    mode: IDBTransactionMode,
    fn: (tx: IDBTransaction) => Promise<T>
  ): Promise<T> {
    return new Promise(async (resolve, reject) => {
      let db: IDBDatabase
      try {
        db = await this.getDb()
      } catch (err) {
        reject(err)
        return
      }

      let tx: IDBTransaction
      try {
        tx = db.transaction(storeNames, mode)
      } catch (err) {
        reject(err)
        return
      }

      let result: T
      let isResultReady = false
      let hasTxFinished = false

      tx.oncomplete = () => {
        hasTxFinished = true
        if (isResultReady) {
          resolve(result)
        } else {
          reject(new Error("Transaction completed before result was produced"))
        }
      }

      tx.onerror = () => {
        hasTxFinished = true
        reject(tx.error || new Error("Transaction error"))
      }

      tx.onabort = () => {
        hasTxFinished = true
        reject(tx.error || new Error("Transaction aborted"))
      }

      try {
        result = await fn(tx)
        isResultReady = true
        if (hasTxFinished) {
          resolve(result)
        }
      } catch (err) {
        try {
          tx.abort()
        } catch {}
        reject(err)
      }
    })
  }

  /**
   * Retrieves the persistent local 32-byte node secret, or null if not yet created.
   */
  async getNodeSecret(): Promise<Uint8Array | null> {
    return this.runTx([STORE_NODE], "readonly", async (tx) => {
      const store = tx.objectStore(STORE_NODE)
      const record = await promisifyRequest<{ key: string; secret: Uint8Array }>(store.get(NODE_SECRET_KEY))
      if (!record || !record.secret) {
        return null
      }
      validateNodeSecret(record.secret)
      return new Uint8Array(record.secret)
    })
  }

  /**
   * Sets or overrides the persistent local 32-byte node secret.
   */
  async setNodeSecret(secret: Uint8Array): Promise<void> {
    validateNodeSecret(secret)
    await this.runTx([STORE_NODE], "readwrite", async (tx) => {
      const store = tx.objectStore(STORE_NODE)
      await promisifyRequest(
        store.put({
          key: NODE_SECRET_KEY,
          secret: new Uint8Array(secret),
          updatedAt: new Date().toISOString(),
        })
      )
    })
  }

  /**
   * Gets the persistent local 32-byte node secret, generating and persisting a new one if absent.
   */
  async getOrCreateNodeSecret(): Promise<Uint8Array> {
    return this.getOrCreateNamedNodeSecret(NODE_SECRET_KEY)
  }

  async getOrCreateInstanceNodeSecret(instanceId: string): Promise<Uint8Array> {
    if (!instanceId || instanceId.length > MAX_STRING_LENGTH) throw new Error("Invalid mesh instanceId")
    return this.getOrCreateNamedNodeSecret(`instance:${instanceId}`, instanceId === "slot-0" ? NODE_SECRET_KEY : undefined)
  }

  async nextInstanceAdvertisementSequence(instanceId: string): Promise<number> {
    if (!instanceId || instanceId.length > MAX_STRING_LENGTH) throw new Error("Invalid mesh instanceId")
    return this.runTx([STORE_NODE], "readwrite", async tx => {
      const store = tx.objectStore(STORE_NODE)
      const key = `${INSTANCE_SEQUENCE_PREFIX}${instanceId}`
      const record = await promisifyRequest<{ key: string; sequence: number } | undefined>(store.get(key))
      const sequence = Number.isSafeInteger(record?.sequence) ? record!.sequence + 1 : 1
      await promisifyRequest(store.put({ key, sequence, updatedAt: new Date().toISOString() }))
      return sequence
    })
  }

  private async getOrCreateNamedNodeSecret(key: string, fallbackKey?: string): Promise<Uint8Array> {
    const existing = await this.runTx([STORE_NODE], "readonly", async tx => {
      const store = tx.objectStore(STORE_NODE)
      const record = await promisifyRequest<{ key: string; secret: Uint8Array }>(store.get(key))
      const fallback = fallbackKey
        ? await promisifyRequest<{ key: string; secret: Uint8Array }>(store.get(fallbackKey))
        : undefined
      if (fallback?.secret) {
        validateNodeSecret(fallback.secret)
        if (!record?.secret || !new Uint8Array(record.secret).every((byte, index) => byte === fallback.secret[index])) return null
        return new Uint8Array(fallback.secret)
      }
      if (!record?.secret) return null
      validateNodeSecret(record.secret)
      return new Uint8Array(record.secret)
    })
    if (existing) {
      return existing
    }

    const newSecret = new Uint8Array(32)
    crypto.getRandomValues(newSecret)

    return this.runTx([STORE_NODE], "readwrite", async (tx) => {
      const store = tx.objectStore(STORE_NODE)
      const current = await promisifyRequest<{ key: string; secret: Uint8Array }>(store.get(key))
      const fallback = fallbackKey
        ? await promisifyRequest<{ key: string; secret: Uint8Array }>(store.get(fallbackKey))
        : undefined
      if (fallback?.secret) validateNodeSecret(fallback.secret)
      if (current?.secret && !fallback?.secret) {
        validateNodeSecret(current.secret)
        return new Uint8Array(current.secret)
      }
      const storedSecret = fallback?.secret ? new Uint8Array(fallback.secret) : new Uint8Array(newSecret)

      await promisifyRequest(
        store.put({
          key,
          secret: storedSecret,
          createdAt: new Date().toISOString(),
        })
      )
      return new Uint8Array(storedSecret)
    })
  }

  async getWorkspaceCredential(workspaceId: string): Promise<WorkspaceMeshCredential | null> {
    if (!workspaceId) throw new Error("Invalid workspaceId")
    return this.runTx([STORE_NODE], "readonly", async tx => {
      const record = await promisifyRequest<{ key: string; credential: WorkspaceMeshCredential } | undefined>(
        tx.objectStore(STORE_NODE).get(`${WORKSPACE_CREDENTIAL_PREFIX}${workspaceId}`)
      )
      if (!record) return null
      validateWorkspaceCredential(record.credential)
      return structuredClone(record.credential)
    })
  }

  async putWorkspaceCredential(credential: WorkspaceMeshCredential): Promise<void> {
    validateWorkspaceCredential(credential)
    await this.runTx([STORE_NODE, STORE_AUTHORITY], "readwrite", async tx => {
      const store = tx.objectStore(STORE_NODE)
      const key = `${WORKSPACE_CREDENTIAL_PREFIX}${credential.workspaceId}`
      const current = await promisifyRequest<{ key: string; credential: WorkspaceMeshCredential } | undefined>(store.get(key))
      if (current) {
        validateWorkspaceCredential(current.credential)
        if (current.credential.ownerPersonId !== credential.ownerPersonId) throw new Error("Workspace mesh owner cannot change")
        credential = mergeCredentialSecurity(current.credential, credential)
      }
      await promisifyRequest(store.put({ key, credential: structuredClone(credential) }))
      await putAuthorityIfNewer(tx.objectStore(STORE_AUTHORITY), authorityFromCredential(credential))
    })
  }

  async transferWorkspaceCredential(expectedOwnerPersonId: string, credential: WorkspaceMeshCredential): Promise<void> {
    validateWorkspaceCredential(credential)
    await this.runTx([STORE_NODE, STORE_AUTHORITY], "readwrite", async tx => {
      const store = tx.objectStore(STORE_NODE)
      const key = `${WORKSPACE_CREDENTIAL_PREFIX}${credential.workspaceId}`
      const current = await promisifyRequest<{ key: string; credential: WorkspaceMeshCredential } | undefined>(store.get(key))
      if (!current) throw new Error("Missing workspace mesh credential")
      validateWorkspaceCredential(current.credential)
      if (current.credential.ownerPersonId !== expectedOwnerPersonId) throw new Error("Workspace owner changed before transfer")
      if (credential.ownerPersonId === expectedOwnerPersonId || credential.epoch < current.credential.epoch) {
        throw new Error("Invalid workspace ownership transfer")
      }
      await promisifyRequest(store.put({ key, credential: structuredClone(credential) }))
      await putAuthorityIfNewer(tx.objectStore(STORE_AUTHORITY), authorityFromCredential(credential))
    })
  }

  async getWorkspaceAuthority(workspaceId: string): Promise<WorkspaceAuthorityRecord | null> {
    if (!workspaceId) throw new Error("Invalid workspaceId")
    const authority = await this.runTx([STORE_AUTHORITY], "readonly", async tx =>
      promisifyRequest<WorkspaceAuthorityRecord | undefined>(tx.objectStore(STORE_AUTHORITY).get(workspaceId)))
    if (authority) {
      validateWorkspaceAuthority(authority)
      return structuredClone(authority)
    }
    // Lazy v1 migration: copy authority before any transport cleanup can remove it.
    const credential = await this.getWorkspaceCredential(workspaceId)
    if (!credential) return null
    const migrated = authorityFromCredential(credential)
    await this.putWorkspaceAuthority(migrated)
    return migrated
  }

  async putWorkspaceAuthority(authority: WorkspaceAuthorityRecord): Promise<void> {
    validateWorkspaceAuthority(authority)
    await this.runTx([STORE_AUTHORITY], "readwrite", async tx => {
      await putAuthorityIfNewer(tx.objectStore(STORE_AUTHORITY), authority)
    })
  }

  async listWorkspaceAuthorities(): Promise<WorkspaceAuthorityRecord[]> {
    const records = await this.runTx([STORE_AUTHORITY], "readonly", async tx =>
      promisifyRequest<WorkspaceAuthorityRecord[]>(tx.objectStore(STORE_AUTHORITY).getAll()))
    for (const record of records) validateWorkspaceAuthority(record)
    return records.map(record => structuredClone(record)).sort((a, b) => a.workspaceId.localeCompare(b.workspaceId))
  }

  async listWorkspaceCredentials(): Promise<WorkspaceMeshCredential[]> {
    return this.runTx([STORE_NODE], "readonly", async tx => {
      const records = await promisifyRequest<Array<{ key: string; credential?: WorkspaceMeshCredential }>>(tx.objectStore(STORE_NODE).getAll())
      const result: WorkspaceMeshCredential[] = []
      for (const record of records) {
        if (!record.key.startsWith(WORKSPACE_CREDENTIAL_PREFIX) || !record.credential) continue
        validateWorkspaceCredential(record.credential)
        result.push(structuredClone(record.credential))
      }
      return result.sort((a, b) => a.workspaceId.localeCompare(b.workspaceId))
    })
  }

  /**
   * Retrieves a single workspace peer record by compound key [workspaceId, deviceId].
   */
  async getPeer(workspaceId: string, deviceId: string): Promise<WorkspacePeerRecord | null> {
    if (typeof workspaceId !== "string" || !workspaceId) {
      throw new Error("Invalid workspaceId")
    }
    if (typeof deviceId !== "string" || !deviceId) {
      throw new Error("Invalid deviceId")
    }

    return this.runTx([STORE_PEERS], "readonly", async (tx) => {
      const store = tx.objectStore(STORE_PEERS)
      const record = await promisifyRequest<WorkspacePeerRecord | undefined>(
        store.get([workspaceId, deviceId])
      )
      return record ?? null
    })
  }

  /**
   * Atomically upserts a peer record, deterministically merging with any existing record.
   */
  async upsertPeer(peer: WorkspacePeerRecord): Promise<WorkspacePeerRecord> {
    validatePeerRecord(peer)

    return this.runTx([STORE_PEERS], "readwrite", async (tx) => {
      const store = tx.objectStore(STORE_PEERS)
      const existing = await promisifyRequest<WorkspacePeerRecord | undefined>(
        store.get([peer.workspaceId, peer.deviceId])
      )

      const merged = existing ? mergePeerRecords(existing, peer) : {
        ...peer,
        transportSecret: peer.transportSecret instanceof Uint8Array
          ? new Uint8Array(peer.transportSecret)
          : peer.transportSecret,
      }

      await promisifyRequest(store.put(merged))
      return merged
    })
  }

  /**
   * Bulk deterministic merge/upsert of multiple peer records in a single transaction.
   */
  async mergePeers(peers: WorkspacePeerRecord[]): Promise<WorkspacePeerRecord[]> {
    for (const peer of peers) {
      validatePeerRecord(peer)
    }

    if (peers.length === 0) return []

    return this.runTx([STORE_PEERS], "readwrite", async (tx) => {
      const store = tx.objectStore(STORE_PEERS)
      const results: WorkspacePeerRecord[] = []

      for (const peer of peers) {
        const existing = await promisifyRequest<WorkspacePeerRecord | undefined>(
          store.get([peer.workspaceId, peer.deviceId])
        )
        const merged = existing ? mergePeerRecords(existing, peer) : {
          ...peer,
          transportSecret: peer.transportSecret instanceof Uint8Array
            ? new Uint8Array(peer.transportSecret)
            : peer.transportSecret,
        }
        await promisifyRequest(store.put(merged))
        results.push(merged)
      }

      return results
    })
  }

  /**
   * Lists peers for a given workspaceId, or across all workspaces if omitted.
   * Returns records sorted deterministically by workspaceId then deviceId.
   */
  async listPeers(workspaceId?: string): Promise<WorkspacePeerRecord[]> {
    return this.runTx([STORE_PEERS], "readonly", async (tx) => {
      const store = tx.objectStore(STORE_PEERS)
      let list: WorkspacePeerRecord[]

      if (workspaceId !== undefined) {
        if (typeof workspaceId !== "string" || !workspaceId) {
          throw new Error("Invalid workspaceId")
        }
        const index = store.index(INDEX_PEERS_WORKSPACE)
        list = await promisifyRequest<WorkspacePeerRecord[]>(index.getAll(workspaceId))
      } else {
        list = await promisifyRequest<WorkspacePeerRecord[]>(store.getAll())
      }

      return list.sort((a, b) => {
        if (a.workspaceId !== b.workspaceId) {
          return a.workspaceId.localeCompare(b.workspaceId)
        }
        return a.deviceId.localeCompare(b.deviceId)
      })
    })
  }

  async listDeviceReplicas(workspaceId?: string): Promise<DeviceReplicaRecord[]> {
    return (await this.listPeers(workspaceId)).map(peer => {
      const routes = new Map<string, PeerTransportInstance>()
      for (const route of peer.instances ?? []) routes.set(route.instanceId, structuredClone(route))
      if (peer.instanceId && !routes.has(peer.instanceId)) routes.set(peer.instanceId, {
        instanceId: peer.instanceId,
        endpoint: peer.endpoint,
        lastSeen: peer.lastSeen,
        ...(peer.advertisement === undefined ? {} : { advertisement: structuredClone(peer.advertisement) }),
      })
      return {
        scopeId: peer.workspaceId,
        deviceId: peer.deviceId,
        personId: peer.personId,
        role: peer.role,
        ...(peer.revokedAt === undefined ? {} : { revokedAt: peer.revokedAt }),
        routes: [...routes.values()].sort((left, right) => left.instanceId.localeCompare(right.instanceId)),
      }
    })
  }

  async listPeerInstances(workspaceId?: string): Promise<WorkspacePeerRecord[]> {
    const peers = await this.listPeers(workspaceId)
    return peers.flatMap(peer => {
      const instances = new Map<string, PeerTransportInstance>()
      for (const instance of peer.instances ?? []) instances.set(instance.instanceId, instance)
      if (peer.instanceId) instances.set(peer.instanceId, {
        instanceId: peer.instanceId, endpoint: peer.endpoint, lastSeen: peer.lastSeen, advertisement: peer.advertisement,
      })
      if (!instances.size) return [peer]
      return [...instances.values()].map(instance => ({ ...peer, instanceId: instance.instanceId,
        endpoint: instance.endpoint, lastSeen: instance.lastSeen, advertisement: instance.advertisement }))
    }).sort((a, b) => a.workspaceId.localeCompare(b.workspaceId) || a.deviceId.localeCompare(b.deviceId) ||
      (a.instanceId ?? "").localeCompare(b.instanceId ?? ""))
  }

  /**
   * Removes a peer record by workspaceId and deviceId.
   * Returns true if existed and removed, false if not found.
   */
  async removePeer(workspaceId: string, deviceId: string): Promise<boolean> {
    if (typeof workspaceId !== "string" || !workspaceId) {
      throw new Error("Invalid workspaceId")
    }
    if (typeof deviceId !== "string" || !deviceId) {
      throw new Error("Invalid deviceId")
    }

    return this.runTx([STORE_PEERS], "readwrite", async (tx) => {
      const store = tx.objectStore(STORE_PEERS)
      const existing = await promisifyRequest<WorkspacePeerRecord | undefined>(
        store.get([workspaceId, deviceId])
      )
      if (!existing) {
        return false
      }
      await promisifyRequest(store.delete([workspaceId, deviceId]))
      return true
    })
  }

  /**
   * Clears peers for a specific workspace, or all peers if omitted.
   */
  async clearPeers(workspaceId?: string): Promise<void> {
    return this.runTx([STORE_PEERS], "readwrite", async (tx) => {
      const store = tx.objectStore(STORE_PEERS)
      if (workspaceId !== undefined) {
        if (typeof workspaceId !== "string" || !workspaceId) {
          throw new Error("Invalid workspaceId")
        }
        const index = store.index(INDEX_PEERS_WORKSPACE)
        const items = await promisifyRequest<WorkspacePeerRecord[]>(index.getAll(workspaceId))
        for (const item of items) {
          await promisifyRequest(store.delete([item.workspaceId, item.deviceId]))
        }
      } else {
        await promisifyRequest(store.clear())
      }
    })
  }

  /** Removes active transport state while preserving durable signed authority and the local document. */
  async removeWorkspaceMeshData(workspaceId: string): Promise<void> {
    if (typeof workspaceId !== "string" || !workspaceId) throw new Error("Invalid workspaceId")
    await this.runTx([STORE_PEERS, STORE_NODE, STORE_AUTHORITY], "readwrite", async tx => {
      const peers = tx.objectStore(STORE_PEERS)
      const items = await promisifyRequest<WorkspacePeerRecord[]>(peers.index(INDEX_PEERS_WORKSPACE).getAll(workspaceId))
      for (const item of items) await promisifyRequest(peers.delete([item.workspaceId, item.deviceId]))
      const node = tx.objectStore(STORE_NODE)
      const key = `${WORKSPACE_CREDENTIAL_PREFIX}${workspaceId}`
      const active = await promisifyRequest<{ key: string; credential: WorkspaceMeshCredential } | undefined>(node.get(key))
      if (active) {
        validateWorkspaceCredential(active.credential)
        const authorityStore = tx.objectStore(STORE_AUTHORITY)
        const authority = authorityFromCredential(active.credential)
        await putAuthorityIfNewer(authorityStore, authority)
      }
      await promisifyRequest(node.delete(key))
    })
  }

  /**
   * Clears all stores (peers and node secret). Useful for test isolation.
   */
  async clearAll(): Promise<void> {
    return this.runTx([STORE_PEERS, STORE_NODE, STORE_AUTHORITY], "readwrite", async (tx) => {
      const peerStore = tx.objectStore(STORE_PEERS)
      const nodeStore = tx.objectStore(STORE_NODE)
      const authorityStore = tx.objectStore(STORE_AUTHORITY)
      await promisifyRequest(peerStore.clear())
      await promisifyRequest(nodeStore.clear())
      await promisifyRequest(authorityStore.clear())
    })
  }

  /**
   * Alias for clearAll().
   */
  async clear(): Promise<void> {
    return this.clearAll()
  }

  /**
   * Closes any open IndexedDB database connection.
   */
  close(): void {
    if (this.dbInstance) {
      try {
        this.dbInstance.close()
      } catch {}
      this.dbInstance = null
    }
  }
}

export const peerStore = new PeerStore()
