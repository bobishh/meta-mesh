import { expect, it, vi } from "vitest"
import { signEnvelope, publicKeyId, toBase64Url } from "@meta-uber/mesh-identity"
import wasmModule from "../../mesh-transport/wasm/policy/meta_mesh_policy_bg.wasm"
import { initSync, WasmStateCore } from "@meta-uber/mesh-transport/wasm"
import { emptyReplicaState, ReplicaEngine, type ReplicaState } from "@meta-uber/mesh-replication/replica-engine"
import { readArchiveBytes, writeArchiveBytes, type ArchiveObjectStore, type ArchiveTreeContext } from "@meta-uber/mesh-replication/history-archive"
import { openArchiveObject, sealArchiveObject } from "@meta-uber/mesh-replication/history-archive-crypto"
import {
  decryptBlindObject,
  encryptBlindObject,
  inventoryRustyObjects,
  rustyHash,
  rustyObjectId,
  uploadRustyObject,
  verifyRustyStorageReceipt,
  type BlindObject,
  type RustyReplicaAccess,
  type RustyStorageReceipt,
} from "@meta-uber/mesh-replication/rusty-replica"

initSync({ module: wasmModule })

function keys(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as Promise<CryptoKeyPair>
}

async function accessFor(pair?: CryptoKeyPair): Promise<{ access: RustyReplicaAccess; pair: CryptoKeyPair }> {
  const keyPair = pair ?? await keys()
  const servicePublicKey = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey)))
  return { access: { origin: "https://rusty.example", scopeId: "board-scope", servicePublicKey,
    readToken: "private-read-token", writeToken: "private-write-token", policyRevision: 4 }, pair: keyPair }
}

async function receipt(access: RustyReplicaAccess, pair: CryptoKeyPair, object: BlindObject, requestId: string,
  changes: Partial<RustyStorageReceipt["payload"]> = {}): Promise<RustyStorageReceipt> {
  const serviceId = await publicKeyId(access.servicePublicKey)
  const payload: RustyStorageReceipt["payload"] = { kind: "blind-storage-receipt", version: 2, serviceId,
    scopeId: access.scopeId, keyEpoch: object.keyEpoch, objectId: await rustyObjectId(object), sequence: 1,
    policyRevision: access.policyRevision, requestId, ...changes }
  return signEnvelope(pair.privateKey, payload, serviceId, "RUSTY/2")
}

it("independent public consumer uses the actual WASM policy and roundtrips encrypted history bytes", async () => {
  expect(WasmStateCore.causalAdmissionPolicyId()).toMatch(/^mesh-causal-admission@/)
  const context: ArchiveTreeContext = { workspaceId: "workspace", historyEpoch: 1, indexId: "consumer-history" }
  const stored = new Map<string, Uint8Array>()
  const store: ArchiveObjectStore = {
    read: async id => stored.get(id)?.slice(),
    write: async (id, bytes) => { stored.set(id, bytes.slice()) },
  }
  const original = new TextEncoder().encode("independent original signed history bytes")
  const reference = await writeArchiveBytes(context, [original], store)
  const parts = await readArchiveBytes(context, reference, store)
  const chunks: Uint8Array[] = []
  let length = 0
  for await (const part of parts) { chunks.push(part); length += part.length }
  const replay = new Uint8Array(length)
  let offset = 0
  for (const part of chunks) { replay.set(part, offset); offset += part.length }
  expect(replay).toEqual(original)

  const scope = { scopeId: "board-scope", keyEpoch: 2, key: new Uint8Array(32).fill(9) }
  const binding = { workspaceId: context.workspaceId, historyEpoch: context.historyEpoch, indexId: context.indexId,
    objectId: await rustyHash(original), objectKind: "part" as const, partIndex: 0, partCount: 1 }
  const sealed = await sealArchiveObject(scope, binding, original)
  expect(await openArchiveObject(scope, binding, sealed.ciphertextId, sealed.object)).toEqual(original)
})

it("verifies exact Rusty receipt scope, epoch, object, pin and request through public exports", async () => {
  const { access, pair } = await accessFor()
  const object = await encryptBlindObject(access.scopeId, 2, new Uint8Array(32).fill(4), new Uint8Array([1, 2, 3]))
  const valid = await receipt(access, pair, object, "request-00000001")
  expect(WasmStateCore.verifyEnvelope(valid, access.servicePublicKey, "RUSTY/2")).toBe(true)
  await expect(verifyRustyStorageReceipt(valid, access, object, "request-00000001")).resolves.toBeUndefined()
  const uploadRequests: Request[] = []
  await expect(uploadRustyObject(access, object, "request-00000001", 0, async (input, init) => {
    uploadRequests.push(new Request(input, init))
    return Response.json(valid)
  })).resolves.toEqual(valid)
  expect(uploadRequests[0]!.headers.get("x-rusty-request-id")).toBe("request-00000001")
  expect(JSON.parse(await uploadRequests[0]!.text())).toEqual(object)
  for (const changes of [
    { scopeId: "other-scope" },
    { keyEpoch: 3 },
    { objectId: "A".repeat(43) },
    { requestId: "other-request" },
  ]) {
    await expect(verifyRustyStorageReceipt(await receipt(access, pair, object, "request-00000001", changes),
      access, object, "request-00000001")).rejects.toThrow()
  }
  const other = await accessFor()
  const wrongPinReceipt = await receipt(other.access, other.pair, object, "request-00000001")
  await expect(verifyRustyStorageReceipt(wrongPinReceipt, access, object, "request-00000001")).rejects.toThrow()
  await expect(decryptBlindObject(object, "other-scope", 2, new Uint8Array(32).fill(4))).rejects.toThrow()
  await expect(decryptBlindObject(object, access.scopeId, 3, new Uint8Array(32).fill(4))).rejects.toThrow()
})

it("persists pending ciphertext before upload and retries exact request after response loss and restart", async () => {
  const { access, pair } = await accessFor()
  const binding = "workspace-replica-binding"
  let saved: ReplicaState<BlindObject> = emptyReplicaState<BlindObject>(binding)
  const requests: Array<{ object: BlindObject; requestId: string; observedSequence: number }> = []
  const httpRequests: Array<{ url: string; requestId: string; object: BlindObject }> = []
  let loseFirstResponse = true
  let storedReceipt: RustyStorageReceipt | undefined
  const content = new TextEncoder().encode("admitted document revision")
  const hash = await rustyHash(content)
  const ports = () => ({
    repository: {
      read: async () => structuredClone(saved),
      commit: async (generation: number, next: ReplicaState<BlindObject>) => {
        if (saved.generation !== generation) throw new Error("durable CAS conflict")
        saved = structuredClone(next)
      },
    },
    content: { revision: async () => "revision-1", capture: async () => ({ hash, bytes: content.length, payload: content }),
      seal: (payload: Uint8Array) => encryptBlindObject(access.scopeId, 2, new Uint8Array(32).fill(8), payload) },
    transport: {
      inventory: async () => ({ objects: [], cursor: 0, hasMore: false }),
      download: async () => { throw new Error("unexpected download") },
      upload: async (object: BlindObject, requestId: string, observedSequence: number) => {
        requests.push({ object: structuredClone(object), requestId, observedSequence })
        return uploadRustyObject(access, object, requestId, observedSequence, async (input, init) => {
          httpRequests.push({ url: String(input), requestId: new Headers(init?.headers).get("x-rusty-request-id") ?? "",
            object: JSON.parse(String(init?.body)) as BlindObject })
          storedReceipt ??= await receipt(access, pair, object, requestId)
          if (loseFirstResponse) { loseFirstResponse = false; throw new Error("response lost after durable server write") }
          return Response.json(storedReceipt)
        })
      },
    },
    admit: async () => ({ hash }),
    verifyReceipt: (value: RustyStorageReceipt, object: BlindObject, requestId: string) =>
      verifyRustyStorageReceipt(value, access, object, requestId),
    guard: async () => {},
  })
  await expect(new ReplicaEngine(binding, ports()).push()).rejects.toThrow("response lost")
  expect(saved.pending).toBeDefined()
  const pending = structuredClone(saved.pending!)
  expect(requests[0]).toEqual({ object: pending.object, requestId: pending.requestId, observedSequence: 0 })
  expect(httpRequests[0]).toMatchObject({ requestId: pending.requestId, object: pending.object })

  await expect(new ReplicaEngine(binding, ports()).push()).resolves.toBe(true)
  expect(requests[1]).toEqual(requests[0])
  expect(httpRequests[1]).toEqual(httpRequests[0])
  expect(saved.pending).toBeUndefined()
  expect(saved.lastUploaded).toBe(hash)
  expect(saved.generation).toBe(2)
})

it("does not acknowledge after failed CAS or stale authority, and bounds HTTP inventory", async () => {
  const { access, pair } = await accessFor()
  const object = await encryptBlindObject(access.scopeId, 1, new Uint8Array(32).fill(3), new Uint8Array([5]))
  const requestId = "request-00000002"
  const valid = await receipt(access, pair, object, requestId)
  const fetcher = vi.fn(async () => Response.json({ objects: [], cursor: 2, hasMore: false }))
  await expect(inventoryRustyObjects(access, 2, fetcher)).resolves.toMatchObject({ cursor: 2, hasMore: false })
  await expect(inventoryRustyObjects(access, 4, fetcher)).rejects.toThrow()

  const binding = "workspace-replica-binding"
  let saved: ReplicaState<BlindObject> = { ...emptyReplicaState<BlindObject>(binding), pending: {
    requestId, observedSequence: 0, hash: "saved-hash", bytes: 1, object,
  } }
  let failAckCas = true
  let authorityCurrent = true
  const ports = {
    repository: { read: async () => structuredClone(saved), commit: async (generation: number, next: ReplicaState<BlindObject>) => {
      if (saved.generation !== generation || failAckCas && !next.pending) throw new Error("durable CAS conflict")
      saved = structuredClone(next)
    } },
    content: { revision: async () => "r", capture: async () => ({ hash: "x", bytes: 1, payload: new Uint8Array([1]) }),
      seal: async () => object },
    transport: { inventory: async () => ({ objects: [], cursor: 0, hasMore: false }), download: async () => object,
      upload: async () => valid }, admit: async () => ({ hash: "x" }),
    verifyReceipt: (value: RustyStorageReceipt, current: BlindObject, id: string) => verifyRustyStorageReceipt(value, access, current, id),
    guard: async () => { if (!authorityCurrent) throw new Error("authority revoked") },
  }
  await expect(new ReplicaEngine(binding, ports).push()).rejects.toThrow("durable CAS conflict")
  expect(saved.pending?.requestId).toBe(requestId)
  failAckCas = false
  authorityCurrent = false
  await expect(new ReplicaEngine(binding, ports).push()).rejects.toThrow("authority revoked")
  expect(saved.pending?.requestId).toBe(requestId)
  expect(saved.lastUploaded).toBe("")
})
