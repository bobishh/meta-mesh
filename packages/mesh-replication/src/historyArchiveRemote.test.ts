import { expect, it, vi } from "vitest"
import { canonicalizeJson, sha256Base64Url, publicKeyId, signEnvelope, toBase64Url } from "@meta-uber/mesh-identity"
import { createArchiveRemote, type ArchiveRemoteAccess } from "./historyArchiveRemote"
import { sealArchiveObject } from "./historyArchiveCrypto"
import { archiveCoverageBranch, archiveCoverageLeaf } from "./historyArchiveCoverage"

async function fixture() {
  const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair
  const servicePublicKey = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)))
  const serviceId = await publicKeyId(servicePublicKey)
  const access: ArchiveRemoteAccess = { origin: "https://rusty.example", scopeId: "opaque-scope", policyRevision: 2,
    servicePublicKey, readToken: "private-read-token", writeToken: "private-write-token" }
  const bytes = new TextEncoder().encode("exact original evidence")
  const sealed = await sealArchiveObject({ scopeId: access.scopeId, keyEpoch: 3, key: new Uint8Array(32).fill(17) },
    { workspaceId: "workspace", historyEpoch: 1, indexId: "proofs", objectId: await sha256Base64Url(bytes), objectKind: "part", partIndex: 0, partCount: 1 }, bytes)
  const receipt = async (extra: Record<string, unknown> & {kind:string}) => signEnvelope(keys.privateKey, { version: 1, serviceId,
    scopeId: access.scopeId, policyRevision: access.policyRevision, requestId: "archive-request-00000001", ...extra }, serviceId, "RUSTY/2")
  const ensureCurrent = vi.fn(() => {})
  return { access, sealed, receipt, ensureCurrent, keys }
}

it("Given signed archive batches, when aggregating, then verify every child and return only the exact service-bound composition", async () => {
  const f = await fixture(), root = f.sealed.ciphertextId
  const objects = [{ objectId: root, keyEpoch: 3 }]
  const child = await f.receipt({ kind: "blind-archive-coverage-batch-receipt", objects })
  const summary = await archiveCoverageBranch(root, [await archiveCoverageLeaf(objects, root)])
  const signed = await f.receipt({ kind: "blind-archive-coverage-aggregate-receipt", archiveRootId: root, ...summary })
  const fetcher = vi.fn(async () => Response.json(signed))
  const remote = createArchiveRemote(f.access, { fetch: fetcher, ensureCurrent: f.ensureCurrent })
  expect(await remote.aggregate(root, [child], "archive-request-00000001")).toEqual(signed)
  const [url, init] = fetcher.mock.calls[0] as unknown as [string, RequestInit]
  expect(url).toBe("https://rusty.example/v2/scopes/opaque-scope/archive-coverage/aggregate")
  expect(new Headers(init.headers).get("Authorization")).toBe(`Bearer ${f.access.readToken}`)
  expect(JSON.parse(init.body as string)).toEqual({ version: 1, requestId: "archive-request-00000001", archiveRootId: root, children: [child] })
})

it("Given malformed or forged aggregate children, when submitted, then reject before sending any request", async () => {
  const f = await fixture(), root = f.sealed.ciphertextId, fetcher = vi.fn(async () => Response.json({}))
  const child = await f.receipt({ kind: "blind-archive-coverage-batch-receipt", objects: [{ objectId: root, keyEpoch: 3 }] })
  const remote = createArchiveRemote(f.access, { fetch: fetcher, ensureCurrent: f.ensureCurrent })
  for (const children of [[], Array.from({ length: 9 }, () => child), [child, child],
    [{ ...child, signature: toBase64Url(new Uint8Array(64)) }]]) {
    await expect(remote.aggregate(root, children, "archive-request-00000001")).rejects.toThrow()
  }
  expect(fetcher).not.toHaveBeenCalled()
})

it("Given a substituted aggregate reply, when signed by the correct service, then still reject wrong set, root, policy, count or request", async () => {
  const f = await fixture(), root = f.sealed.ciphertextId
  const objects = [{ objectId: root, keyEpoch: 3 }]
  const child = await f.receipt({ kind: "blind-archive-coverage-batch-receipt", objects })
  const summary = await archiveCoverageBranch(root, [await archiveCoverageLeaf(objects, root)])
  for (const change of [{ setDigest: "A".repeat(43) }, { archiveRootId: "A".repeat(43) }, { policyRevision: 1 },
    { objectCount: 2 }, { rootCovered: false }, { requestId: "other-request-00000001" }, { extra: true }]) {
    const signed = await f.receipt({ kind: "blind-archive-coverage-aggregate-receipt", archiveRootId: root, ...summary, ...change })
    const remote = createArchiveRemote(f.access, { fetch: vi.fn(async () => Response.json(signed)), ensureCurrent: f.ensureCurrent })
    await expect(remote.aggregate(root, [child], "archive-request-00000001")).rejects.toThrow()
  }
})

it("Given a sealed archive object, when uploaded, then use its separate namespace and return only a verified exact durable receipt", async () => {
  const f = await fixture()
  const signed = await f.receipt({ kind: "blind-archive-storage-receipt", objectId: f.sealed.ciphertextId, keyEpoch: 3 })
  const fetcher = vi.fn(async () => Response.json(signed))
  const remote = createArchiveRemote(f.access, { fetch: fetcher, ensureCurrent: f.ensureCurrent })
  expect(await remote.upload(f.sealed.object, "archive-request-00000001")).toEqual(signed)
  expect(fetcher).toHaveBeenCalledTimes(1)
  const [url, init] = fetcher.mock.calls[0] as unknown as [string, RequestInit]
  expect(url).toBe(`https://rusty.example/v2/scopes/opaque-scope/archives/${f.sealed.ciphertextId}?writerVersion=2`)
  expect(new Headers(init.headers).get("Authorization")).toBe(`Bearer ${f.access.writeToken}`)
  expect(new Headers(init.headers).get("X-Rusty-Request-Id")).toBe("archive-request-00000001")
  expect(JSON.parse(init.body as string)).toEqual(f.sealed.object)
  expect(f.ensureCurrent.mock.calls.length).toBeGreaterThanOrEqual(2)
})

it("Given a cold reader, when downloading, then verify opaque object identity and read token without publishing", async () => {
  const f = await fixture()
  const fetcher = vi.fn(async () => Response.json(f.sealed.object))
  const remote = createArchiveRemote(f.access, { fetch: fetcher, ensureCurrent: f.ensureCurrent })
  expect(await remote.download(f.sealed.ciphertextId)).toEqual(f.sealed.object)
  const [url, init] = fetcher.mock.calls[0] as unknown as [string, RequestInit]
  expect(url).toBe(`https://rusty.example/v2/scopes/opaque-scope/archives/${f.sealed.ciphertextId}`)
  expect(new Headers(init.headers).get("Authorization")).toBe(`Bearer ${f.access.readToken}`)
  expect(init.body).toBeUndefined()
})

it("Given archive coverage entries, when confirming, then bind the sorted exact set and distinguish a batch from complete archive coverage", async () => {
  const f = await fixture()
  const entries = [{ objectId: f.sealed.ciphertextId, keyEpoch: 3 }, { objectId: await sha256Base64Url(new Uint8Array([2])), keyEpoch: 2 }]
  const sorted = [...entries].sort((a,b)=>a.objectId<b.objectId?-1:1)
  const signed = await f.receipt({ kind: "blind-archive-coverage-batch-receipt", objects: sorted })
  const fetcher = vi.fn(async () => Response.json(signed))
  const remote = createArchiveRemote(f.access, { fetch: fetcher, ensureCurrent: f.ensureCurrent })
  expect(await remote.coverage(entries,"archive-request-00000001")).toEqual(signed)
  const [url, init] = fetcher.mock.calls[0] as unknown as [string, RequestInit]
  expect(url).toBe("https://rusty.example/v2/scopes/opaque-scope/archive-coverage")
  expect(new Headers(init.headers).get("Authorization")).toBe(`Bearer ${f.access.readToken}`)
  expect(JSON.parse(init.body as string)).toEqual({version:1, requestId:"archive-request-00000001", objects: sorted})
})

it("Given a valid service signature for a different purpose, object, scope, policy, epoch or request, when uploading, then reject that receipt", async () => {
  const f = await fixture()
  for (const change of [{kind:"blind-blob-storage-receipt"},{objectId:"A".repeat(43)},{scopeId:"other"},
    {policyRevision:1},{keyEpoch:4},{requestId:"another-request-00000001"},{extra:true}]) {
    const signed=await f.receipt({kind:"blind-archive-storage-receipt",objectId:f.sealed.ciphertextId,keyEpoch:3,...change})
    const remote=createArchiveRemote(f.access,{fetch:vi.fn(async()=>Response.json(signed)),ensureCurrent:f.ensureCurrent})
    await expect(remote.upload(f.sealed.object,"archive-request-00000001")).rejects.toThrow()
  }
})

it("Given forged signatures, when upload or coverage returns, then never acknowledge storage", async () => {
  const f=await fixture()
  for(const kind of ["blind-archive-storage-receipt","blind-archive-coverage-batch-receipt"]){
    const entries=[{objectId:f.sealed.ciphertextId,keyEpoch:3}]
    const signed=await f.receipt(kind.includes("batch") ? {kind,objects:entries} : {kind,objectId:f.sealed.ciphertextId,keyEpoch:3})
    signed.signature=toBase64Url(new Uint8Array(64))
    const remote=createArchiveRemote(f.access,{fetch:vi.fn(async()=>Response.json(signed)),ensureCurrent:f.ensureCurrent})
    await expect(kind.includes("batch")?remote.coverage(entries,"archive-request-00000001"):remote.upload(f.sealed.object,"archive-request-00000001")).rejects.toThrow()
  }
})

it("Given an identity change during network I/O, when a valid reply arrives, then reject stale completion", async () => {
  const f=await fixture()
  let current=true
  const guard=()=>{if(!current)throw new Error("Session replaced")}
  const signed=await f.receipt({kind:"blind-archive-storage-receipt",objectId:f.sealed.ciphertextId,keyEpoch:3})
  const remote=createArchiveRemote(f.access,{fetch:vi.fn(async()=>{current=false;return Response.json(signed)}),ensureCurrent:guard})
  await expect(remote.upload(f.sealed.object,"archive-request-00000001")).rejects.toThrow(/Session replaced/)
})

it("Given malformed IDs, challenge, oversized set or revoked context, when called, then make no network request", async () => {
  const f=await fixture(), fetcher=vi.fn(async()=>Response.json({}))
  const remote=createArchiveRemote(f.access,{fetch:fetcher,ensureCurrent:f.ensureCurrent})
  await expect(remote.download("../secret")).rejects.toThrow()
  await expect(remote.upload(f.sealed.object,"short")).rejects.toThrow()
  await expect(remote.coverage([],"archive-request-00000001")).rejects.toThrow()
  await expect(remote.coverage(Array.from({length:65},()=>({objectId:f.sealed.ciphertextId,keyEpoch:3})),"archive-request-00000001")).rejects.toThrow()
  const revoked=createArchiveRemote(f.access,{fetch:fetcher,ensureCurrent:()=>{throw new Error("Revoked")}})
  await expect(revoked.download(f.sealed.ciphertextId)).rejects.toThrow(/Revoked/)
  expect(fetcher).not.toHaveBeenCalled()
})

it("Given an unbounded response stream or oversized declared response, when downloading, then cancel instead of retaining partial evidence", async () => {
  const f=await fixture(), cancel=vi.fn()
  const response=new Response(new ReadableStream({pull(c){c.enqueue(new Uint8Array(370*1024))},cancel}))
  const remote=createArchiveRemote(f.access,{fetch:vi.fn(async()=>response),ensureCurrent:f.ensureCurrent})
  await expect(remote.download(f.sealed.ciphertextId)).rejects.toThrow(/limit|large|size/)
  expect(cancel).toHaveBeenCalled()
})

it.each([true,false])("Given an HTTP capacity refusal with JSON=%s, when transport fails, then retain actionable status and capacity classification",async json=>{
  const f=await fixture()
  const response=json?Response.json({message:"Storage capacity exceeded"},{status:507}):new Response("unavailable",{status:507})
  const remote=createArchiveRemote(f.access,{fetch:vi.fn(async()=>response),ensureCurrent:f.ensureCurrent})
  await expect(remote.upload(f.sealed.object,"archive-request-00000001")).rejects.toMatchObject({status:507,code:"capacity_exceeded"})
})

it("Given corrupt download bytes or an unsafe origin, when opening transport, then reject integrity and origin substitution", async () => {
  const f=await fixture()
  const object={...f.sealed.object,nonce:toBase64Url(new Uint8Array(12).fill(5))}
  const remote=createArchiveRemote(f.access,{fetch:vi.fn(async()=>Response.json(object)),ensureCurrent:f.ensureCurrent})
  await expect(remote.download(f.sealed.ciphertextId)).rejects.toThrow(/hash|integrity/)
  for(const origin of ["https://user:pass@rusty.example","https://rusty.example/path","http://rusty.example","https://rusty.example?token=private"]){
    expect(()=>createArchiveRemote({...f.access,origin},{fetch,ensureCurrent:f.ensureCurrent})).toThrow()
  }
})

it("Given a redirect response, when sending credentials, then disable following redirects and reject redirected completion",async()=>{
  const f=await fixture()
  const fetcher=vi.fn(async()=>new Response("redirect",{status:302,headers:{Location:"https://other.example"}}))
  const remote=createArchiveRemote(f.access,{fetch:fetcher,ensureCurrent:f.ensureCurrent})
  await expect(remote.download(f.sealed.ciphertextId)).rejects.toThrow(/redirect/i)
  const [,init]=fetcher.mock.calls[0] as unknown as [string,RequestInit]
  expect(init.redirect).toBe("manual")
})

it("Given mutable inputs during crypto, when uploading, then send captured ciphertext and credentials", async () => {
  const f=await fixture(), expected=structuredClone(f.sealed.object), access=structuredClone(f.access)
  const signed=await f.receipt({kind:"blind-archive-storage-receipt",objectId:f.sealed.ciphertextId,keyEpoch:3})
  const fetcher=vi.fn(async()=>Response.json(signed))
  const remote=createArchiveRemote(f.access,{fetch:fetcher,ensureCurrent:f.ensureCurrent})
  const uploading=remote.upload(f.sealed.object,"archive-request-00000001")
  f.sealed.object.ciphertext="changed";f.access.writeToken="changed";f.access.origin="https://other.example"
  await uploading
  const [url,init]=fetcher.mock.calls[0] as unknown as [string,RequestInit]
  expect(url).toContain(access.origin)
  expect(JSON.parse(init.body as string)).toEqual(expected)
  expect(new Headers(init.headers).get("Authorization")).toBe(`Bearer ${access.writeToken}`)
  expect(canonicalizeJson(signed.payload)).not.toContain(access.writeToken)
})
