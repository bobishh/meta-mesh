import { expect, it } from "vitest"
import { publicKeyId, signEnvelope, toBase64Url } from "@meta-uber/mesh-identity"
import { archiveCoverageLeaf, archiveCoverageBranch, verifyArchiveCoverageChild, type ArchiveCoverageObject,
  type ArchiveCoverageAuthority, type ArchiveCoverageSummary } from "./historyArchiveCoverage"

const id = (n: number) => n.toString(16).padStart(8,"0") + "A".repeat(35)
const entries = (start: number, count: number): ArchiveCoverageObject[] => Array.from({length:count},(_,i)=>({objectId:id(start+i),keyEpoch:1}))

it("Given several encrypted archive batches, when composed, then bind exact ordered set, count and catalogue presence without retaining the object list in the result",async()=>{
  const root=id(70), left=await archiveCoverageLeaf(entries(0,64),root), right=await archiveCoverageLeaf(entries(64,15),root)
  expect(left).toMatchObject({height:0,objectCount:64,firstObjectId:id(0),lastObjectId:id(63),rootCovered:false})
  expect(right.rootCovered).toBe(true)
  const result=await archiveCoverageBranch(root,[left,right])
  expect(result).toMatchObject({height:1,objectCount:79,firstObjectId:id(0),lastObjectId:id(78),rootCovered:true})
  expect(result.setDigest).toHaveLength(43)
  expect(JSON.stringify(result).length).toBeLessThan(512)
  expect((await archiveCoverageBranch(root,[left])).setDigest).not.toBe(result.setDigest)
  expect((await archiveCoverageBranch(id(71),[left,right])).setDigest).not.toBe(result.setDigest)
})

it("Given malformed or overlapping summaries, when combined, then reject unsafe counts, ranges, depth and mixed heights",async()=>{
  const root=id(1), one=await archiveCoverageLeaf(entries(0,2),root), two=await archiveCoverageLeaf(entries(2,2),root)
  const bad:ArchiveCoverageSummary[][]=[[],Array.from({length:9},()=>one),[one,one],[two,one],
    [one,{...two,height:1}],[{...one,height:31},{...two,height:31}],
    [{...one,objectCount:Number.MAX_SAFE_INTEGER},two],[{...one,objectCount:0}],
    [{...one,setDigest:"-".repeat(43)}],[{...one,lastObjectId:id(0),firstObjectId:id(2)}]]
  for(const values of bad)await expect(archiveCoverageBranch(root,values)).rejects.toThrow()
})

it("Given malformed leaves, when deriving coverage, then reject duplicates, ordering, unsafe epochs and extra schema fields",async()=>{
  for(const values of [[],entries(0,65),[...entries(0,1),...entries(0,1)],entries(0,2).reverse(),
    [{objectId:id(0),keyEpoch:0}],[{objectId:id(0),keyEpoch:2**53}],[{objectId:"-".repeat(43),keyEpoch:1}],
    [{objectId:id(0),keyEpoch:1,extra:true}]]){
    await expect(archiveCoverageLeaf(values,id(0))).rejects.toThrow()
  }
})

async function signer(){
  const pair=await crypto.subtle.generateKey("Ed25519",true,["sign","verify"]) as CryptoKeyPair
  const servicePublicKey=toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw",pair.publicKey)))
  const authority:ArchiveCoverageAuthority={servicePublicKey,scopeId:"opaque-scope",policyRevision:3}
  const serviceId=await publicKeyId(servicePublicKey)
  const sign=(payload:Record<string,unknown>&{kind:string})=>signEnvelope(pair.privateKey,{version:1,serviceId,scopeId:authority.scopeId,
    policyRevision:3,requestId:"coverage-request-00000001",...payload},serviceId,"RUSTY/2")
  return {authority,sign}
}

it("Given actual service-signed leaf and aggregate receipts, when verified, then derive the same exact summary under the pinned service and root",async()=>{
  const f=await signer(),root=id(4),objects=entries(0,7)
  const leaf=await f.sign({kind:"blind-archive-coverage-batch-receipt",objects})
  const summary=await verifyArchiveCoverageChild(leaf,f.authority,root)
  expect(summary).toEqual(await archiveCoverageLeaf(objects,root))
  const parent=await archiveCoverageBranch(root,[summary])
  const signed=await f.sign({kind:"blind-archive-coverage-aggregate-receipt",archiveRootId:root,...parent})
  expect(await verifyArchiveCoverageChild(signed,f.authority,root)).toEqual(parent)
  await expect(verifyArchiveCoverageChild(signed,f.authority,id(5))).rejects.toThrow()
})

it("Given forged, substituted or stale service receipts, when composed, then reject instead of accepting a claimed rootCovered flag",async()=>{
  const f=await signer(),root=id(1),objects=entries(0,2)
  const signed=await f.sign({kind:"blind-archive-coverage-batch-receipt",objects})
  for(const value of [{...signed,signature:toBase64Url(new Uint8Array(64))},
    {...signed,payload:{...signed.payload,objects:entries(0,3)}},
    {...signed,extra:true},await f.sign({kind:"blind-blob-coverage-receipt",objects}),
    await f.sign({kind:"blind-archive-coverage-batch-receipt",objects,extra:true})]){
    await expect(verifyArchiveCoverageChild(value,f.authority,root)).rejects.toThrow()
  }
  await expect(verifyArchiveCoverageChild(signed,{...f.authority,policyRevision:4},root)).rejects.toThrow()
  await expect(verifyArchiveCoverageChild(signed,{...f.authority,scopeId:"other"},root)).rejects.toThrow()
  await expect(verifyArchiveCoverageChild(signed,(await signer()).authority,root)).rejects.toThrow()
})
