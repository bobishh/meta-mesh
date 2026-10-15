import { expect, it } from "vitest"
import { archiveCoverageBranch, verifyArchiveCoverageChild, type ArchiveCoverageAuthority, type ArchiveCoverageObject,
  type ArchiveCoverageChild, type ArchiveCoverageBatchReceipt, type ArchiveCoverageAggregateReceipt } from "./historyArchiveCoverage"
import { confirmArchiveCoverageSet, deriveArchiveCoverageSet, verifyCompleteArchiveCoverage } from "./historyArchiveCoverageSet"
import { publicKeyId, signEnvelope } from "@meta-uber/mesh-identity"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"

const fixturePath = resolve(import.meta.dirname, "../fixtures/history-archive-coverage-v1.json")
const transitionId = "native-coverage-fixture-00001"
const counts = [1, 64, 65, 512, 513, 4101]
const objectId = (n: number) => n.toString(16).padStart(8, "0") + "A".repeat(35)
function* objects(count: number): Generator<ArchiveCoverageObject> {
  for (let n = 0; n < count; n++) yield { objectId: objectId(n), keyEpoch: 3 }
}

async function fixtureAuthority() {
  const seed = Uint8Array.from({ length: 32 }, (_, i) => i + 1)
  const prefix = Uint8Array.from([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20])
  const pkcs8 = new Uint8Array(prefix.length + seed.length); pkcs8.set(prefix); pkcs8.set(seed, prefix.length)
  const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"])
  const jwk = await crypto.subtle.exportKey("jwk", privateKey)
  const servicePublicKey = jwk.x!

  const authority: ArchiveCoverageAuthority = { servicePublicKey, scopeId: "opaque-coverage-fixture", policyRevision: 7 }
  const serviceId = await publicKeyId(servicePublicKey)
  const sign = <T extends { kind: string }>(payload: T) => signEnvelope(privateKey, payload, serviceId, "RUSTY/2")
  const port = {
    ensureCurrent: () => {},
    coverage: async (batch: ArchiveCoverageObject[], requestId: string): Promise<ArchiveCoverageBatchReceipt> => sign({
      kind: "blind-archive-coverage-batch-receipt", version: 1, serviceId, scopeId: authority.scopeId,
      policyRevision: authority.policyRevision, requestId, objects: batch }),
    aggregate: async (root: string, children: ArchiveCoverageChild[], requestId: string): Promise<ArchiveCoverageAggregateReceipt> => {
      const summaries = []
      for (const child of children) summaries.push(await verifyArchiveCoverageChild(child, authority, root))
      return sign({ kind: "blind-archive-coverage-aggregate-receipt", version: 1, serviceId, scopeId: authority.scopeId,
        policyRevision: authority.policyRevision, requestId, archiveRootId: root, ...await archiveCoverageBranch(root, summaries) })
    },
  }
  return { authority, port }
}

async function generateFixture() {
  const { authority, port } = await fixtureAuthority()
  const sets = []
  for (const count of counts) {
    const root = objectId(count - 1)
    const receipt = await confirmArchiveCoverageSet(authority, root, transitionId, objects(count), port)
    const summary = await deriveArchiveCoverageSet(root, objects(count))
    await verifyCompleteArchiveCoverage(receipt, authority, root, objects(count))
    sets.push({ count, root, summary, receipt })
  }
  return { authority, transitionId, keyEpoch: 3, sets }
}

it("Given Native coverage consumers, when reading SDK-signed boundary vectors, then verify exact canonical summaries and receipts", async () => {
  const generated = await generateFixture()
  if (process.env.MESH_COVERAGE_FIXTURE_OUTPUT) {
    const output = resolve(process.env.MESH_COVERAGE_FIXTURE_OUTPUT)
    await mkdir(dirname(output), { recursive: true })
    await writeFile(output, JSON.stringify(generated, null, 2) + "\n")
  }
  const fixture = JSON.parse(await readFile(fixturePath, "utf8"))
  expect(generated).toEqual(fixture)
  const { port } = await fixtureAuthority()
  for (const item of fixture.sets) {
    expect(await verifyCompleteArchiveCoverage(item.receipt, fixture.authority, item.root, objects(item.count))).toEqual(item.summary)
  }
  const sample = fixture.sets.find((item: { count: number }) => item.count === 65)!
  const repeated = await confirmArchiveCoverageSet(fixture.authority, sample.root, fixture.transitionId, objects(sample.count), port)
  expect(repeated).toEqual(sample.receipt)
})
