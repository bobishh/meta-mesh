import type { HistoryPreparationJournal, HistoryPreparationRemote, HistoryPreparationState } from "./historyPreparationJournal"
import type { ArchiveEncryptionScope } from "./historyArchiveCrypto"
import type { ArchiveLocatorRoot } from "./historyArchiveLocators"
import { canonicalizeJson, sha256Base64Url } from "@meta-uber/mesh-identity"
import { captureArchiveEncryptionScope } from "./historyArchiveCrypto"
import { buildArchiveLocators } from "./historyArchiveLocators"
import { capturePreparationIdentity, fail } from "./historyPreparationData"

export type PreparedArchiveLocators = { root: ArchiveLocatorRoot; directory: HistoryPreparationState }

/** Separate durable directory and data coverage; neither authorizes baseline activation. */
export async function prepareArchiveLocators(input: { data: HistoryPreparationJournal; directory: HistoryPreparationJournal;
  scope: ArchiveEncryptionScope; remote: HistoryPreparationRemote; ensureCurrent(): void | Promise<void> }): Promise<PreparedArchiveLocators> {
  const scope = captureArchiveEncryptionScope(input.scope)
  const dataIdentity = capturePreparationIdentity(input.data.identity), directoryIdentity = capturePreparationIdentity(input.directory.identity)
  const { read: readData, locators } = input.data
  const { capture, stage, archive, cover } = input.directory
  const remote = { upload: input.remote.upload, coverage: input.remote.coverage, aggregate: input.remote.aggregate }
  const guard = input.ensureCurrent
  if (typeof guard !== "function") fail("Invalid archive locator preparation guard")
  const ensureCurrent = async () => {
    if (await guard() !== undefined) fail("Archive locator preparation guard must return no value")
  }
  if (dataIdentity.transitionId === directoryIdentity.transitionId) fail("Archive locator preparation requires a separate journal")
  if (canonicalizeJson({ ...directoryIdentity, transitionId: dataIdentity.transitionId }) !== canonicalizeJson(dataIdentity) ||
      scope.scopeId !== dataIdentity.storage.scopeId || scope.keyEpoch !== dataIdentity.storage.keyEpoch) fail("Archive locator preparation binding mismatch")
  await ensureCurrent()
  if (await sha256Base64Url(scope.key) !== dataIdentity.storage.keyDigest) fail("Archive locator preparation key binding mismatch")
  await ensureCurrent()
  const data = await readData()
  if (data?.phase !== "covered") fail("Archive data must be covered before locator preparation")
  if (canonicalizeJson(data.identity) !== canonicalizeJson(dataIdentity)) fail("Archive locator data identity binding mismatch")
  const capturedData = canonicalizeJson(data)
  const checkData = async () => {
    await ensureCurrent()
    if (canonicalizeJson(await readData()) !== capturedData) fail("Covered archive data changed during locator preparation")
    await ensureCurrent()
  }
  const source = new TextEncoder().encode(canonicalizeJson({ kind: "workspace-history-locator-preparation-source", version: 1,
    dataIdentity, dataRoot: data.root, dataObjectCount: data.objectCount, dataObjectDigest: data.objectDigest, dataSource: data.source }))
  await ensureCurrent()
  await capture([source])
  const context = { workspaceId: dataIdentity.workspaceId, historyEpoch: dataIdentity.historyEpoch, indexId: "archive-locators" }
  const root = await buildArchiveLocators(scope, context, locators(), { ensureCurrent,
    write: async (binding, bytes) => (await stage(scope, binding, bytes)).sealed })
  if (root.root.count !== data.objectCount) fail("Archive locator data set is incomplete")
  await checkData()
  await archive({ ...context, objectId: root.root.objectId, objectKind: "page", partIndex: 0, partCount: 1 })
  await checkData()
  const directory = await cover(remote)
  await checkData()
  return { root, directory }
}
