export type RustStateCore = {
  verifyWorkspaceGrant(grant: unknown, workspaceId: string, memberPersonId: string, authority: unknown): "owner" | "editor" | "visitor"
  hasConflictingOwnershipTransfers(records: unknown): boolean
  verifyWorkspaceRevocation(record: unknown, workspaceId: string, authority: unknown, nowMs: number): unknown
  verifyWorkspaceOwnershipTransfer(record: unknown, workspaceId: string, authority: unknown, minimumEpoch: number, nowMs: number): unknown
  verifyWorkspaceSuccessionPolicy(policy: unknown, workspaceId: string, authority: unknown, nowMs: number): unknown
  verifyWorkspaceSuccessionVote(vote: unknown, policy: unknown, candidatePersonId: string, authority: unknown, revoked: string[], nowMs: number): unknown
  verifyWorkspaceSuccessionClaim(claim: unknown, workspaceId: string, authority: unknown, minimumEpoch: number, revoked: string[], nowMs: number): unknown
  planChangeAdmission(documentId: string, changes: unknown, verifiedAt: string): unknown
  transitionOutboxClaim(current: unknown, input: unknown): unknown
  mergePeerRecords(existing: unknown, incoming: unknown): unknown
  reconcileReplicaSets(left: unknown, right: unknown): unknown
  selectScopedNeighbors(localDeviceId: string, candidates: unknown, bounds: unknown, nowMs: number, rotation: number): string[]
  validateDeviceRoute(route: unknown): void
  validateDeviceRoutePayload(payload: unknown): void
  validateDurableAckPayload(payload: unknown): void
  verifyDeviceRoute(envelope: unknown, publicKey: string, nowMs: number, allowExpired: boolean): unknown
  verifyDurableAck(envelope: unknown, publicKey: string): unknown
  durableAckMatches(ack: unknown, batch: unknown, targetDeviceId: string): boolean
  orderDeliveryRoutes(targetDeviceId: string, routes: unknown): unknown
}

export type RustDeviceRouteCatalog = {
  admit(route: unknown): unknown
  routesFor(scopeId: string, deviceId: string): unknown
  free?(): void
}

export type RustAutomergeSyncEngine = {
  loadDocument(scopeId: string, documentId: string, bytes: Uint8Array): void
  saveDocument(documentId: string): Uint8Array
  heads(documentId: string): string[]
  reset(documentId: string, remoteDeviceId: string): void
  generate(documentId: string, remoteDeviceId: string, authorized: boolean, proof: unknown): unknown
  receive(remoteDeviceId: string, frame: unknown, authorized: boolean, responseProof: unknown): unknown
  free?(): void
}

export type MeshRustRuntime = {
  state: RustStateCore
  createDeviceRouteCatalog(): RustDeviceRouteCatalog
  createAutomergeSyncEngine(localDeviceId: string, maximumFrameBytes?: number): RustAutomergeSyncEngine
}

let installed: MeshRustRuntime | undefined

export function installMeshRustRuntime(runtime: MeshRustRuntime | undefined): () => void {
  const previous = installed
  installed = runtime
  return () => { installed = previous }
}

export function meshRustRuntime(): MeshRustRuntime {
  if (!installed) throw new Error("Rust mesh runtime is not installed")
  return installed
}
