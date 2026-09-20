export type RustStateCore = {
  mergePeerRecords(existing: unknown, incoming: unknown): unknown
  reconcileReplicaSets(left: unknown, right: unknown): unknown
  selectScopedNeighbors(localDeviceId: string, candidates: unknown, bounds: unknown, nowMs: number, rotation: number): string[]
  validateDeviceRoute(route: unknown): void
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
