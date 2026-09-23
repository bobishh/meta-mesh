export type RustStateCore = {
  decideWorkspaceAccess(input: unknown, nowMs: number): "owner" | "editor" | "visitor"
  validateMeshCatalog(raw: unknown): unknown
  validateMeshHandshake(raw: unknown, expectedWorkspaceId?: string): unknown
  admitMeshPeer(handshake: unknown, snapshot: unknown, remoteEndpoint: string, nowMs: number): {
    workspaceId: string; personId: string; deviceId: string; endpoint: string; instanceId?: string | null;
    role: "owner" | "editor" | "visitor"
  }
  meshCapabilities(): string[]
  validateMeshCapabilities(capabilities: unknown): void
  verifyWorkspaceMemberBundle(raw: unknown, options: unknown, nowMs: number): unknown
  verifyWorkspaceGrant(grant: unknown, workspaceId: string, memberPersonId: string, authority: unknown): "owner" | "editor" | "visitor"
  admitWorkspaceChangeAuthorization(authorization: unknown, snapshot: unknown, neededHashes: string[], nowMs: number): Array<{
    hash: string; role: "owner" | "editor" | "visitor"
  }>
  admitWorkspaceChangeAuthorizations(authorizations: unknown[], snapshot: unknown, neededHashes: string[], nowMs: number): Array<{
    hash: string; role: "owner" | "editor" | "visitor"
  }>
  hasConflictingOwnershipTransfers(records: unknown): boolean
  planOwnershipTransitions(records: unknown, initialOwnerPersonId: string, initialEpoch: number): { records: unknown[], conflicted: boolean }
  nextVerifiedOwnershipTransition(records: unknown, workspaceId: string, currentOwner: unknown, currentEpoch: number,
    revokedPeople: string[], nowMs: number): { candidates: unknown[], selected?: unknown | null, conflicted: boolean }
  summarizeSuccession(policy: unknown, claims: unknown, votes: unknown, transfers: unknown, revocations: unknown, epoch: number): unknown
  eligibleEditorPersonIds(peers: unknown): string[]
  canonicalRevocations(records: unknown): unknown
  verifyWorkspaceDeparture(record: unknown, workspaceId: string, authority: unknown, nowMs: number): unknown
  verifyWorkspaceDeviceRevocation(record: unknown, workspaceId: string, ownerPersonId: string, authority: unknown, nowMs: number): unknown
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
  prepareReceive(remoteDeviceId: string, frame: unknown, authorized: boolean, responseProof: unknown): unknown
  commitPreparedReceive(documentId: string, remoteDeviceId: string): void
  abortPreparedReceive(documentId: string, remoteDeviceId: string): void
  free?(): void
}

export type RustMeshRuntimeState = {
  readonly running: boolean
  start(): void
  stop(): string[]
  sessions(): Array<{
    key: { workspaceId: string; deviceId: string; instanceId: string }
    connectionId: string
    remoteIssuedAt: string
    remoteRouteSequence?: number | null
    direction: "incoming" | "outgoing"
    generation: number
  }>
  beginRouteAttempt(routeKey: string, nowMs: number): { routeKey: string; token: number; startedAtMs: number }
  routeAttemptActive(routeKey: string): boolean
  clearRouteAttempt(routeKey: string): void
  finishRouteAttempt(routeKey: string, token: number): boolean
  scheduleReconnect(routeKey: string, nowMs: number, baseDelayMs: number, maximumDelayMs: number): {
    failures: number; retryAtMs: number
  }
  clearReconnect(routeKey: string): void
  reconnectState(routeKey: string): { failures: number; retryAtMs: number } | null
  clearReconnectsWithPrefix(prefix: string): void
  dueReconnects(nowMs: number): string[]
  admitSession(candidate: unknown, preferredDirection: "incoming" | "outgoing"): {
    decision: "accepted" | "rejected"
    generation?: number
    replacedConnectionId?: string | null
    retainedConnectionId?: string
  }
  removeSession(key: unknown, generation: number): string | null
  connectedDevices(workspaceId: string): string[]
  setGossipEndpoints(workspaceId: string, endpoints: string[]): { changed: boolean; endpoints: string[] }
  clearGossip(workspaceId: string): void
  controlFrames(workspaceId: string, bytes: Uint8Array): Uint8Array[]
  receiveControlFrame(workspaceId: string, frame: Uint8Array): Uint8Array | undefined
  planDial(peerKey: string, relayAvailable: boolean, nowMs: number): {
    mode: "direct" | "relay"; relayFallbackAtMs?: number
  }
  recordNetworkFailure(peerKey: string, nowMs: number): void
  recordDialSuccess(peerKey: string, mode: "direct" | "relay", nowMs: number): void
  free?(): void
}

export type RustMeshHandshakeFlow = {
  step(): string
  advance(completed: string, decision?: boolean): string
  free?(): void
}

export type RustMeshAuthenticatedSessions = {
  admit(handshake: unknown, snapshot: unknown, remoteEndpoint: string, nowMs: number): {
    workspaceId: string; personId: string; deviceId: string; endpoint: string; instanceId?: string | null;
    role: "owner" | "editor" | "visitor"
  }
  peer(workspaceId: string, remoteEndpoint: string): {
    workspaceId: string; personId: string; deviceId: string; endpoint: string; role: "owner" | "editor" | "visitor"
  } | null
  refresh(snapshot: unknown, nowMs: number): string[]
  remove(workspaceId: string, remoteEndpoint: string): boolean
  clear(): void
  free?(): void
}

export type MeshRustRuntime = {
  state: RustStateCore
  createDeviceRouteCatalog(): RustDeviceRouteCatalog
  createAutomergeSyncEngine(localDeviceId: string, maximumFrameBytes?: number): RustAutomergeSyncEngine
  createMeshRuntimeState(): RustMeshRuntimeState
  createMeshHandshakeFlow(direction: "incoming" | "outgoing"): RustMeshHandshakeFlow
  createMeshAuthenticatedSessions(): RustMeshAuthenticatedSessions
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
