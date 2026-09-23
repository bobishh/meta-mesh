export type RustStateCore = {
  validateScopeAuthority(snapshot: unknown): unknown
  requireChangeAuthorizationCoverage(changeHashes: string[], records: unknown[]): void
  createScopeGenesis(input: unknown): { scopeId: string; creatorPersonId: string;
    creatorPublicKey: string; creatorCertificates: unknown[] }
  createScopeGenesisPayload(input: unknown): unknown
  planScopeGenesis(input: unknown): unknown
  createScopeControlTransferPayload(input: unknown): unknown
  preferredSessionDirection(localDeviceId: string, remoteDeviceId: string): "incoming" | "outgoing"
  hasAuthorityConflict(credential: unknown): boolean
  prepareWriteEvidence(input: unknown): unknown
  planSuccessionCatalog(input: unknown): { credential: unknown; persist: boolean; publish: boolean }
  planOwnershipMerge(input: unknown): { accepted: unknown[];
    steps: Array<{ record: unknown; accepted: unknown[]; previousOwnerEpoch: number }>;
    conflicted: boolean; persistCatalog: boolean }
  canRemoveWorkspaceDevice(credential: unknown, localPersonId: string, localPublicKey: string,
    localDeviceId: string, targetPersonId: string, targetDeviceId: string, peerPersonId?: string): boolean
  partitionCredentials(input: unknown): { activeIndices: number[]; mismatchedIndices: number[] }
  ownedWorkspaceIds(credentials: unknown[], personId: string, publicKey: string): string[]
  planAuthorityImport(kind: "invitation" | "handshake", hasRevocations: boolean, hasTransfers: boolean):
    Array<"validateCapabilities" | "deviceRevocations" | "departures" | "revocations" | "ownershipTransfers" |
      "succession" | "refreshCredential" | "peers">
  planMeshHandshakeAuthorityImport(): Array<"validateCapabilities" | "deviceRevocations" | "departures" |
    "revocations" | "ownershipTransfers" | "succession" | "refreshCredential" | "peers">
  selectMeshHandshakeBundle(candidates: Array<{ deviceId: string; instanceId?: string }>, localDeviceId: string,
    localInstanceId: string): number | null
  shouldAdvertiseOwnerWorkspaceIds(credentialOwnerPersonId: string, localPersonId: string,
    remotePersonId: string): boolean
  meshHandshakeFeatures(capabilities: string[]): { heartbeatSupported: boolean;
    ownershipReceiptSupported: boolean; ownerWorkspaceSupported: boolean;
    ownerWorkspaceOfferFrame?: "mesh-owner-workspace-offer"; blobTransferSupported: boolean }
  credentialBelongsToProfile(credential: unknown, personId: string, publicKey: string): boolean
  canReuseMemberBundle(input: unknown): boolean
  planSuccessionPolicyRefresh(current: unknown, eligible: string[], epoch: number): {
    changed: boolean; successorPersonId: string | null }
  missingOwnerWorkspaces(owned: string[], remote: unknown): string[]
  planGuestAdvertisements(input: unknown): Array<{ workspaceId: string; bundleIndex: number; grantIndex: number }>
  validateOwnerWorkspaceOffer(raw: unknown, remotePersonId: string, localPersonId: string): string
  knowsWorkspaceIssuer(workspaces: unknown[], issuerPersonId: string, localPersonId: string, localDeviceId: string): boolean
  nextAccessEpoch(credential: unknown, issuedGrants: unknown[]): number
  planInvitationCredential(input: unknown): unknown
  planCatalogMerge(): Array<"ownership" | "revocations" | "refreshCredential" | "succession" | "peers" | "notify">
  selectOwnershipTransfer(input: unknown): { peerIndices: number[]; advertisementIndex: number | null;
    pendingIndex: number | null; targetOnline: boolean }
  planOwnershipAuthorityFlow(input: unknown): { selection: { peerIndices: number[];
    advertisementIndex: number | null; pendingIndex: number | null; targetOnline: boolean };
    actions: Array<"verifyTarget" | "createTransfer" | "persistProposal" | "confirmDelivery" | "mergeTransfer" | "notify" | "publish"> }
  isWorkspaceEnvelope(raw: unknown): boolean
  hasLeftWorkspace(credential: unknown, personId: string, grant: unknown): boolean
  isGrantRevoked(credential: unknown, personId: string, grant: unknown): boolean
  isDeviceRevoked(credential: unknown, personId: string, deviceId: string): boolean
  planDialSchedule(input: unknown): { readyGroups: number[][]; retries: Record<string, number> }
  planOwnerCertificateRefresh(credential: unknown, localPersonId: string, certificates: unknown[], updatedAt: string): unknown | null
  decideOwnerCredential(existingOwnerPersonId: string | undefined, localPersonId: string): string
  planInvitation(input: unknown): Array<{ workspaceId: string; envelopeIndex: number; grantIndex: number | null }>
  planMemberGrant(input: unknown): { bundle?: unknown; credential?: unknown; grant?: unknown; grantId?: string }
  planAuthorityMerge(input: unknown): { credential: unknown; peers: unknown[]; evictDeviceIds: string[];
    evictPersonIds: string[]; localAccessRevoked: boolean }
  planOwnershipAdoption(input: unknown): { previousOwnerPersonId: string; credential: unknown; peers: unknown[] }
  planSuccessionMerge(input: unknown, nowMs: number): {
    noop: boolean
    policy?: unknown
    votes: unknown[]
    claims: unknown[]
    transitions: unknown[]
    conflicted: boolean
  }
  encodeWorkspaceSet(entries: unknown[]): Uint8Array
  decodeWorkspaceSet(bytes: Uint8Array, allowedIds: string[]): Array<{
    id: string; bytes: string; authorization?: unknown; chat?: unknown; mesh?: unknown
  }>
  planAuthorityCommand(input: unknown): Array<
    "createRevocation" | "mergeRevocation" | "refreshSuccessionPolicy" | "publish" | "reloadCredential" |
    "disconnectRevoked" | "notify" | "leave" | "createPolicy" | "setPolicy" | "createVote" |
    "mergeVote" | "createClaim" | "mergeClaim" | "verifyTarget" | "createTransfer" |
    "persistProposal" | "confirmDelivery" | "mergeTransfer" | "createGrant" | "persistGrant"
  >
  decideWorkspaceAccess(input: unknown, nowMs: number): "owner" | "editor" | "visitor"
  validateMeshCatalog(raw: unknown): unknown
  validateMeshHandshake(raw: unknown, expectedWorkspaceId?: string): unknown
  encodeMeshHandshake(frameType: "mesh-handshake-request" | "mesh-handshake-response", secret: string, payload: unknown): Uint8Array
  inspectMeshHandshake(frame: Uint8Array): { type: "mesh-handshake-request" | "mesh-handshake-response"; secret: string }
  decodeMeshHandshake(frame: Uint8Array, expectedType: "mesh-handshake-request" | "mesh-handshake-response",
    secret: string, workspaceId: string): unknown
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
  planChangeAdmissionFlow(input: unknown, nowMs: number): unknown
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
  encodeWorkspaceUpdate(workspaceId: string, nonce: string): Uint8Array
  isWorkspaceUpdate(payload: Uint8Array, workspaceId: string): boolean
  controlFrames(workspaceId: string, bytes: Uint8Array): Uint8Array[]
  receiveControlFrame(workspaceId: string, frame: Uint8Array): Uint8Array | undefined
  planDial(peerKey: string, relayAvailable: boolean, nowMs: number): {
    mode: "direct" | "relay"; relayFallbackAtMs?: number
  }
  recordNetworkFailure(peerKey: string, nowMs: number): void
  recordDialSuccess(peerKey: string, mode: "direct" | "relay", nowMs: number): void
  free?(): void
}

export type RustLiveSessionAction = {
  kind: "durableBatch" | "heartbeat" | "control" | "ownerWorkspaceOffer" | "gossip" |
    "blobRequest" | "handoffRequest" | "automergeSync" | "snapshot"
  payload?: number[]
}

export type RustPreparedLiveDocument = {
  document: Uint8Array | number[]
  acceptedChanges: number
  acceptedHashes: string[]
  heads: string[]
  response?: Uint8Array | number[] | null
  proof?: unknown
  shouldPersist: boolean
}

export type RustLiveWorkspaceSession = {
  receive(frame: Uint8Array): RustLiveSessionAction | null
  receiveWithPlan(frame: Uint8Array): {
    action: RustLiveSessionAction
    plan: { effects: string[]; serializeDocument: boolean; control?: unknown }
  } | null
  encode(frameType: string, payload: Uint8Array): Uint8Array
  encodeAutomergeFrame(frame: unknown): Uint8Array
  decodeAutomergePayload(payload: Uint8Array): unknown
  startDocumentSync(localDeviceId: string, remoteDeviceId: string): void
  generateDocument(document: Uint8Array, proof: unknown): Uint8Array | undefined
  prepareDocument(payload: Uint8Array, document: Uint8Array, responseProof: unknown): RustPreparedLiveDocument
  preparePublish(document: Uint8Array, proof: unknown, authorization: unknown, chat: unknown, mesh: unknown): {
    documentFrame?: Uint8Array | number[]
    controlSnapshot: Uint8Array | number[]
    controlFrames: Array<Uint8Array | number[]>
  }
  prepareControlPublish(authorization: unknown, chat: unknown, mesh: unknown): {
    controlSnapshot: Uint8Array | number[]
    controlFrames: Array<Uint8Array | number[]>
  }
  prepareSnapshotPublish(snapshot: Uint8Array): { snapshot: Uint8Array | number[]; frame?: Uint8Array | number[] }
  finishPublish(controlSnapshot: Uint8Array, allFramesSent: boolean): void
  commitDocument(): void
  abortDocument(): void
  resetDocument(): void
  encodeControl(authorization: unknown, chat: unknown, mesh: unknown): Uint8Array
  decodeControl(bytes: Uint8Array): { version: number; workspaceId: string; authorization?: unknown; chat?: unknown; mesh?: unknown }
  controlChanged(snapshot: Uint8Array): boolean
  controlFrames(snapshot: Uint8Array): Uint8Array[]
  markControlSent(snapshot: Uint8Array): void
  acknowledgeSaved(bytes: Uint8Array): Uint8Array
  verifySavedReceipt(frame: Uint8Array, bytes: Uint8Array): void
  verifyHeartbeatAck(frame: Uint8Array): void
  free?(): void
}

export type RustMeshHandshakeFlow = {
  step(): string
  advance(completed: string, decision?: boolean): string
  isPeerRevoked(credential: unknown, personId: string, grant: unknown, deviceId: string): boolean
  matchesExpectedPeer(expectedDeviceId: string, verifiedDeviceId: string): boolean
  matchesAdmittedPeer(verifiedDeviceId: string, verifiedPersonId: string, verifiedEndpoint: string,
    admittedDeviceId: string, admittedPersonId: string, admittedEndpoint: string): boolean
  free?(): void
}

export type RustMeshLifecycleState = {
  readonly stopped: boolean
  readonly externallyPaused: boolean
  readonly disposed: boolean
  beginStart(): boolean
  canContinueStart(): boolean
  completeStart(): boolean
  cancelStart(): void
  stop(): boolean
  finishStop(): void
  pause(): void
  resume(): boolean
  dispose(): void
  free?(): void
}

export type RustGossipLifecycleState = {
  topic(workspaceId: string): string
  planRebuild(input: { workspaceId: string; endpoints: string[]; stopped: boolean;
    engineAvailable: boolean; transportSecretAvailable: boolean }): {
    action: "reuse" | "start" | "close" | "idle"; closePrevious: boolean; topic: string;
    endpoints: string[]; topologyChanged: boolean
  }
  started(workspaceId: string): void
  startFailed(workspaceId: string): void
  close(workspaceId: string): void
  closeAll(): void
  receiveAction(workspaceId: string, driverAvailable: boolean, sessionAvailable: boolean): "refresh" | "handle" | "drop"
  deliveryAction(workspaceId: string, topic: string, sessionAvailable: boolean, packetValid: boolean):
    "publish" | "ignoreTopic" | "rejectSession" | "ignorePayload"
  observeNeighbors(workspaceId: string, count: number): { change: "up" | "down" | "same"; publishAll: boolean }
  broadcastPlan(workspaceId: string, driverAvailable: boolean): { broadcast: boolean; topic: string }
  free?(): void
}

export type RustMeshSessionLifecycle = {
  register(key: unknown, connectionId: string, generation: number, nowMs: number): {
    generation: number; replacedGeneration?: number | null; replacedConnectionId?: string | null; stableAfterMs: number
  }
  markStable(key: unknown, generation: number, nowMs: number): boolean
  reportFailure(key: unknown, generation: number): boolean
  publishRecovery(key: unknown, generation: number): boolean
  callbackPlan(key: unknown, generation: number,
    event: "recovery" | "stable" | "heartbeatFailed" | "receiveSucceeded" | "receiveFailed", nowMs: number): {
      publishRecovery: boolean; stable: boolean; reportFailure: boolean; evict: boolean
    }
  publishPlan(): Array<{ workspaceId: string; connectionIds: string[] }>
  evict(key: unknown, generation: number): { shouldClose: boolean; wasCurrent: boolean; connectionId?: string | null }
  clear(): void
  free?(): void
}
export type RustMeshSessionLifecycleState = RustMeshSessionLifecycle

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

export type RustAutomergeDeviceSyncFlow = {
  nextRound(frame: unknown): { kind: "round"; value: {
    round: number
    batch: { protocolVersion: 1; scopeId: string; documentId: string; batchId: string;
      changes: Array<{ hash: string; bytes: Uint8Array | number[] }> }
    request: { kind: "mesh-automerge-device-sync"; version: 1; batchId: string; frame: unknown }
    selectedRouteInstanceId: string | null
  } } | { kind: "converged"; value: { rounds: number; routeInstanceIds: string[] } }
  validateResponse(response: unknown): void
  completeRound(routeInstanceId: string, response: unknown): unknown
  free?(): void
}

export type RustBatchDeliveryAction =
  | { kind: "launchRoute"; round: number; routeIndex: number }
  | { kind: "armFallback" | "armRetry"; round: number; delayMs: number }
  | { kind: "cancelOtherRoutes"; round: number; routeIndex: number }
  | { kind: "cancelAllRoutes"; round: number }
  | { kind: "completed"; round: number; routeIndex: number; attemptedRouteIds: string[] }
  | { kind: "exhausted"; attemptedRouteIds: string[]; message: string }
  | { kind: "aborted" }

export type RustBatchDeliveryFlow = {
  start(): { actions: RustBatchDeliveryAction[] }
  routeResult(round: number, routeIndex: number, accepted: boolean, failure: string): { actions: RustBatchDeliveryAction[] }
  fallbackElapsed(round: number): { actions: RustBatchDeliveryAction[] }
  retryElapsed(round: number): { actions: RustBatchDeliveryAction[] }
  abort(): { actions: RustBatchDeliveryAction[] }
  free?(): void
}

export type MeshRustRuntime = {
  state: RustStateCore
  createDeviceRouteCatalog(): RustDeviceRouteCatalog
  createAutomergeSyncEngine(localDeviceId: string, maximumFrameBytes?: number): RustAutomergeSyncEngine
  createAutomergeDeviceSyncFlow(targetDeviceId: string, documentId: string, maximumRounds: number): RustAutomergeDeviceSyncFlow
  decodeAutomergeDeviceSyncRequest(request: unknown, expectedRemoteDeviceId: string): {
    frame: unknown
    batch: { protocolVersion: 1; scopeId: string; documentId: string; batchId: string;
      changes: Array<{ hash: string; bytes: Uint8Array | number[] }> }
  }
  encodeAutomergeDeviceSyncResponse(batchId: string, ack: unknown, frame: unknown): unknown
  createBatchDeliveryFlow(targetDeviceId: string, routeInstanceIds: string[], fallbackDelayMs: number,
    retryDelaysMs: number[]): RustBatchDeliveryFlow
  createMeshRuntimeState(): RustMeshRuntimeState
  createLiveWorkspaceSession(workspaceId: string, secret: string): RustLiveWorkspaceSession
  createMeshHandshakeFlow(direction: "incoming" | "outgoing"): RustMeshHandshakeFlow
  createMeshLifecycleState(): RustMeshLifecycleState
  createGossipLifecycleState(topicPrefix?: string): RustGossipLifecycleState
  createMeshSessionLifecycleState(stableAfterMs?: number): RustMeshSessionLifecycle
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
