/* tslint:disable */
/* eslint-disable */
/**
 * The `ReadableStreamType` enum.
 *
 * *This API requires the following crate features to be activated: `ReadableStreamType`*
 */

type ReadableStreamType = "bytes";

export class BrowserAcceptor {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    accept(): Promise<BrowserConnection | undefined>;
    close(): Promise<void>;
}

export class BrowserConnection {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    acceptStream(): Promise<BrowserStream>;
    close(): Promise<void>;
    openStream(): Promise<BrowserStream>;
    readonly remoteEndpointId: string;
}

export class BrowserNode {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    accept(): Promise<BrowserAcceptor>;
    close(reason?: string | null): Promise<void>;
    dial(remote_endpoint: string): Promise<BrowserConnection>;
    dialRelay(remote_endpoint: string): Promise<BrowserConnection>;
    static start(secret?: Uint8Array | null): Promise<BrowserNode>;
    readonly endpointId: string;
}

export class BrowserStream {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    closeSend(): Promise<void>;
    read(): Promise<Uint8Array>;
    send(bytes: Uint8Array): Promise<void>;
}

export class IntoUnderlyingByteSource {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    cancel(): void;
    pull(controller: ReadableByteStreamController): Promise<any>;
    start(controller: ReadableByteStreamController): void;
    readonly autoAllocateChunkSize: number;
    readonly type: ReadableStreamType;
}

export class IntoUnderlyingSink {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    abort(reason: any): Promise<any>;
    close(): Promise<any>;
    write(chunk: any): Promise<any>;
}

export class IntoUnderlyingSource {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    cancel(): void;
    pull(controller: ReadableStreamDefaultController): Promise<any>;
}

export class WasmAutomergeDeviceSyncFlow {
    free(): void;
    [Symbol.dispose](): void;
    completeRound(route_instance_id: string, response: any): any;
    static decodeIncomingRequest(request: any, expected_remote_device_id: string): any;
    static encodeResponse(batch_id: string, ack: any, frame: any): any;
    constructor(target_device_id: string, document_id: string, maximum_rounds: number);
    nextRound(frame: any): any;
    validateResponse(response: any): void;
}

export class WasmAutomergeSyncEngine {
    free(): void;
    [Symbol.dispose](): void;
    abortPreparedReceive(document_id: string, remote_device_id: string): void;
    commitPreparedReceive(document_id: string, remote_device_id: string): void;
    generate(document_id: string, remote_device_id: string, authorized: boolean, proof: any): any;
    heads(document_id: string): string[];
    loadDocument(scope_id: string, document_id: string, bytes: Uint8Array): void;
    constructor(local_device_id: string, maximum_frame_bytes?: number | null);
    prepareReceive(remote_device_id: string, frame: any, authorized: boolean, response_proof: any): any;
    receive(remote_device_id: string, frame: any, authorized: boolean, response_proof: any): any;
    reset(document_id: string, remote_device_id: string): void;
    saveDocument(document_id: string): Uint8Array;
}

export class WasmBlobEngine {
    free(): void;
    [Symbol.dispose](): void;
    createBlob(data: Uint8Array, name: string, media_type: string, node_endpoint?: string | null): any;
    getBlob(hash: string): Uint8Array | undefined;
    hasBlob(hash: string): boolean;
    constructor();
    static parseTicket(ticket: string): any;
    putBlob(hash: string, data: Uint8Array): void;
    verifyBlob(hash: string, data: Uint8Array): boolean;
}

export class WasmDeviceRouteCatalog {
    free(): void;
    [Symbol.dispose](): void;
    admit(route: any): any;
    constructor();
    routesFor(scope_id: string, device_id: string): any;
}

export class WasmGossipEngine {
    free(): void;
    [Symbol.dispose](): void;
    activeNeighbors(topic_name: string): string[];
    broadcast(topic_name: string, content: Uint8Array): any;
    expireTimer(timer_id: bigint): any;
    handleMessage(sender: string, raw_packet: Uint8Array): any;
    joinTopic(topic_name: string, bootstrap_peers: string[]): any;
    leaveTopic(topic_name: string): any;
    constructor(local_peer_id: string);
    peerDisconnected(peer: string): any;
}

export class WasmGossipLifecycleState {
    free(): void;
    [Symbol.dispose](): void;
    broadcastPlan(workspace_id: string, driver_available: boolean): any;
    close(workspace_id: string): void;
    closeAll(): void;
    deliveryAction(workspace_id: string, topic: string, session_available: boolean, packet_valid: boolean): any;
    constructor(topic_prefix?: string | null);
    observeNeighbors(workspace_id: string, count: number): any;
    planRebuild(raw: any): any;
    receiveAction(workspace_id: string, driver_available: boolean, session_available: boolean): any;
    startFailed(workspace_id: string): void;
    started(workspace_id: string): void;
    topic(workspace_id: string): string;
}

export class WasmIdentityCrypto {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static canonicalizeJson(value: any): string;
    static certificateHash(certificate: any): string;
    static deriveDeviceSeed(device_entropy: Uint8Array): Uint8Array;
    static identitySecurityForRecovery(value: string): string | undefined;
    static legacyRecoveryFromSamples(samples: Uint16Array): string;
    static openIdentitySeed(envelope: any, recovery_key: string): Uint8Array;
    static openIdentitySeedWithPassphrase(envelope: any, passphrase: string): Uint8Array;
    static publicKeyFromSeed(seed: Uint8Array): string;
    static publicKeyId(public_key: string): string;
    static recoveryPhraseFromEntropy(entropy: Uint8Array): string;
    static recoveryPhraseToEntropy(value: string): Uint8Array;
    static sealIdentitySeed(seed: Uint8Array, person_id: string, recovery_key: string, security: string, salt: Uint8Array, iv: Uint8Array): any;
    static sealIdentitySeedWithPassphrase(seed: Uint8Array, person_id: string, passphrase: string, salt: Uint8Array, iv: Uint8Array): any;
    static signEnvelope(seed: Uint8Array, payload: any, signer_key_id: string, domain?: string | null): any;
    static verifyDeviceCertificateChain(identity: any, device_id: string, certificates: any, domain?: string | null): string;
    static verifyEnvelope(envelope: any, public_key: string, domain?: string | null): boolean;
    static verifyWorkspaceGrant(grant: any, workspace_id: string, member_person_id: string, owner: any, owner_certificates: any): string;
}

export class WasmInvitations {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static createDeviceEnrollment(endpoint: string, secret: string, issuer: any, invitation_id: string, now_ms: number): any;
    static createWorkspaceJoin(endpoint: string, secret: string, issuer: any, invitation_id: string, workspaces: any, role: string, now_ms: number): any;
    static invitationUrl(origin: string, invitation: any): string;
    static pairingInviteUrl(origin: string, invite: any): string;
    static parseInvitation(raw: string, now_ms: number): any;
    static parsePairingInvite(raw: string): any;
}

export class WasmLiveWorkspaceSession {
    free(): void;
    [Symbol.dispose](): void;
    abortDocument(): void;
    acknowledgeSaved(bytes: Uint8Array): Uint8Array;
    commitDocument(): void;
    controlChanged(snapshot: Uint8Array): boolean;
    controlFrames(snapshot: Uint8Array): any;
    decodeAutomergePayload(payload: Uint8Array): any;
    decodeControl(bytes: Uint8Array): any;
    encode(frame_type: string, payload: Uint8Array): Uint8Array;
    encodeAutomergeFrame(frame: any): Uint8Array;
    encodeControl(authorization: any, chat: any, mesh: any): Uint8Array;
    finishPublish(control_snapshot: Uint8Array, all_frames_sent: boolean): void;
    generateDocument(document: Uint8Array, proof: any): Uint8Array | undefined;
    markControlSent(snapshot: Uint8Array): void;
    constructor(workspace_id: string, secret: string);
    prepareControlPublish(authorization: any, chat: any, mesh: any): any;
    prepareDocument(payload: Uint8Array, document: Uint8Array, response_proof: any): any;
    preparePublish(document: Uint8Array, proof: any, authorization: any, chat: any, mesh: any): any;
    prepareSnapshotPublish(snapshot: Uint8Array): any;
    receive(frame: Uint8Array): any;
    receiveWithPlan(frame: Uint8Array): any;
    resetDocument(): void;
    startDocumentSync(local_device_id: string, remote_device_id: string): void;
    verifyHeartbeatAck(frame: Uint8Array): void;
    verifySavedReceipt(frame: Uint8Array, bytes: Uint8Array): void;
}

export class WasmMeshAuthenticatedSessions {
    free(): void;
    [Symbol.dispose](): void;
    admit(handshake: any, snapshot: any, remote_endpoint: string, now_ms: number): any;
    clear(): void;
    constructor();
    peer(workspace_id: string, remote_endpoint: string): any;
    refresh(snapshot: any, now_ms: number): any;
    remove(workspace_id: string, remote_endpoint: string): boolean;
}

export class WasmMeshBatchDeliveryFlow {
    free(): void;
    [Symbol.dispose](): void;
    abort(): any;
    fallbackElapsed(round: number): any;
    constructor(target_device_id: string, route_ids: any, fallback_delay_ms: number, retry_delays_ms: any);
    retryElapsed(round: number): any;
    routeResult(round: number, route_index: number, accepted: boolean, failure: string): any;
    start(): any;
}

export class WasmMeshHandshakeFlow {
    free(): void;
    [Symbol.dispose](): void;
    advance(completed: string, decision?: boolean | null): string;
    isPeerRevoked(credential: any, person_id: string, grant: any, device_id: string): boolean;
    matchesAdmittedPeer(verified_device_id: string, verified_person_id: string, verified_endpoint: string, admitted_device_id: string, admitted_person_id: string, admitted_endpoint: string): boolean;
    matchesExpectedPeer(expected_device_id: string, verified_device_id: string): boolean;
    constructor(direction_name: string);
    step(): string;
}

export class WasmMeshLifecycleState {
    free(): void;
    [Symbol.dispose](): void;
    beginStart(): boolean;
    canContinueStart(): boolean;
    cancelStart(): void;
    completeStart(): boolean;
    dispose(): void;
    finishStop(): void;
    constructor();
    pause(): void;
    resume(): boolean;
    stop(): boolean;
    readonly disposed: boolean;
    readonly externallyPaused: boolean;
    readonly stopped: boolean;
}

export class WasmMeshRuntimeState {
    free(): void;
    [Symbol.dispose](): void;
    admitSession(candidate: any, preferred_direction: string): any;
    beginRouteAttempt(route_key: string, now_ms: number): any;
    clearReconnect(route_key: string): void;
    clearReconnectsWithPrefix(prefix: string): void;
    clearRouteAttempt(route_key: string): void;
    connectedDevices(workspace_id: string): any;
    controlFrames(workspace_id: string, bytes: Uint8Array): any;
    dueReconnects(now_ms: number): any;
    encodeWorkspaceUpdate(workspace_id: string, nonce: string): Uint8Array;
    finishRouteAttempt(route_key: string, token: number): boolean;
    isWorkspaceUpdate(payload: Uint8Array, workspace_id: string): boolean;
    constructor();
    planDial(peer_key: string, relay_available: boolean, now_ms: number): any;
    receiveControlFrame(workspace_id: string, frame: Uint8Array): Uint8Array | undefined;
    reconnectState(route_key: string): any;
    recordDialSuccess(peer_key: string, mode: string, now_ms: number): void;
    recordNetworkFailure(peer_key: string, now_ms: number): void;
    removeSession(key: any, generation: number): any;
    routeAttemptActive(route_key: string): boolean;
    scheduleReconnect(route_key: string, now_ms: number, base_delay_ms: number, maximum_delay_ms: number): any;
    sessions(): any;
    start(): void;
    stop(): any;
    readonly running: boolean;
}

/**
 * WASM host boundary for one authenticated workspace scope stream.
 */
export class WasmMeshScopeRuntime {
    free(): void;
    [Symbol.dispose](): void;
    completeDocumentReceive(persisted: boolean): any;
    completeSavedReceive(persisted: boolean): any;
    finishPublish(control_snapshot: Uint8Array, all_frames_sent: boolean): void;
    constructor(workspace_id: string, secret: string);
    preparePublish(document: Uint8Array, proof: any, authorization: any, chat: any, mesh: any): any;
    provideDocument(document: Uint8Array, response_proof: any): any;
    publishFrame(document: Uint8Array, proof: any): Uint8Array | undefined;
    receiveFrame(frame: Uint8Array): any;
    rejectDocumentReceive(): void;
    resetDocument(): void;
    startDocumentSync(local_device_id: string, remote_device_id: string): void;
}

export class WasmMeshSessionLifecycle {
    free(): void;
    [Symbol.dispose](): void;
    callbackPlan(key: any, generation: number, event: string, now_ms: number): any;
    clear(): void;
    evict(key: any, generation: number): any;
    markStable(key: any, generation: number, now_ms: number): boolean;
    constructor(stable_after_ms?: number | null);
    publishPlan(): any;
    publishRecovery(key: any, generation: number): boolean;
    register(key: any, connection_id: string, generation: number, now_ms: number): any;
    reportFailure(key: any, generation: number): boolean;
}

export class WasmPairingCodec {
    free(): void;
    [Symbol.dispose](): void;
    decode(frame: Uint8Array, expected_type: string, expected_secret: string): Uint8Array;
    encode(frame_type: string, secret: string, payload: Uint8Array): Uint8Array;
    inspect(frame: Uint8Array): any;
    constructor();
}

export class WasmStateCore {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static admitMeshPeer(handshake: any, snapshot: any, remote_endpoint: string, now_ms: number): any;
    static admitWorkspaceChangeAuthorization(authorization: any, snapshot: any, needed_hashes: any, now_ms: number): any;
    static admitWorkspaceChangeAuthorizations(authorization: any, snapshot: any, needed_hashes: any, now_ms: number): any;
    static canRemoveWorkspaceDevice(credential: any, local_person_id: string, local_public_key: string, local_device_id: string, target_person_id: string, target_device_id: string, peer_person_id?: string | null): boolean;
    static canReuseMemberBundle(raw: any): boolean;
    static canonicalRevocations(records: any): any;
    static createScopeControlTransferPayload(raw: any): any;
    static createScopeGenesis(raw: any): any;
    static createScopeGenesisPayload(raw: any): any;
    static credentialBelongsToProfile(credential: any, person_id: string, public_key: string): boolean;
    static decideOwnerCredential(existing_owner_person_id: string | null | undefined, local_person_id: string): string;
    static decideWorkspaceAccess(raw: any, now_ms: number): any;
    static decodeMeshHandshake(frame: Uint8Array, expected_type: string, secret: string, workspace_id: string): any;
    static decodeWorkspaceSet(bytes: Uint8Array, allowed_ids: any): any;
    static durableAckMatches(ack: any, batch: any, target_device_id: string): boolean;
    static eligibleEditorPersonIds(peers: any): any;
    static encodeMeshHandshake(frame_type: string, secret: string, raw: any): Uint8Array;
    static encodeWorkspaceSet(entries: any): Uint8Array;
    static hasAuthorityConflict(raw: any): boolean;
    static hasConflictingOwnershipTransfers(records: any): boolean;
    static hasLeftWorkspace(credential: any, person_id: string, grant: any): boolean;
    static inspectMeshHandshake(frame: Uint8Array): any;
    static isDeviceRevoked(credential: any, person_id: string, device_id: string): boolean;
    static isGrantRevoked(credential: any, person_id: string, grant: any): boolean;
    static isWorkspaceEnvelope(raw: any): boolean;
    static knowsWorkspaceIssuer(raw: any, issuer_person_id: string, local_person_id: string, local_device_id: string): boolean;
    static mergePeerRecords(existing: any, incoming: any): any;
    static meshCapabilities(): any;
    static meshHandshakeFeatures(raw: any): any;
    static missingOwnerWorkspaces(owned: any, remote: any): any;
    static nextAccessEpoch(credential: any, issued_grants: any): number;
    static nextVerifiedOwnershipTransition(records: any, workspace_id: string, current_owner: any, current_epoch: number, revoked_people: any, now_ms: number): any;
    static orderDeliveryRoutes(target_device_id: string, routes: any): any;
    static ownedWorkspaceIds(credentials: any, person_id: string, public_key: string): any;
    static partitionCredentials(raw: any): any;
    static planAuthorityCommand(raw: any): any;
    static planAuthorityImport(kind: string, has_revocations: boolean, has_transfers: boolean): any;
    static planAuthorityMerge(raw: any): any;
    static planCatalogMerge(): any;
    static planChangeAdmission(document_id: string, changes: any, verified_at: string): any;
    static planChangeAdmissionFlow(raw: any, now_ms: number): any;
    static planDialSchedule(raw: any): any;
    static planGuestAdvertisements(raw: any): any;
    static planInvitation(raw: any): any;
    static planInvitationCredential(raw: any): any;
    static planMemberGrant(raw: any): any;
    static planMeshHandshakeAuthorityImport(): any;
    static planOwnerCertificateRefresh(credential: any, local_person_id: string, certificates: any, updated_at: string): any;
    static planOwnershipAdoption(raw: any): any;
    static planOwnershipAuthorityFlow(raw: any): any;
    static planOwnershipMerge(raw: any): any;
    static planOwnershipTransitions(records: any, initial_owner_person_id: string, initial_epoch: number): any;
    static planScopeGenesis(raw: any): any;
    static planSuccessionCatalog(raw: any): any;
    static planSuccessionMerge(raw: any, now_ms: number): any;
    static planSuccessionPolicyRefresh(current: any, eligible: any, epoch: number): any;
    static preferredSessionDirection(local_device_id: string, local_instance_id: string, remote_device_id: string, remote_instance_id: string): any;
    static prepareWriteEvidence(raw: any): any;
    static reconcileReplicaSets(left: any, right: any): any;
    static requireChangeAuthorizationCoverage(change_hashes: any, records: any): void;
    static selectMeshHandshakeBundle(candidates: any, local_device_id: string, local_instance_id: string): any;
    static selectOwnershipTransfer(raw: any): any;
    static selectScopedNeighbors(local_device_id: string, candidates: any, bounds: any, now_ms: number, rotation: number): string[];
    static shouldAdvertiseOwnerWorkspaceIds(credential_owner_person_id: string, local_person_id: string, remote_person_id: string): boolean;
    static signDeviceRoute(seed: Uint8Array, signer_key_id: string, payload: any): any;
    static signDurableAck(seed: Uint8Array, signer_key_id: string, payload: any): any;
    static summarizeSuccession(policy: any, claims: any, votes: any, transfers: any, revocations: any, epoch: number): any;
    static transitionOutboxClaim(current: any, input: any): any;
    static validateDeviceRoute(route: any): void;
    static validateDeviceRoutePayload(payload: any): void;
    static validateDurableAckPayload(payload: any): void;
    static validateMeshCapabilities(capabilities: any): void;
    static validateMeshCatalog(raw: any): any;
    static validateMeshHandshake(raw: any, expected_workspace_id?: string | null): any;
    static validateOwnerWorkspaceOffer(raw: any, remote_person_id: string, local_person_id: string): string;
    static validateScopeAuthority(raw: any): any;
    static verifyDeviceRoute(envelope: any, public_key: string, now_ms: number, allow_expired: boolean): any;
    static verifyDurableAck(envelope: any, public_key: string): any;
    static verifyWorkspaceDeparture(record: any, workspace_id: string, authority: any, now_ms: number): any;
    static verifyWorkspaceDeviceRevocation(record: any, workspace_id: string, owner_person_id: string, authority: any, now_ms: number): any;
    static verifyWorkspaceGrant(grant: any, workspace_id: string, member_person_id: string, authority: any): any;
    static verifyWorkspaceMemberBundle(raw: any, options: any, now_ms: number): any;
    static verifyWorkspaceOwnershipTransfer(record: any, workspace_id: string, authority: any, minimum_epoch: number, now_ms: number): any;
    static verifyWorkspaceRevocation(record: any, workspace_id: string, authority: any, now_ms: number): any;
    static verifyWorkspaceSuccessionClaim(claim: any, workspace_id: string, authority: any, minimum_epoch: number, revoked: any, now_ms: number): any;
    static verifyWorkspaceSuccessionPolicy(policy: any, workspace_id: string, authority: any, now_ms: number): any;
    static verifyWorkspaceSuccessionVote(vote: any, policy: any, candidate_person_id: string, authority: any, revoked: any, now_ms: number): any;
}

export class WasmWorkspaceJoinHandoff {
    free(): void;
    [Symbol.dispose](): void;
    guestBeginConfirmation(): Uint8Array;
    guestConfirmationFailed(): string;
    guestConfirmationSent(): string;
    guestReceiveReady(frame: Uint8Array): void;
    guestRequest(): Uint8Array;
    guestResumeFailed(retryable: boolean): string;
    guestResumeSucceeded(): void;
    guestTransportFailed(retryable: boolean): string;
    hostReceiveConfirmation(frame: Uint8Array): void;
    hostReceiveRequest(frame: Uint8Array): Uint8Array;
    constructor(secret: string, side: string);
}

export class WasmWorkspaceJoinHandshake {
    free(): void;
    [Symbol.dispose](): void;
    acknowledgeRejection(): Uint8Array;
    acknowledgeSuccess(payload: Uint8Array): Uint8Array;
    constructor(secret: string, side: string);
    receiveAck(frame: Uint8Array): any;
    receiveRequest(frame: Uint8Array): Uint8Array;
    receiveResponse(frame: Uint8Array): any;
    reject(message: string): Uint8Array;
    rejectAcceptedResponse(message: string): Uint8Array;
    respond(payload: Uint8Array): Uint8Array;
    sendRequest(payload: Uint8Array): Uint8Array;
}

export function browserTransportDebugLoggingEnabled(): boolean;

export function mesh_version(): string;

export function setBrowserTransportDebugLogging(enabled: boolean): void;

export function start_browser_node(secret?: Uint8Array | null): Promise<BrowserNode>;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmgossiplifecyclestate_free: (a: number, b: number) => void;
    readonly __wbg_wasmliveworkspacesession_free: (a: number, b: number) => void;
    readonly __wbg_wasmmeshbatchdeliveryflow_free: (a: number, b: number) => void;
    readonly __wbg_wasmmeshhandshakeflow_free: (a: number, b: number) => void;
    readonly __wbg_wasmmeshlifecyclestate_free: (a: number, b: number) => void;
    readonly __wbg_wasmmeshruntimestate_free: (a: number, b: number) => void;
    readonly __wbg_wasmmeshscoperuntime_free: (a: number, b: number) => void;
    readonly __wbg_wasmmeshsessionlifecycle_free: (a: number, b: number) => void;
    readonly wasmgossiplifecyclestate_broadcastPlan: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmgossiplifecyclestate_close: (a: number, b: number, c: number) => [number, number];
    readonly wasmgossiplifecyclestate_closeAll: (a: number) => void;
    readonly wasmgossiplifecyclestate_deliveryAction: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly wasmgossiplifecyclestate_new: (a: number, b: number) => [number, number, number];
    readonly wasmgossiplifecyclestate_observeNeighbors: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmgossiplifecyclestate_planRebuild: (a: number, b: any) => [number, number, number];
    readonly wasmgossiplifecyclestate_receiveAction: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmgossiplifecyclestate_startFailed: (a: number, b: number, c: number) => [number, number];
    readonly wasmgossiplifecyclestate_started: (a: number, b: number, c: number) => [number, number];
    readonly wasmgossiplifecyclestate_topic: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmliveworkspacesession_abortDocument: (a: number) => void;
    readonly wasmliveworkspacesession_acknowledgeSaved: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmliveworkspacesession_commitDocument: (a: number) => [number, number];
    readonly wasmliveworkspacesession_controlChanged: (a: number, b: number, c: number) => number;
    readonly wasmliveworkspacesession_controlFrames: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmliveworkspacesession_decodeAutomergePayload: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmliveworkspacesession_decodeControl: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmliveworkspacesession_encode: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasmliveworkspacesession_encodeAutomergeFrame: (a: number, b: any) => [number, number, number, number];
    readonly wasmliveworkspacesession_encodeControl: (a: number, b: any, c: any, d: any) => [number, number, number, number];
    readonly wasmliveworkspacesession_finishPublish: (a: number, b: number, c: number, d: number) => void;
    readonly wasmliveworkspacesession_generateDocument: (a: number, b: number, c: number, d: any) => [number, number, number, number];
    readonly wasmliveworkspacesession_markControlSent: (a: number, b: number, c: number) => void;
    readonly wasmliveworkspacesession_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmliveworkspacesession_prepareControlPublish: (a: number, b: any, c: any, d: any) => [number, number, number];
    readonly wasmliveworkspacesession_prepareDocument: (a: number, b: number, c: number, d: number, e: number, f: any) => [number, number, number];
    readonly wasmliveworkspacesession_preparePublish: (a: number, b: number, c: number, d: any, e: any, f: any, g: any) => [number, number, number];
    readonly wasmliveworkspacesession_prepareSnapshotPublish: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmliveworkspacesession_receive: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmliveworkspacesession_receiveWithPlan: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmliveworkspacesession_resetDocument: (a: number) => void;
    readonly wasmliveworkspacesession_startDocumentSync: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly wasmliveworkspacesession_verifyHeartbeatAck: (a: number, b: number, c: number) => [number, number];
    readonly wasmliveworkspacesession_verifySavedReceipt: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly wasmmeshbatchdeliveryflow_abort: (a: number) => [number, number, number];
    readonly wasmmeshbatchdeliveryflow_fallbackElapsed: (a: number, b: number) => [number, number, number];
    readonly wasmmeshbatchdeliveryflow_new: (a: number, b: number, c: any, d: number, e: any) => [number, number, number];
    readonly wasmmeshbatchdeliveryflow_retryElapsed: (a: number, b: number) => [number, number, number];
    readonly wasmmeshbatchdeliveryflow_routeResult: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly wasmmeshbatchdeliveryflow_start: (a: number) => [number, number, number];
    readonly wasmmeshhandshakeflow_advance: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasmmeshhandshakeflow_isPeerRevoked: (a: number, b: any, c: number, d: number, e: any, f: number, g: number) => [number, number, number];
    readonly wasmmeshhandshakeflow_matchesAdmittedPeer: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => number;
    readonly wasmmeshhandshakeflow_matchesExpectedPeer: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly wasmmeshhandshakeflow_new: (a: number, b: number) => [number, number, number];
    readonly wasmmeshhandshakeflow_step: (a: number) => [number, number];
    readonly wasmmeshlifecyclestate_beginStart: (a: number) => number;
    readonly wasmmeshlifecyclestate_canContinueStart: (a: number) => number;
    readonly wasmmeshlifecyclestate_cancelStart: (a: number) => void;
    readonly wasmmeshlifecyclestate_completeStart: (a: number) => number;
    readonly wasmmeshlifecyclestate_dispose: (a: number) => void;
    readonly wasmmeshlifecyclestate_disposed: (a: number) => number;
    readonly wasmmeshlifecyclestate_externallyPaused: (a: number) => number;
    readonly wasmmeshlifecyclestate_finishStop: (a: number) => void;
    readonly wasmmeshlifecyclestate_new: () => number;
    readonly wasmmeshlifecyclestate_pause: (a: number) => void;
    readonly wasmmeshlifecyclestate_resume: (a: number) => number;
    readonly wasmmeshlifecyclestate_stop: (a: number) => number;
    readonly wasmmeshlifecyclestate_stopped: (a: number) => number;
    readonly wasmmeshruntimestate_admitSession: (a: number, b: any, c: number, d: number) => [number, number, number];
    readonly wasmmeshruntimestate_beginRouteAttempt: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmmeshruntimestate_clearReconnect: (a: number, b: number, c: number) => void;
    readonly wasmmeshruntimestate_clearReconnectsWithPrefix: (a: number, b: number, c: number) => void;
    readonly wasmmeshruntimestate_clearRouteAttempt: (a: number, b: number, c: number) => void;
    readonly wasmmeshruntimestate_connectedDevices: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmmeshruntimestate_controlFrames: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmmeshruntimestate_dueReconnects: (a: number, b: number) => [number, number, number];
    readonly wasmmeshruntimestate_encodeWorkspaceUpdate: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly wasmmeshruntimestate_finishRouteAttempt: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmmeshruntimestate_isWorkspaceUpdate: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly wasmmeshruntimestate_new: () => number;
    readonly wasmmeshruntimestate_planDial: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmmeshruntimestate_receiveControlFrame: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasmmeshruntimestate_reconnectState: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmmeshruntimestate_recordDialSuccess: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly wasmmeshruntimestate_recordNetworkFailure: (a: number, b: number, c: number, d: number) => [number, number];
    readonly wasmmeshruntimestate_removeSession: (a: number, b: any, c: number) => [number, number, number];
    readonly wasmmeshruntimestate_routeAttemptActive: (a: number, b: number, c: number) => number;
    readonly wasmmeshruntimestate_running: (a: number) => number;
    readonly wasmmeshruntimestate_scheduleReconnect: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly wasmmeshruntimestate_sessions: (a: number) => [number, number, number];
    readonly wasmmeshruntimestate_start: (a: number) => void;
    readonly wasmmeshruntimestate_stop: (a: number) => [number, number, number];
    readonly wasmmeshscoperuntime_completeDocumentReceive: (a: number, b: number) => [number, number, number];
    readonly wasmmeshscoperuntime_completeSavedReceive: (a: number, b: number) => [number, number, number];
    readonly wasmmeshscoperuntime_finishPublish: (a: number, b: number, c: number, d: number) => void;
    readonly wasmmeshscoperuntime_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmmeshscoperuntime_preparePublish: (a: number, b: number, c: number, d: any, e: any, f: any, g: any) => [number, number, number];
    readonly wasmmeshscoperuntime_provideDocument: (a: number, b: number, c: number, d: any) => [number, number, number];
    readonly wasmmeshscoperuntime_publishFrame: (a: number, b: number, c: number, d: any) => [number, number, number, number];
    readonly wasmmeshscoperuntime_receiveFrame: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmmeshscoperuntime_rejectDocumentReceive: (a: number) => [number, number];
    readonly wasmmeshscoperuntime_resetDocument: (a: number) => void;
    readonly wasmmeshscoperuntime_startDocumentSync: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly wasmmeshsessionlifecycle_callbackPlan: (a: number, b: any, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly wasmmeshsessionlifecycle_clear: (a: number) => void;
    readonly wasmmeshsessionlifecycle_evict: (a: number, b: any, c: number) => [number, number, number];
    readonly wasmmeshsessionlifecycle_markStable: (a: number, b: any, c: number, d: number) => [number, number, number];
    readonly wasmmeshsessionlifecycle_new: (a: number, b: number) => [number, number, number];
    readonly wasmmeshsessionlifecycle_publishPlan: (a: number) => [number, number, number];
    readonly wasmmeshsessionlifecycle_publishRecovery: (a: number, b: any, c: number) => [number, number, number];
    readonly wasmmeshsessionlifecycle_register: (a: number, b: any, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly wasmmeshsessionlifecycle_reportFailure: (a: number, b: any, c: number) => [number, number, number];
    readonly __wbg_wasmautomergedevicesyncflow_free: (a: number, b: number) => void;
    readonly __wbg_wasmautomergesyncengine_free: (a: number, b: number) => void;
    readonly __wbg_wasminvitations_free: (a: number, b: number) => void;
    readonly wasmautomergedevicesyncflow_completeRound: (a: number, b: number, c: number, d: any) => [number, number, number];
    readonly wasmautomergedevicesyncflow_decodeIncomingRequest: (a: any, b: number, c: number) => [number, number, number];
    readonly wasmautomergedevicesyncflow_encodeResponse: (a: number, b: number, c: any, d: any) => [number, number, number];
    readonly wasmautomergedevicesyncflow_new: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmautomergedevicesyncflow_nextRound: (a: number, b: any) => [number, number, number];
    readonly wasmautomergedevicesyncflow_validateResponse: (a: number, b: any) => [number, number];
    readonly wasmautomergesyncengine_abortPreparedReceive: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly wasmautomergesyncengine_commitPreparedReceive: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly wasmautomergesyncengine_generate: (a: number, b: number, c: number, d: number, e: number, f: number, g: any) => [number, number, number];
    readonly wasmautomergesyncengine_heads: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmautomergesyncengine_loadDocument: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
    readonly wasmautomergesyncengine_new: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmautomergesyncengine_prepareReceive: (a: number, b: number, c: number, d: any, e: number, f: any) => [number, number, number];
    readonly wasmautomergesyncengine_receive: (a: number, b: number, c: number, d: any, e: number, f: any) => [number, number, number];
    readonly wasmautomergesyncengine_reset: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly wasmautomergesyncengine_saveDocument: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasminvitations_createDeviceEnrollment: (a: number, b: number, c: number, d: number, e: any, f: number, g: number, h: number) => [number, number, number];
    readonly wasminvitations_createWorkspaceJoin: (a: number, b: number, c: number, d: number, e: any, f: number, g: number, h: any, i: number, j: number, k: number) => [number, number, number];
    readonly wasminvitations_invitationUrl: (a: number, b: number, c: any) => [number, number, number, number];
    readonly wasminvitations_pairingInviteUrl: (a: number, b: number, c: any) => [number, number, number, number];
    readonly wasminvitations_parseInvitation: (a: number, b: number, c: number) => [number, number, number];
    readonly wasminvitations_parsePairingInvite: (a: number, b: number) => [number, number, number];
    readonly __wbg_wasmgossipengine_free: (a: number, b: number) => void;
    readonly __wbg_wasmpairingcodec_free: (a: number, b: number) => void;
    readonly __wbg_wasmworkspacejoinhandoff_free: (a: number, b: number) => void;
    readonly __wbg_wasmworkspacejoinhandshake_free: (a: number, b: number) => void;
    readonly wasmgossipengine_activeNeighbors: (a: number, b: number, c: number) => [number, number];
    readonly wasmgossipengine_broadcast: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmgossipengine_expireTimer: (a: number, b: bigint) => [number, number, number];
    readonly wasmgossipengine_handleMessage: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmgossipengine_joinTopic: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmgossipengine_leaveTopic: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmgossipengine_new: (a: number, b: number) => number;
    readonly wasmgossipengine_peerDisconnected: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmpairingcodec_decode: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly wasmpairingcodec_encode: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly wasmpairingcodec_inspect: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmworkspacejoinhandoff_guestBeginConfirmation: (a: number) => [number, number, number, number];
    readonly wasmworkspacejoinhandoff_guestConfirmationFailed: (a: number) => [number, number, number, number];
    readonly wasmworkspacejoinhandoff_guestConfirmationSent: (a: number) => [number, number, number, number];
    readonly wasmworkspacejoinhandoff_guestReceiveReady: (a: number, b: number, c: number) => [number, number];
    readonly wasmworkspacejoinhandoff_guestRequest: (a: number) => [number, number, number, number];
    readonly wasmworkspacejoinhandoff_guestResumeFailed: (a: number, b: number) => [number, number, number, number];
    readonly wasmworkspacejoinhandoff_guestResumeSucceeded: (a: number) => [number, number];
    readonly wasmworkspacejoinhandoff_guestTransportFailed: (a: number, b: number) => [number, number, number, number];
    readonly wasmworkspacejoinhandoff_hostReceiveConfirmation: (a: number, b: number, c: number) => [number, number];
    readonly wasmworkspacejoinhandoff_hostReceiveRequest: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmworkspacejoinhandoff_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmworkspacejoinhandshake_acknowledgeRejection: (a: number) => [number, number, number, number];
    readonly wasmworkspacejoinhandshake_acknowledgeSuccess: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmworkspacejoinhandshake_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmworkspacejoinhandshake_receiveAck: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmworkspacejoinhandshake_receiveRequest: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmworkspacejoinhandshake_receiveResponse: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmworkspacejoinhandshake_reject: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmworkspacejoinhandshake_rejectAcceptedResponse: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmworkspacejoinhandshake_respond: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmworkspacejoinhandshake_sendRequest: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmpairingcodec_new: () => number;
    readonly __wbg_wasmblobengine_free: (a: number, b: number) => void;
    readonly wasmblobengine_createBlob: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number];
    readonly wasmblobengine_getBlob: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmblobengine_hasBlob: (a: number, b: number, c: number) => number;
    readonly wasmblobengine_new: () => number;
    readonly wasmblobengine_parseTicket: (a: number, b: number) => [number, number, number];
    readonly wasmblobengine_putBlob: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly wasmblobengine_verifyBlob: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly __wbg_browseracceptor_free: (a: number, b: number) => void;
    readonly __wbg_browserconnection_free: (a: number, b: number) => void;
    readonly __wbg_browsernode_free: (a: number, b: number) => void;
    readonly __wbg_browserstream_free: (a: number, b: number) => void;
    readonly browserTransportDebugLoggingEnabled: () => number;
    readonly browseracceptor_accept: (a: number) => any;
    readonly browseracceptor_close: (a: number) => any;
    readonly browserconnection_acceptStream: (a: number) => any;
    readonly browserconnection_close: (a: number) => any;
    readonly browserconnection_openStream: (a: number) => any;
    readonly browserconnection_remoteEndpointId: (a: number) => [number, number];
    readonly browsernode_accept: (a: number) => any;
    readonly browsernode_close: (a: number, b: number, c: number) => any;
    readonly browsernode_dial: (a: number, b: number, c: number) => any;
    readonly browsernode_dialRelay: (a: number, b: number, c: number) => any;
    readonly browsernode_endpointId: (a: number) => [number, number];
    readonly browsernode_start: (a: number, b: number) => any;
    readonly browserstream_closeSend: (a: number) => any;
    readonly browserstream_read: (a: number) => any;
    readonly browserstream_send: (a: number, b: number, c: number) => any;
    readonly mesh_version: () => [number, number];
    readonly setBrowserTransportDebugLogging: (a: number) => void;
    readonly start_browser_node: (a: number, b: number) => any;
    readonly __wbg_wasmidentitycrypto_free: (a: number, b: number) => void;
    readonly wasmidentitycrypto_canonicalizeJson: (a: any) => [number, number, number, number];
    readonly wasmidentitycrypto_certificateHash: (a: any) => [number, number, number, number];
    readonly wasmidentitycrypto_deriveDeviceSeed: (a: number, b: number) => [number, number, number, number];
    readonly wasmidentitycrypto_identitySecurityForRecovery: (a: number, b: number) => [number, number];
    readonly wasmidentitycrypto_legacyRecoveryFromSamples: (a: number, b: number) => [number, number, number, number];
    readonly wasmidentitycrypto_openIdentitySeed: (a: any, b: number, c: number) => [number, number, number, number];
    readonly wasmidentitycrypto_openIdentitySeedWithPassphrase: (a: any, b: number, c: number) => [number, number, number, number];
    readonly wasmidentitycrypto_publicKeyFromSeed: (a: number, b: number) => [number, number, number, number];
    readonly wasmidentitycrypto_publicKeyId: (a: number, b: number) => [number, number, number, number];
    readonly wasmidentitycrypto_recoveryPhraseFromEntropy: (a: number, b: number) => [number, number, number, number];
    readonly wasmidentitycrypto_recoveryPhraseToEntropy: (a: number, b: number) => [number, number, number, number];
    readonly wasmidentitycrypto_sealIdentitySeed: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number];
    readonly wasmidentitycrypto_sealIdentitySeedWithPassphrase: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number];
    readonly wasmidentitycrypto_signEnvelope: (a: number, b: number, c: any, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly wasmidentitycrypto_verifyDeviceCertificateChain: (a: any, b: number, c: number, d: any, e: number, f: number) => [number, number, number, number];
    readonly wasmidentitycrypto_verifyEnvelope: (a: any, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmidentitycrypto_verifyWorkspaceGrant: (a: any, b: number, c: number, d: number, e: number, f: any, g: any) => [number, number, number, number];
    readonly __wbg_wasmdeviceroutecatalog_free: (a: number, b: number) => void;
    readonly __wbg_wasmmeshauthenticatedsessions_free: (a: number, b: number) => void;
    readonly __wbg_wasmstatecore_free: (a: number, b: number) => void;
    readonly wasmdeviceroutecatalog_admit: (a: number, b: any) => [number, number, number];
    readonly wasmdeviceroutecatalog_new: () => number;
    readonly wasmdeviceroutecatalog_routesFor: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmmeshauthenticatedsessions_admit: (a: number, b: any, c: any, d: number, e: number, f: number) => [number, number, number];
    readonly wasmmeshauthenticatedsessions_clear: (a: number) => void;
    readonly wasmmeshauthenticatedsessions_peer: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmmeshauthenticatedsessions_refresh: (a: number, b: any, c: number) => [number, number, number];
    readonly wasmmeshauthenticatedsessions_remove: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly wasmstatecore_admitMeshPeer: (a: any, b: any, c: number, d: number, e: number) => [number, number, number];
    readonly wasmstatecore_admitWorkspaceChangeAuthorization: (a: any, b: any, c: any, d: number) => [number, number, number];
    readonly wasmstatecore_admitWorkspaceChangeAuthorizations: (a: any, b: any, c: any, d: number) => [number, number, number];
    readonly wasmstatecore_canRemoveWorkspaceDevice: (a: any, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => [number, number, number];
    readonly wasmstatecore_canReuseMemberBundle: (a: any) => [number, number, number];
    readonly wasmstatecore_canonicalRevocations: (a: any) => [number, number, number];
    readonly wasmstatecore_createScopeControlTransferPayload: (a: any) => [number, number, number];
    readonly wasmstatecore_createScopeGenesis: (a: any) => [number, number, number];
    readonly wasmstatecore_createScopeGenesisPayload: (a: any) => [number, number, number];
    readonly wasmstatecore_credentialBelongsToProfile: (a: any, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmstatecore_decideOwnerCredential: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasmstatecore_decideWorkspaceAccess: (a: any, b: number) => [number, number, number];
    readonly wasmstatecore_decodeMeshHandshake: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly wasmstatecore_decodeWorkspaceSet: (a: number, b: number, c: any) => [number, number, number];
    readonly wasmstatecore_durableAckMatches: (a: any, b: any, c: number, d: number) => [number, number, number];
    readonly wasmstatecore_eligibleEditorPersonIds: (a: any) => [number, number, number];
    readonly wasmstatecore_encodeMeshHandshake: (a: number, b: number, c: number, d: number, e: any) => [number, number, number, number];
    readonly wasmstatecore_encodeWorkspaceSet: (a: any) => [number, number, number, number];
    readonly wasmstatecore_hasAuthorityConflict: (a: any) => [number, number, number];
    readonly wasmstatecore_hasConflictingOwnershipTransfers: (a: any) => [number, number, number];
    readonly wasmstatecore_hasLeftWorkspace: (a: any, b: number, c: number, d: any) => [number, number, number];
    readonly wasmstatecore_inspectMeshHandshake: (a: number, b: number) => [number, number, number];
    readonly wasmstatecore_isDeviceRevoked: (a: any, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmstatecore_isGrantRevoked: (a: any, b: number, c: number, d: any) => [number, number, number];
    readonly wasmstatecore_isWorkspaceEnvelope: (a: any) => [number, number, number];
    readonly wasmstatecore_knowsWorkspaceIssuer: (a: any, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly wasmstatecore_mergePeerRecords: (a: any, b: any) => [number, number, number];
    readonly wasmstatecore_meshCapabilities: () => [number, number, number];
    readonly wasmstatecore_meshHandshakeFeatures: (a: any) => [number, number, number];
    readonly wasmstatecore_missingOwnerWorkspaces: (a: any, b: any) => [number, number, number];
    readonly wasmstatecore_nextAccessEpoch: (a: any, b: any) => [number, number, number];
    readonly wasmstatecore_nextVerifiedOwnershipTransition: (a: any, b: number, c: number, d: any, e: number, f: any, g: number) => [number, number, number];
    readonly wasmstatecore_orderDeliveryRoutes: (a: number, b: number, c: any) => [number, number, number];
    readonly wasmstatecore_ownedWorkspaceIds: (a: any, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmstatecore_partitionCredentials: (a: any) => [number, number, number];
    readonly wasmstatecore_planAuthorityCommand: (a: any) => [number, number, number];
    readonly wasmstatecore_planAuthorityImport: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmstatecore_planAuthorityMerge: (a: any) => [number, number, number];
    readonly wasmstatecore_planCatalogMerge: () => [number, number, number];
    readonly wasmstatecore_planChangeAdmission: (a: number, b: number, c: any, d: number, e: number) => [number, number, number];
    readonly wasmstatecore_planChangeAdmissionFlow: (a: any, b: number) => [number, number, number];
    readonly wasmstatecore_planDialSchedule: (a: any) => [number, number, number];
    readonly wasmstatecore_planGuestAdvertisements: (a: any) => [number, number, number];
    readonly wasmstatecore_planInvitation: (a: any) => [number, number, number];
    readonly wasmstatecore_planInvitationCredential: (a: any) => [number, number, number];
    readonly wasmstatecore_planMemberGrant: (a: any) => [number, number, number];
    readonly wasmstatecore_planMeshHandshakeAuthorityImport: () => [number, number, number];
    readonly wasmstatecore_planOwnerCertificateRefresh: (a: any, b: number, c: number, d: any, e: number, f: number) => [number, number, number];
    readonly wasmstatecore_planOwnershipAdoption: (a: any) => [number, number, number];
    readonly wasmstatecore_planOwnershipAuthorityFlow: (a: any) => [number, number, number];
    readonly wasmstatecore_planOwnershipMerge: (a: any) => [number, number, number];
    readonly wasmstatecore_planOwnershipTransitions: (a: any, b: number, c: number, d: number) => [number, number, number];
    readonly wasmstatecore_planScopeGenesis: (a: any) => [number, number, number];
    readonly wasmstatecore_planSuccessionCatalog: (a: any) => [number, number, number];
    readonly wasmstatecore_planSuccessionMerge: (a: any, b: number) => [number, number, number];
    readonly wasmstatecore_planSuccessionPolicyRefresh: (a: any, b: any, c: number) => [number, number, number];
    readonly wasmstatecore_preferredSessionDirection: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly wasmstatecore_prepareWriteEvidence: (a: any) => [number, number, number];
    readonly wasmstatecore_reconcileReplicaSets: (a: any, b: any) => [number, number, number];
    readonly wasmstatecore_requireChangeAuthorizationCoverage: (a: any, b: any) => [number, number];
    readonly wasmstatecore_selectMeshHandshakeBundle: (a: any, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmstatecore_selectOwnershipTransfer: (a: any) => [number, number, number];
    readonly wasmstatecore_selectScopedNeighbors: (a: number, b: number, c: any, d: any, e: number, f: number) => [number, number, number, number];
    readonly wasmstatecore_shouldAdvertiseOwnerWorkspaceIds: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly wasmstatecore_signDeviceRoute: (a: number, b: number, c: number, d: number, e: any) => [number, number, number];
    readonly wasmstatecore_signDurableAck: (a: number, b: number, c: number, d: number, e: any) => [number, number, number];
    readonly wasmstatecore_summarizeSuccession: (a: any, b: any, c: any, d: any, e: any, f: number) => [number, number, number];
    readonly wasmstatecore_transitionOutboxClaim: (a: any, b: any) => [number, number, number];
    readonly wasmstatecore_validateDeviceRoute: (a: any) => [number, number];
    readonly wasmstatecore_validateDeviceRoutePayload: (a: any) => [number, number];
    readonly wasmstatecore_validateDurableAckPayload: (a: any) => [number, number];
    readonly wasmstatecore_validateMeshCapabilities: (a: any) => [number, number];
    readonly wasmstatecore_validateMeshCatalog: (a: any) => [number, number, number];
    readonly wasmstatecore_validateMeshHandshake: (a: any, b: number, c: number) => [number, number, number];
    readonly wasmstatecore_validateOwnerWorkspaceOffer: (a: any, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasmstatecore_validateScopeAuthority: (a: any) => [number, number, number];
    readonly wasmstatecore_verifyDeviceRoute: (a: any, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmstatecore_verifyDurableAck: (a: any, b: number, c: number) => [number, number, number];
    readonly wasmstatecore_verifyWorkspaceDeparture: (a: any, b: number, c: number, d: any, e: number) => [number, number, number];
    readonly wasmstatecore_verifyWorkspaceDeviceRevocation: (a: any, b: number, c: number, d: number, e: number, f: any, g: number) => [number, number, number];
    readonly wasmstatecore_verifyWorkspaceGrant: (a: any, b: number, c: number, d: number, e: number, f: any) => [number, number, number];
    readonly wasmstatecore_verifyWorkspaceMemberBundle: (a: any, b: any, c: number) => [number, number, number];
    readonly wasmstatecore_verifyWorkspaceOwnershipTransfer: (a: any, b: number, c: number, d: any, e: number, f: number) => [number, number, number];
    readonly wasmstatecore_verifyWorkspaceRevocation: (a: any, b: number, c: number, d: any, e: number) => [number, number, number];
    readonly wasmstatecore_verifyWorkspaceSuccessionClaim: (a: any, b: number, c: number, d: any, e: number, f: any, g: number) => [number, number, number];
    readonly wasmstatecore_verifyWorkspaceSuccessionPolicy: (a: any, b: number, c: number, d: any, e: number) => [number, number, number];
    readonly wasmstatecore_verifyWorkspaceSuccessionVote: (a: any, b: any, c: number, d: number, e: any, f: any, g: number) => [number, number, number];
    readonly wasmmeshauthenticatedsessions_new: () => number;
    readonly __wbg_intounderlyingsource_free: (a: number, b: number) => void;
    readonly intounderlyingsource_cancel: (a: number) => void;
    readonly intounderlyingsource_pull: (a: number, b: any) => any;
    readonly __wbg_intounderlyingbytesource_free: (a: number, b: number) => void;
    readonly __wbg_intounderlyingsink_free: (a: number, b: number) => void;
    readonly intounderlyingbytesource_autoAllocateChunkSize: (a: number) => number;
    readonly intounderlyingbytesource_cancel: (a: number) => void;
    readonly intounderlyingbytesource_pull: (a: number, b: any) => any;
    readonly intounderlyingbytesource_start: (a: number, b: any) => void;
    readonly intounderlyingbytesource_type: (a: number) => number;
    readonly intounderlyingsink_abort: (a: number, b: any) => any;
    readonly intounderlyingsink_close: (a: number) => any;
    readonly intounderlyingsink_write: (a: number, b: any) => any;
    readonly ring_core_0_17_14__bn_mul_mont: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___wasm_bindgen_b3c7b8e9241432f4___JsValue__core_ed718c3d60ebd546___result__Result_____wasm_bindgen_b3c7b8e9241432f4___JsError___true_: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___js_sys_a2fff126d43a4d3e___Function_fn_wasm_bindgen_b3c7b8e9241432f4___JsValue_____wasm_bindgen_b3c7b8e9241432f4___sys__Undefined___js_sys_a2fff126d43a4d3e___Function_fn_wasm_bindgen_b3c7b8e9241432f4___JsValue_____wasm_bindgen_b3c7b8e9241432f4___sys__Undefined_______true_: (a: number, b: number, c: any, d: any) => void;
    readonly wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___wasm_bindgen_b3c7b8e9241432f4___JsValue______true_: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_CloseEvent__CloseEvent______true_: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_RtcDataChannelEvent__RtcDataChannelEvent______true_: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_MessageEvent__MessageEvent______true_: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_RtcDataChannelEvent__RtcDataChannelEvent______true__5: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_RtcDataChannelEvent__RtcDataChannelEvent______true__6: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true_: (a: number, b: number) => void;
    readonly wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true__1_: (a: number, b: number) => void;
    readonly wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true__2_: (a: number, b: number) => void;
    readonly wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true__3_: (a: number, b: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __externref_drop_slice: (a: number, b: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
