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

export class WasmAutomergeSyncEngine {
    free(): void;
    [Symbol.dispose](): void;
    generate(document_id: string, remote_device_id: string, authorized: boolean, proof: any): any;
    heads(document_id: string): string[];
    loadDocument(scope_id: string, document_id: string, bytes: Uint8Array): void;
    constructor(local_device_id: string, maximum_frame_bytes?: number | null);
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

export class WasmMeshHandshakeFlow {
    free(): void;
    [Symbol.dispose](): void;
    advance(completed: string, decision?: boolean | null): string;
    constructor(direction_name: string);
    step(): string;
}

export class WasmMeshRuntimeState {
    free(): void;
    [Symbol.dispose](): void;
    admitSession(candidate: any, preferred_direction: string): any;
    beginRouteAttempt(route_key: string, now_ms: number): any;
    clearGossip(workspace_id: string): void;
    clearReconnect(route_key: string): void;
    clearReconnectsWithPrefix(prefix: string): void;
    clearRouteAttempt(route_key: string): void;
    connectedDevices(workspace_id: string): any;
    controlFrames(workspace_id: string, bytes: Uint8Array): any;
    dueReconnects(now_ms: number): any;
    finishRouteAttempt(route_key: string, token: number): boolean;
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
    setGossipEndpoints(workspace_id: string, endpoints: any): any;
    start(): void;
    stop(): any;
    readonly running: boolean;
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
    static canonicalRevocations(records: any): any;
    static decideWorkspaceAccess(raw: any, now_ms: number): any;
    static durableAckMatches(ack: any, batch: any, target_device_id: string): boolean;
    static eligibleEditorPersonIds(peers: any): any;
    static hasConflictingOwnershipTransfers(records: any): boolean;
    static mergePeerRecords(existing: any, incoming: any): any;
    static meshCapabilities(): any;
    static nextVerifiedOwnershipTransition(records: any, workspace_id: string, current_owner: any, current_epoch: number, revoked_people: any, now_ms: number): any;
    static orderDeliveryRoutes(target_device_id: string, routes: any): any;
    static planChangeAdmission(document_id: string, changes: any, verified_at: string): any;
    static planOwnershipTransitions(records: any, initial_owner_person_id: string, initial_epoch: number): any;
    static reconcileReplicaSets(left: any, right: any): any;
    static selectScopedNeighbors(local_device_id: string, candidates: any, bounds: any, now_ms: number, rotation: number): string[];
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
    readonly __wbg_wasmautomergesyncengine_free: (a: number, b: number) => void;
    readonly __wbg_wasminvitations_free: (a: number, b: number) => void;
    readonly wasmautomergesyncengine_generate: (a: number, b: number, c: number, d: number, e: number, f: number, g: any) => [number, number, number];
    readonly wasmautomergesyncengine_heads: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmautomergesyncengine_loadDocument: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
    readonly wasmautomergesyncengine_new: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmautomergesyncengine_receive: (a: number, b: number, c: number, d: any, e: number, f: any) => [number, number, number];
    readonly wasmautomergesyncengine_reset: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly wasmautomergesyncengine_saveDocument: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasminvitations_createDeviceEnrollment: (a: number, b: number, c: number, d: number, e: any, f: number, g: number, h: number) => [number, number, number];
    readonly wasminvitations_createWorkspaceJoin: (a: number, b: number, c: number, d: number, e: any, f: number, g: number, h: any, i: number, j: number, k: number) => [number, number, number];
    readonly wasminvitations_invitationUrl: (a: number, b: number, c: any) => [number, number, number, number];
    readonly wasminvitations_pairingInviteUrl: (a: number, b: number, c: any) => [number, number, number, number];
    readonly wasminvitations_parseInvitation: (a: number, b: number, c: number) => [number, number, number];
    readonly wasminvitations_parsePairingInvite: (a: number, b: number) => [number, number, number];
    readonly __wbg_browseracceptor_free: (a: number, b: number) => void;
    readonly __wbg_browserconnection_free: (a: number, b: number) => void;
    readonly __wbg_browsernode_free: (a: number, b: number) => void;
    readonly __wbg_browserstream_free: (a: number, b: number) => void;
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
    readonly start_browser_node: (a: number, b: number) => any;
    readonly __wbg_wasmpairingcodec_free: (a: number, b: number) => void;
    readonly __wbg_wasmworkspacejoinhandoff_free: (a: number, b: number) => void;
    readonly __wbg_wasmworkspacejoinhandshake_free: (a: number, b: number) => void;
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
    readonly wasmstatecore_canonicalRevocations: (a: any) => [number, number, number];
    readonly wasmstatecore_decideWorkspaceAccess: (a: any, b: number) => [number, number, number];
    readonly wasmstatecore_durableAckMatches: (a: any, b: any, c: number, d: number) => [number, number, number];
    readonly wasmstatecore_eligibleEditorPersonIds: (a: any) => [number, number, number];
    readonly wasmstatecore_hasConflictingOwnershipTransfers: (a: any) => [number, number, number];
    readonly wasmstatecore_mergePeerRecords: (a: any, b: any) => [number, number, number];
    readonly wasmstatecore_meshCapabilities: () => [number, number, number];
    readonly wasmstatecore_nextVerifiedOwnershipTransition: (a: any, b: number, c: number, d: any, e: number, f: any, g: number) => [number, number, number];
    readonly wasmstatecore_orderDeliveryRoutes: (a: number, b: number, c: any) => [number, number, number];
    readonly wasmstatecore_planChangeAdmission: (a: number, b: number, c: any, d: number, e: number) => [number, number, number];
    readonly wasmstatecore_planOwnershipTransitions: (a: any, b: number, c: number, d: number) => [number, number, number];
    readonly wasmstatecore_reconcileReplicaSets: (a: any, b: any) => [number, number, number];
    readonly wasmstatecore_selectScopedNeighbors: (a: number, b: number, c: any, d: any, e: number, f: number) => [number, number, number, number];
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
    readonly browserTransportDebugLoggingEnabled: () => number;
    readonly mesh_version: () => [number, number];
    readonly setBrowserTransportDebugLogging: (a: number) => void;
    readonly __wbg_wasmblobengine_free: (a: number, b: number) => void;
    readonly __wbg_wasmgossipengine_free: (a: number, b: number) => void;
    readonly __wbg_wasmmeshhandshakeflow_free: (a: number, b: number) => void;
    readonly __wbg_wasmmeshruntimestate_free: (a: number, b: number) => void;
    readonly wasmblobengine_createBlob: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number];
    readonly wasmblobengine_getBlob: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmblobengine_hasBlob: (a: number, b: number, c: number) => number;
    readonly wasmblobengine_new: () => number;
    readonly wasmblobengine_parseTicket: (a: number, b: number) => [number, number, number];
    readonly wasmblobengine_putBlob: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly wasmblobengine_verifyBlob: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmgossipengine_activeNeighbors: (a: number, b: number, c: number) => [number, number];
    readonly wasmgossipengine_broadcast: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmgossipengine_expireTimer: (a: number, b: bigint) => [number, number, number];
    readonly wasmgossipengine_handleMessage: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmgossipengine_joinTopic: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmgossipengine_leaveTopic: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmgossipengine_new: (a: number, b: number) => number;
    readonly wasmgossipengine_peerDisconnected: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmmeshhandshakeflow_advance: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasmmeshhandshakeflow_new: (a: number, b: number) => [number, number, number];
    readonly wasmmeshhandshakeflow_step: (a: number) => [number, number];
    readonly wasmmeshruntimestate_admitSession: (a: number, b: any, c: number, d: number) => [number, number, number];
    readonly wasmmeshruntimestate_beginRouteAttempt: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmmeshruntimestate_clearGossip: (a: number, b: number, c: number) => void;
    readonly wasmmeshruntimestate_clearReconnect: (a: number, b: number, c: number) => void;
    readonly wasmmeshruntimestate_clearReconnectsWithPrefix: (a: number, b: number, c: number) => void;
    readonly wasmmeshruntimestate_clearRouteAttempt: (a: number, b: number, c: number) => void;
    readonly wasmmeshruntimestate_connectedDevices: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmmeshruntimestate_controlFrames: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly wasmmeshruntimestate_dueReconnects: (a: number, b: number) => [number, number, number];
    readonly wasmmeshruntimestate_finishRouteAttempt: (a: number, b: number, c: number, d: number) => [number, number, number];
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
    readonly wasmmeshruntimestate_setGossipEndpoints: (a: number, b: number, c: number, d: any) => [number, number, number];
    readonly wasmmeshruntimestate_start: (a: number) => void;
    readonly wasmmeshruntimestate_stop: (a: number) => [number, number, number];
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
