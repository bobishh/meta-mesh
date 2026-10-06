/* @ts-self-types="./meta_mesh_policy.d.ts" */

export class WasmAutomergeDeviceSyncFlow {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmAutomergeDeviceSyncFlowFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmautomergedevicesyncflow_free(ptr, 0);
    }
    /**
     * @param {string} route_instance_id
     * @param {any} response
     * @returns {any}
     */
    completeRound(route_instance_id, response) {
        const ptr0 = passStringToWasm0(route_instance_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmautomergedevicesyncflow_completeRound(this.__wbg_ptr, ptr0, len0, response);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} request
     * @param {string} expected_remote_device_id
     * @returns {any}
     */
    static decodeIncomingRequest(request, expected_remote_device_id) {
        const ptr0 = passStringToWasm0(expected_remote_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmautomergedevicesyncflow_decodeIncomingRequest(request, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} batch_id
     * @param {any} ack
     * @param {any} frame
     * @returns {any}
     */
    static encodeResponse(batch_id, ack, frame) {
        const ptr0 = passStringToWasm0(batch_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmautomergedevicesyncflow_encodeResponse(ptr0, len0, ack, frame);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} target_device_id
     * @param {string} document_id
     * @param {number} maximum_rounds
     */
    constructor(target_device_id, document_id, maximum_rounds) {
        const ptr0 = passStringToWasm0(target_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(document_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmautomergedevicesyncflow_new(ptr0, len0, ptr1, len1, maximum_rounds);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmAutomergeDeviceSyncFlowFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {any} frame
     * @returns {any}
     */
    nextRound(frame) {
        const ret = wasm.wasmautomergedevicesyncflow_nextRound(this.__wbg_ptr, frame);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} response
     */
    validateResponse(response) {
        const ret = wasm.wasmautomergedevicesyncflow_validateResponse(this.__wbg_ptr, response);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
}
if (Symbol.dispose) WasmAutomergeDeviceSyncFlow.prototype[Symbol.dispose] = WasmAutomergeDeviceSyncFlow.prototype.free;

export class WasmAutomergeSyncEngine {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmAutomergeSyncEngineFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmautomergesyncengine_free(ptr, 0);
    }
    /**
     * @param {string} document_id
     * @param {string} remote_device_id
     */
    abortPreparedReceive(document_id, remote_device_id) {
        const ptr0 = passStringToWasm0(document_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(remote_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        wasm.wasmautomergesyncengine_abortPreparedReceive(this.__wbg_ptr, ptr0, len0, ptr1, len1);
    }
    /**
     * @param {string} document_id
     * @param {string} remote_device_id
     */
    commitPreparedReceive(document_id, remote_device_id) {
        const ptr0 = passStringToWasm0(document_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(remote_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmautomergesyncengine_commitPreparedReceive(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {string} document_id
     * @param {string} remote_device_id
     * @param {boolean} authorized
     * @param {any} proof
     * @returns {any}
     */
    generate(document_id, remote_device_id, authorized, proof) {
        const ptr0 = passStringToWasm0(document_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(remote_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmautomergesyncengine_generate(this.__wbg_ptr, ptr0, len0, ptr1, len1, authorized, proof);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} document_id
     * @returns {string[]}
     */
    heads(document_id) {
        const ptr0 = passStringToWasm0(document_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmautomergesyncengine_heads(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v2;
    }
    /**
     * @param {string} scope_id
     * @param {string} document_id
     * @param {Uint8Array} bytes
     */
    loadDocument(scope_id, document_id, bytes) {
        const ptr0 = passStringToWasm0(scope_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(document_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmautomergesyncengine_loadDocument(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {string} local_device_id
     * @param {number | null} [maximum_frame_bytes]
     */
    constructor(local_device_id, maximum_frame_bytes) {
        const ptr0 = passStringToWasm0(local_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmautomergesyncengine_new(ptr0, len0, isLikeNone(maximum_frame_bytes) ? 0x100000001 : (maximum_frame_bytes) >>> 0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmAutomergeSyncEngineFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} remote_device_id
     * @param {any} frame
     * @param {boolean} authorized
     * @param {any} response_proof
     * @returns {any}
     */
    prepareReceive(remote_device_id, frame, authorized, response_proof) {
        const ptr0 = passStringToWasm0(remote_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmautomergesyncengine_prepareReceive(this.__wbg_ptr, ptr0, len0, frame, authorized, response_proof);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} remote_device_id
     * @param {any} frame
     * @param {boolean} authorized
     * @param {any} response_proof
     * @returns {any}
     */
    receive(remote_device_id, frame, authorized, response_proof) {
        const ptr0 = passStringToWasm0(remote_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmautomergesyncengine_receive(this.__wbg_ptr, ptr0, len0, frame, authorized, response_proof);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} document_id
     * @param {string} remote_device_id
     */
    reset(document_id, remote_device_id) {
        const ptr0 = passStringToWasm0(document_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(remote_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        wasm.wasmautomergesyncengine_reset(this.__wbg_ptr, ptr0, len0, ptr1, len1);
    }
    /**
     * @param {string} document_id
     * @returns {Uint8Array}
     */
    saveDocument(document_id) {
        const ptr0 = passStringToWasm0(document_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmautomergesyncengine_saveDocument(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
}
if (Symbol.dispose) WasmAutomergeSyncEngine.prototype[Symbol.dispose] = WasmAutomergeSyncEngine.prototype.free;

export class WasmDeviceRouteCatalog {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmDeviceRouteCatalogFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmdeviceroutecatalog_free(ptr, 0);
    }
    /**
     * @param {any} route
     * @returns {any}
     */
    admit(route) {
        const ret = wasm.wasmdeviceroutecatalog_admit(this.__wbg_ptr, route);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    constructor() {
        const ret = wasm.wasmdeviceroutecatalog_new();
        this.__wbg_ptr = ret >>> 0;
        WasmDeviceRouteCatalogFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} scope_id
     * @param {string} device_id
     * @returns {any}
     */
    routesFor(scope_id, device_id) {
        const ptr0 = passStringToWasm0(scope_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmdeviceroutecatalog_routesFor(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
}
if (Symbol.dispose) WasmDeviceRouteCatalog.prototype[Symbol.dispose] = WasmDeviceRouteCatalog.prototype.free;

export class WasmGossipLifecycleState {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmGossipLifecycleStateFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmgossiplifecyclestate_free(ptr, 0);
    }
    /**
     * @param {string} workspace_id
     * @param {boolean} driver_available
     * @returns {any}
     */
    broadcastPlan(workspace_id, driver_available) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossiplifecyclestate_broadcastPlan(this.__wbg_ptr, ptr0, len0, driver_available);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} workspace_id
     */
    close(workspace_id) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossiplifecyclestate_close(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    closeAll() {
        wasm.wasmgossiplifecyclestate_closeAll(this.__wbg_ptr);
    }
    /**
     * @param {string} workspace_id
     * @param {string} topic
     * @param {boolean} session_available
     * @param {boolean} packet_valid
     * @returns {any}
     */
    deliveryAction(workspace_id, topic, session_available, packet_valid) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(topic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossiplifecyclestate_deliveryAction(this.__wbg_ptr, ptr0, len0, ptr1, len1, session_available, packet_valid);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string | null} [topic_prefix]
     */
    constructor(topic_prefix) {
        var ptr0 = isLikeNone(topic_prefix) ? 0 : passStringToWasm0(topic_prefix, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossiplifecyclestate_new(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmGossipLifecycleStateFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} workspace_id
     * @param {number} count
     * @returns {any}
     */
    observeNeighbors(workspace_id, count) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossiplifecyclestate_observeNeighbors(this.__wbg_ptr, ptr0, len0, count);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    planRebuild(raw) {
        const ret = wasm.wasmgossiplifecyclestate_planRebuild(this.__wbg_ptr, raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} workspace_id
     * @param {boolean} driver_available
     * @param {boolean} session_available
     * @returns {any}
     */
    receiveAction(workspace_id, driver_available, session_available) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossiplifecyclestate_receiveAction(this.__wbg_ptr, ptr0, len0, driver_available, session_available);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} workspace_id
     */
    startFailed(workspace_id) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossiplifecyclestate_startFailed(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {string} workspace_id
     */
    started(workspace_id) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossiplifecyclestate_started(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {string} workspace_id
     * @returns {string}
     */
    topic(workspace_id) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmgossiplifecyclestate_topic(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
}
if (Symbol.dispose) WasmGossipLifecycleState.prototype[Symbol.dispose] = WasmGossipLifecycleState.prototype.free;

export class WasmIdentityCrypto {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmIdentityCryptoFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmidentitycrypto_free(ptr, 0);
    }
    /**
     * @param {any} value
     * @returns {string}
     */
    static canonicalizeJson(value) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.wasmidentitycrypto_canonicalizeJson(value);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @param {any} certificate
     * @returns {string}
     */
    static certificateHash(certificate) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.wasmidentitycrypto_certificateHash(certificate);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @param {Uint8Array} device_entropy
     * @returns {Uint8Array}
     */
    static deriveDeviceSeed(device_entropy) {
        const ptr0 = passArray8ToWasm0(device_entropy, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmidentitycrypto_deriveDeviceSeed(ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {string} value
     * @returns {string | undefined}
     */
    static identitySecurityForRecovery(value) {
        const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmidentitycrypto_identitySecurityForRecovery(ptr0, len0);
        let v2;
        if (ret[0] !== 0) {
            v2 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v2;
    }
    /**
     * @param {Uint16Array} samples
     * @returns {string}
     */
    static legacyRecoveryFromSamples(samples) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passArray16ToWasm0(samples, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmidentitycrypto_legacyRecoveryFromSamples(ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * @param {any} envelope
     * @param {string} recovery_key
     * @returns {Uint8Array}
     */
    static openIdentitySeed(envelope, recovery_key) {
        const ptr0 = passStringToWasm0(recovery_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmidentitycrypto_openIdentitySeed(envelope, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {any} envelope
     * @param {string} passphrase
     * @returns {Uint8Array}
     */
    static openIdentitySeedWithPassphrase(envelope, passphrase) {
        const ptr0 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmidentitycrypto_openIdentitySeedWithPassphrase(envelope, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {Uint8Array} seed
     * @returns {string}
     */
    static publicKeyFromSeed(seed) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmidentitycrypto_publicKeyFromSeed(ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * @param {string} public_key
     * @returns {string}
     */
    static publicKeyId(public_key) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmidentitycrypto_publicKeyId(ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * @param {Uint8Array} entropy
     * @returns {string}
     */
    static recoveryPhraseFromEntropy(entropy) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passArray8ToWasm0(entropy, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmidentitycrypto_recoveryPhraseFromEntropy(ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * @param {string} value
     * @returns {Uint8Array}
     */
    static recoveryPhraseToEntropy(value) {
        const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmidentitycrypto_recoveryPhraseToEntropy(ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {Uint8Array} seed
     * @param {string} person_id
     * @param {string} recovery_key
     * @param {string} security
     * @param {Uint8Array} salt
     * @param {Uint8Array} iv
     * @returns {any}
     */
    static sealIdentitySeed(seed, person_id, recovery_key, security, salt, iv) {
        const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(recovery_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(security, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(salt, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passArray8ToWasm0(iv, wasm.__wbindgen_malloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.wasmidentitycrypto_sealIdentitySeed(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} seed
     * @param {string} person_id
     * @param {string} passphrase
     * @param {Uint8Array} salt
     * @param {Uint8Array} iv
     * @returns {any}
     */
    static sealIdentitySeedWithPassphrase(seed, person_id, passphrase, salt, iv) {
        const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(salt, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(iv, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.wasmidentitycrypto_sealIdentitySeedWithPassphrase(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} seed
     * @param {any} payload
     * @param {string} signer_key_id
     * @param {string | null} [domain]
     * @returns {any}
     */
    static signEnvelope(seed, payload, signer_key_id, domain) {
        const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(signer_key_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(domain) ? 0 : passStringToWasm0(domain, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmidentitycrypto_signEnvelope(ptr0, len0, payload, ptr1, len1, ptr2, len2);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} identity
     * @param {string} device_id
     * @param {any} certificates
     * @param {string | null} [domain]
     * @returns {string}
     */
    static verifyDeviceCertificateChain(identity, device_id, certificates, domain) {
        let deferred4_0;
        let deferred4_1;
        try {
            const ptr0 = passStringToWasm0(device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            var ptr1 = isLikeNone(domain) ? 0 : passStringToWasm0(domain, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            const ret = wasm.wasmidentitycrypto_verifyDeviceCertificateChain(identity, ptr0, len0, certificates, ptr1, len1);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * @param {any} envelope
     * @param {string} public_key
     * @param {string | null} [domain]
     * @returns {boolean}
     */
    static verifyEnvelope(envelope, public_key, domain) {
        const ptr0 = passStringToWasm0(public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(domain) ? 0 : passStringToWasm0(domain, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmidentitycrypto_verifyEnvelope(envelope, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {any} grant
     * @param {string} workspace_id
     * @param {string} member_person_id
     * @param {any} owner
     * @param {any} owner_certificates
     * @returns {string}
     */
    static verifyWorkspaceGrant(grant, workspace_id, member_person_id, owner, owner_certificates) {
        let deferred4_0;
        let deferred4_1;
        try {
            const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(member_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.wasmidentitycrypto_verifyWorkspaceGrant(grant, ptr0, len0, ptr1, len1, owner, owner_certificates);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
}
if (Symbol.dispose) WasmIdentityCrypto.prototype[Symbol.dispose] = WasmIdentityCrypto.prototype.free;

export class WasmInvitations {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmInvitationsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasminvitations_free(ptr, 0);
    }
    /**
     * @param {string} endpoint
     * @param {string} secret
     * @param {any} issuer
     * @param {string} invitation_id
     * @param {number} now_ms
     * @returns {any}
     */
    static createDeviceEnrollment(endpoint, secret, issuer, invitation_id, now_ms) {
        const ptr0 = passStringToWasm0(endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(invitation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasminvitations_createDeviceEnrollment(ptr0, len0, ptr1, len1, issuer, ptr2, len2, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} endpoint
     * @param {string} secret
     * @param {any} issuer
     * @param {string} invitation_id
     * @param {any} workspaces
     * @param {string} role
     * @param {number} now_ms
     * @returns {any}
     */
    static createWorkspaceJoin(endpoint, secret, issuer, invitation_id, workspaces, role, now_ms) {
        const ptr0 = passStringToWasm0(endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(invitation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(role, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasminvitations_createWorkspaceJoin(ptr0, len0, ptr1, len1, issuer, ptr2, len2, workspaces, ptr3, len3, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} origin
     * @param {any} invitation
     * @returns {string}
     */
    static invitationUrl(origin, invitation) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(origin, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasminvitations_invitationUrl(ptr0, len0, invitation);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * @param {string} origin
     * @param {any} invite
     * @returns {string}
     */
    static pairingInviteUrl(origin, invite) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(origin, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasminvitations_pairingInviteUrl(ptr0, len0, invite);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * @param {string} raw
     * @param {number} now_ms
     * @returns {any}
     */
    static parseInvitation(raw, now_ms) {
        const ptr0 = passStringToWasm0(raw, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasminvitations_parseInvitation(ptr0, len0, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} raw
     * @returns {any}
     */
    static parsePairingInvite(raw) {
        const ptr0 = passStringToWasm0(raw, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasminvitations_parsePairingInvite(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
}
if (Symbol.dispose) WasmInvitations.prototype[Symbol.dispose] = WasmInvitations.prototype.free;

export class WasmLiveWorkspaceSession {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmLiveWorkspaceSessionFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmliveworkspacesession_free(ptr, 0);
    }
    abortDocument() {
        wasm.wasmliveworkspacesession_abortDocument(this.__wbg_ptr);
    }
    /**
     * @param {Uint8Array} bytes
     * @returns {Uint8Array}
     */
    acknowledgeSaved(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_acknowledgeSaved(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    commitDocument() {
        const ret = wasm.wasmliveworkspacesession_commitDocument(this.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Uint8Array} snapshot
     * @returns {boolean}
     */
    controlChanged(snapshot) {
        const ptr0 = passArray8ToWasm0(snapshot, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_controlChanged(this.__wbg_ptr, ptr0, len0);
        return ret !== 0;
    }
    /**
     * @param {Uint8Array} snapshot
     * @returns {any}
     */
    controlFrames(snapshot) {
        const ptr0 = passArray8ToWasm0(snapshot, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_controlFrames(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} payload
     * @returns {any}
     */
    decodeAutomergePayload(payload) {
        const ptr0 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_decodeAutomergePayload(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} bytes
     * @returns {any}
     */
    decodeControl(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_decodeControl(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} frame_type
     * @param {Uint8Array} payload
     * @returns {Uint8Array}
     */
    encode(frame_type, payload) {
        const ptr0 = passStringToWasm0(frame_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_encode(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * @param {any} frame
     * @returns {Uint8Array}
     */
    encodeAutomergeFrame(frame) {
        const ret = wasm.wasmliveworkspacesession_encodeAutomergeFrame(this.__wbg_ptr, frame);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {any} authorization
     * @param {any} chat
     * @param {any} mesh
     * @returns {Uint8Array}
     */
    encodeControl(authorization, chat, mesh) {
        const ret = wasm.wasmliveworkspacesession_encodeControl(this.__wbg_ptr, authorization, chat, mesh);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} control_snapshot
     * @param {boolean} all_frames_sent
     */
    finishPublish(control_snapshot, all_frames_sent) {
        const ptr0 = passArray8ToWasm0(control_snapshot, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.wasmliveworkspacesession_finishPublish(this.__wbg_ptr, ptr0, len0, all_frames_sent);
    }
    /**
     * @param {Uint8Array} document
     * @param {any} proof
     * @returns {Uint8Array | undefined}
     */
    generateDocument(document, proof) {
        const ptr0 = passArray8ToWasm0(document, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_generateDocument(this.__wbg_ptr, ptr0, len0, proof);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v2;
        if (ret[0] !== 0) {
            v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v2;
    }
    /**
     * @param {Uint8Array} snapshot
     */
    markControlSent(snapshot) {
        const ptr0 = passArray8ToWasm0(snapshot, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.wasmliveworkspacesession_markControlSent(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} workspace_id
     * @param {string} secret
     */
    constructor(workspace_id, secret) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_new(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmLiveWorkspaceSessionFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {any} authorization
     * @param {any} chat
     * @param {any} mesh
     * @returns {any}
     */
    prepareControlPublish(authorization, chat, mesh) {
        const ret = wasm.wasmliveworkspacesession_prepareControlPublish(this.__wbg_ptr, authorization, chat, mesh);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} payload
     * @param {Uint8Array} document
     * @param {any} response_proof
     * @returns {any}
     */
    prepareDocument(payload, document, response_proof) {
        const ptr0 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(document, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_prepareDocument(this.__wbg_ptr, ptr0, len0, ptr1, len1, response_proof);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} document
     * @param {any} proof
     * @param {any} authorization
     * @param {any} chat
     * @param {any} mesh
     * @returns {any}
     */
    preparePublish(document, proof, authorization, chat, mesh) {
        const ptr0 = passArray8ToWasm0(document, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_preparePublish(this.__wbg_ptr, ptr0, len0, proof, authorization, chat, mesh);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} snapshot
     * @returns {any}
     */
    prepareSnapshotPublish(snapshot) {
        const ptr0 = passArray8ToWasm0(snapshot, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_prepareSnapshotPublish(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} frame
     * @returns {any}
     */
    receive(frame) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_receive(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} frame
     * @returns {any}
     */
    receiveWithPlan(frame) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_receiveWithPlan(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    resetDocument() {
        wasm.wasmliveworkspacesession_resetDocument(this.__wbg_ptr);
    }
    /**
     * @param {string} local_device_id
     * @param {string} remote_device_id
     */
    startDocumentSync(local_device_id, remote_device_id) {
        const ptr0 = passStringToWasm0(local_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(remote_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_startDocumentSync(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Uint8Array} frame
     */
    verifyHeartbeatAck(frame) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_verifyHeartbeatAck(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Uint8Array} frame
     * @param {Uint8Array} bytes
     */
    verifySavedReceipt(frame, bytes) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmliveworkspacesession_verifySavedReceipt(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
}
if (Symbol.dispose) WasmLiveWorkspaceSession.prototype[Symbol.dispose] = WasmLiveWorkspaceSession.prototype.free;

export class WasmMeshAuthenticatedSessions {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmMeshAuthenticatedSessionsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmmeshauthenticatedsessions_free(ptr, 0);
    }
    /**
     * @param {any} handshake
     * @param {any} snapshot
     * @param {string} remote_endpoint
     * @param {number} now_ms
     * @returns {any}
     */
    admit(handshake, snapshot, remote_endpoint, now_ms) {
        const ptr0 = passStringToWasm0(remote_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshauthenticatedsessions_admit(this.__wbg_ptr, handshake, snapshot, ptr0, len0, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    clear() {
        wasm.wasmmeshauthenticatedsessions_clear(this.__wbg_ptr);
    }
    constructor() {
        const ret = wasm.wasmmeshauthenticatedsessions_new();
        this.__wbg_ptr = ret >>> 0;
        WasmMeshAuthenticatedSessionsFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} workspace_id
     * @param {string} remote_endpoint
     * @returns {any}
     */
    peer(workspace_id, remote_endpoint) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(remote_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshauthenticatedsessions_peer(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} snapshot
     * @param {number} now_ms
     * @returns {any}
     */
    refresh(snapshot, now_ms) {
        const ret = wasm.wasmmeshauthenticatedsessions_refresh(this.__wbg_ptr, snapshot, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} workspace_id
     * @param {string} remote_endpoint
     * @returns {boolean}
     */
    remove(workspace_id, remote_endpoint) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(remote_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshauthenticatedsessions_remove(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret !== 0;
    }
}
if (Symbol.dispose) WasmMeshAuthenticatedSessions.prototype[Symbol.dispose] = WasmMeshAuthenticatedSessions.prototype.free;

export class WasmMeshBatchDeliveryFlow {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmMeshBatchDeliveryFlowFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmmeshbatchdeliveryflow_free(ptr, 0);
    }
    /**
     * @returns {any}
     */
    abort() {
        const ret = wasm.wasmmeshbatchdeliveryflow_abort(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {number} round
     * @returns {any}
     */
    fallbackElapsed(round) {
        const ret = wasm.wasmmeshbatchdeliveryflow_fallbackElapsed(this.__wbg_ptr, round);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} target_device_id
     * @param {any} route_ids
     * @param {number} fallback_delay_ms
     * @param {any} retry_delays_ms
     */
    constructor(target_device_id, route_ids, fallback_delay_ms, retry_delays_ms) {
        const ptr0 = passStringToWasm0(target_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshbatchdeliveryflow_new(ptr0, len0, route_ids, fallback_delay_ms, retry_delays_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmMeshBatchDeliveryFlowFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {number} round
     * @returns {any}
     */
    retryElapsed(round) {
        const ret = wasm.wasmmeshbatchdeliveryflow_retryElapsed(this.__wbg_ptr, round);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {number} round
     * @param {number} route_index
     * @param {boolean} accepted
     * @param {string} failure
     * @returns {any}
     */
    routeResult(round, route_index, accepted, failure) {
        const ptr0 = passStringToWasm0(failure, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshbatchdeliveryflow_routeResult(this.__wbg_ptr, round, route_index, accepted, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @returns {any}
     */
    start() {
        const ret = wasm.wasmmeshbatchdeliveryflow_start(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
}
if (Symbol.dispose) WasmMeshBatchDeliveryFlow.prototype[Symbol.dispose] = WasmMeshBatchDeliveryFlow.prototype.free;

export class WasmMeshHandshakeFlow {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmMeshHandshakeFlowFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmmeshhandshakeflow_free(ptr, 0);
    }
    /**
     * @param {string} completed
     * @param {boolean | null} [decision]
     * @returns {string}
     */
    advance(completed, decision) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(completed, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmmeshhandshakeflow_advance(this.__wbg_ptr, ptr0, len0, isLikeNone(decision) ? 0xFFFFFF : decision ? 1 : 0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * @param {any} credential
     * @param {string} person_id
     * @param {any} grant
     * @param {string} device_id
     * @returns {boolean}
     */
    isPeerRevoked(credential, person_id, grant, device_id) {
        const ptr0 = passStringToWasm0(person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshhandshakeflow_isPeerRevoked(this.__wbg_ptr, credential, ptr0, len0, grant, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {string} verified_device_id
     * @param {string} verified_person_id
     * @param {string} verified_endpoint
     * @param {string} admitted_device_id
     * @param {string} admitted_person_id
     * @param {string} admitted_endpoint
     * @returns {boolean}
     */
    matchesAdmittedPeer(verified_device_id, verified_person_id, verified_endpoint, admitted_device_id, admitted_person_id, admitted_endpoint) {
        const ptr0 = passStringToWasm0(verified_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(verified_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(verified_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(admitted_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(admitted_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(admitted_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshhandshakeflow_matchesAdmittedPeer(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        return ret !== 0;
    }
    /**
     * @param {string} expected_device_id
     * @param {string} verified_device_id
     * @returns {boolean}
     */
    matchesExpectedPeer(expected_device_id, verified_device_id) {
        const ptr0 = passStringToWasm0(expected_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(verified_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshhandshakeflow_matchesExpectedPeer(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret !== 0;
    }
    /**
     * @param {string} direction_name
     */
    constructor(direction_name) {
        const ptr0 = passStringToWasm0(direction_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshhandshakeflow_new(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmMeshHandshakeFlowFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @returns {string}
     */
    step() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.wasmmeshhandshakeflow_step(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) WasmMeshHandshakeFlow.prototype[Symbol.dispose] = WasmMeshHandshakeFlow.prototype.free;

export class WasmMeshLifecycleState {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmMeshLifecycleStateFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmmeshlifecyclestate_free(ptr, 0);
    }
    /**
     * @returns {boolean}
     */
    beginStart() {
        const ret = wasm.wasmmeshlifecyclestate_beginStart(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {boolean}
     */
    canContinueStart() {
        const ret = wasm.wasmmeshlifecyclestate_canContinueStart(this.__wbg_ptr);
        return ret !== 0;
    }
    cancelStart() {
        wasm.wasmmeshlifecyclestate_cancelStart(this.__wbg_ptr);
    }
    /**
     * @returns {boolean}
     */
    completeStart() {
        const ret = wasm.wasmmeshlifecyclestate_completeStart(this.__wbg_ptr);
        return ret !== 0;
    }
    dispose() {
        wasm.wasmmeshlifecyclestate_dispose(this.__wbg_ptr);
    }
    /**
     * @returns {boolean}
     */
    get disposed() {
        const ret = wasm.wasmmeshlifecyclestate_disposed(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {boolean}
     */
    get externallyPaused() {
        const ret = wasm.wasmmeshlifecyclestate_externallyPaused(this.__wbg_ptr);
        return ret !== 0;
    }
    finishStop() {
        wasm.wasmmeshlifecyclestate_finishStop(this.__wbg_ptr);
    }
    constructor() {
        const ret = wasm.wasmmeshlifecyclestate_new();
        this.__wbg_ptr = ret >>> 0;
        WasmMeshLifecycleStateFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    pause() {
        wasm.wasmmeshlifecyclestate_pause(this.__wbg_ptr);
    }
    /**
     * @returns {boolean}
     */
    resume() {
        const ret = wasm.wasmmeshlifecyclestate_resume(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {boolean}
     */
    stop() {
        const ret = wasm.wasmmeshlifecyclestate_stop(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {boolean}
     */
    get stopped() {
        const ret = wasm.wasmmeshlifecyclestate_stopped(this.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) WasmMeshLifecycleState.prototype[Symbol.dispose] = WasmMeshLifecycleState.prototype.free;

export class WasmMeshRuntimeState {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmMeshRuntimeStateFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmmeshruntimestate_free(ptr, 0);
    }
    /**
     * @param {any} candidate
     * @param {string} preferred_direction
     * @returns {any}
     */
    admitSession(candidate, preferred_direction) {
        const ptr0 = passStringToWasm0(preferred_direction, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_admitSession(this.__wbg_ptr, candidate, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} route_key
     * @param {number} now_ms
     * @returns {any}
     */
    beginRouteAttempt(route_key, now_ms) {
        const ptr0 = passStringToWasm0(route_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_beginRouteAttempt(this.__wbg_ptr, ptr0, len0, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} route_key
     */
    clearReconnect(route_key) {
        const ptr0 = passStringToWasm0(route_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.wasmmeshruntimestate_clearReconnect(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} prefix
     */
    clearReconnectsWithPrefix(prefix) {
        const ptr0 = passStringToWasm0(prefix, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.wasmmeshruntimestate_clearReconnectsWithPrefix(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} route_key
     */
    clearRouteAttempt(route_key) {
        const ptr0 = passStringToWasm0(route_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.wasmmeshruntimestate_clearRouteAttempt(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} workspace_id
     * @returns {any}
     */
    connectedDevices(workspace_id) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_connectedDevices(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} workspace_id
     * @param {Uint8Array} bytes
     * @returns {any}
     */
    controlFrames(workspace_id, bytes) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_controlFrames(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {number} now_ms
     * @returns {any}
     */
    dueReconnects(now_ms) {
        const ret = wasm.wasmmeshruntimestate_dueReconnects(this.__wbg_ptr, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} workspace_id
     * @param {string} nonce
     * @returns {Uint8Array}
     */
    encodeWorkspaceUpdate(workspace_id, nonce) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_encodeWorkspaceUpdate(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * @param {string} route_key
     * @param {number} token
     * @returns {boolean}
     */
    finishRouteAttempt(route_key, token) {
        const ptr0 = passStringToWasm0(route_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_finishRouteAttempt(this.__wbg_ptr, ptr0, len0, token);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {Uint8Array} payload
     * @param {string} workspace_id
     * @returns {boolean}
     */
    isWorkspaceUpdate(payload, workspace_id) {
        const ptr0 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_isWorkspaceUpdate(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret !== 0;
    }
    constructor() {
        const ret = wasm.wasmmeshruntimestate_new();
        this.__wbg_ptr = ret >>> 0;
        WasmMeshRuntimeStateFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} peer_key
     * @param {boolean} relay_available
     * @param {number} now_ms
     * @returns {any}
     */
    planDial(peer_key, relay_available, now_ms) {
        const ptr0 = passStringToWasm0(peer_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_planDial(this.__wbg_ptr, ptr0, len0, relay_available, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} workspace_id
     * @param {Uint8Array} frame
     * @returns {Uint8Array | undefined}
     */
    receiveControlFrame(workspace_id, frame) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_receiveControlFrame(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v3;
        if (ret[0] !== 0) {
            v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v3;
    }
    /**
     * @param {string} route_key
     * @returns {any}
     */
    reconnectState(route_key) {
        const ptr0 = passStringToWasm0(route_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_reconnectState(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} peer_key
     * @param {string} mode
     * @param {number} now_ms
     */
    recordDialSuccess(peer_key, mode, now_ms) {
        const ptr0 = passStringToWasm0(peer_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_recordDialSuccess(this.__wbg_ptr, ptr0, len0, ptr1, len1, now_ms);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {string} peer_key
     * @param {number} now_ms
     */
    recordNetworkFailure(peer_key, now_ms) {
        const ptr0 = passStringToWasm0(peer_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_recordNetworkFailure(this.__wbg_ptr, ptr0, len0, now_ms);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {any} key
     * @param {number} generation
     * @returns {any}
     */
    removeSession(key, generation) {
        const ret = wasm.wasmmeshruntimestate_removeSession(this.__wbg_ptr, key, generation);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} route_key
     * @returns {boolean}
     */
    routeAttemptActive(route_key) {
        const ptr0 = passStringToWasm0(route_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_routeAttemptActive(this.__wbg_ptr, ptr0, len0);
        return ret !== 0;
    }
    /**
     * @returns {boolean}
     */
    get running() {
        const ret = wasm.wasmmeshruntimestate_running(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @param {string} route_key
     * @param {number} now_ms
     * @param {number} base_delay_ms
     * @param {number} maximum_delay_ms
     * @returns {any}
     */
    scheduleReconnect(route_key, now_ms, base_delay_ms, maximum_delay_ms) {
        const ptr0 = passStringToWasm0(route_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_scheduleReconnect(this.__wbg_ptr, ptr0, len0, now_ms, base_delay_ms, maximum_delay_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @returns {any}
     */
    sessions() {
        const ret = wasm.wasmmeshruntimestate_sessions(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    start() {
        wasm.wasmmeshruntimestate_start(this.__wbg_ptr);
    }
    /**
     * @returns {any}
     */
    stop() {
        const ret = wasm.wasmmeshruntimestate_stop(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
}
if (Symbol.dispose) WasmMeshRuntimeState.prototype[Symbol.dispose] = WasmMeshRuntimeState.prototype.free;

/**
 * WASM host boundary for one authenticated workspace scope stream.
 */
export class WasmMeshScopeRuntime {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmMeshScopeRuntimeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmmeshscoperuntime_free(ptr, 0);
    }
    /**
     * @param {Uint8Array} payload
     * @returns {any}
     */
    acceptProofPage(payload) {
        const ptr0 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshscoperuntime_acceptProofPage(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} candidate
     * @param {Uint8Array} local
     * @param {any} manifest
     * @returns {any}
     */
    beginAuthorizationTransfer(candidate, local, manifest) {
        const ptr0 = passArray8ToWasm0(candidate, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(local, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshscoperuntime_beginAuthorizationTransfer(this.__wbg_ptr, ptr0, len0, ptr1, len1, manifest);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {boolean} persisted
     * @returns {any}
     */
    completeDocumentReceive(persisted) {
        const ret = wasm.wasmmeshscoperuntime_completeDocumentReceive(this.__wbg_ptr, persisted);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {boolean} persisted
     * @returns {any}
     */
    completeSavedReceive(persisted) {
        const ret = wasm.wasmmeshscoperuntime_completeSavedReceive(this.__wbg_ptr, persisted);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @returns {any}
     */
    continueProofReceive() {
        const ret = wasm.wasmmeshscoperuntime_continueProofReceive(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} control_snapshot
     * @param {boolean} all_frames_sent
     */
    finishPublish(control_snapshot, all_frames_sent) {
        const ptr0 = passArray8ToWasm0(control_snapshot, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.wasmmeshscoperuntime_finishPublish(this.__wbg_ptr, ptr0, len0, all_frames_sent);
    }
    /**
     * @param {string} workspace_id
     * @param {string} secret
     */
    constructor(workspace_id, secret) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshscoperuntime_new(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmMeshScopeRuntimeFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {Uint8Array} document
     * @param {any} proof
     * @param {any} authorization
     * @param {any} chat
     * @param {any} mesh
     * @returns {any}
     */
    preparePublish(document, proof, authorization, chat, mesh) {
        const ptr0 = passArray8ToWasm0(document, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshscoperuntime_preparePublish(this.__wbg_ptr, ptr0, len0, proof, authorization, chat, mesh);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} payload
     * @returns {Uint8Array | undefined}
     */
    provideCachedProofPage(payload) {
        const ptr0 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshscoperuntime_provideCachedProofPage(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v2;
        if (ret[0] !== 0) {
            v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v2;
    }
    /**
     * @param {Uint8Array} document
     * @param {any} response_proof
     * @returns {any}
     */
    provideDocument(document, response_proof) {
        const ptr0 = passArray8ToWasm0(document, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshscoperuntime_provideDocument(this.__wbg_ptr, ptr0, len0, response_proof);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} payload
     * @param {Uint8Array} document
     * @param {any} authorization
     * @returns {Uint8Array}
     */
    provideProofPage(payload, document, authorization) {
        const ptr0 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(document, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshscoperuntime_provideProofPage(this.__wbg_ptr, ptr0, len0, ptr1, len1, authorization);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * @param {Uint8Array} document
     * @param {any} proof
     * @returns {Uint8Array | undefined}
     */
    publishFrame(document, proof) {
        const ptr0 = passArray8ToWasm0(document, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshscoperuntime_publishFrame(this.__wbg_ptr, ptr0, len0, proof);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v2;
        if (ret[0] !== 0) {
            v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v2;
    }
    /**
     * @param {Uint8Array} frame
     * @returns {any}
     */
    receiveFrame(frame) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshscoperuntime_receiveFrame(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    rejectDocumentReceive() {
        const ret = wasm.wasmmeshscoperuntime_rejectDocumentReceive(this.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    resetDocument() {
        wasm.wasmmeshscoperuntime_resetDocument(this.__wbg_ptr);
    }
    /**
     * @param {string} local_device_id
     * @param {string} remote_device_id
     */
    startDocumentSync(local_device_id, remote_device_id) {
        const ptr0 = passStringToWasm0(local_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(remote_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshscoperuntime_startDocumentSync(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
}
if (Symbol.dispose) WasmMeshScopeRuntime.prototype[Symbol.dispose] = WasmMeshScopeRuntime.prototype.free;

export class WasmMeshSessionLifecycle {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmMeshSessionLifecycleFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmmeshsessionlifecycle_free(ptr, 0);
    }
    /**
     * @param {any} key
     * @param {number} generation
     * @param {string} event
     * @param {number} now_ms
     * @returns {any}
     */
    callbackPlan(key, generation, event, now_ms) {
        const ptr0 = passStringToWasm0(event, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshsessionlifecycle_callbackPlan(this.__wbg_ptr, key, generation, ptr0, len0, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    clear() {
        wasm.wasmmeshsessionlifecycle_clear(this.__wbg_ptr);
    }
    /**
     * @param {any} key
     * @param {number} generation
     * @returns {any}
     */
    evict(key, generation) {
        const ret = wasm.wasmmeshsessionlifecycle_evict(this.__wbg_ptr, key, generation);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} key
     * @param {number} generation
     * @param {number} now_ms
     * @returns {boolean}
     */
    markStable(key, generation, now_ms) {
        const ret = wasm.wasmmeshsessionlifecycle_markStable(this.__wbg_ptr, key, generation, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {number | null} [stable_after_ms]
     */
    constructor(stable_after_ms) {
        const ret = wasm.wasmmeshsessionlifecycle_new(!isLikeNone(stable_after_ms), isLikeNone(stable_after_ms) ? 0 : stable_after_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmMeshSessionLifecycleFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @returns {any}
     */
    publishPlan() {
        const ret = wasm.wasmmeshsessionlifecycle_publishPlan(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} key
     * @param {number} generation
     * @returns {boolean}
     */
    publishRecovery(key, generation) {
        const ret = wasm.wasmmeshsessionlifecycle_publishRecovery(this.__wbg_ptr, key, generation);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {any} key
     * @param {string} connection_id
     * @param {number} generation
     * @param {number} now_ms
     * @returns {any}
     */
    register(key, connection_id, generation, now_ms) {
        const ptr0 = passStringToWasm0(connection_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshsessionlifecycle_register(this.__wbg_ptr, key, ptr0, len0, generation, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} key
     * @param {number} generation
     * @returns {boolean}
     */
    reportFailure(key, generation) {
        const ret = wasm.wasmmeshsessionlifecycle_reportFailure(this.__wbg_ptr, key, generation);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
}
if (Symbol.dispose) WasmMeshSessionLifecycle.prototype[Symbol.dispose] = WasmMeshSessionLifecycle.prototype.free;

export class WasmPairingCodec {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmPairingCodecFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmpairingcodec_free(ptr, 0);
    }
    /**
     * @param {Uint8Array} frame
     * @param {string} expected_type
     * @param {string} expected_secret
     * @returns {Uint8Array}
     */
    decode(frame, expected_type, expected_secret) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(expected_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(expected_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmpairingcodec_decode(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v4;
    }
    /**
     * @param {string} frame_type
     * @param {string} secret
     * @param {Uint8Array} payload
     * @returns {Uint8Array}
     */
    encode(frame_type, secret, payload) {
        const ptr0 = passStringToWasm0(frame_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmpairingcodec_encode(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v4;
    }
    /**
     * @param {Uint8Array} frame
     * @returns {any}
     */
    inspect(frame) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmpairingcodec_inspect(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    constructor() {
        const ret = wasm.wasmpairingcodec_new();
        this.__wbg_ptr = ret >>> 0;
        WasmPairingCodecFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}
if (Symbol.dispose) WasmPairingCodec.prototype[Symbol.dispose] = WasmPairingCodec.prototype.free;

export class WasmStateCore {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmStateCoreFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmstatecore_free(ptr, 0);
    }
    /**
     * @param {any} handshake
     * @param {any} snapshot
     * @param {string} remote_endpoint
     * @param {number} now_ms
     * @returns {any}
     */
    static admitMeshPeer(handshake, snapshot, remote_endpoint, now_ms) {
        const ptr0 = passStringToWasm0(remote_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_admitMeshPeer(handshake, snapshot, ptr0, len0, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} authorization
     * @param {any} snapshot
     * @param {any} needed_hashes
     * @param {number} now_ms
     * @returns {any}
     */
    static admitWorkspaceChangeAuthorization(authorization, snapshot, needed_hashes, now_ms) {
        const ret = wasm.wasmstatecore_admitWorkspaceChangeAuthorization(authorization, snapshot, needed_hashes, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} authorization
     * @param {any} snapshot
     * @param {any} needed_hashes
     * @param {number} now_ms
     * @returns {any}
     */
    static admitWorkspaceChangeAuthorizations(authorization, snapshot, needed_hashes, now_ms) {
        const ret = wasm.wasmstatecore_admitWorkspaceChangeAuthorizations(authorization, snapshot, needed_hashes, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} document
     * @param {any} raw
     * @returns {any}
     */
    static authorizationExport(document, raw) {
        const ptr0 = passArray8ToWasm0(document, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_authorizationExport(ptr0, len0, raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static authorizationRecordPages(raw) {
        const ret = wasm.wasmstatecore_authorizationRecordPages(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} credential
     * @param {string} local_person_id
     * @param {string} local_public_key
     * @param {string} local_device_id
     * @param {string} target_person_id
     * @param {string} target_device_id
     * @param {string | null} [peer_person_id]
     * @returns {boolean}
     */
    static canRemoveWorkspaceDevice(credential, local_person_id, local_public_key, local_device_id, target_person_id, target_device_id, peer_person_id) {
        const ptr0 = passStringToWasm0(local_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(local_public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(local_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(target_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(target_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        var ptr5 = isLikeNone(peer_person_id) ? 0 : passStringToWasm0(peer_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len5 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_canRemoveWorkspaceDevice(credential, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {any} raw
     * @returns {boolean}
     */
    static canReuseMemberBundle(raw) {
        const ret = wasm.wasmstatecore_canReuseMemberBundle(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {any} records
     * @returns {any}
     */
    static canonicalRevocations(records) {
        const ret = wasm.wasmstatecore_canonicalRevocations(records);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @param {number} now_ms
     * @returns {any}
     */
    static createScopeControlTransferPayload(raw, now_ms) {
        const ret = wasm.wasmstatecore_createScopeControlTransferPayload(raw, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static createScopeGenesis(raw) {
        const ret = wasm.wasmstatecore_createScopeGenesis(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static createScopeGenesisPayload(raw) {
        const ret = wasm.wasmstatecore_createScopeGenesisPayload(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} credential
     * @param {string} person_id
     * @param {string} public_key
     * @returns {boolean}
     */
    static credentialBelongsToProfile(credential, person_id, public_key) {
        const ptr0 = passStringToWasm0(person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_credentialBelongsToProfile(credential, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {string | null | undefined} existing_owner_person_id
     * @param {string} local_person_id
     * @returns {string}
     */
    static decideOwnerCredential(existing_owner_person_id, local_person_id) {
        let deferred4_0;
        let deferred4_1;
        try {
            var ptr0 = isLikeNone(existing_owner_person_id) ? 0 : passStringToWasm0(existing_owner_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(local_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.wasmstatecore_decideOwnerCredential(ptr0, len0, ptr1, len1);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * @param {any} raw
     * @param {number} now_ms
     * @returns {any}
     */
    static decideWorkspaceAccess(raw, now_ms) {
        const ret = wasm.wasmstatecore_decideWorkspaceAccess(raw, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} frame
     * @param {string} expected_type
     * @param {string} secret
     * @param {string} workspace_id
     * @returns {any}
     */
    static decodeMeshHandshake(frame, expected_type, secret, workspace_id) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(expected_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_decodeMeshHandshake(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} bytes
     * @param {any} allowed_ids
     * @returns {any}
     */
    static decodeWorkspaceSet(bytes, allowed_ids) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_decodeWorkspaceSet(ptr0, len0, allowed_ids);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} ack
     * @param {any} batch
     * @param {string} target_device_id
     * @returns {boolean}
     */
    static durableAckMatches(ack, batch, target_device_id) {
        const ptr0 = passStringToWasm0(target_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_durableAckMatches(ack, batch, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {any} peers
     * @returns {any}
     */
    static eligibleEditorPersonIds(peers) {
        const ret = wasm.wasmstatecore_eligibleEditorPersonIds(peers);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} frame_type
     * @param {string} secret
     * @param {any} raw
     * @returns {Uint8Array}
     */
    static encodeMeshHandshake(frame_type, secret, raw) {
        const ptr0 = passStringToWasm0(frame_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_encodeMeshHandshake(ptr0, len0, ptr1, len1, raw);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * @param {any} entries
     * @returns {Uint8Array}
     */
    static encodeWorkspaceSet(entries) {
        const ret = wasm.wasmstatecore_encodeWorkspaceSet(entries);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {any} raw
     * @returns {boolean}
     */
    static hasAuthorityConflict(raw) {
        const ret = wasm.wasmstatecore_hasAuthorityConflict(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {any} records
     * @returns {boolean}
     */
    static hasConflictingOwnershipTransfers(records) {
        const ret = wasm.wasmstatecore_hasConflictingOwnershipTransfers(records);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {any} credential
     * @param {string} person_id
     * @param {any} grant
     * @returns {boolean}
     */
    static hasLeftWorkspace(credential, person_id, grant) {
        const ptr0 = passStringToWasm0(person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_hasLeftWorkspace(credential, ptr0, len0, grant);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {Uint8Array} frame
     * @returns {any}
     */
    static inspectMeshHandshake(frame) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_inspectMeshHandshake(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} credential
     * @param {string} person_id
     * @param {string} device_id
     * @returns {boolean}
     */
    static isDeviceRevoked(credential, person_id, device_id) {
        const ptr0 = passStringToWasm0(person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_isDeviceRevoked(credential, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {any} credential
     * @param {string} person_id
     * @param {any} grant
     * @returns {boolean}
     */
    static isGrantRevoked(credential, person_id, grant) {
        const ptr0 = passStringToWasm0(person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_isGrantRevoked(credential, ptr0, len0, grant);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {any} raw
     * @param {number} now_ms
     * @returns {boolean}
     */
    static isWorkspaceEnvelope(raw, now_ms) {
        const ret = wasm.wasmstatecore_isWorkspaceEnvelope(raw, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {any} raw
     * @param {string} issuer_person_id
     * @param {string} local_person_id
     * @param {string} local_device_id
     * @returns {boolean}
     */
    static knowsWorkspaceIssuer(raw, issuer_person_id, local_person_id, local_device_id) {
        const ptr0 = passStringToWasm0(issuer_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(local_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(local_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_knowsWorkspaceIssuer(raw, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {any} existing
     * @param {any} incoming
     * @returns {any}
     */
    static mergePeerRecords(existing, incoming) {
        const ret = wasm.wasmstatecore_mergePeerRecords(existing, incoming);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} current
     * @param {any} incoming
     * @param {number} now_ms
     * @returns {any}
     */
    static mergeScopeAuthoritySnapshots(current, incoming, now_ms) {
        const ret = wasm.wasmstatecore_mergeScopeAuthoritySnapshots(current, incoming, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @returns {any}
     */
    static meshCapabilities() {
        const ret = wasm.wasmstatecore_meshCapabilities();
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static meshHandshakeFeatures(raw) {
        const ret = wasm.wasmstatecore_meshHandshakeFeatures(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} owned
     * @param {any} remote
     * @returns {any}
     */
    static missingOwnerWorkspaces(owned, remote) {
        const ret = wasm.wasmstatecore_missingOwnerWorkspaces(owned, remote);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} credential
     * @param {any} issued_grants
     * @returns {number}
     */
    static nextAccessEpoch(credential, issued_grants) {
        const ret = wasm.wasmstatecore_nextAccessEpoch(credential, issued_grants);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0];
    }
    /**
     * @param {any} records
     * @param {string} workspace_id
     * @param {any} current_owner
     * @param {number} current_epoch
     * @param {any} revoked_people
     * @param {number} now_ms
     * @returns {any}
     */
    static nextVerifiedOwnershipTransition(records, workspace_id, current_owner, current_epoch, revoked_people, now_ms) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_nextVerifiedOwnershipTransition(records, ptr0, len0, current_owner, current_epoch, revoked_people, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} target_device_id
     * @param {any} routes
     * @returns {any}
     */
    static orderDeliveryRoutes(target_device_id, routes) {
        const ptr0 = passStringToWasm0(target_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_orderDeliveryRoutes(ptr0, len0, routes);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} credentials
     * @param {string} person_id
     * @param {string} public_key
     * @returns {any}
     */
    static ownedWorkspaceIds(credentials, person_id, public_key) {
        const ptr0 = passStringToWasm0(person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_ownedWorkspaceIds(credentials, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static partitionCredentials(raw) {
        const ret = wasm.wasmstatecore_partitionCredentials(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static planAuthorityCommand(raw) {
        const ret = wasm.wasmstatecore_planAuthorityCommand(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} kind
     * @param {boolean} has_revocations
     * @param {boolean} has_transfers
     * @returns {any}
     */
    static planAuthorityImport(kind, has_revocations, has_transfers) {
        const ptr0 = passStringToWasm0(kind, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_planAuthorityImport(ptr0, len0, has_revocations, has_transfers);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static planAuthorityMerge(raw) {
        const ret = wasm.wasmstatecore_planAuthorityMerge(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @returns {any}
     */
    static planCatalogMerge() {
        const ret = wasm.wasmstatecore_planCatalogMerge();
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} document_id
     * @param {any} changes
     * @param {string} verified_at
     * @returns {any}
     */
    static planChangeAdmission(document_id, changes, verified_at) {
        const ptr0 = passStringToWasm0(document_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(verified_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_planChangeAdmission(ptr0, len0, changes, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @param {number} now_ms
     * @returns {any}
     */
    static planChangeAdmissionFlow(raw, now_ms) {
        const ret = wasm.wasmstatecore_planChangeAdmissionFlow(raw, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static planDialSchedule(raw) {
        const ret = wasm.wasmstatecore_planDialSchedule(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static planGuestAdvertisements(raw) {
        const ret = wasm.wasmstatecore_planGuestAdvertisements(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static planInvitation(raw) {
        const ret = wasm.wasmstatecore_planInvitation(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static planInvitationCredential(raw) {
        const ret = wasm.wasmstatecore_planInvitationCredential(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static planMemberGrant(raw) {
        const ret = wasm.wasmstatecore_planMemberGrant(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @returns {any}
     */
    static planMeshHandshakeAuthorityImport() {
        const ret = wasm.wasmstatecore_planMeshHandshakeAuthorityImport();
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} credential
     * @param {string} local_person_id
     * @param {any} certificates
     * @param {string} updated_at
     * @returns {any}
     */
    static planOwnerCertificateRefresh(credential, local_person_id, certificates, updated_at) {
        const ptr0 = passStringToWasm0(local_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(updated_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_planOwnerCertificateRefresh(credential, ptr0, len0, certificates, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static planOwnershipAdoption(raw) {
        const ret = wasm.wasmstatecore_planOwnershipAdoption(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static planOwnershipAuthorityFlow(raw) {
        const ret = wasm.wasmstatecore_planOwnershipAuthorityFlow(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static planOwnershipMerge(raw) {
        const ret = wasm.wasmstatecore_planOwnershipMerge(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} records
     * @param {string} initial_owner_person_id
     * @param {number} initial_epoch
     * @returns {any}
     */
    static planOwnershipTransitions(records, initial_owner_person_id, initial_epoch) {
        const ptr0 = passStringToWasm0(initial_owner_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_planOwnershipTransitions(records, ptr0, len0, initial_epoch);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static planScopeGenesis(raw) {
        const ret = wasm.wasmstatecore_planScopeGenesis(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static planSuccessionCatalog(raw) {
        const ret = wasm.wasmstatecore_planSuccessionCatalog(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @param {number} now_ms
     * @returns {any}
     */
    static planSuccessionMerge(raw, now_ms) {
        const ret = wasm.wasmstatecore_planSuccessionMerge(raw, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} current
     * @param {any} eligible
     * @param {number} epoch
     * @returns {any}
     */
    static planSuccessionPolicyRefresh(current, eligible, epoch) {
        const ret = wasm.wasmstatecore_planSuccessionPolicyRefresh(current, eligible, epoch);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} local_device_id
     * @param {string} local_instance_id
     * @param {string} remote_device_id
     * @param {string} remote_instance_id
     * @returns {any}
     */
    static preferredSessionDirection(local_device_id, local_instance_id, remote_device_id, remote_instance_id) {
        const ptr0 = passStringToWasm0(local_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(local_instance_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(remote_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(remote_instance_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_preferredSessionDirection(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static prepareWriteEvidence(raw) {
        const ret = wasm.wasmstatecore_prepareWriteEvidence(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} left
     * @param {any} right
     * @returns {any}
     */
    static reconcileReplicaSets(left, right) {
        const ret = wasm.wasmstatecore_reconcileReplicaSets(left, right);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} change_hashes
     * @param {any} records
     */
    static requireChangeAuthorizationCoverage(change_hashes, records) {
        const ret = wasm.wasmstatecore_requireChangeAuthorizationCoverage(change_hashes, records);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {any} candidates
     * @param {string} local_device_id
     * @param {string} local_instance_id
     * @returns {any}
     */
    static selectMeshHandshakeBundle(candidates, local_device_id, local_instance_id) {
        const ptr0 = passStringToWasm0(local_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(local_instance_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_selectMeshHandshakeBundle(candidates, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @returns {any}
     */
    static selectOwnershipTransfer(raw) {
        const ret = wasm.wasmstatecore_selectOwnershipTransfer(raw);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} local_device_id
     * @param {any} candidates
     * @param {any} bounds
     * @param {number} now_ms
     * @param {number} rotation
     * @returns {string[]}
     */
    static selectScopedNeighbors(local_device_id, candidates, bounds, now_ms, rotation) {
        const ptr0 = passStringToWasm0(local_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_selectScopedNeighbors(ptr0, len0, candidates, bounds, now_ms, rotation);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v2;
    }
    /**
     * @param {string} credential_owner_person_id
     * @param {string} local_person_id
     * @param {string} remote_person_id
     * @returns {boolean}
     */
    static shouldAdvertiseOwnerWorkspaceIds(credential_owner_person_id, local_person_id, remote_person_id) {
        const ptr0 = passStringToWasm0(credential_owner_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(local_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(remote_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_shouldAdvertiseOwnerWorkspaceIds(ptr0, len0, ptr1, len1, ptr2, len2);
        return ret !== 0;
    }
    /**
     * @param {Uint8Array} seed
     * @param {string} signer_key_id
     * @param {any} payload
     * @returns {any}
     */
    static signDeviceRoute(seed, signer_key_id, payload) {
        const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(signer_key_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_signDeviceRoute(ptr0, len0, ptr1, len1, payload);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} seed
     * @param {string} signer_key_id
     * @param {any} payload
     * @returns {any}
     */
    static signDurableAck(seed, signer_key_id, payload) {
        const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(signer_key_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_signDurableAck(ptr0, len0, ptr1, len1, payload);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} policy
     * @param {any} claims
     * @param {any} votes
     * @param {any} transfers
     * @param {any} revocations
     * @param {number} epoch
     * @returns {any}
     */
    static summarizeSuccession(policy, claims, votes, transfers, revocations, epoch) {
        const ret = wasm.wasmstatecore_summarizeSuccession(policy, claims, votes, transfers, revocations, epoch);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} current
     * @param {any} input
     * @returns {any}
     */
    static transitionOutboxClaim(current, input) {
        const ret = wasm.wasmstatecore_transitionOutboxClaim(current, input);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} route
     */
    static validateDeviceRoute(route) {
        const ret = wasm.wasmstatecore_validateDeviceRoute(route);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {any} payload
     */
    static validateDeviceRoutePayload(payload) {
        const ret = wasm.wasmstatecore_validateDeviceRoutePayload(payload);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {any} payload
     */
    static validateDurableAckPayload(payload) {
        const ret = wasm.wasmstatecore_validateDurableAckPayload(payload);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {any} capabilities
     */
    static validateMeshCapabilities(capabilities) {
        const ret = wasm.wasmstatecore_validateMeshCapabilities(capabilities);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {any} raw
     * @param {number} now_ms
     * @returns {any}
     */
    static validateMeshCatalog(raw, now_ms) {
        const ret = wasm.wasmstatecore_validateMeshCatalog(raw, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @param {string | null} [expected_workspace_id]
     * @returns {any}
     */
    static validateMeshHandshake(raw, expected_workspace_id) {
        var ptr0 = isLikeNone(expected_workspace_id) ? 0 : passStringToWasm0(expected_workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_validateMeshHandshake(raw, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @param {string} remote_person_id
     * @param {string} local_person_id
     * @returns {string}
     */
    static validateOwnerWorkspaceOffer(raw, remote_person_id, local_person_id) {
        let deferred4_0;
        let deferred4_1;
        try {
            const ptr0 = passStringToWasm0(remote_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(local_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.wasmstatecore_validateOwnerWorkspaceOffer(raw, ptr0, len0, ptr1, len1);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * @param {any} raw
     * @param {number} now_ms
     * @returns {any}
     */
    static validateScopeAuthority(raw, now_ms) {
        const ret = wasm.wasmstatecore_validateScopeAuthority(raw, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} envelope
     * @param {string} public_key
     * @param {number} now_ms
     * @param {boolean} allow_expired
     * @returns {any}
     */
    static verifyDeviceRoute(envelope, public_key, now_ms, allow_expired) {
        const ptr0 = passStringToWasm0(public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_verifyDeviceRoute(envelope, ptr0, len0, now_ms, allow_expired);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} envelope
     * @param {string} public_key
     * @returns {any}
     */
    static verifyDurableAck(envelope, public_key) {
        const ptr0 = passStringToWasm0(public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_verifyDurableAck(envelope, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} record
     * @param {string} workspace_id
     * @param {any} authority
     * @param {number} now_ms
     * @returns {any}
     */
    static verifyWorkspaceDeparture(record, workspace_id, authority, now_ms) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_verifyWorkspaceDeparture(record, ptr0, len0, authority, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} record
     * @param {string} workspace_id
     * @param {string} owner_person_id
     * @param {any} authority
     * @param {number} now_ms
     * @returns {any}
     */
    static verifyWorkspaceDeviceRevocation(record, workspace_id, owner_person_id, authority, now_ms) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(owner_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_verifyWorkspaceDeviceRevocation(record, ptr0, len0, ptr1, len1, authority, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} grant
     * @param {string} workspace_id
     * @param {string} member_person_id
     * @param {any} authority
     * @returns {any}
     */
    static verifyWorkspaceGrant(grant, workspace_id, member_person_id, authority) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(member_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_verifyWorkspaceGrant(grant, ptr0, len0, ptr1, len1, authority);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} raw
     * @param {any} options
     * @param {number} now_ms
     * @returns {any}
     */
    static verifyWorkspaceMemberBundle(raw, options, now_ms) {
        const ret = wasm.wasmstatecore_verifyWorkspaceMemberBundle(raw, options, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} record
     * @param {string} workspace_id
     * @param {any} authority
     * @param {number} minimum_epoch
     * @param {number} now_ms
     * @returns {any}
     */
    static verifyWorkspaceOwnershipTransfer(record, workspace_id, authority, minimum_epoch, now_ms) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_verifyWorkspaceOwnershipTransfer(record, ptr0, len0, authority, minimum_epoch, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} record
     * @param {string} workspace_id
     * @param {any} authority
     * @param {number} now_ms
     * @returns {any}
     */
    static verifyWorkspaceRevocation(record, workspace_id, authority, now_ms) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_verifyWorkspaceRevocation(record, ptr0, len0, authority, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} claim
     * @param {string} workspace_id
     * @param {any} authority
     * @param {number} minimum_epoch
     * @param {any} revoked
     * @param {number} now_ms
     * @returns {any}
     */
    static verifyWorkspaceSuccessionClaim(claim, workspace_id, authority, minimum_epoch, revoked, now_ms) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_verifyWorkspaceSuccessionClaim(claim, ptr0, len0, authority, minimum_epoch, revoked, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} policy
     * @param {string} workspace_id
     * @param {any} authority
     * @param {number} now_ms
     * @returns {any}
     */
    static verifyWorkspaceSuccessionPolicy(policy, workspace_id, authority, now_ms) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_verifyWorkspaceSuccessionPolicy(policy, ptr0, len0, authority, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} vote
     * @param {any} policy
     * @param {string} candidate_person_id
     * @param {any} authority
     * @param {any} revoked
     * @param {number} now_ms
     * @returns {any}
     */
    static verifyWorkspaceSuccessionVote(vote, policy, candidate_person_id, authority, revoked, now_ms) {
        const ptr0 = passStringToWasm0(candidate_person_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmstatecore_verifyWorkspaceSuccessionVote(vote, policy, ptr0, len0, authority, revoked, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
}
if (Symbol.dispose) WasmStateCore.prototype[Symbol.dispose] = WasmStateCore.prototype.free;

export class WasmWorkspaceJoinHandoff {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmWorkspaceJoinHandoffFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmworkspacejoinhandoff_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    guestBeginConfirmation() {
        const ret = wasm.wasmworkspacejoinhandoff_guestBeginConfirmation(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {string}
     */
    guestConfirmationFailed() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.wasmworkspacejoinhandoff_guestConfirmationFailed(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    guestConfirmationSent() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.wasmworkspacejoinhandoff_guestConfirmationSent(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @param {Uint8Array} frame
     */
    guestReceiveReady(frame) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmworkspacejoinhandoff_guestReceiveReady(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    guestRequest() {
        const ret = wasm.wasmworkspacejoinhandoff_guestRequest(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {boolean} retryable
     * @returns {string}
     */
    guestResumeFailed(retryable) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.wasmworkspacejoinhandoff_guestResumeFailed(this.__wbg_ptr, retryable);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    guestResumeSucceeded() {
        const ret = wasm.wasmworkspacejoinhandoff_guestResumeSucceeded(this.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {boolean} retryable
     * @returns {string}
     */
    guestTransportFailed(retryable) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.wasmworkspacejoinhandoff_guestTransportFailed(this.__wbg_ptr, retryable);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @param {Uint8Array} frame
     */
    hostReceiveConfirmation(frame) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmworkspacejoinhandoff_hostReceiveConfirmation(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Uint8Array} frame
     * @returns {Uint8Array}
     */
    hostReceiveRequest(frame) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmworkspacejoinhandoff_hostReceiveRequest(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {string} secret
     * @param {string} side
     */
    constructor(secret, side) {
        const ptr0 = passStringToWasm0(secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(side, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmworkspacejoinhandoff_new(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmWorkspaceJoinHandoffFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}
if (Symbol.dispose) WasmWorkspaceJoinHandoff.prototype[Symbol.dispose] = WasmWorkspaceJoinHandoff.prototype.free;

export class WasmWorkspaceJoinHandshake {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmWorkspaceJoinHandshakeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmworkspacejoinhandshake_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    acknowledgeRejection() {
        const ret = wasm.wasmworkspacejoinhandshake_acknowledgeRejection(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} payload
     * @returns {Uint8Array}
     */
    acknowledgeSuccess(payload) {
        const ptr0 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmworkspacejoinhandshake_acknowledgeSuccess(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {string} secret
     * @param {string} side
     */
    constructor(secret, side) {
        const ptr0 = passStringToWasm0(secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(side, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmworkspacejoinhandshake_new(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmWorkspaceJoinHandshakeFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {Uint8Array} frame
     * @returns {any}
     */
    receiveAck(frame) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmworkspacejoinhandshake_receiveAck(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {Uint8Array} frame
     * @returns {Uint8Array}
     */
    receiveRequest(frame) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmworkspacejoinhandshake_receiveRequest(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {Uint8Array} frame
     * @returns {any}
     */
    receiveResponse(frame) {
        const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmworkspacejoinhandshake_receiveResponse(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} message
     * @returns {Uint8Array}
     */
    reject(message) {
        const ptr0 = passStringToWasm0(message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmworkspacejoinhandshake_reject(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {string} message
     * @returns {Uint8Array}
     */
    rejectAcceptedResponse(message) {
        const ptr0 = passStringToWasm0(message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmworkspacejoinhandshake_rejectAcceptedResponse(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {Uint8Array} payload
     * @returns {Uint8Array}
     */
    respond(payload) {
        const ptr0 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmworkspacejoinhandshake_respond(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {Uint8Array} payload
     * @returns {Uint8Array}
     */
    sendRequest(payload) {
        const ptr0 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmworkspacejoinhandshake_sendRequest(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
}
if (Symbol.dispose) WasmWorkspaceJoinHandshake.prototype[Symbol.dispose] = WasmWorkspaceJoinHandshake.prototype.free;

/**
 * @returns {string}
 */
export function mesh_version() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.mesh_version();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_960c155d3d49e4c2: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_Number_32bf70a599af1d4b: function(arg0) {
            const ret = Number(arg0);
            return ret;
        },
        __wbg_String_8564e559799eccda: function(arg0, arg1) {
            const ret = String(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_bigint_get_as_i64_3d3aba5d616c6a51: function(arg0, arg1) {
            const v = arg1;
            const ret = typeof(v) === 'bigint' ? v : undefined;
            getDataViewMemory0().setBigInt64(arg0 + 8 * 1, isLikeNone(ret) ? BigInt(0) : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_boolean_get_6ea149f0a8dcc5ff: function(arg0) {
            const v = arg0;
            const ret = typeof(v) === 'boolean' ? v : undefined;
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg___wbindgen_debug_string_ab4b34d23d6778bd: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_in_a5d8b22e52b24dd1: function(arg0, arg1) {
            const ret = arg0 in arg1;
            return ret;
        },
        __wbg___wbindgen_is_bigint_ec25c7f91b4d9e93: function(arg0) {
            const ret = typeof(arg0) === 'bigint';
            return ret;
        },
        __wbg___wbindgen_is_function_3baa9db1a987f47d: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_null_52ff4ec04186736f: function(arg0) {
            const ret = arg0 === null;
            return ret;
        },
        __wbg___wbindgen_is_object_63322ec0cd6ea4ef: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_6df3bf7ef1164ed3: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_29a43b4d42920abd: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_jsval_eq_d3465d8a07697228: function(arg0, arg1) {
            const ret = arg0 === arg1;
            return ret;
        },
        __wbg___wbindgen_jsval_loose_eq_cac3565e89b4134c: function(arg0, arg1) {
            const ret = arg0 == arg1;
            return ret;
        },
        __wbg___wbindgen_number_get_c7f42aed0525c451: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'number' ? obj : undefined;
            getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_string_get_7ed5322991caaec5: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_6b64449b9b9ed33c: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_14b169f759b26747: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
            return ret;
        }, arguments); },
        __wbg_done_9158f7cc8751ba32: function(arg0) {
            const ret = arg0.done;
            return ret;
        },
        __wbg_entries_e0b73aa8571ddb56: function(arg0) {
            const ret = Object.entries(arg0);
            return ret;
        },
        __wbg_getRandomValues_cc7f052a444bb2ce: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_get_1affdbdd5573b16a: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_8360291721e2339f: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_unchecked_17f53dad852b9588: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_with_ref_key_6412cf3094599694: function(arg0, arg1) {
            const ret = arg0[arg1];
            return ret;
        },
        __wbg_instanceof_ArrayBuffer_7c8433c6ed14ffe3: function(arg0) {
            let result;
            try {
                result = arg0 instanceof ArrayBuffer;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Map_1b76fd4635be43eb: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Map;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Uint8Array_152ba1f289edcf3f: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Uint8Array;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_isArray_c3109d14ffc06469: function(arg0) {
            const ret = Array.isArray(arg0);
            return ret;
        },
        __wbg_isSafeInteger_4fc213d1989d6d2a: function(arg0) {
            const ret = Number.isSafeInteger(arg0);
            return ret;
        },
        __wbg_iterator_013bc09ec998c2a7: function() {
            const ret = Symbol.iterator;
            return ret;
        },
        __wbg_length_3d4ecd04bd8d22f1: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_9f1775224cf1d815: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_log_7e1aa9064a1dbdbd: function(arg0) {
            console.log(arg0);
        },
        __wbg_new_0c7403db6e782f19: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_34d45cc8e36aaead: function() {
            const ret = new Map();
            return ret;
        },
        __wbg_new_682678e2f47e32bc: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_aa8d0fa9762c29bd: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_from_slice_b5ea43e23f6008c0: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_next_0340c4ae324393c3: function() { return handleError(function (arg0) {
            const ret = arg0.next();
            return ret;
        }, arguments); },
        __wbg_next_7646edaa39458ef7: function(arg0) {
            const ret = arg0.next;
            return ret;
        },
        __wbg_prototypesetcall_a6b02eb00b0f4ce2: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_set_022bee52d0b05b19: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = Reflect.set(arg0, arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_set_3bf1de9fab0cd644: function(arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        },
        __wbg_set_6be42768c690e380: function(arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        },
        __wbg_set_fde2cec06c23692b: function(arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        },
        __wbg_value_ee3a06f4579184fa: function(arg0) {
            const ret = arg0.value;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0) {
            // Cast intrinsic for `I64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0) {
            // Cast intrinsic for `U64 -> Externref`.
            const ret = BigInt.asUintN(64, arg0);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./meta_mesh_policy_bg.js": import0,
    };
}

const WasmAutomergeDeviceSyncFlowFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmautomergedevicesyncflow_free(ptr >>> 0, 1));
const WasmAutomergeSyncEngineFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmautomergesyncengine_free(ptr >>> 0, 1));
const WasmDeviceRouteCatalogFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmdeviceroutecatalog_free(ptr >>> 0, 1));
const WasmGossipLifecycleStateFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmgossiplifecyclestate_free(ptr >>> 0, 1));
const WasmIdentityCryptoFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmidentitycrypto_free(ptr >>> 0, 1));
const WasmInvitationsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasminvitations_free(ptr >>> 0, 1));
const WasmLiveWorkspaceSessionFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmliveworkspacesession_free(ptr >>> 0, 1));
const WasmMeshAuthenticatedSessionsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmmeshauthenticatedsessions_free(ptr >>> 0, 1));
const WasmMeshBatchDeliveryFlowFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmmeshbatchdeliveryflow_free(ptr >>> 0, 1));
const WasmMeshHandshakeFlowFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmmeshhandshakeflow_free(ptr >>> 0, 1));
const WasmMeshLifecycleStateFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmmeshlifecyclestate_free(ptr >>> 0, 1));
const WasmMeshRuntimeStateFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmmeshruntimestate_free(ptr >>> 0, 1));
const WasmMeshScopeRuntimeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmmeshscoperuntime_free(ptr >>> 0, 1));
const WasmMeshSessionLifecycleFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmmeshsessionlifecycle_free(ptr >>> 0, 1));
const WasmPairingCodecFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmpairingcodec_free(ptr >>> 0, 1));
const WasmStateCoreFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmstatecore_free(ptr >>> 0, 1));
const WasmWorkspaceJoinHandoffFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmworkspacejoinhandoff_free(ptr >>> 0, 1));
const WasmWorkspaceJoinHandshakeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmworkspacejoinhandshake_free(ptr >>> 0, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(wasm.__wbindgen_externrefs.get(mem.getUint32(i, true)));
    }
    wasm.__externref_drop_slice(ptr, len);
    return result;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint16ArrayMemory0 = null;
function getUint16ArrayMemory0() {
    if (cachedUint16ArrayMemory0 === null || cachedUint16ArrayMemory0.byteLength === 0) {
        cachedUint16ArrayMemory0 = new Uint16Array(wasm.memory.buffer);
    }
    return cachedUint16ArrayMemory0;
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray16ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 2, 2) >>> 0;
    getUint16ArrayMemory0().set(arg, ptr / 2);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasm;
function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint16ArrayMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('meta_mesh_policy_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
