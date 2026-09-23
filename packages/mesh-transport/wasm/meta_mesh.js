/* @ts-self-types="./meta_mesh.d.ts" */

export class BrowserAcceptor {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(BrowserAcceptor.prototype);
        obj.__wbg_ptr = ptr;
        BrowserAcceptorFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BrowserAcceptorFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_browseracceptor_free(ptr, 0);
    }
    /**
     * @returns {Promise<BrowserConnection | undefined>}
     */
    accept() {
        const ret = wasm.browseracceptor_accept(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<void>}
     */
    close() {
        const ret = wasm.browseracceptor_close(this.__wbg_ptr);
        return ret;
    }
}
if (Symbol.dispose) BrowserAcceptor.prototype[Symbol.dispose] = BrowserAcceptor.prototype.free;

export class BrowserConnection {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(BrowserConnection.prototype);
        obj.__wbg_ptr = ptr;
        BrowserConnectionFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BrowserConnectionFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_browserconnection_free(ptr, 0);
    }
    /**
     * @returns {Promise<BrowserStream>}
     */
    acceptStream() {
        const ret = wasm.browserconnection_acceptStream(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<void>}
     */
    close() {
        const ret = wasm.browserconnection_close(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<BrowserStream>}
     */
    openStream() {
        const ret = wasm.browserconnection_openStream(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {string}
     */
    get remoteEndpointId() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.browserconnection_remoteEndpointId(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) BrowserConnection.prototype[Symbol.dispose] = BrowserConnection.prototype.free;

export class BrowserNode {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(BrowserNode.prototype);
        obj.__wbg_ptr = ptr;
        BrowserNodeFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BrowserNodeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_browsernode_free(ptr, 0);
    }
    /**
     * @returns {Promise<BrowserAcceptor>}
     */
    accept() {
        const ret = wasm.browsernode_accept(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {string | null} [reason]
     * @returns {Promise<void>}
     */
    close(reason) {
        var ptr0 = isLikeNone(reason) ? 0 : passStringToWasm0(reason, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        const ret = wasm.browsernode_close(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} remote_endpoint
     * @returns {Promise<BrowserConnection>}
     */
    dial(remote_endpoint) {
        const ptr0 = passStringToWasm0(remote_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.browsernode_dial(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} remote_endpoint
     * @returns {Promise<BrowserConnection>}
     */
    dialRelay(remote_endpoint) {
        const ptr0 = passStringToWasm0(remote_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.browsernode_dialRelay(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @returns {string}
     */
    get endpointId() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.browsernode_endpointId(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @param {Uint8Array | null} [secret]
     * @returns {Promise<BrowserNode>}
     */
    static start(secret) {
        var ptr0 = isLikeNone(secret) ? 0 : passArray8ToWasm0(secret, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        const ret = wasm.browsernode_start(ptr0, len0);
        return ret;
    }
}
if (Symbol.dispose) BrowserNode.prototype[Symbol.dispose] = BrowserNode.prototype.free;

export class BrowserStream {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(BrowserStream.prototype);
        obj.__wbg_ptr = ptr;
        BrowserStreamFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BrowserStreamFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_browserstream_free(ptr, 0);
    }
    /**
     * @returns {Promise<void>}
     */
    closeSend() {
        const ret = wasm.browserstream_closeSend(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<Uint8Array>}
     */
    read() {
        const ret = wasm.browserstream_read(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {Uint8Array} bytes
     * @returns {Promise<void>}
     */
    send(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.browserstream_send(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
}
if (Symbol.dispose) BrowserStream.prototype[Symbol.dispose] = BrowserStream.prototype.free;

export class IntoUnderlyingByteSource {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        IntoUnderlyingByteSourceFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_intounderlyingbytesource_free(ptr, 0);
    }
    /**
     * @returns {number}
     */
    get autoAllocateChunkSize() {
        const ret = wasm.intounderlyingbytesource_autoAllocateChunkSize(this.__wbg_ptr);
        return ret >>> 0;
    }
    cancel() {
        const ptr = this.__destroy_into_raw();
        wasm.intounderlyingbytesource_cancel(ptr);
    }
    /**
     * @param {ReadableByteStreamController} controller
     * @returns {Promise<any>}
     */
    pull(controller) {
        const ret = wasm.intounderlyingbytesource_pull(this.__wbg_ptr, controller);
        return ret;
    }
    /**
     * @param {ReadableByteStreamController} controller
     */
    start(controller) {
        wasm.intounderlyingbytesource_start(this.__wbg_ptr, controller);
    }
    /**
     * @returns {ReadableStreamType}
     */
    get type() {
        const ret = wasm.intounderlyingbytesource_type(this.__wbg_ptr);
        return __wbindgen_enum_ReadableStreamType[ret];
    }
}
if (Symbol.dispose) IntoUnderlyingByteSource.prototype[Symbol.dispose] = IntoUnderlyingByteSource.prototype.free;

export class IntoUnderlyingSink {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        IntoUnderlyingSinkFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_intounderlyingsink_free(ptr, 0);
    }
    /**
     * @param {any} reason
     * @returns {Promise<any>}
     */
    abort(reason) {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.intounderlyingsink_abort(ptr, reason);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    close() {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.intounderlyingsink_close(ptr);
        return ret;
    }
    /**
     * @param {any} chunk
     * @returns {Promise<any>}
     */
    write(chunk) {
        const ret = wasm.intounderlyingsink_write(this.__wbg_ptr, chunk);
        return ret;
    }
}
if (Symbol.dispose) IntoUnderlyingSink.prototype[Symbol.dispose] = IntoUnderlyingSink.prototype.free;

export class IntoUnderlyingSource {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        IntoUnderlyingSourceFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_intounderlyingsource_free(ptr, 0);
    }
    cancel() {
        const ptr = this.__destroy_into_raw();
        wasm.intounderlyingsource_cancel(ptr);
    }
    /**
     * @param {ReadableStreamDefaultController} controller
     * @returns {Promise<any>}
     */
    pull(controller) {
        const ret = wasm.intounderlyingsource_pull(this.__wbg_ptr, controller);
        return ret;
    }
}
if (Symbol.dispose) IntoUnderlyingSource.prototype[Symbol.dispose] = IntoUnderlyingSource.prototype.free;

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

export class WasmBlobEngine {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmBlobEngineFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmblobengine_free(ptr, 0);
    }
    /**
     * @param {Uint8Array} data
     * @param {string} name
     * @param {string} media_type
     * @param {string | null} [node_endpoint]
     * @returns {any}
     */
    createBlob(data, name, media_type, node_endpoint) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(media_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        var ptr3 = isLikeNone(node_endpoint) ? 0 : passStringToWasm0(node_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasmblobengine_createBlob(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} hash
     * @returns {Uint8Array | undefined}
     */
    getBlob(hash) {
        const ptr0 = passStringToWasm0(hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmblobengine_getBlob(this.__wbg_ptr, ptr0, len0);
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
     * @param {string} hash
     * @returns {boolean}
     */
    hasBlob(hash) {
        const ptr0 = passStringToWasm0(hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmblobengine_hasBlob(this.__wbg_ptr, ptr0, len0);
        return ret !== 0;
    }
    constructor() {
        const ret = wasm.wasmblobengine_new();
        this.__wbg_ptr = ret >>> 0;
        WasmBlobEngineFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} ticket
     * @returns {any}
     */
    static parseTicket(ticket) {
        const ptr0 = passStringToWasm0(ticket, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmblobengine_parseTicket(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} hash
     * @param {Uint8Array} data
     */
    putBlob(hash, data) {
        const ptr0 = passStringToWasm0(hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmblobengine_putBlob(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {string} hash
     * @param {Uint8Array} data
     * @returns {boolean}
     */
    verifyBlob(hash, data) {
        const ptr0 = passStringToWasm0(hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmblobengine_verifyBlob(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
}
if (Symbol.dispose) WasmBlobEngine.prototype[Symbol.dispose] = WasmBlobEngine.prototype.free;

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

export class WasmGossipEngine {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmGossipEngineFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmgossipengine_free(ptr, 0);
    }
    /**
     * @param {string} topic_name
     * @returns {string[]}
     */
    activeNeighbors(topic_name) {
        const ptr0 = passStringToWasm0(topic_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossipengine_activeNeighbors(this.__wbg_ptr, ptr0, len0);
        var v2 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v2;
    }
    /**
     * @param {string} topic_name
     * @param {Uint8Array} content
     * @returns {any}
     */
    broadcast(topic_name, content) {
        const ptr0 = passStringToWasm0(topic_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(content, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossipengine_broadcast(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {bigint} timer_id
     * @returns {any}
     */
    expireTimer(timer_id) {
        const ret = wasm.wasmgossipengine_expireTimer(this.__wbg_ptr, timer_id);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} sender
     * @param {Uint8Array} raw_packet
     * @returns {any}
     */
    handleMessage(sender, raw_packet) {
        const ptr0 = passStringToWasm0(sender, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(raw_packet, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossipengine_handleMessage(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} topic_name
     * @param {string[]} bootstrap_peers
     * @returns {any}
     */
    joinTopic(topic_name, bootstrap_peers) {
        const ptr0 = passStringToWasm0(topic_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArrayJsValueToWasm0(bootstrap_peers, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossipengine_joinTopic(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} topic_name
     * @returns {any}
     */
    leaveTopic(topic_name) {
        const ptr0 = passStringToWasm0(topic_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossipengine_leaveTopic(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} local_peer_id
     */
    constructor(local_peer_id) {
        const ptr0 = passStringToWasm0(local_peer_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossipengine_new(ptr0, len0);
        this.__wbg_ptr = ret >>> 0;
        WasmGossipEngineFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} peer
     * @returns {any}
     */
    peerDisconnected(peer) {
        const ptr0 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmgossipengine_peerDisconnected(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
}
if (Symbol.dispose) WasmGossipEngine.prototype[Symbol.dispose] = WasmGossipEngine.prototype.free;

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
     * @param {string} workspace_id
     */
    clearGossip(workspace_id) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.wasmmeshruntimestate_clearGossip(this.__wbg_ptr, ptr0, len0);
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
    /**
     * @param {string} workspace_id
     * @param {any} endpoints
     * @returns {any}
     */
    setGossipEndpoints(workspace_id, endpoints) {
        const ptr0 = passStringToWasm0(workspace_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmmeshruntimestate_setGossipEndpoints(this.__wbg_ptr, ptr0, len0, endpoints);
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
    static decideWorkspaceAccess(raw, now_ms) {
        const ret = wasm.wasmstatecore_decideWorkspaceAccess(raw, now_ms);
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
     * @returns {any}
     */
    static validateMeshCatalog(raw) {
        const ret = wasm.wasmstatecore_validateMeshCatalog(raw);
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
 * @returns {boolean}
 */
export function browserTransportDebugLoggingEnabled() {
    const ret = wasm.browserTransportDebugLoggingEnabled();
    return ret !== 0;
}

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

/**
 * @param {boolean} enabled
 */
export function setBrowserTransportDebugLogging(enabled) {
    wasm.setBrowserTransportDebugLogging(enabled);
}

/**
 * @param {Uint8Array | null} [secret]
 * @returns {Promise<BrowserNode>}
 */
export function start_browser_node(secret) {
    var ptr0 = isLikeNone(secret) ? 0 : passArray8ToWasm0(secret, wasm.__wbindgen_malloc);
    var len0 = WASM_VECTOR_LEN;
    const ret = wasm.start_browser_node(ptr0, len0);
    return ret;
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
        __wbg__wbg_cb_unref_b46c9b5a9f08ec37: function(arg0) {
            arg0._wbg_cb_unref();
        },
        __wbg_abort_4ce5b484434ef6fd: function(arg0) {
            arg0.abort();
        },
        __wbg_abort_d53712380a54cc81: function(arg0, arg1) {
            arg0.abort(arg1);
        },
        __wbg_addEventListener_8176dab41b09531c: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            arg0.addEventListener(getStringFromWasm0(arg1, arg2), arg3);
        }, arguments); },
        __wbg_addEventListener_872d6537eadf7bec: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            arg0.addEventListener(getStringFromWasm0(arg1, arg2), arg3);
        }, arguments); },
        __wbg_addIceCandidate_ca41452441700546: function(arg0, arg1) {
            const ret = arg0.addIceCandidate(arg1);
            return ret;
        },
        __wbg_append_e8fc56ce7c00e874: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            arg0.append(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments); },
        __wbg_arrayBuffer_848c392b70c67d3d: function() { return handleError(function (arg0) {
            const ret = arg0.arrayBuffer();
            return ret;
        }, arguments); },
        __wbg_body_0c3a51aec038a31a: function(arg0) {
            const ret = arg0.body;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_browseracceptor_new: function(arg0) {
            const ret = BrowserAcceptor.__wrap(arg0);
            return ret;
        },
        __wbg_browserconnection_new: function(arg0) {
            const ret = BrowserConnection.__wrap(arg0);
            return ret;
        },
        __wbg_browsernode_new: function(arg0) {
            const ret = BrowserNode.__wrap(arg0);
            return ret;
        },
        __wbg_browserstream_new: function(arg0) {
            const ret = BrowserStream.__wrap(arg0);
            return ret;
        },
        __wbg_buffer_d0f5ea0926a691fd: function(arg0) {
            const ret = arg0.buffer;
            return ret;
        },
        __wbg_bufferedAmount_35b531bb7933bdc3: function(arg0) {
            const ret = arg0.bufferedAmount;
            return ret;
        },
        __wbg_byobRequest_dc6aed9db01b12c6: function(arg0) {
            const ret = arg0.byobRequest;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_byteLength_3e660e5661f3327e: function(arg0) {
            const ret = arg0.byteLength;
            return ret;
        },
        __wbg_byteOffset_ecd62abe44dd28d4: function(arg0) {
            const ret = arg0.byteOffset;
            return ret;
        },
        __wbg_call_14b169f759b26747: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
            return ret;
        }, arguments); },
        __wbg_call_a24592a6f349a97e: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_cancel_ceb1bda02e29f0a9: function(arg0) {
            const ret = arg0.cancel();
            return ret;
        },
        __wbg_candidate_770f2da8df8e2fd4: function(arg0, arg1) {
            const ret = arg1.candidate;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_candidate_b4c2dd5b9ce044c8: function(arg0) {
            const ret = arg0.candidate;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_catch_e9362815fd0b24cf: function(arg0, arg1) {
            const ret = arg0.catch(arg1);
            return ret;
        },
        __wbg_channel_1ce8842a9717b93a: function(arg0) {
            const ret = arg0.channel;
            return ret;
        },
        __wbg_clearTimeout_1daad5c6ee4fcd3b: function(arg0) {
            const ret = clearTimeout(arg0);
            return ret;
        },
        __wbg_clearTimeout_47a40e3be01ed7a3: function() { return handleError(function (arg0, arg1) {
            arg0.clearTimeout(arg1);
        }, arguments); },
        __wbg_close_88106990eea7f544: function() { return handleError(function (arg0) {
            arg0.close();
        }, arguments); },
        __wbg_close_c2f057da49646ced: function(arg0) {
            arg0.close();
        },
        __wbg_close_e6c8977a002e9e13: function() { return handleError(function (arg0) {
            arg0.close();
        }, arguments); },
        __wbg_close_fb954dfaf67b5732: function() { return handleError(function (arg0) {
            arg0.close();
        }, arguments); },
        __wbg_code_c4f315d8dc91de14: function(arg0) {
            const ret = arg0.code;
            return ret;
        },
        __wbg_code_e2d14bb68011f972: function(arg0) {
            const ret = arg0.code;
            return ret;
        },
        __wbg_createAnswer_c3b85ae3f2b2063c: function(arg0) {
            const ret = arg0.createAnswer();
            return ret;
        },
        __wbg_createDataChannel_9d1347f2a2f1f331: function(arg0, arg1, arg2, arg3) {
            const ret = arg0.createDataChannel(getStringFromWasm0(arg1, arg2), arg3);
            return ret;
        },
        __wbg_createOffer_5d9288d2b3b397b6: function(arg0) {
            const ret = arg0.createOffer();
            return ret;
        },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_data_bb9dffdd1e99cf2d: function(arg0) {
            const ret = arg0.data;
            return ret;
        },
        __wbg_debug_c014a160490283dc: function(arg0) {
            console.debug(arg0);
        },
        __wbg_done_9158f7cc8751ba32: function(arg0) {
            const ret = arg0.done;
            return ret;
        },
        __wbg_enqueue_4767ce322820c94d: function() { return handleError(function (arg0, arg1) {
            arg0.enqueue(arg1);
        }, arguments); },
        __wbg_entries_bf727fcd7bf35a41: function(arg0) {
            const ret = arg0.entries();
            return ret;
        },
        __wbg_entries_e0b73aa8571ddb56: function(arg0) {
            const ret = Object.entries(arg0);
            return ret;
        },
        __wbg_error_2001591ad2463697: function(arg0) {
            console.error(arg0);
        },
        __wbg_fetch_0d322c0aed196b8b: function(arg0, arg1) {
            const ret = arg0.fetch(arg1);
            return ret;
        },
        __wbg_fetch_7a37768ab67c5bd8: function(arg0) {
            const ret = fetch(arg0);
            return ret;
        },
        __wbg_from_0dbf29f09e7fb200: function(arg0) {
            const ret = Array.from(arg0);
            return ret;
        },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_getRandomValues_cc7f052a444bb2ce: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getReader_9facd4f899beac89: function() { return handleError(function (arg0) {
            const ret = arg0.getReader();
            return ret;
        }, arguments); },
        __wbg_get_1affdbdd5573b16a: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_6011fa3a58f61074: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_8360291721e2339f: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_done_282bca5d3f90e0a8: function(arg0) {
            const ret = arg0.done;
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg_get_unchecked_17f53dad852b9588: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_value_65a7a2c60b42fd75: function(arg0) {
            const ret = arg0.value;
            return ret;
        },
        __wbg_get_with_ref_key_6412cf3094599694: function(arg0, arg1) {
            const ret = arg0[arg1];
            return ret;
        },
        __wbg_has_880f1d472f7cecba: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.has(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_headers_6022deb4e576fb8e: function(arg0) {
            const ret = arg0.headers;
            return ret;
        },
        __wbg_info_7479429238bffbce: function(arg0) {
            console.info(arg0);
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
        __wbg_instanceof_Blob_10148a11a16aee87: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Blob;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Error_6872d63ba7922898: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Error;
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
        __wbg_instanceof_Response_9b2d111407865ff2: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Response;
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
        __wbg_message_cb4f84ee66e5e341: function(arg0) {
            const ret = arg0.message;
            return ret;
        },
        __wbg_message_ec476bcf269dd7c4: function(arg0, arg1) {
            const ret = arg1.message;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_name_d3c35622d14bb080: function(arg0) {
            const ret = arg0.name;
            return ret;
        },
        __wbg_new_0c7403db6e782f19: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_15a4889b4b90734d: function() { return handleError(function () {
            const ret = new Headers();
            return ret;
        }, arguments); },
        __wbg_new_2a6e9133304ae2bf: function() { return handleError(function (arg0, arg1) {
            const ret = new WebSocket(getStringFromWasm0(arg0, arg1));
            return ret;
        }, arguments); },
        __wbg_new_34d45cc8e36aaead: function() {
            const ret = new Map();
            return ret;
        },
        __wbg_new_5e360d2ff7b9e1c3: function(arg0, arg1) {
            const ret = new Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_682678e2f47e32bc: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_98c22165a42231aa: function() { return handleError(function () {
            const ret = new AbortController();
            return ret;
        }, arguments); },
        __wbg_new_aa8d0fa9762c29bd: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_from_slice_b5ea43e23f6008c0: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_typed_323f37fd55ab048d: function(arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___js_sys_a2fff126d43a4d3e___Function_fn_wasm_bindgen_b3c7b8e9241432f4___JsValue_____wasm_bindgen_b3c7b8e9241432f4___sys__Undefined___js_sys_a2fff126d43a4d3e___Function_fn_wasm_bindgen_b3c7b8e9241432f4___JsValue_____wasm_bindgen_b3c7b8e9241432f4___sys__Undefined_______true_(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = 0;
            }
        },
        __wbg_new_with_byte_offset_and_length_01848e8d6a3d49ad: function(arg0, arg1, arg2) {
            const ret = new Uint8Array(arg0, arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_new_with_configuration_83fa420a48d71a6d: function() { return handleError(function (arg0) {
            const ret = new RTCPeerConnection(arg0);
            return ret;
        }, arguments); },
        __wbg_new_with_length_8c854e41ea4dae9b: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_new_with_str_and_init_897be1708e42f39d: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = new Request(getStringFromWasm0(arg0, arg1), arg2);
            return ret;
        }, arguments); },
        __wbg_new_with_str_sequence_6453b755acdcc2e7: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = new WebSocket(getStringFromWasm0(arg0, arg1), arg2);
            return ret;
        }, arguments); },
        __wbg_next_0340c4ae324393c3: function() { return handleError(function (arg0) {
            const ret = arg0.next();
            return ret;
        }, arguments); },
        __wbg_next_7646edaa39458ef7: function(arg0) {
            const ret = arg0.next;
            return ret;
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_a9b7df1cbee90986: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_now_e7c6795a7f81e10f: function(arg0) {
            const ret = arg0.now();
            return ret;
        },
        __wbg_performance_3fcf6e32a7e1ed0a: function(arg0) {
            const ret = arg0.performance;
            return ret;
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_protocol_b901d6b01a8d0d83: function(arg0, arg1) {
            const ret = arg1.protocol;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_prototypesetcall_a6b02eb00b0f4ce2: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_push_471a5b068a5295f6: function(arg0, arg1) {
            const ret = arg0.push(arg1);
            return ret;
        },
        __wbg_queueMicrotask_5d15a957e6aa920e: function(arg0) {
            queueMicrotask(arg0);
        },
        __wbg_queueMicrotask_f8819e5ffc402f36: function(arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_read_ddc2d178d2e57272: function(arg0) {
            const ret = arg0.read();
            return ret;
        },
        __wbg_readyState_0d7e7e7154c7bc89: function(arg0) {
            const ret = arg0.readyState;
            return (__wbindgen_enum_RtcDataChannelState.indexOf(ret) + 1 || 5) - 1;
        },
        __wbg_readyState_c78e609c7de3b381: function(arg0) {
            const ret = arg0.readyState;
            return ret;
        },
        __wbg_reason_e943590a4ef0d587: function(arg0, arg1) {
            const ret = arg1.reason;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_releaseLock_9baaf3ccc5cfad69: function(arg0) {
            arg0.releaseLock();
        },
        __wbg_removeEventListener_0634324250b098cc: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            arg0.removeEventListener(getStringFromWasm0(arg1, arg2), arg3);
        }, arguments); },
        __wbg_removeEventListener_7bdf07404d9b24bd: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            arg0.removeEventListener(getStringFromWasm0(arg1, arg2), arg3);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_resolve_e6c466bc1052f16c: function(arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        },
        __wbg_respond_008ca9525ae22847: function() { return handleError(function (arg0, arg1) {
            arg0.respond(arg1 >>> 0);
        }, arguments); },
        __wbg_sdpMLineIndex_9eeb1e97bcdbea9d: function(arg0) {
            const ret = arg0.sdpMLineIndex;
            return isLikeNone(ret) ? 0xFFFFFF : ret;
        },
        __wbg_sdpMid_0be5d24b5eec5543: function(arg0, arg1) {
            const ret = arg1.sdpMid;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_send_15358dbe221c6258: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.send(getStringFromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_send_186c85704c7f2d00: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.send(getArrayU8FromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_send_ec54dbf167bba1d4: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.send(getArrayU8FromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_setLocalDescription_f325e5e4b975443c: function(arg0, arg1) {
            const ret = arg0.setLocalDescription(arg1);
            return ret;
        },
        __wbg_setRemoteDescription_808ec45573e321da: function(arg0, arg1) {
            const ret = arg0.setRemoteDescription(arg1);
            return ret;
        },
        __wbg_setTimeout_6613a51400c1bf9f: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.setTimeout(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_setTimeout_b4a9096784635514: function(arg0, arg1) {
            const ret = setTimeout(arg0, arg1);
            return ret;
        },
        __wbg_set_022bee52d0b05b19: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = Reflect.set(arg0, arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_set_3bf1de9fab0cd644: function(arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        },
        __wbg_set_3d484eb794afec82: function(arg0, arg1, arg2) {
            arg0.set(getArrayU8FromWasm0(arg1, arg2));
        },
        __wbg_set_6be42768c690e380: function(arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        },
        __wbg_set_binaryType_770e68648ca5e83d: function(arg0, arg1) {
            arg0.binaryType = __wbindgen_enum_BinaryType[arg1];
        },
        __wbg_set_binaryType_aa93f40df43c7629: function(arg0, arg1) {
            arg0.binaryType = __wbindgen_enum_RtcDataChannelType[arg1];
        },
        __wbg_set_body_be11680f34217f75: function(arg0, arg1) {
            arg0.body = arg1;
        },
        __wbg_set_bufferedAmountLowThreshold_d0cc9561ff04ed40: function(arg0, arg1) {
            arg0.bufferedAmountLowThreshold = arg1 >>> 0;
        },
        __wbg_set_cache_968edea422613d1b: function(arg0, arg1) {
            arg0.cache = __wbindgen_enum_RequestCache[arg1];
        },
        __wbg_set_candidate_4e0df3162610f37e: function(arg0, arg1, arg2) {
            arg0.candidate = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_credentials_6577be90e0e85eb6: function(arg0, arg1) {
            arg0.credentials = __wbindgen_enum_RequestCredentials[arg1];
        },
        __wbg_set_fde2cec06c23692b: function(arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        },
        __wbg_set_handle_event_18c81b21e4853d37: function(arg0, arg1) {
            arg0.handleEvent = arg1;
        },
        __wbg_set_headers_50fc01786240a440: function(arg0, arg1) {
            arg0.headers = arg1;
        },
        __wbg_set_ice_servers_cc143896b6f29661: function(arg0, arg1) {
            arg0.iceServers = arg1;
        },
        __wbg_set_max_retransmits_f2ba7a76b35dc98c: function(arg0, arg1) {
            arg0.maxRetransmits = arg1;
        },
        __wbg_set_method_c9f1f985f6b6c427: function(arg0, arg1, arg2) {
            arg0.method = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_mode_5e08d503428c06b9: function(arg0, arg1) {
            arg0.mode = __wbindgen_enum_RequestMode[arg1];
        },
        __wbg_set_onclose_17fa3bbcc4ba3541: function(arg0, arg1) {
            arg0.onclose = arg1;
        },
        __wbg_set_onclose_7666b6e1cc1cccb8: function(arg0, arg1) {
            arg0.onclose = arg1;
        },
        __wbg_set_ondatachannel_09eaf307af12de3a: function(arg0, arg1) {
            arg0.ondatachannel = arg1;
        },
        __wbg_set_onerror_a98be4cd402fcca9: function(arg0, arg1) {
            arg0.onerror = arg1;
        },
        __wbg_set_onerror_da99c4232662a084: function(arg0, arg1) {
            arg0.onerror = arg1;
        },
        __wbg_set_onicecandidate_39803e5d172e0d96: function(arg0, arg1) {
            arg0.onicecandidate = arg1;
        },
        __wbg_set_onmessage_bd4aa1a3b666a5d6: function(arg0, arg1) {
            arg0.onmessage = arg1;
        },
        __wbg_set_onmessage_c1db358b9c38e3f1: function(arg0, arg1) {
            arg0.onmessage = arg1;
        },
        __wbg_set_onopen_cd47b8fb1d92dee9: function(arg0, arg1) {
            arg0.onopen = arg1;
        },
        __wbg_set_onopen_ec0cde8f1f91369b: function(arg0, arg1) {
            arg0.onopen = arg1;
        },
        __wbg_set_ordered_5e7b4b0df35404a1: function(arg0, arg1) {
            arg0.ordered = arg1 !== 0;
        },
        __wbg_set_protocol_de4294341c987ce5: function(arg0, arg1, arg2) {
            arg0.protocol = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_referrer_478d9a69d0d97a98: function(arg0, arg1, arg2) {
            arg0.referrer = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_referrer_policy_84fedaa88bc9d667: function(arg0, arg1) {
            arg0.referrerPolicy = __wbindgen_enum_ReferrerPolicy[arg1];
        },
        __wbg_set_sdp_1b3512f1d4d75443: function(arg0, arg1, arg2) {
            arg0.sdp = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_sdp_m_line_index_76cc4410489904ec: function(arg0, arg1) {
            arg0.sdpMLineIndex = arg1 === 0xFFFFFF ? undefined : arg1;
        },
        __wbg_set_sdp_mid_612df723a380cb7a: function(arg0, arg1, arg2) {
            arg0.sdpMid = arg1 === 0 ? undefined : getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_signal_1d4e73c2305a0e7c: function(arg0, arg1) {
            arg0.signal = arg1;
        },
        __wbg_set_type_e681927393d674ce: function(arg0, arg1) {
            arg0.type = __wbindgen_enum_RtcSdpType[arg1];
        },
        __wbg_signal_fdc54643b47bf85b: function(arg0) {
            const ret = arg0.signal;
            return ret;
        },
        __wbg_static_accessor_GLOBAL_8cfadc87a297ca02: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_602256ae5c8f42cf: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_e445c1c7484aecc3: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_f20e8576ef1e0f17: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_status_43e0d2f15b22d69f: function(arg0) {
            const ret = arg0.status;
            return ret;
        },
        __wbg_stringify_91082ed7a5a5769e: function() { return handleError(function (arg0) {
            const ret = JSON.stringify(arg0);
            return ret;
        }, arguments); },
        __wbg_subarray_f8ca46a25b1f5e0d: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_then_792e0c862b060889: function(arg0, arg1, arg2) {
            const ret = arg0.then(arg1, arg2);
            return ret;
        },
        __wbg_then_8e16ee11f05e4827: function(arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        },
        __wbg_url_2bf741820e6563a0: function(arg0, arg1) {
            const ret = arg1.url;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_url_7e153eff46938d20: function(arg0, arg1) {
            const ret = arg1.url;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_value_ee3a06f4579184fa: function(arg0) {
            const ret = arg0.value;
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbg_view_701664ffb3b1ce67: function(arg0) {
            const ret = arg0.view;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_warn_3cc416af27dbdc02: function(arg0) {
            console.warn(arg0);
        },
        __wbg_wasClean_bd109e45fffa711a: function(arg0) {
            const ret = arg0.wasClean;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 3554, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___wasm_bindgen_b3c7b8e9241432f4___JsValue______true_);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 6170, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___wasm_bindgen_b3c7b8e9241432f4___JsValue__core_ed718c3d60ebd546___result__Result_____wasm_bindgen_b3c7b8e9241432f4___JsError___true_);
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("CloseEvent")], shim_idx: 3113, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_CloseEvent__CloseEvent______true_);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("Event")], shim_idx: 1582, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_RtcDataChannelEvent__RtcDataChannelEvent______true_);
            return ret;
        },
        __wbindgen_cast_0000000000000005: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("MessageEvent")], shim_idx: 4044, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_MessageEvent__MessageEvent______true_);
            return ret;
        },
        __wbindgen_cast_0000000000000006: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("RTCDataChannelEvent")], shim_idx: 1582, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_RtcDataChannelEvent__RtcDataChannelEvent______true__5);
            return ret;
        },
        __wbindgen_cast_0000000000000007: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("RTCPeerConnectionIceEvent")], shim_idx: 1582, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_RtcDataChannelEvent__RtcDataChannelEvent______true__6);
            return ret;
        },
        __wbindgen_cast_0000000000000008: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [], shim_idx: 3503, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true_);
            return ret;
        },
        __wbindgen_cast_0000000000000009: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [], shim_idx: 3563, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true__1_);
            return ret;
        },
        __wbindgen_cast_000000000000000a: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [], shim_idx: 3586, ret: Unit, inner_ret: Some(Unit) }, mutable: false }) -> Externref`.
            const ret = makeClosure(arg0, arg1, wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true__2_);
            return ret;
        },
        __wbindgen_cast_000000000000000b: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [], shim_idx: 5279, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true__3_);
            return ret;
        },
        __wbindgen_cast_000000000000000c: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_000000000000000d: function(arg0) {
            // Cast intrinsic for `I64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_000000000000000e: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_000000000000000f: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000010: function(arg0) {
            // Cast intrinsic for `U64 -> Externref`.
            const ret = BigInt.asUintN(64, arg0);
            return ret;
        },
        __wbindgen_cast_0000000000000011: function(arg0, arg1) {
            var v0 = getArrayU8FromWasm0(arg0, arg1).slice();
            wasm.__wbindgen_free(arg0, arg1 * 1, 1);
            // Cast intrinsic for `Vector(U8) -> Externref`.
            const ret = v0;
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
        "./meta_mesh_bg.js": import0,
    };
}

function wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true_(arg0, arg1) {
    wasm.wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true_(arg0, arg1);
}

function wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true__1_(arg0, arg1) {
    wasm.wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true__1_(arg0, arg1);
}

function wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true__2_(arg0, arg1) {
    wasm.wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true__2_(arg0, arg1);
}

function wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true__3_(arg0, arg1) {
    wasm.wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke_______true__3_(arg0, arg1);
}

function wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___wasm_bindgen_b3c7b8e9241432f4___JsValue______true_(arg0, arg1, arg2) {
    wasm.wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___wasm_bindgen_b3c7b8e9241432f4___JsValue______true_(arg0, arg1, arg2);
}

function wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_CloseEvent__CloseEvent______true_(arg0, arg1, arg2) {
    wasm.wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_CloseEvent__CloseEvent______true_(arg0, arg1, arg2);
}

function wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_RtcDataChannelEvent__RtcDataChannelEvent______true_(arg0, arg1, arg2) {
    wasm.wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_RtcDataChannelEvent__RtcDataChannelEvent______true_(arg0, arg1, arg2);
}

function wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_MessageEvent__MessageEvent______true_(arg0, arg1, arg2) {
    wasm.wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_MessageEvent__MessageEvent______true_(arg0, arg1, arg2);
}

function wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_RtcDataChannelEvent__RtcDataChannelEvent______true__5(arg0, arg1, arg2) {
    wasm.wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_RtcDataChannelEvent__RtcDataChannelEvent______true__5(arg0, arg1, arg2);
}

function wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_RtcDataChannelEvent__RtcDataChannelEvent______true__6(arg0, arg1, arg2) {
    wasm.wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___web_sys_8faf822951051c1a___features__gen_RtcDataChannelEvent__RtcDataChannelEvent______true__6(arg0, arg1, arg2);
}

function wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___wasm_bindgen_b3c7b8e9241432f4___JsValue__core_ed718c3d60ebd546___result__Result_____wasm_bindgen_b3c7b8e9241432f4___JsError___true_(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___wasm_bindgen_b3c7b8e9241432f4___JsValue__core_ed718c3d60ebd546___result__Result_____wasm_bindgen_b3c7b8e9241432f4___JsError___true_(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___js_sys_a2fff126d43a4d3e___Function_fn_wasm_bindgen_b3c7b8e9241432f4___JsValue_____wasm_bindgen_b3c7b8e9241432f4___sys__Undefined___js_sys_a2fff126d43a4d3e___Function_fn_wasm_bindgen_b3c7b8e9241432f4___JsValue_____wasm_bindgen_b3c7b8e9241432f4___sys__Undefined_______true_(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen_b3c7b8e9241432f4___convert__closures_____invoke___js_sys_a2fff126d43a4d3e___Function_fn_wasm_bindgen_b3c7b8e9241432f4___JsValue_____wasm_bindgen_b3c7b8e9241432f4___sys__Undefined___js_sys_a2fff126d43a4d3e___Function_fn_wasm_bindgen_b3c7b8e9241432f4___JsValue_____wasm_bindgen_b3c7b8e9241432f4___sys__Undefined_______true_(arg0, arg1, arg2, arg3);
}


const __wbindgen_enum_BinaryType = ["blob", "arraybuffer"];


const __wbindgen_enum_ReadableStreamType = ["bytes"];


const __wbindgen_enum_ReferrerPolicy = ["", "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "unsafe-url", "same-origin", "strict-origin", "strict-origin-when-cross-origin"];


const __wbindgen_enum_RequestCache = ["default", "no-store", "reload", "no-cache", "force-cache", "only-if-cached"];


const __wbindgen_enum_RequestCredentials = ["omit", "same-origin", "include"];


const __wbindgen_enum_RequestMode = ["same-origin", "no-cors", "cors", "navigate"];


const __wbindgen_enum_RtcDataChannelState = ["connecting", "open", "closing", "closed"];


const __wbindgen_enum_RtcDataChannelType = ["arraybuffer", "blob"];


const __wbindgen_enum_RtcSdpType = ["offer", "pranswer", "answer", "rollback"];
const BrowserAcceptorFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_browseracceptor_free(ptr >>> 0, 1));
const BrowserConnectionFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_browserconnection_free(ptr >>> 0, 1));
const BrowserNodeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_browsernode_free(ptr >>> 0, 1));
const BrowserStreamFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_browserstream_free(ptr >>> 0, 1));
const IntoUnderlyingByteSourceFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_intounderlyingbytesource_free(ptr >>> 0, 1));
const IntoUnderlyingSinkFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_intounderlyingsink_free(ptr >>> 0, 1));
const IntoUnderlyingSourceFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_intounderlyingsource_free(ptr >>> 0, 1));
const WasmAutomergeSyncEngineFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmautomergesyncengine_free(ptr >>> 0, 1));
const WasmBlobEngineFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmblobengine_free(ptr >>> 0, 1));
const WasmDeviceRouteCatalogFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmdeviceroutecatalog_free(ptr >>> 0, 1));
const WasmGossipEngineFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmgossipengine_free(ptr >>> 0, 1));
const WasmIdentityCryptoFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmidentitycrypto_free(ptr >>> 0, 1));
const WasmInvitationsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasminvitations_free(ptr >>> 0, 1));
const WasmMeshAuthenticatedSessionsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmmeshauthenticatedsessions_free(ptr >>> 0, 1));
const WasmMeshHandshakeFlowFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmmeshhandshakeflow_free(ptr >>> 0, 1));
const WasmMeshRuntimeStateFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmmeshruntimestate_free(ptr >>> 0, 1));
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

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => wasm.__wbindgen_destroy_closure(state.a, state.b));

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

function makeClosure(arg0, arg1, f) {
    const state = { a: arg0, b: arg1, cnt: 1 };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        try {
            return f(state.a, state.b, ...args);
        } finally {
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            wasm.__wbindgen_destroy_closure(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function makeMutClosure(arg0, arg1, f) {
    const state = { a: arg0, b: arg1, cnt: 1 };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            wasm.__wbindgen_destroy_closure(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
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

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    for (let i = 0; i < array.length; i++) {
        const add = addToExternrefTable0(array[i]);
        getDataViewMemory0().setUint32(ptr + 4 * i, add, true);
    }
    WASM_VECTOR_LEN = array.length;
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
        module_or_path = new URL('meta_mesh_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
