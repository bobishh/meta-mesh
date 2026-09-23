import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { installMeshRustRuntime } from "@meta-uber/mesh-replication/runtime"
import {
  initSync,
  WasmAutomergeSyncEngine,
  WasmAutomergeDeviceSyncFlow,
  WasmMeshBatchDeliveryFlow,
  WasmDeviceRouteCatalog,
  WasmMeshRuntimeState,
  WasmGossipLifecycleState,
  WasmMeshLifecycleState,
  WasmMeshSessionLifecycle,
  WasmMeshHandshakeFlow,
  WasmStateCore,
} from "@meta-uber/mesh-transport/wasm"

const wasm = readFileSync(resolve(process.cwd(), "packages/mesh-transport/wasm/meta_mesh_bg.wasm"))
initSync({ module: wasm })
installMeshRustRuntime({
  state: WasmStateCore,
  createDeviceRouteCatalog: () => new WasmDeviceRouteCatalog(),
  createAutomergeSyncEngine: (localDeviceId, maximumFrameBytes) =>
    new WasmAutomergeSyncEngine(localDeviceId, maximumFrameBytes),
  createAutomergeDeviceSyncFlow: (targetDeviceId, documentId, maximumRounds) =>
    new WasmAutomergeDeviceSyncFlow(targetDeviceId, documentId, maximumRounds),
  decodeAutomergeDeviceSyncRequest: (request, expectedRemoteDeviceId) =>
    WasmAutomergeDeviceSyncFlow.decodeIncomingRequest(request, expectedRemoteDeviceId),
  encodeAutomergeDeviceSyncResponse: (batchId, ack, frame) =>
    WasmAutomergeDeviceSyncFlow.encodeResponse(batchId, ack, frame),
  createBatchDeliveryFlow: (targetDeviceId, routeInstanceIds, fallbackDelayMs, retryDelaysMs) =>
    new WasmMeshBatchDeliveryFlow(targetDeviceId, routeInstanceIds, fallbackDelayMs, retryDelaysMs),
  createMeshRuntimeState: () => new WasmMeshRuntimeState(),
  createGossipLifecycleState: topicPrefix => new WasmGossipLifecycleState(topicPrefix),
  createMeshLifecycleState: () => new WasmMeshLifecycleState(),
  createMeshSessionLifecycleState: stableAfterMs => new WasmMeshSessionLifecycle(stableAfterMs),
  createMeshHandshakeFlow: direction => new WasmMeshHandshakeFlow(direction),
})
