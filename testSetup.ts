import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { installMeshRustRuntime } from "@meta-uber/mesh-replication/runtime"
import {
  initSync,
  WasmAutomergeSyncEngine,
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
  createMeshRuntimeState: () => new WasmMeshRuntimeState(),
  createGossipLifecycleState: topicPrefix => new WasmGossipLifecycleState(topicPrefix),
  createMeshLifecycleState: () => new WasmMeshLifecycleState(),
  createMeshSessionLifecycleState: stableAfterMs => new WasmMeshSessionLifecycle(stableAfterMs),
  createMeshHandshakeFlow: direction => new WasmMeshHandshakeFlow(direction),
})
