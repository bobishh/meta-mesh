import { meshRustRuntime, type RustMeshRuntimeState } from "@meta-uber/mesh-replication/runtime"

export type { RustMeshRuntimeState as MeshRuntimeState }

/** Creates the shared Rust/WASM mesh runtime state machine. */
export function createMeshRuntime(): RustMeshRuntimeState {
  return meshRustRuntime().createMeshRuntimeState()
}
