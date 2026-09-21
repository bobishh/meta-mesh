import { meshRustRuntime, type RustMeshRuntimeState } from "@meta-uber/mesh-replication/runtime"

export type { RustMeshRuntimeState as MeshRuntimeState }

/** Creates the shared Rust/WASM mesh runtime state machine. */
export function createMeshRuntime(): RustMeshRuntimeState {
  return meshRustRuntime().createMeshRuntimeState()
}

export function* controlFrames(workspaceId: string, bytes: Uint8Array): Generator<Uint8Array> {
  const runtime = createMeshRuntime()
  try {
    for (const frame of runtime.controlFrames(workspaceId, bytes)) yield Uint8Array.from(frame)
  } finally {
    runtime.free?.()
  }
}

export class ControlFrameReceiver {
  private readonly runtime = createMeshRuntime()

  constructor(private readonly workspaceId: string) {}

  receive(bytes: Uint8Array): Uint8Array | undefined {
    return this.runtime.receiveControlFrame(this.workspaceId, bytes)
  }

  free() {
    this.runtime.free?.()
  }
}
