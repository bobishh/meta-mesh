import { isMeshNetworkFailure } from "@meta-uber/mesh-transport"

export class MeshDialCancelled extends Error {
  constructor() { super("Mesh dial cancelled"); this.name = "AbortError" }
}

export class MeshNodeRestart extends Error {
  constructor(readonly reason: string) { super(reason); this.name = "MeshNodeRestart" }
}

export function isMeshDialNetworkFailure(error: unknown): boolean {
  if (isMeshNetworkFailure(error)) return true
  if (error instanceof AggregateError) return error.errors.length > 0 && error.errors.every(isMeshDialNetworkFailure)
  return /all promises were rejected|no addressing information available|pkarr.*404/i.test(
    error instanceof Error ? error.message : String(error),
  )
}
