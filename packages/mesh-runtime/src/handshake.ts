import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
import type {
  WorkspaceDeparture, WorkspaceDeviceRevocation, WorkspaceMemberBundle, WorkspaceOwnershipTransfer, WorkspaceRevocation,
  WorkspaceSuccessionClaim, WorkspaceSuccessionPolicy, WorkspaceSuccessionVote,
} from "@meta-uber/mesh-workspace"

export type MeshHandshakePayload = {
  workspaceId: string
  departures?: WorkspaceDeparture[]
  deviceRevocations?: WorkspaceDeviceRevocation[]
  peer: WorkspaceMemberBundle
  revocations: WorkspaceRevocation[]
  ownershipTransfers: WorkspaceOwnershipTransfer[]
  successionPolicy?: WorkspaceSuccessionPolicy
  successionVotes: WorkspaceSuccessionVote[]
  successionClaims: WorkspaceSuccessionClaim[]
  ownerWorkspaceIds?: string[]
  capabilities: string[]
}

export type MeshHandshakeFeatures = {
  heartbeatSupported: boolean
  ownershipReceiptSupported: boolean
  ownerWorkspaceSupported: boolean
  ownerWorkspaceOfferFrame?: "mesh-owner-workspace-offer"
  blobTransferSupported: boolean
}

/** Host diagnostics around the Rust-owned mesh handshake codec. */
export class MeshHandshakeCodec {
  validate(raw: unknown, workspaceId: string): MeshHandshakePayload {
    try { return meshRustRuntime().state.validateMeshHandshake(raw, workspaceId) as MeshHandshakePayload }
    catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      if (!/Break-glass authority is no longer supported/i.test(message)) throw error
      throw new Error(`${message}. ${reportedSource(raw, workspaceId)}`)
    }
  }

  capabilities(): string[] { return meshRustRuntime().state.meshCapabilities() }

  features(capabilities: unknown): MeshHandshakeFeatures {
    return meshRustRuntime().state.meshHandshakeFeatures(Array.isArray(capabilities) ? capabilities : [])
  }

  encodeRequest(secret: string, payload: MeshHandshakePayload): Uint8Array {
    return meshRustRuntime().state.encodeMeshHandshake("mesh-handshake-request", secret, payload)
  }

  encodeResponse(secret: string, payload: MeshHandshakePayload): Uint8Array {
    return meshRustRuntime().state.encodeMeshHandshake("mesh-handshake-response", secret, payload)
  }

  readRequest(frame: Uint8Array, secret: string, workspaceId: string): MeshHandshakePayload {
    return this.read(frame, "mesh-handshake-request", secret, workspaceId)
  }

  readResponse(frame: Uint8Array, secret: string, workspaceId: string): MeshHandshakePayload {
    return this.read(frame, "mesh-handshake-response", secret, workspaceId)
  }

  inspect(frame: Uint8Array): { type: string; secret: string } {
    return meshRustRuntime().state.inspectMeshHandshake(frame)
  }

  private read(frame: Uint8Array, type: "mesh-handshake-request" | "mesh-handshake-response", secret: string, workspaceId: string): MeshHandshakePayload {
    return meshRustRuntime().state.decodeMeshHandshake(frame, type, secret, workspaceId) as MeshHandshakePayload
  }
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null
}

function label(value: unknown, maximum: number): string {
  return typeof value === "string" ? value.replace(/[\p{Cc}\p{Bidi_Control}]/gu, "").trim().slice(0, maximum) : ""
}

function reportedSource(raw: unknown, workspaceId: string): string {
  const payload = object(object(object(raw)?.peer)?.advertisement)?.payload
  const peer = object(payload)
  const name = label(peer?.deviceName, 80)
  const id = label(peer?.deviceId, 64)
  const device = name ? `"${name}"${id ? ` (${id.slice(0, 10)})` : ""}` : id || "unknown"
  return `Reported device (unverified): ${device}; workspace: ${workspaceId}`
}
