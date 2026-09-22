import { decodePairingFrame, encodePairingFrame, inspectPairingFrame } from "@meta-uber/mesh-pairing"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
import type {
  WorkspaceDeparture, WorkspaceDeviceRevocation, WorkspaceBreakGlassClaim, WorkspaceMemberBundle, WorkspaceOwnershipTransfer, WorkspaceRevocation,
  WorkspaceSuccessionClaim, WorkspaceSuccessionPolicy, WorkspaceSuccessionVote,
} from "@meta-uber/mesh-workspace"

export type MeshHandshakePayload = {
  workspaceId: string
  departures?: WorkspaceDeparture[]
  deviceRevocations?: WorkspaceDeviceRevocation[]
  peer: WorkspaceMemberBundle
  revocations: WorkspaceRevocation[]
  ownershipTransfers: WorkspaceOwnershipTransfer[]
  breakGlassClaims: WorkspaceBreakGlassClaim[]
  successionPolicy?: WorkspaceSuccessionPolicy
  successionVotes: WorkspaceSuccessionVote[]
  successionClaims: WorkspaceSuccessionClaim[]
  ownerWorkspaceIds?: string[]
  capabilities: string[]
}

export type MeshHandshakeFeatures = {
  heartbeatSupported: boolean
  incrementalSupported: boolean
  ownershipReceiptSupported: boolean
  ownerWorkspaceSupported: boolean
  ownerWorkspaceOfferFrame?: "mesh-owner-workspace-offer"
  blobTransferSupported: boolean
}

/** Canonical authenticated wire framing for browser, native and mobile hosts. */
export class MeshHandshakeCodec {
  validate(raw: unknown, workspaceId: string): MeshHandshakePayload {
    return meshRustRuntime().state.validateMeshHandshake(raw, workspaceId) as MeshHandshakePayload
  }

  capabilities(): string[] { return meshRustRuntime().state.meshCapabilities() }

  features(capabilities: unknown): MeshHandshakeFeatures {
    const values = Array.isArray(capabilities) ? capabilities : []
    return {
      heartbeatSupported: values.includes("heartbeat-v1"),
      incrementalSupported: values.includes("automerge-sync-v1"),
      ownershipReceiptSupported: values.includes("ownership-receipt-v1"),
      ownerWorkspaceSupported: values.includes("owner-workspace-v2"),
      ownerWorkspaceOfferFrame: values.includes("owner-workspace-v2") ? "mesh-owner-workspace-offer" : undefined,
      blobTransferSupported: values.includes("blob-transfer-v1"),
    }
  }

  encodeRequest(secret: string, payload: MeshHandshakePayload): Uint8Array {
    return encodePairingFrame("mesh-handshake-request", secret, encode(payload))
  }

  encodeResponse(secret: string, payload: MeshHandshakePayload): Uint8Array {
    return encodePairingFrame("mesh-handshake-response", secret, encode(payload))
  }

  readRequest(frame: Uint8Array, secret: string, workspaceId: string): MeshHandshakePayload {
    return this.read(frame, "mesh-handshake-request", secret, workspaceId)
  }

  readResponse(frame: Uint8Array, secret: string, workspaceId: string): MeshHandshakePayload {
    return this.read(frame, "mesh-handshake-response", secret, workspaceId)
  }

  inspect(frame: Uint8Array): { type: string; secret: string } { return inspectPairingFrame(frame) }

  private read(frame: Uint8Array, type: "mesh-handshake-request" | "mesh-handshake-response", secret: string, workspaceId: string): MeshHandshakePayload {
    let raw: unknown
    try { raw = JSON.parse(new TextDecoder().decode(decodePairingFrame(frame, type, secret))) }
    catch (error) { throw error instanceof Error ? error : new Error(String(error)) }
    return this.validate(raw, workspaceId)
  }
}

function encode(payload: MeshHandshakePayload): Uint8Array { return new TextEncoder().encode(JSON.stringify(payload)) }
