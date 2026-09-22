import { describe, expect, it, vi } from "vitest"
import { BrowserMeshHandshake } from "./browserHandshake"

const request = { workspaceId: "workspace", peer: {} as never, revocations: [], ownershipTransfers: [], successionVotes: [], successionClaims: [], capabilities: ["heartbeat-v1"] }
const response = { ...request, peer: {} as never }

describe("BrowserMeshHandshake", () => {
  it("merges authority before installing an authenticated inbound session", async () => {
    const send = vi.fn(async () => {})
    const stream = { read: vi.fn(async () => new Uint8Array([1])), send, closeSend: vi.fn(async () => {}) }
    const connection = { acceptStream: vi.fn(async () => stream), close: vi.fn(async () => {}) }
    const merged = { id: "merged", secret: "secret", workspaceId: "workspace" }
    const host = {
      credentials: vi.fn(async () => [{ id: "stored", secret: "secret", workspaceId: "workspace" }]),
      secret: (credential: typeof merged) => credential.secret,
      workspaceId: (credential: typeof merged) => credential.workspaceId,
      mergeAuthority: vi.fn(async () => merged),
      verifyPeer: vi.fn(async () => ({ deviceId: "remote", instanceId: "slot", issuedAt: "2026-01-01T00:00:00.000Z", personId: "person", endpoint: "endpoint" })),
      revoked: () => false, revocations: () => [], ownBundle: vi.fn(async () => ({} as never)),
      response: vi.fn(async () => response), putVerifiedBundle: vi.fn(async () => {}),
      install: vi.fn(async () => true), afterInstalled: vi.fn(async () => {}),
      trace: vi.fn(), failed: vi.fn(),
    }
    const codec = { inspect: vi.fn(() => ({ type: "mesh-handshake-request", secret: "secret" })), readRequest: vi.fn(() => request),
      features: vi.fn(() => ({ heartbeatSupported: true, incrementalSupported: false, ownershipReceiptSupported: false, ownerWorkspaceSupported: false })),
      encodeResponse: vi.fn(() => new Uint8Array([2])) } as never
    const handshake = new BrowserMeshHandshake(host, codec)

    await expect(handshake.accept(connection, undefined, "in-1")).resolves.toBe(true)

    expect(host.mergeAuthority).toHaveBeenCalledBefore(host.verifyPeer)
    expect(host.install).toHaveBeenCalledWith(expect.objectContaining({ credential: merged, connectionId: "in-1" }))
    expect(send).toHaveBeenCalledWith(new Uint8Array([2]))
    expect(host.afterInstalled).toHaveBeenCalledOnce()
  })

  it("returns the owner revocation catalog before closing a revoked peer", async () => {
    const stream = { read: vi.fn(async () => new Uint8Array([1])), send: vi.fn(async () => {}), closeSend: vi.fn(async () => {}) }
    const connection = { acceptStream: vi.fn().mockResolvedValueOnce(stream).mockRejectedValueOnce(new Error("closed")), close: vi.fn(async () => {}) }
    const credential = { secret: "secret", workspaceId: "workspace" }
    const host = {
      credentials: vi.fn(async () => [credential]), secret: () => "secret", workspaceId: () => "workspace", mergeAuthority: vi.fn(async () => credential),
      verifyPeer: vi.fn(async () => ({ deviceId: "remote", instanceId: "slot", issuedAt: "2026-01-01T00:00:00.000Z", personId: "revoked", endpoint: "endpoint" })),
      revoked: () => true, revocations: () => [{ payload: { personId: "revoked" } }] as never, ownBundle: vi.fn(async () => ({} as never)),
      response: vi.fn(async () => response), putVerifiedBundle: vi.fn(async () => {}), install: vi.fn(async () => true), afterInstalled: vi.fn(async () => {}), trace: vi.fn(), failed: vi.fn(),
    }
    const codec = { inspect: () => ({ type: "mesh-handshake-request", secret: "secret" }), readRequest: () => request,
      features: () => ({}), encodeResponse: vi.fn(() => new Uint8Array([2])) }
    const handshake = new BrowserMeshHandshake(host, codec as never)

    await expect(handshake.accept(connection, undefined, "in-1")).resolves.toBe(false)

    expect(codec.encodeResponse).toHaveBeenCalledWith("secret", expect.objectContaining({ revocations: [{ payload: { personId: "revoked" } }] }))
    expect(host.install).not.toHaveBeenCalled()
  })
})

describe("BrowserMeshOutgoingHandshake", () => {
  it("writes a canonical request then merges authority before returning the verified peer", async () => {
    const { BrowserMeshOutgoingHandshake } = await import("./browserHandshake")
    const stream = { read: vi.fn(async () => new Uint8Array([3])), send: vi.fn(async () => {}), closeSend: vi.fn(async () => {}) }
    const connection = { openStream: vi.fn(async () => stream) }
    const credential = { secret: "secret", workspaceId: "workspace" }
    const response = { ...request, peer: {} as never }
    const host = {
      secret: () => "secret", workspaceId: () => "workspace", request: vi.fn(async () => request),
      mergeAuthority: vi.fn(async () => credential),
      verifyPeer: vi.fn(async () => ({ deviceId: "remote", instanceId: "slot", issuedAt: "2026-01-01T00:00:00.000Z", personId: "person", endpoint: "endpoint" })),
      putVerifiedBundle: vi.fn(async () => {}), trace: vi.fn(),
    }
    const codec = { encodeRequest: vi.fn(() => new Uint8Array([2])), readResponse: vi.fn(() => response),
      features: vi.fn(() => ({ heartbeatSupported: false, incrementalSupported: true, ownershipReceiptSupported: false, ownerWorkspaceSupported: false })) }
    const handshake = new BrowserMeshOutgoingHandshake(host, codec as never)

    const result = await handshake.exchange(connection, credential, "out-1", "remote")

    expect(stream.send).toHaveBeenCalledWith(new Uint8Array([2]))
    expect(host.mergeAuthority).toHaveBeenCalledBefore(host.verifyPeer)
    expect(result.remote.deviceId).toBe("remote")
  })
})
