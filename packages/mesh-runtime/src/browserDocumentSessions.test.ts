import { describe, expect, it, vi } from "vitest"
import { BrowserMeshDocumentSessions } from "./browserDocumentSessions"

type Engine = { reset: ReturnType<typeof vi.fn> }
type Session = { mode: "legacy" | "incremental" }
type Profile = { deviceId: string; personId: string }
type Credential = { secret: string }

function fixture() {
  const engines: Engine[] = []
  const host = {
    localDeviceId: (profile: Profile) => profile.deviceId,
    localPersonId: (profile: Profile) => profile.personId,
    secret: (credential: Credential) => credential.secret,
    createEngine: vi.fn(() => {
      const engine = { reset: vi.fn() }
      engines.push(engine)
      return engine
    }),
    legacy: vi.fn((_input: unknown): Session => ({ mode: "legacy" })),
    incremental: vi.fn((_input: any): Session => ({ mode: "incremental" })),
    ownerWorkspaceOffer: vi.fn(async () => undefined),
    gossipPacket: vi.fn(async () => undefined),
    rejected: vi.fn(),
    cleared: vi.fn(),
    trace: vi.fn(),
  }
  return { runtime: new BrowserMeshDocumentSessions<unknown, Session, Credential, Profile, Engine>(host), host, engines }
}

const base = {
  connection: {}, credential: { secret: "secret" }, workspaceId: "workspace", deviceId: "remote-device",
  instanceId: "instance-a", profile: { deviceId: "local-device", personId: "same-person" }, connectionId: "out-1",
  remotePersonId: "same-person", ownerWorkspaceSupported: true, remoteEndpoint: "endpoint-a",
}

describe("BrowserMeshDocumentSessions", () => {
  it("keeps legacy peers out of the incremental engine", () => {
    const { runtime, host } = fixture()
    const created = runtime.create({ ...base, incrementalSupported: false })
    expect(created.session).toEqual({ mode: "legacy" })
    expect(created.reset).toBeUndefined()
    expect(host.createEngine).not.toHaveBeenCalled()
  })

  it("owns one incremental engine per remote instance and resets it on eviction", () => {
    const { runtime, host, engines } = fixture()
    const first = runtime.create({ ...base, incrementalSupported: true })
    const again = runtime.create({ ...base, connectionId: "out-2", incrementalSupported: true })
    const sibling = runtime.create({ ...base, instanceId: "instance-b", incrementalSupported: true })

    expect(host.createEngine).toHaveBeenCalledTimes(2)
    expect(host.incremental.mock.calls[0]![0].engine).toBe(host.incremental.mock.calls[1]![0].engine)
    expect(host.incremental.mock.calls[2]![0].engine).not.toBe(host.incremental.mock.calls[0]![0].engine)
    first.reset?.()
    expect(engines[0]!.reset).toHaveBeenCalledWith("workspace", "remote-device")
    expect(again.session).toEqual({ mode: "incremental" })
    expect(sibling.session).toEqual({ mode: "incremental" })
  })

  it("routes document status, owner offers and gossip through runtime policy", async () => {
    const { runtime, host } = fixture()
    runtime.create({ ...base, incrementalSupported: true })
    const input = host.incremental.mock.calls[0]![0]
    const rejection = new Error("unsigned change")

    input.onDocumentStatus(rejection)
    input.onDocumentStatus(null)
    await input.onOwnerWorkspaceOffer(new Uint8Array([1]))
    await input.onGossipPacket(new Uint8Array([2]))

    expect(host.rejected).toHaveBeenCalledWith("Workspace workspac from remote-d", rejection)
    expect(host.cleared).toHaveBeenCalledWith("Workspace workspac from remote-d")
    expect(host.ownerWorkspaceOffer).toHaveBeenCalledWith(new Uint8Array([1]), "same-person")
    expect(host.gossipPacket).toHaveBeenCalledWith("workspace", "endpoint-a", new Uint8Array([2]))
  })

  it("does not expose owner or gossip handlers without negotiated support", () => {
    const { runtime, host } = fixture()
    runtime.create({ ...base, incrementalSupported: true, ownerWorkspaceSupported: false, remoteEndpoint: "" })
    const input = host.incremental.mock.calls[0]![0]
    expect(input.onOwnerWorkspaceOffer).toBeUndefined()
    expect(input.onGossipPacket).toBeUndefined()
  })
})
