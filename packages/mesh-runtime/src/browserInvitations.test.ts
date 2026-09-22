import { describe, expect, it } from "vitest"
import { BrowserMeshInvitations } from "./browserInvitations"

type Credential = { workspaceId: string; ownerPersonId: string }
type Envelope = { workspaceId: string; ownerPersonId: string; peers: string[]; proof?: string }

describe("BrowserMeshInvitations", () => {
  it("builds an invitation from the credential and active peers", async () => {
    const runtime = new BrowserMeshInvitations<Credential, Envelope, string, string, undefined>({
      credential: async id => id === "one" ? { workspaceId: id, ownerPersonId: "owner" } : undefined,
      peers: async () => ["active"],
      createEnvelope: (credential, peers) => ({ workspaceId: credential.workspaceId, ownerPersonId: credential.ownerPersonId, peers }),
      isEnvelope: (value): value is Envelope => typeof value === "object" && value !== null && "workspaceId" in value && "ownerPersonId" in value && "peers" in value,
      ownerPersonId: envelope => envelope.ownerPersonId,
      mergeOwnershipProof: async credential => credential,
      install: async () => undefined,
    })

    await expect(runtime.payload(["one"])).resolves.toEqual([
      { workspaceId: "one", ownerPersonId: "owner", peers: ["active"] },
    ])
  })

  it("requires ownership proof before replacing an existing owner", async () => {
    let installed = false
    const runtime = new BrowserMeshInvitations<Credential, Envelope, string, string, undefined>({
      credential: async () => ({ workspaceId: "one", ownerPersonId: "old-owner" }),
      peers: async () => [],
      createEnvelope: credential => ({ workspaceId: credential.workspaceId, ownerPersonId: credential.ownerPersonId, peers: [] }),
      isEnvelope: (value): value is Envelope => typeof value === "object" && value !== null && "workspaceId" in value && "ownerPersonId" in value && "peers" in value,
      ownerPersonId: envelope => envelope.ownerPersonId,
      mergeOwnershipProof: async credential => credential,
      install: async () => { installed = true },
    })

    await expect(runtime.receive([{ workspaceId: "one", ownerPersonId: "new-owner", peers: [] }], ["one"], undefined, [], grant => grant)).rejects
      .toThrow("Workspace ownership proof is missing")
    expect(installed).toBe(false)
  })

  it("validates every workspace before installing the first credential", async () => {
    const installed: string[] = []
    const runtime = new BrowserMeshInvitations<Credential, Envelope, string, string, undefined>({
      credential: async () => undefined,
      peers: async () => [],
      createEnvelope: credential => ({ workspaceId: credential.workspaceId, ownerPersonId: credential.ownerPersonId, peers: [] }),
      isEnvelope: (value): value is Envelope => typeof value === "object" && value !== null && "workspaceId" in value && "ownerPersonId" in value && "peers" in value,
      ownerPersonId: envelope => envelope.ownerPersonId,
      mergeOwnershipProof: async credential => credential,
      validate: async workspaceId => { if (workspaceId === "second") throw new Error("Invalid grant") },
      install: async workspaceId => { installed.push(workspaceId) },
    })

    await expect(runtime.receive([
      { workspaceId: "first", ownerPersonId: "owner", peers: [] },
      { workspaceId: "second", ownerPersonId: "owner", peers: [] },
    ], ["first", "second"], undefined, [], grant => grant)).rejects.toThrow("Invalid grant")
    expect(installed).toEqual([])
  })
})
