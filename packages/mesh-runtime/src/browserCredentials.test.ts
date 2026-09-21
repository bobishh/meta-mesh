import { describe, expect, it, vi } from "vitest"
import { BrowserMeshCredentials } from "./browserCredentials"

describe("BrowserMeshCredentials", () => {
  it("creates an owner credential once and rejects another owner", async () => {
    const credentials = new Map<string, { workspaceId: string; ownerPersonId: string; publicKey: string }>()
    const runtime = new BrowserMeshCredentials({
      credential: async id => credentials.get(id), putCredential: async value => { credentials.set(value.workspaceId, value) },
      createCredential: (workspaceId, profile) => ({ workspaceId, ownerPersonId: profile.personId, publicKey: profile.publicKey }),
      refreshOwnerCertificates: vi.fn(async value => value),
    })
    await runtime.ensureOwnerCredential("workspace", { personId: "owner", publicKey: "key" }, [])
    await expect(runtime.ensureOwnerCredential("workspace", { personId: "other", publicKey: "other" }, [])).rejects.toThrow("Only the workspace owner")
    expect(credentials.get("workspace")?.ownerPersonId).toBe("owner")
  })
})
