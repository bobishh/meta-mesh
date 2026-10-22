import { describe, expect, it } from "vitest"
import { createIdentityProfileRecovery, createRecoverableIdentity, identitySeedFromPrivateKey,
  openIdentityProfileRecovery, sealIdentityProfileRecovery } from "./index"

const validWebp128 = "data:image/webp;base64,UklGRhYAAABXRUJQVlA4WAoAAAAAAAAAfwAAfwAA"

describe("identity portable profile recovery", () => {
  it("Given a profile and recovery words, when exported then imported, then the same root restores its name and avatar", async () => {
    const created = await createRecoverableIdentity("better", "Private Profile")
    const seed = await identitySeedFromPrivateKey(created.profile.privateKeys.identityPrivateKey!, created.profile.identity.personId)
    const payload = { displayName: "Portable Name", avatarData: validWebp128 }
    const file = await sealIdentityProfileRecovery(created.recoveryEnvelope, seed, payload)
    seed.fill(0)
    const opened = await openIdentityProfileRecovery(file, created.recoveryKey)

    expect(opened.profile).toEqual(payload)
    expect(opened.recovery.personId).toBe(created.profile.identity.personId)
    expect(JSON.stringify(file)).not.toContain("Portable Name")
    expect(JSON.stringify(file)).not.toContain(payload.avatarData)
    expect(JSON.stringify(file)).not.toContain(created.recoveryKey)
  })

  it("Given a changed file or wrong words, when opened, then authenticated recovery rejects it", async () => {
    const created = await createRecoverableIdentity("better", "Owner")
    const seed = await identitySeedFromPrivateKey(created.profile.privateKeys.identityPrivateKey!, created.profile.identity.personId)
    const file = await sealIdentityProfileRecovery(created.recoveryEnvelope, seed,
      { displayName: "Owner", avatarData: null })
    seed.fill(0)
    const changedCiphertext = `${file.ciphertext.slice(0, -1)}${file.ciphertext.endsWith("A") ? "B" : "A"}`

    await expect(openIdentityProfileRecovery({ ...file, ciphertext: changedCiphertext }, created.recoveryKey)).rejects.toThrow()
    await expect(openIdentityProfileRecovery(file, "wrong words")).rejects.toThrow()
  })

  it("Given another person's root, when sealing profile details against an envelope, then reject the mismatch", async () => {
    const [owner, other] = await Promise.all([
      createRecoverableIdentity("better", "Owner"),
      createRecoverableIdentity("better", "Other"),
    ])
    const seed = await identitySeedFromPrivateKey(other.profile.privateKeys.identityPrivateKey!, other.profile.identity.personId)
    await expect(sealIdentityProfileRecovery(owner.recoveryEnvelope, seed,
      { displayName: "Other", avatarData: null })).rejects.toThrow(/does not match/i)
    seed.fill(0)
  })

  it("Given an existing identity after reload, when a recovery package is created, then keep person and include signed profile history", async () => {
    const created = (await createRecoverableIdentity("better", "Owner")).profile
    const bundle = await createIdentityProfileRecovery(created,
      { displayName: "Same Person", avatarData: null }, "insane")
    const opened = await openIdentityProfileRecovery(bundle.file, bundle.recoveryKey)

    expect(bundle.recoveryEnvelope.personId).toBe(created.identity.personId)
    expect(opened.recovery.personId).toBe(created.identity.personId)
    expect(opened.profile.displayName).toBe("Same Person")
    expect(opened.profile.profileState?.operations).toHaveLength(2)
    expect(bundle.recoveryKey.split(" ")).toHaveLength(24)
  })
})
