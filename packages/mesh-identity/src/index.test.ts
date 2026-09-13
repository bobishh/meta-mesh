import { describe, expect, it } from "vitest"
import {
  BrowserIdentityStore,
  chatKeyIsValid,
  createPassphraseIdentity,
  createRecoverableIdentity,
  generateChatKey,
  generateIdentityRecovery,
  generateRecoveryPhrase,
  identitySecurityForRecovery,
  identitySecurityWordCount,
  openIdentityRecoveryEnvelope,
  openIdentityPassphraseEnvelope,
  recoveryPhraseFromEntropy,
  recoveryPhraseIsValid,
  recoveryPhraseToEntropy,
  rewrapIdentityRecoveryEnvelope,
  verifyDeviceCertificateChain,
} from "./index"

describe("mesh recovery phrase", () => {
  it.each([
    ["legacy", 4],
    ["better", 12],
    ["insane", 24],
  ] as const)("Given %s recovery, when a recoverable identity is created, then its random root opens with %i words", async (security, count) => {
    const created = await createRecoverableIdentity(security, "One", new Uint8Array(32).fill(7))
    const opened = await openIdentityRecoveryEnvelope(
      created.recoveryEnvelope,
      created.recoveryKey,
      "Two",
      new Uint8Array(32).fill(8),
    )

    expect(created.recoveryKey.split(" ")).toHaveLength(count)
    expect(created.recoveryEnvelope.version).toBe(3)
    expect(opened.identity.personId).toBe(created.profile.identity.personId)
    expect(opened.device.deviceId).not.toBe(created.profile.device.deviceId)
  })

  it("Given legacy recovery, when promoted to insane, then the identity stays and the old words cannot open the new envelope", async () => {
    const created = await createRecoverableIdentity("legacy", "One")
    const promoted = await rewrapIdentityRecoveryEnvelope(
      created.recoveryEnvelope,
      created.recoveryKey,
      "insane",
    )
    const opened = await openIdentityRecoveryEnvelope(promoted.recoveryEnvelope, promoted.recoveryKey, "One")

    expect(promoted.recoveryKey.split(" ")).toHaveLength(24)
    expect(opened.identity.personId).toBe(created.profile.identity.personId)
    await expect(openIdentityRecoveryEnvelope(
      promoted.recoveryEnvelope,
      created.recoveryKey,
      "One",
    )).rejects.toThrow("Recovery words do not open this identity")
  })

  it("Given a modified recovery envelope, when opened, then authenticated decryption rejects it", async () => {
    const created = await createRecoverableIdentity("better", "One")
    const ciphertext = created.recoveryEnvelope.ciphertext
    const replacement = ciphertext.endsWith("A") ? "B" : "A"

    await expect(openIdentityRecoveryEnvelope({
      ...created.recoveryEnvelope,
      ciphertext: `${ciphertext.slice(0, -1)}${replacement}`,
    }, created.recoveryKey, "One")).rejects.toThrow("Recovery words do not open this identity")
  })

  it("Given an application passphrase, when its envelope opens on another device, then only the random root defines identity", async () => {
    const created = await createPassphraseIdentity("hey little rich boy", "Owner", new Uint8Array(32).fill(3))
    const opened = await openIdentityPassphraseEnvelope(
      created.passphraseEnvelope,
      "hey little rich boy",
      "Owner",
      new Uint8Array(32).fill(4),
    )

    expect(opened.identity.personId).toBe(created.profile.identity.personId)
    expect(opened.device.deviceId).not.toBe(created.profile.device.deviceId)
    await expect(openIdentityPassphraseEnvelope(
      created.passphraseEnvelope,
      "wrong phrase",
      "Owner",
    )).rejects.toThrow("Passphrase does not open this identity")
  })

  it("Given a recoverable browser identity, when reopened, then its device key stays stable", async () => {
    const storage = new Map<string, string>()
    const browserStorage = {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => { storage.set(key, value) },
      removeItem: (key: string) => { storage.delete(key) },
    }
    const store = new BrowserIdentityStore({ storageKey: "recoverable", storage: browserStorage })
    const created = await store.createRecoverable("better", "One")
    store.clearMemory()
    const restored = await store.restoreEnvelope(created.recoveryEnvelope, created.recoveryKey, "One")

    expect(restored.identity.personId).toBe(created.profile.identity.personId)
    expect(restored.device.deviceId).toBe(created.profile.device.deviceId)
  })

  it("Given 128 bits, when encoded as words, then the original bytes return", () => {
    const entropy = Uint8Array.from({ length: 16 }, (_, index) => index)
    const phrase = recoveryPhraseFromEntropy(entropy)

    expect(phrase.split(" ")).toHaveLength(12)
    expect(recoveryPhraseToEntropy(phrase)).toEqual(entropy)
  })

  it.each([
    [128, 12],
    [192, 18],
    [256, 24],
  ] as const)("Given %i-bit recovery strength, when generated, then it has %i BIP39 words", (strength, count) => {
    expect(generateRecoveryPhrase(strength).split(" ")).toHaveLength(count)
  })

  it.each([
    ["legacy", 4],
    ["better", 12],
    ["insane", 24],
  ] as const)("Given %s identity security, when recovery is generated, then %i words identify its level", (security, count) => {
    const phrase = generateIdentityRecovery(security)

    expect(identitySecurityWordCount(security)).toBe(count)
    expect(phrase.split(" ")).toHaveLength(count)
    expect(identitySecurityForRecovery(phrase)).toBe(security)
  })

  it("Given unsupported or malformed words, when identity security is detected, then recovery is rejected", () => {
    expect(identitySecurityForRecovery("not a valid key")).toBeNull()
    expect(identitySecurityForRecovery(generateRecoveryPhrase(192))).toBeNull()
  })

  it("Given one wrong word, when validated, then recovery is rejected", () => {
    const words = generateRecoveryPhrase().split(" ")
    words[11] = "not-a-bip39-word"

    expect(recoveryPhraseIsValid(words.join(" "))).toBe(false)
  })

  it("Given a four-word recovery key, when validated, then it identifies legacy-strength wrapping", () => {
    const key = generateChatKey()

    expect(key.split(" ")).toHaveLength(4)
    expect(chatKeyIsValid(key)).toBe(true)
  })

  it("Given one recovery envelope on two devices, when opened, then person ids match and device ids differ", async () => {
    const created = await createRecoverableIdentity("better", "One", new Uint8Array(32).fill(1))
    const second = await openIdentityRecoveryEnvelope(
      created.recoveryEnvelope,
      created.recoveryKey,
      "One",
      new Uint8Array(32).fill(2),
    )

    expect(second.identity.personId).toBe(created.profile.identity.personId)
    expect(second.device.deviceId).not.toBe(created.profile.device.deviceId)
    await expect(verifyDeviceCertificateChain(
      created.profile.identity,
      second.device.deviceId,
      [second.certificate],
    )).resolves.toBe(second.device.publicKey)
  })

  it.each(["legacy", "better", "insane"] as const)("Given a %s identity, when restored on one device twice, then its device stays stable", async security => {
    const storage = new Map<string, string>()
    const browserStorage = {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => { storage.set(key, value) },
      removeItem: (key: string) => { storage.delete(key) },
    }
    const store = new BrowserIdentityStore({ storageKey: "identity", storage: browserStorage })
    const created = await store.createRecoverable(security, "One")
    store.clearMemory()
    const restored = await store.restoreEnvelope(created.recoveryEnvelope, created.recoveryKey, "One")

    expect(restored.identity.personId).toBe(created.profile.identity.personId)
    expect(restored.device.deviceId).toBe(created.profile.device.deviceId)
  })
})
