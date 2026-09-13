import { describe, expect, it } from "vitest"
import {
  BrowserIdentityStore,
  chatKeyIsValid,
  createRecoverableIdentity,
  generateChatKey,
  generateIdentityRecovery,
  generateRecoveryPhrase,
  identitySecurityForRecovery,
  identitySecurityWordCount,
  migrateIdentityToRecoveryEnvelope,
  openIdentityRecoveryEnvelope,
  profileFromRecoveryPhrase,
  profileFromRecoveryPhraseForDevice,
  profileFromChatKey,
  profileFromChatKeyForDevice,
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
    expect(created.recoveryEnvelope.origin).toBe("random-root")
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

  it("Given an existing direct-derived identity, when migrated, then its person id is retained", async () => {
    const recoveryKey = generateChatKey()
    const legacy = await profileFromChatKeyForDevice(recoveryKey, "Legacy", new Uint8Array(32).fill(5))
    const envelope = await migrateIdentityToRecoveryEnvelope(legacy, recoveryKey)
    const opened = await openIdentityRecoveryEnvelope(envelope, recoveryKey, "Migrated", new Uint8Array(32).fill(6))

    expect(opened.identity.personId).toBe(legacy.identity.personId)
    expect(envelope.origin).toBe("direct-v1")
    expect(opened.device.deviceId).not.toBe(legacy.device.deviceId)
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

  it("Given one phrase, when restored twice, then person and device ids stay stable", async () => {
    const phrase = generateRecoveryPhrase()
    const first = await profileFromRecoveryPhrase(phrase, "First label")
    const restored = await profileFromRecoveryPhrase(phrase, "Second label")

    expect(recoveryPhraseIsValid(phrase)).toBe(true)
    expect(restored.identity.personId).toBe(first.identity.personId)
    expect(restored.device.deviceId).toBe(first.device.deviceId)
  })

  it("Given one wrong word, when validated, then recovery is rejected", () => {
    const words = generateRecoveryPhrase().split(" ")
    words[11] = "not-a-bip39-word"

    expect(recoveryPhraseIsValid(words.join(" "))).toBe(false)
  })

  it("Given a chat identity, when restored from four words, then its ids stay stable", async () => {
    const key = generateChatKey()
    const first = await profileFromChatKey(key, "One")
    const restored = await profileFromChatKey(key, "Two")

    expect(key.split(" ")).toHaveLength(4)
    expect(chatKeyIsValid(key)).toBe(true)
    expect(restored.identity.personId).toBe(first.identity.personId)
    expect(restored.device.deviceId).toBe(first.device.deviceId)
  })

  it("Given one chat identity on two devices, when enrolled, then person ids match and device ids differ", async () => {
    const key = generateChatKey()
    const first = await profileFromChatKeyForDevice(key, "One", new Uint8Array(32).fill(1))
    const second = await profileFromChatKeyForDevice(key, "One", new Uint8Array(32).fill(2))

    expect(second.identity.personId).toBe(first.identity.personId)
    expect(second.device.deviceId).not.toBe(first.device.deviceId)
    await expect(verifyDeviceCertificateChain(
      first.identity,
      second.device.deviceId,
      [second.certificate],
    )).resolves.toBe(second.device.publicKey)
  })

  it("Given one recovery identity on two devices, when enrolled, then person ids match and device ids differ", async () => {
    const key = generateRecoveryPhrase(128)
    const first = await profileFromRecoveryPhraseForDevice(key, "One", new Uint8Array(32).fill(1))
    const second = await profileFromRecoveryPhraseForDevice(key, "One", new Uint8Array(32).fill(2))

    expect(second.identity.personId).toBe(first.identity.personId)
    expect(second.device.deviceId).not.toBe(first.device.deviceId)
    await expect(verifyDeviceCertificateChain(
      first.identity,
      second.device.deviceId,
      [second.certificate],
    )).resolves.toBe(second.device.publicKey)
  })

  it("Given one browser store, when the same chat identity returns, then its device stays stable", async () => {
    const storage = new Map<string, string>()
    const browserStorage = {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => { storage.set(key, value) },
      removeItem: (key: string) => { storage.delete(key) },
    }
    const store = new BrowserIdentityStore({ storageKey: "identity", storage: browserStorage })
    const key = generateChatKey()
    const first = await store.restoreChat(key, "One")
    store.clearMemory()
    const restored = await store.restoreChat(key, "One")

    expect(restored.identity.personId).toBe(first.identity.personId)
    expect(restored.device.deviceId).toBe(first.device.deviceId)
  })

  it.each(["legacy", "better", "insane"] as const)("Given a %s identity, when restored on one device twice, then its device stays stable", async security => {
    const storage = new Map<string, string>()
    const browserStorage = {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => { storage.set(key, value) },
      removeItem: (key: string) => { storage.delete(key) },
    }
    const store = new BrowserIdentityStore({ storageKey: "identity", storage: browserStorage })
    const key = generateIdentityRecovery(security)
    const first = await store.restoreIdentity(key, "One")
    store.clearMemory()
    const restored = await store.restoreIdentity(key, "One")

    expect(restored.identity.personId).toBe(first.identity.personId)
    expect(restored.device.deviceId).toBe(first.device.deviceId)
  })

  it("Given one chat key in two browser stores, when restored, then person ids match and device ids differ", async () => {
    const key = generateChatKey()
    const first = await new BrowserIdentityStore({ storageKey: "first" }).restoreChat(key, "One")
    const second = await new BrowserIdentityStore({ storageKey: "second" }).restoreChat(key, "Two")

    expect(second.identity.personId).toBe(first.identity.personId)
    expect(second.device.deviceId).not.toBe(first.device.deviceId)
  })

  it("Given one owner phrase in two browser stores, when restored, then person ids match and device ids differ", async () => {
    const first = await new BrowserIdentityStore({ storageKey: "owner-first" }).restoreSecret("shared phrase", "One")
    const second = await new BrowserIdentityStore({ storageKey: "owner-second" }).restoreSecret("shared phrase", "Two")

    expect(second.identity.personId).toBe(first.identity.personId)
    expect(second.device.deviceId).not.toBe(first.device.deviceId)
  })
})
