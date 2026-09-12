import { describe, expect, it } from "vitest"
import {
  BrowserIdentityStore,
  chatKeyIsValid,
  generateChatKey,
  generateRecoveryPhrase,
  profileFromRecoveryPhrase,
  profileFromChatKey,
  profileFromChatKeyForDevice,
  recoveryPhraseFromEntropy,
  recoveryPhraseIsValid,
  recoveryPhraseToEntropy,
  verifyDeviceCertificateChain,
} from "./index"

describe("mesh recovery phrase", () => {
  it("Given 128 bits, when encoded as words, then the original bytes return", () => {
    const entropy = Uint8Array.from({ length: 16 }, (_, index) => index)
    const phrase = recoveryPhraseFromEntropy(entropy)

    expect(phrase.split(" ")).toHaveLength(12)
    expect(recoveryPhraseToEntropy(phrase)).toEqual(entropy)
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
    words[11] = words[11] === "zoo" ? "abandon" : "zoo"

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
})
