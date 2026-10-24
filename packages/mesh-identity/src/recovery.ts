import { entropyToMnemonic, generateMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39"
import { wordlist } from "@scure/bip39/wordlists/english.js"
import { EFF_LONG_WORDS } from "./eff-long"
import { normalizeRecoveryPhrase } from "./recoveryNormalization"

export { normalizeRecoveryPhrase } from "./recoveryNormalization"

export type RecoveryStrengthBits = 128 | 192 | 256
export type IdentitySecurity = "legacy" | "better" | "insane"

export function generateRecoveryPhrase(strengthBits: RecoveryStrengthBits = 128): string {
  return generateMnemonic(wordlist, strengthBits)
}

export function identitySecurityWordCount(security: IdentitySecurity): 4 | 12 | 24 {
  if (security === "legacy") return 4
  return security === "insane" ? 24 : 12
}

export function generateIdentityRecovery(security: IdentitySecurity = "better"): string {
  if (security === "legacy") return generateChatKey()
  return generateRecoveryPhrase(security === "insane" ? 256 : 128)
}

export function generateChatKey(): string {
  const words: string[] = []
  const limit = Math.floor(65_536 / EFF_LONG_WORDS.length) * EFF_LONG_WORDS.length
  while (words.length < 4) {
    const sample = crypto.getRandomValues(new Uint16Array(1))[0]
    if (sample < limit) words.push(EFF_LONG_WORDS[sample % EFF_LONG_WORDS.length])
  }
  return words.join(" ")
}

export function recoveryPhraseIsValid(value: string): boolean {
  return validateMnemonic(normalizeRecoveryPhrase(value), wordlist)
}

export function chatKeyIsValid(value: string): boolean {
  const words = normalizeRecoveryPhrase(value).split(" ")
  return words.length === 4 && words.every(word => (EFF_LONG_WORDS as readonly string[]).includes(word))
}

export function identitySecurityForRecovery(value: string): IdentitySecurity | null {
  const normalized = normalizeRecoveryPhrase(value)
  if (chatKeyIsValid(normalized)) return "legacy"
  if (!recoveryPhraseIsValid(normalized)) return null
  const count = normalized.split(" ").length
  if (count === 12) return "better"
  if (count === 24) return "insane"
  return null
}

export function recoveryPhraseFromEntropy(entropy: Uint8Array): string {
  return entropyToMnemonic(entropy, wordlist)
}

export function recoveryPhraseToEntropy(value: string): Uint8Array {
  return mnemonicToEntropy(normalizeRecoveryPhrase(value), wordlist)
}
