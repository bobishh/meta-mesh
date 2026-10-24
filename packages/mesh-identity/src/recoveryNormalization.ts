export function normalizeRecoveryPhrase(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, " ")
}
