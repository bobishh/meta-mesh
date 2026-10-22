const maxAvatarBytes = 16 * 1024
const maxAvatarDataUrlLength = 22_000
const avatarDataUrl = /^data:image\/(?:webp|jpeg);base64,([A-Za-z0-9+/]+={0,2})$/u

export function normalizeIdentityDisplayName(name: string): string {
  return name.normalize("NFKC").replace(/\p{White_Space}+/gu, " ").trim()
}

export function isValidIdentityDisplayName(name: unknown): name is string {
  if (typeof name !== "string" || !name || /\p{Cc}/u.test(name) || /\p{Bidi_Control}/u.test(name)) return false
  const normalized = normalizeIdentityDisplayName(name)
  return [...normalized].length > 0 && [...normalized].length <= 48 && normalized === name
}

export function isValidIdentityAvatar(value: unknown): value is string {
  if (typeof value !== "string" || value.length > maxAvatarDataUrlLength) return false
  const match = avatarDataUrl.exec(value)
  if (!match) return false
  const encoded = match[1]!
  if (encoded.length % 4 !== 0) return false
  const byteLength = Math.floor(encoded.length * 3 / 4) - (encoded.endsWith("==") ? 2 : encoded.endsWith("=") ? 1 : 0)
  if (byteLength > maxAvatarBytes) return false
  try {
    const bytes = Uint8Array.from(atob(encoded), character => character.charCodeAt(0))
    return value.startsWith("data:image/webp") ? webp128(bytes) : jpeg128(bytes)
  } catch { return false }
}

export function isValidIdentityProfilePhoto(value: unknown): value is { avatarData: string | null; changedAt: string } {
  if (!isRecord(value) || Object.keys(value).length !== 2 || !Object.hasOwn(value, "avatarData") ||
      !Object.hasOwn(value, "changedAt") || !(value.avatarData === null || isValidIdentityAvatar(value.avatarData)) ||
      typeof value.changedAt !== "string" || !Number.isFinite(Date.parse(value.changedAt))) return false
  try { return new Date(value.changedAt).toISOString() === value.changedAt } catch { return false }
}

function webp128(bytes: Uint8Array): boolean {
  if (bytes.length < 30 || !textAt(bytes, 0, "RIFF") || !textAt(bytes, 8, "WEBP")) return false
  return (textAt(bytes, 12, "VP8X") && bytes[24] === 127 && bytes[25] === 0 && bytes[26] === 0 && bytes[27] === 127 && bytes[28] === 0 && bytes[29] === 0) ||
    (textAt(bytes, 12, "VP8 ") && bytes[23] === 0x9d && bytes[24] === 0x01 && bytes[25] === 0x2a &&
      ((bytes[26]! | (bytes[27]! << 8)) & 0x3fff) === 128 && ((bytes[28]! | (bytes[29]! << 8)) & 0x3fff) === 128) ||
    (textAt(bytes, 12, "VP8L") && bytes.length >= 25 && bytes[20] === 0x2f &&
      1 + bytes[21]! + ((bytes[22]! & 0x3f) << 8) === 128 &&
      1 + ((bytes[22]! & 0xc0) >> 6) + (bytes[23]! << 2) + ((bytes[24]! & 0x0f) << 10) === 128)
}

function jpeg128(bytes: Uint8Array): boolean {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return false
  let offset = 2
  while (offset + 3 < bytes.length) {
    if (bytes[offset] !== 0xff) return false
    const marker = bytes[offset + 1]!
    offset += 2
    if (marker === 0xd8 || marker === 0xd9 || (marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) continue
    const length = (bytes[offset]! << 8) | bytes[offset + 1]!
    if (length < 2 || offset + length > bytes.length) return false
    if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) {
      return ((bytes[offset + 3]! << 8) | bytes[offset + 4]!) === 128 &&
        ((bytes[offset + 5]! << 8) | bytes[offset + 6]!) === 128
    }
    offset += length
  }
  return false
}

function textAt(bytes: Uint8Array, offset: number, text: string): boolean {
  return [...text].every((character, index) => bytes[offset + index] === character.charCodeAt(0))
}

function isRecord(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value) }
