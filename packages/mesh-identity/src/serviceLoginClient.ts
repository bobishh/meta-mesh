import { toBase64Url, verifyDeviceCertificateChain, verifyEnvelope } from "./index"
import { parseServiceLoginRequest, serviceLoginPayload, snapshotServiceLoginRequest,
  type ServiceLoginApproval, type ServiceLoginRequest } from "./serviceLogin"

/** Fresh-browser session login needs no pre-existing application identity or device key. */
export function createServiceLoginRequest(origin: string,
  options: { now?: () => number } = {}): ServiceLoginRequest {
  const now = (options.now ?? Date.now)()
  const challenge = Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, "0")).join("")
  const request: ServiceLoginRequest = { kind: "mesh-service-login-request", version: 1, origin, challenge,
    expires_at: Math.floor(now / 1000) + 120 }
  encodeServiceLoginRequest(request, now)
  return request
}

/** Reuse the issuer's wire validator before opening a popup. */
export function encodeServiceLoginRequest(request: ServiceLoginRequest, now = Date.now()): string {
  const encoded = toBase64Url(new TextEncoder().encode(JSON.stringify(request)))
  parseServiceLoginRequest(encoded, Math.floor(now / 1000))
  return encoded
}

/** Verify locally; the returned certificate remains usable after the sign-in proof expires. */
export async function verifyServiceLoginApproval(
  approvalValue: unknown,
  requestValue: ServiceLoginRequest,
  options: { now?: () => number } = {},
): Promise<ServiceLoginApproval> {
  const request = snapshotServiceLoginRequest(requestValue)
  const now = options.now ?? Date.now
  encodeServiceLoginRequest(request, now())
  // postMessage input is untrusted and must be bounded before crypto or chain traversal.
  const serialized = JSON.stringify(approvalValue)
  if (!serialized || serialized.length > 64_000) throw new Error("Invalid Identity approval")
  const approval = JSON.parse(serialized) as ServiceLoginApproval
  if (!isExactApproval(approval) || approval.proof.signerKeyId !== approval.deviceId) {
    throw new Error("Invalid Identity approval")
  }
  const payload = approval.proof.payload
  const expected = serviceLoginPayload(request, Math.floor(now() / 1000))
  if (payload.kind !== expected.kind || payload.version !== expected.version ||
    payload.origin !== expected.origin || payload.challenge !== expected.challenge || payload.expiresAt !== expected.expiresAt ||
    !Number.isSafeInteger(payload.issuedAt) || payload.issuedAt > now() + 30_000 ||
    payload.issuedAt < now() - 120_000 || payload.expiresAt <= payload.issuedAt ||
    payload.expiresAt > payload.issuedAt + 120_000) throw new Error("Identity approval request mismatch")
  const publicKey = await verifyDeviceCertificateChain(approval.identity, approval.deviceId, approval.certificates)
  if (!await verifyEnvelope(approval.proof, publicKey, "MESH-SERVICE-LOGIN/1")) throw new Error("Invalid Identity signature")
  encodeServiceLoginRequest(request, now())
  return approval
}

function isExactApproval(value: unknown): value is ServiceLoginApproval {
  if (!isRecord(value) || !hasExactKeys(value, ["identity", "deviceId", "certificates", "proof"]) ||
      typeof value.deviceId !== "string" || !Array.isArray(value.certificates) || value.certificates.length === 0 ||
      value.certificates.length > 32 || !isRecord(value.identity) ||
      !hasExactKeys(value.identity, ["personId", "publicKey", "displayName"]) ||
      typeof value.identity.personId !== "string" || typeof value.identity.publicKey !== "string" ||
      typeof value.identity.displayName !== "string" || !isRecord(value.proof) ||
      !hasExactKeys(value.proof, ["payload", "signerKeyId", "signature"]) ||
      typeof value.proof.signerKeyId !== "string" || typeof value.proof.signature !== "string" ||
      !isRecord(value.proof.payload) ||
      !hasExactKeys(value.proof.payload, ["kind", "version", "origin", "challenge", "issuedAt", "expiresAt"])) return false
  return value.certificates.every(certificate => isRecord(certificate) &&
    hasExactKeys(certificate, ["payload", "signerKeyId", "signature"]))
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}
