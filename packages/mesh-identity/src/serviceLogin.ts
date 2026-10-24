import { signEnvelope, verifyDeviceCertificateChain, verifyEnvelope,
  type DeviceCertificate, type LocalProfile, type SignedEnvelope } from "./index"

export type ServiceLoginRequest = {
  kind: "mesh-service-login-request"
  version: 2
  origin: string
  challenge: string
  expires_at: number
  return_to: string
}

export const SERVICE_LOGIN_CALLBACK_PATH = "/.well-known/mesh-service-login/callback"

export type ServiceLoginPayload = {
  kind: "mesh-service-login"
  version: 1
  origin: string
  challenge: string
  issuedAt: number
  expiresAt: number
}

export type ServiceLoginApproval = {
  identity: LocalProfile["identity"]
  deviceId: string
  certificates: DeviceCertificate[]
  proof: SignedEnvelope<ServiceLoginPayload>
}

export type ServiceLoginApprovalOptions = {
  certificates?: readonly DeviceCertificate[]
  ensureCurrent?: () => void | Promise<void>
  /** Wall-clock milliseconds, defaulting to Date.now. */
  now?: () => number
}

/** Parse an explicitly negotiated login request carried as unpadded base64url JSON. */
export function parseServiceLoginRequest(encoded: string, now: number): ServiceLoginRequest {
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > 4096 ||
      !Number.isSafeInteger(now) || now < 0 || !/^[A-Za-z0-9_-]+$/u.test(encoded)) {
    throw new Error("Invalid sign-in request")
  }
  let value: unknown
  try {
    const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - encoded.length % 4) % 4)
    const binary = atob(base64)
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(
      Uint8Array.from(binary, character => character.charCodeAt(0)))) as unknown
  } catch {
    throw new Error("Invalid sign-in request")
  }
  if (!isExactRequest(value) || !validServiceOrigin(value.origin) || !validServiceCallback(value.return_to, value.origin) || !/^[a-f0-9]{64}$/u.test(value.challenge) ||
      !Number.isSafeInteger(value.expires_at) || value.expires_at <= now || value.expires_at > now + 120) {
    throw new Error("Sign-in request is invalid or expired. Retry from the service.")
  }
  return { ...value }
}

/** Copy validated scalar request fields so reactive proxies never reach structured cloning. */
export function snapshotServiceLoginRequest(value: ServiceLoginRequest): ServiceLoginRequest {
  return { kind: value.kind, version: value.version, origin: value.origin,
    challenge: value.challenge, expires_at: value.expires_at, return_to: value.return_to }
}

export function serviceLoginPayload(request: ServiceLoginRequest, now: number): ServiceLoginPayload {
  assertRequest(request, now)
  return { kind: "mesh-service-login", version: 1, origin: request.origin,
    challenge: request.challenge, issuedAt: now * 1000, expiresAt: request.expires_at * 1000 }
}

/** Keep approval attached to the exact fresh request before signing. */
export function assertServiceLoginRequest(
  current: ServiceLoginRequest | undefined,
  expected: ServiceLoginRequest,
  now = Math.floor(Date.now() / 1000),
): void {
  if (!isExactRequest(current) || !sameRequest(current, expected)) {
    throw new Error("Service login approval changed")
  }
  assertRequest(expected, now)
}

/** Sign a short-lived service session proof from the user's existing certified device key. */
export async function createServiceLoginApproval(
  profileValue: LocalProfile,
  requestValue: ServiceLoginRequest,
  options: ServiceLoginApprovalOptions = {},
): Promise<ServiceLoginApproval> {
  const profile: LocalProfile = {
    ...profileValue,
    identity: structuredClone(profileValue.identity),
    device: structuredClone(profileValue.device),
    certificate: structuredClone(profileValue.certificate),
    privateKeys: { ...profileValue.privateKeys },
  }
  const request = snapshotServiceLoginRequest(requestValue)
  const ensureCurrent = options.ensureCurrent
  const now = options.now ?? (() => Date.now())
  const certificates = [structuredClone(profile.certificate), ...structuredClone(Array.from(options.certificates ?? []))]
  await ensureCurrent?.()
  const issuedAt = Math.floor(now() / 1000)
  assertRequest(request, issuedAt)
  const certifiedKey = await verifyDeviceCertificateChain(profile.identity, profile.device.deviceId, certificates, "MATCH/1")
  if (certifiedKey !== profile.device.publicKey || profile.certificate.payload.devicePublicKey !== profile.device.publicKey) {
    throw new Error("Certified signing device key mismatch")
  }
  const payload = serviceLoginPayload(request, issuedAt)
  const proof = await signEnvelope(profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId, "MESH-SERVICE-LOGIN/1")
  await ensureCurrent?.()
  assertRequest(request, Math.floor(now() / 1000))
  if (!await verifyEnvelope(proof, profile.device.publicKey, "MESH-SERVICE-LOGIN/1")) {
    throw new Error("Private signing key does not match its certified device")
  }
  assertRequest(request, Math.floor(now() / 1000))
  return { identity: profile.identity, deviceId: profile.device.deviceId, certificates, proof }
}

function assertRequest(request: ServiceLoginRequest, now: number): void {
  if (!isExactRequest(request) || !validServiceOrigin(request.origin) || !validServiceCallback(request.return_to, request.origin) || !/^[a-f0-9]{64}$/u.test(request.challenge) ||
      !Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(request.expires_at) ||
      request.expires_at <= now || request.expires_at > now + 120) {
    throw new Error("Sign-in request is invalid or expired. Retry from the service.")
  }
}

function isExactRequest(value: unknown): value is ServiceLoginRequest {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false
  const record = value as Record<string, unknown>
  const keys = Object.keys(record)
  return Object.getPrototypeOf(value) === Object.prototype &&
    keys.length === 6 &&
    Object.hasOwn(record, "kind") && Object.hasOwn(record, "version") && Object.hasOwn(record, "origin") &&
    Object.hasOwn(record, "challenge") && Object.hasOwn(record, "expires_at") && Object.hasOwn(record, "return_to") &&
    record.kind === "mesh-service-login-request" && record.version === 2 &&
    typeof record.origin === "string" && typeof record.challenge === "string" && typeof record.expires_at === "number" &&
    typeof record.return_to === "string"
}

function sameRequest(left: ServiceLoginRequest, right: ServiceLoginRequest): boolean {
  return left.kind === right.kind && left.version === right.version && left.origin === right.origin &&
    left.challenge === right.challenge && left.expires_at === right.expires_at
}

function validServiceOrigin(origin: string): boolean {
  try {
    const url = new URL(origin)
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
    return url.origin === origin && !url.username && !url.password &&
      (url.protocol === "https:" || (url.protocol === "http:" && loopback))
  } catch {
    return false
  }
}

function validServiceCallback(returnTo: string, origin: string): boolean {
  try {
    const callback = new URL(returnTo)
    return callback.origin === origin && callback.pathname === SERVICE_LOGIN_CALLBACK_PATH &&
      callback.search === "" && callback.hash === ""
  } catch {
    return false
  }
}
