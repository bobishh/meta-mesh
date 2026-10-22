import { publicKeyId, signEnvelope, verifyEnvelope,
  type DeviceCertificate, type LocalProfile, type SignedEnvelope } from "./index"

export type DeviceAuthorizationRequest = SignedEnvelope<{
  kind: "mesh-device-authorization-request"
  version: 1
  applicationOrigin: string
  challenge: string
  expiresAt: number
  personId: string | null
  deviceId: string
  devicePublicKey: string
}>

type Binding = { applicationOrigin: string; challenge: string; now?: () => number }

/** Existing certificate format; identity enrollment does not belong to workspace governance. */
export async function createDelegatedCertificate(
  delegatorDevicePrivateKey: CryptoKey,
  delegatorDeviceId: string,
  personId: string,
  subjectDeviceId: string,
  subjectDevicePublicKey: string,
  issuerCertificateHash: string,
): Promise<DeviceCertificate> {
  return signEnvelope(delegatorDevicePrivateKey, {
    kind: "device-certificate" as const, version: 1 as const, personId,
    deviceId: subjectDeviceId, devicePublicKey: subjectDevicePublicKey,
    issuerCertificateHash, canEnrollDevices: true,
  }, delegatorDeviceId)
}

/** Only the application's device public key crosses into the Identity origin. */
export async function createDeviceAuthorizationRequest(
  profile: LocalProfile,
  options: { applicationOrigin: string; challenge: string; expiresAt: number; personId?: string | null },
): Promise<DeviceAuthorizationRequest> {
  const payload: DeviceAuthorizationRequest["payload"] = {
    kind: "mesh-device-authorization-request", version: 1,
    applicationOrigin: options.applicationOrigin, challenge: options.challenge, expiresAt: options.expiresAt,
    personId: options.personId ?? null, deviceId: profile.device.deviceId, devicePublicKey: profile.device.publicKey,
  }
  const request = await signEnvelope(profile.privateKeys.devicePrivateKey, payload, payload.deviceId,
    "MESH-DEVICE-AUTHORIZATION/1")
  await verifyDeviceAuthorizationRequest(request, options)
  return request
}

export async function verifyDeviceAuthorizationRequest(
  request: DeviceAuthorizationRequest,
  binding: Binding,
): Promise<void> {
  const value = request?.payload
  const now = (binding.now ?? Date.now)()
  if (!value || value.kind !== "mesh-device-authorization-request" || value.version !== 1 ||
    value.applicationOrigin !== binding.applicationOrigin || value.challenge !== binding.challenge ||
    !validOrigin(value.applicationOrigin) || !/^[a-f0-9]{64}$/u.test(value.challenge) ||
    !Number.isSafeInteger(value.expiresAt) || !Number.isSafeInteger(now) ||
    value.expiresAt <= now || value.expiresAt > now + 120_000 ||
    !(value.personId === null || (typeof value.personId === "string" && value.personId.length > 0)) ||
    request.signerKeyId !== value.deviceId || await publicKeyId(value.devicePublicKey) !== value.deviceId ||
    !await verifyEnvelope(request, value.devicePublicKey, "MESH-DEVICE-AUTHORIZATION/1")) {
    throw new Error("Invalid or expired application device request")
  }
}

/** Root-approved device certificate. It conveys identity, never board or service administration rights. */
export async function issueDeviceAuthorization(
  issuer: LocalProfile,
  requestValue: DeviceAuthorizationRequest,
  options: Binding & { ensureCurrent?: () => void | Promise<void> },
): Promise<DeviceCertificate> {
  const request = structuredClone(requestValue)
  const identity = structuredClone(issuer.identity)
  const rootKey = issuer.privateKeys.identityPrivateKey
  if (!rootKey) throw new Error("Open the Identity profile to authorize an application device")
  await options.ensureCurrent?.()
  await verifyDeviceAuthorizationRequest(request, options)
  if (request.payload.personId !== null && request.payload.personId !== identity.personId) {
    throw new Error("Application selected a different person")
  }
  if (await publicKeyId(identity.publicKey) !== identity.personId) throw new Error("Identity key mismatch")
  const certificate: DeviceCertificate = await signEnvelope(rootKey, {
    kind: "device-certificate" as const, version: 1 as const, personId: identity.personId,
    deviceId: request.payload.deviceId, devicePublicKey: request.payload.devicePublicKey,
    issuerCertificateHash: null, canEnrollDevices: false,
  }, identity.personId)
  if (!await verifyEnvelope(certificate, identity.publicKey)) throw new Error("Identity private key mismatch")
  await options.ensureCurrent?.()
  await verifyDeviceAuthorizationRequest(request, options)
  return certificate
}

function validOrigin(origin: string): boolean {
  try {
    const value = new URL(origin)
    return value.origin === origin && (value.protocol === "https:" ||
      (value.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(value.hostname)))
  } catch { return false }
}
