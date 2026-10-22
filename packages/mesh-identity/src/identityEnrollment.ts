import { createDelegatedCertificate } from "./deviceAuthorization"
import { certificateHash, publicKeyId, signEnvelope, verifyDeviceCertificateChain,
  verifyEnvelope, type DeviceCertificate, type LocalProfile, type SignedEnvelope } from "./index"
import type { DeviceEnrollmentInvitation } from "@meta-uber/mesh-pairing"

export type IdentityDeviceEnrollmentRequest = SignedEnvelope<{
  kind: "mesh-identity-device-enrollment-request"
  version: 1
  invitationId: string
  personId: string
  issuerDeviceId: string
  requestId: string
  challenge: string
  deviceId: string
  devicePublicKey: string
  displayName: string
  fullRecoveryConsent: boolean
  expiresAt: number
}>

export type IdentityEnrollmentDevice = {
  device: { deviceId: string; publicKey: string; displayName: string }
  privateKey: CryptoKey
}

/** Create only the local device key needed to join an existing Identity. */
export async function createIdentityEnrollmentDevice(displayName: string): Promise<IdentityEnrollmentDevice> {
  const cleanName = displayName.trim()
  if (!cleanName || cleanName.length > 128) throw new Error("Identity device name must be between 1 and 128 characters")
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
  const publicKey = bytesToBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)))
  return {
    device: { deviceId: await publicKeyId(publicKey), publicKey, displayName: cleanName },
    privateKey: keys.privateKey,
  }
}

export async function createIdentityDeviceEnrollmentRequest(
  device: IdentityEnrollmentDevice,
  invitation: DeviceEnrollmentInvitation,
  options: { displayName: string; fullRecoveryConsent: boolean; now?: number },
): Promise<IdentityDeviceEnrollmentRequest> {
  const now = options.now ?? Date.now()
  const cleanName = options.displayName.trim()
  if (invitation.kind !== "device-enrollment" || !validInvitationTime(invitation, now) ||
    await publicKeyId(device.device.publicKey) !== device.device.deviceId || !cleanName || cleanName.length > 128 ||
    typeof options.fullRecoveryConsent !== "boolean") {
    throw new Error("Invalid Identity device enrollment inputs")
  }
  const expiresAt = Math.min(Date.parse(invitation.expiresAt), now + 120_000)
  const payload: IdentityDeviceEnrollmentRequest["payload"] = {
    kind: "mesh-identity-device-enrollment-request", version: 1,
    invitationId: invitation.invitationId, personId: invitation.issuerPersonId,
    issuerDeviceId: invitation.issuerDeviceId, requestId: crypto.randomUUID(),
    challenge: randomChallenge(), deviceId: device.device.deviceId, devicePublicKey: device.device.publicKey,
    displayName: cleanName, fullRecoveryConsent: options.fullRecoveryConsent, expiresAt,
  }
  const request = await signEnvelope(device.privateKey, payload, payload.deviceId, "MESH-IDENTITY-ENROLLMENT/1")
  await verifyIdentityDeviceEnrollmentRequest(request, invitation, { now })
  return request
}

export async function verifyIdentityDeviceEnrollmentRequest(
  request: IdentityDeviceEnrollmentRequest,
  invitation: DeviceEnrollmentInvitation,
  options: { now?: number } = {},
): Promise<void> {
  const now = options.now ?? Date.now()
  const value = request?.payload
  if (!value || invitation?.kind !== "device-enrollment" || !validInvitationTime(invitation, now) ||
    value.kind !== "mesh-identity-device-enrollment-request" || value.version !== 1 ||
    value.invitationId !== invitation.invitationId || value.personId !== invitation.issuerPersonId ||
    value.issuerDeviceId !== invitation.issuerDeviceId || !value.requestId || !/^[A-Za-z0-9_-]{43}$/u.test(value.challenge) ||
    typeof value.fullRecoveryConsent !== "boolean" ||
    !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= now || value.expiresAt > Date.parse(invitation.expiresAt) ||
    value.expiresAt > now + 120_000 || !value.displayName || value.displayName.trim() !== value.displayName || value.displayName.length > 128 ||
    request.signerKeyId !== value.deviceId || await publicKeyId(value.devicePublicKey) !== value.deviceId ||
    !await verifyEnvelope(request, value.devicePublicKey, "MESH-IDENTITY-ENROLLMENT/1")) {
    throw new Error("Invalid or expired Identity device enrollment request")
  }
}

/** Signed request consent only authorizes sending the recovery package; it does not grant board roles. */
export function identityRequestAllowsRecoveryTransfer(request: IdentityDeviceEnrollmentRequest): boolean {
  return request?.payload?.kind === "mesh-identity-device-enrollment-request" &&
    request.payload.version === 1 && request.payload.fullRecoveryConsent === true
}

/** Explicit Identity-device consent. Issued certificate is identity-wide, not application-scoped. */
export async function issueIdentityDeviceEnrollment(
  issuer: LocalProfile,
  requestValue: IdentityDeviceEnrollmentRequest,
  invitation: DeviceEnrollmentInvitation,
  certificates: DeviceCertificate[],
  options: { now?: number; ensureCurrent?: () => void | Promise<void> } = {},
): Promise<DeviceCertificate> {
  const request = structuredClone(requestValue)
  const identity = structuredClone(issuer.identity)
  const chain = structuredClone(certificates)
  await options.ensureCurrent?.()
  await verifyIdentityDeviceEnrollmentRequest(request, invitation, options)
  const issuerCertificateHash = await certificateHash(issuer.certificate)
  let issuerCertificateIsInChain = false
  for (const certificate of chain) {
    if (certificate.payload.deviceId === issuer.device.deviceId &&
      await certificateHash(certificate) === issuerCertificateHash) {
      issuerCertificateIsInChain = true
      break
    }
  }
  if (request.payload.personId !== identity.personId || invitation.issuerPersonId !== identity.personId ||
    await publicKeyId(identity.publicKey) !== identity.personId ||
    !issuerCertificateIsInChain) {
    throw new Error("Identity enrollment invitation does not match issuer")
  }
  await verifyDeviceCertificateChain(identity, issuer.device.deviceId, chain)
  let certificate: DeviceCertificate
  if (issuer.privateKeys.identityPrivateKey) {
    certificate = await signEnvelope(issuer.privateKeys.identityPrivateKey, {
      kind: "device-certificate" as const, version: 1 as const, personId: identity.personId,
      deviceId: request.payload.deviceId, devicePublicKey: request.payload.devicePublicKey,
      issuerCertificateHash: null, canEnrollDevices: true,
    }, identity.personId)
  } else {
    if (!issuer.certificate.payload.canEnrollDevices) throw new Error("This Identity device cannot enroll devices")
    certificate = await createDelegatedCertificate(issuer.privateKeys.devicePrivateKey, issuer.device.deviceId,
      identity.personId, request.payload.deviceId, request.payload.devicePublicKey, issuerCertificateHash)
  }
  await verifyDeviceCertificateChain(identity, request.payload.deviceId, [...chain, certificate])
  await options.ensureCurrent?.()
  await verifyIdentityDeviceEnrollmentRequest(request, invitation, options)
  return certificate
}

function randomChallenge(): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)))
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")
}

function validInvitationTime(invitation: DeviceEnrollmentInvitation, now: number): boolean {
  const createdAt = Date.parse(invitation.createdAt)
  const expiresAt = Date.parse(invitation.expiresAt)
  return Number.isSafeInteger(now) && invitation.version === 1 && Boolean(invitation.invitationId) &&
    Boolean(invitation.issuerPersonId) && Boolean(invitation.issuerDeviceId) && Boolean(invitation.issuerPublicKey) &&
    Boolean(invitation.issuerEndpoint) && Boolean(invitation.secret) && Number.isFinite(createdAt) &&
    Number.isFinite(expiresAt) && createdAt <= now && expiresAt > now && expiresAt > createdAt
}
