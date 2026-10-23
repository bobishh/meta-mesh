import { canonicalizeJson, publicKeyId, signEnvelope, toBase64Url, verifyEnvelope,
  certificateHash, verifyDeviceCertificateChain,
  createIdentityAuthorityView, verifyIdentityAuthorityView,
  type DeviceCertificate, type IdentityAuthorityHead, type IdentityAuthorityView,
  type IdentityDeviceRevocation, type LocalProfile, type SignedEnvelope } from "./index"
import type { IdentityProfileState } from "./identityProfile"

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

type DeviceAuthorizationApprovalPayloadV1 = {
  kind: "mesh-device-authorization-approval"
  version: 1
  request: DeviceAuthorizationRequest
  certificateHash: string
  issuedAt: number
  expiresAt: number
}

type DeviceAuthorizationApprovalPayloadV2 = Omit<DeviceAuthorizationApprovalPayloadV1, "version"> & {
  version: 2
  authorityViewDigest: string
  revocationHead: IdentityAuthorityHead
}
export type DeviceAuthorizationApprovalPayload = DeviceAuthorizationApprovalPayloadV1 | DeviceAuthorizationApprovalPayloadV2

export type DeviceAuthorizationApproval = {
  identity: LocalProfile["identity"]
  issuerDeviceId: string
  certificates: DeviceCertificate[]
  certificate: DeviceCertificate
  authorityView?: IdentityAuthorityView
  proof: SignedEnvelope<DeviceAuthorizationApprovalPayload>
}

type Binding = { applicationOrigin: string; challenge: string; now?: () => number; certificates?: readonly DeviceCertificate[] }

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

export function encodeDeviceAuthorizationRequest(request: DeviceAuthorizationRequest): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(request)))
}

export async function parseDeviceAuthorizationRequest(encoded: string, now = Date.now()): Promise<DeviceAuthorizationRequest> {
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > 4096 ||
      !Number.isSafeInteger(now) || !/^[A-Za-z0-9_-]+$/u.test(encoded)) {
    throw new Error("Invalid application device request")
  }
  let value: unknown
  try {
    const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - encoded.length % 4) % 4)
    const binary = atob(base64)
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(
      Uint8Array.from(binary, character => character.charCodeAt(0)))) as unknown
  } catch { throw new Error("Invalid application device request") }
  if (!isSignedRequest(value)) throw new Error("Invalid application device request")
  await verifyDeviceAuthorizationRequest(value, {
    applicationOrigin: value.payload.applicationOrigin,
    challenge: value.payload.challenge,
    now: () => now,
  })
  return value
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
  await options.ensureCurrent?.()
  await verifyDeviceAuthorizationRequest(request, options)
  if (request.payload.personId !== null && request.payload.personId !== identity.personId) {
    throw new Error("Application selected a different person")
  }
  if (await publicKeyId(identity.publicKey) !== identity.personId) throw new Error("Identity key mismatch")
  let issuerCertificateHash: string | null = null
  let signerKey: CryptoKey
  let signerId: string
  if (rootKey) {
    signerKey = rootKey
    signerId = identity.personId
  } else {
    const chain = Array.from(options.certificates ?? [])
    const certifiedKey = await verifyDeviceCertificateChain(identity, issuer.device.deviceId, chain)
    if (certifiedKey !== issuer.device.publicKey || issuer.certificate.payload.deviceId !== issuer.device.deviceId ||
        !issuer.certificate.payload.canEnrollDevices ||
        !chain.some(certificate => certificate.payload.deviceId === issuer.device.deviceId &&
          certificate.signature === issuer.certificate.signature)) {
      throw new Error("This Identity device cannot authorize app devices")
    }
    issuerCertificateHash = await certificateHash(issuer.certificate)
    signerKey = issuer.privateKeys.devicePrivateKey
    signerId = issuer.device.deviceId
  }
  const certificate: DeviceCertificate = await signEnvelope(signerKey, {
    kind: "device-certificate" as const, version: 1 as const, personId: identity.personId,
    deviceId: request.payload.deviceId, devicePublicKey: request.payload.devicePublicKey,
    issuerCertificateHash, canEnrollDevices: false,
  }, signerId)
  const certificates = [...Array.from(options.certificates ?? []), certificate]
  const certifiedApplicationKey = await verifyDeviceCertificateChain(identity, request.payload.deviceId, certificates)
  if (certifiedApplicationKey !== request.payload.devicePublicKey) throw new Error("Application device key mismatch")
  await options.ensureCurrent?.()
  await verifyDeviceAuthorizationRequest(request, options)
  return certificate
}

/** Sign an app-device certificate and bind it to the exact short-lived request. */
export async function createDeviceAuthorizationApproval(
  issuerValue: LocalProfile,
  requestValue: DeviceAuthorizationRequest,
  options: Binding & { ensureCurrent?: () => void | Promise<void>; profileState?: IdentityProfileState;
    revocations?: readonly IdentityDeviceRevocation[] },
): Promise<DeviceAuthorizationApproval> {
  const issuer: LocalProfile = { ...issuerValue, identity: structuredClone(issuerValue.identity),
    device: structuredClone(issuerValue.device), certificate: structuredClone(issuerValue.certificate),
    privateKeys: { ...issuerValue.privateKeys } }
  const request = structuredClone(requestValue)
  const certificates = Array.from(options.certificates ?? [], value => structuredClone(value))
  if (!certificates.some(value => value.payload.deviceId === issuer.device.deviceId)) certificates.push(issuer.certificate)
  const issuerPublicKey = await verifyDeviceCertificateChain(issuer.identity, issuer.device.deviceId, certificates)
  if (issuerPublicKey !== issuer.device.publicKey || issuer.certificate.payload.devicePublicKey !== issuer.device.publicKey) {
    throw new Error("Identity signing device does not match its certificate")
  }
  await options.ensureCurrent?.()
  const certificate = await issueDeviceAuthorization(issuer, request, { ...options, certificates })
  const allCertificates = [...certificates, certificate]
  const issuedAt = (options.now ?? Date.now)()
  if (!Number.isSafeInteger(issuedAt) || issuedAt >= request.payload.expiresAt) throw new Error("Application device request expired")
  let authorityView: IdentityAuthorityView | undefined
  let proofPayload: DeviceAuthorizationApprovalPayload
  if (options.profileState !== undefined || options.revocations !== undefined) {
    if (!options.profileState || !options.revocations) throw new Error("Application device approval requires complete Identity authority state")
    const verifiedView = await createIdentityAuthorityView(issuer.identity,
      { certificates: allCertificates, revocations: Array.from(options.revocations) }, options.profileState)
    authorityView = JSON.parse(JSON.stringify(verifiedView)) as IdentityAuthorityView
    proofPayload = {
      kind: "mesh-device-authorization-approval", version: 2, request,
      certificateHash: await certificateHash(certificate), issuedAt, expiresAt: request.payload.expiresAt,
      authorityViewDigest: authorityView.viewDigest, revocationHead: authorityView.revocationHead,
    }
  } else {
    proofPayload = {
      kind: "mesh-device-authorization-approval", version: 1, request,
      certificateHash: await certificateHash(certificate), issuedAt, expiresAt: request.payload.expiresAt,
    }
  }
  const proof = await signEnvelope(issuer.privateKeys.devicePrivateKey, proofPayload,
    issuer.device.deviceId, "MESH-APP-DEVICE-AUTHORIZATION/1")
  if (!await verifyEnvelope(proof, issuer.device.publicKey, "MESH-APP-DEVICE-AUTHORIZATION/1")) {
    throw new Error("Identity device signing key mismatch")
  }
  await options.ensureCurrent?.()
  return { identity: issuer.identity, issuerDeviceId: issuer.device.deviceId,
    certificates: allCertificates, certificate, ...(authorityView ? { authorityView } : {}), proof }
}

/** Validate the redirect payload against the caller's original request. */
export async function verifyDeviceAuthorizationApproval(
  approvalValue: unknown,
  requestValue: DeviceAuthorizationRequest,
  options: { now?: () => number } = {},
): Promise<DeviceAuthorizationApproval> {
  const request = structuredClone(requestValue)
  const serialized = JSON.stringify(approvalValue)
  if (!serialized || serialized.length > 64_000) throw new Error("Invalid Identity device approval")
  const approval = JSON.parse(serialized) as DeviceAuthorizationApproval
  if (!isRecord(approval) || !(hasExactKeys(approval, ["identity", "issuerDeviceId", "certificates", "certificate", "proof"]) ||
      hasExactKeys(approval, ["identity", "issuerDeviceId", "certificates", "certificate", "authorityView", "proof"])) ||
      !isRecord(approval.identity) || !Array.isArray(approval.certificates) || approval.certificates.length < 1 ||
      approval.certificates.length > 32 || typeof approval.issuerDeviceId !== "string" ||
      !isRecord(approval.certificate) || !isRecord(approval.proof) || !isRecord(approval.proof.payload)) {
    throw new Error("Invalid Identity device approval")
  }
  const payload = approval.proof.payload
  const now = (options.now ?? Date.now)()
  const version2 = payload.version === 2
  if (!hasExactKeys(payload, version2
      ? ["kind", "version", "request", "certificateHash", "issuedAt", "expiresAt", "authorityViewDigest", "revocationHead"]
      : ["kind", "version", "request", "certificateHash", "issuedAt", "expiresAt"]) ||
      payload.kind !== "mesh-device-authorization-approval" || (payload.version !== 1 && payload.version !== 2) ||
      canonicalizeJson(payload.request) !== canonicalizeJson(request) ||
      payload.certificateHash !== await certificateHash(approval.certificate) ||
      payload.expiresAt !== request.payload.expiresAt || !Number.isSafeInteger(payload.issuedAt) ||
      payload.issuedAt > now + 30_000 || payload.issuedAt >= payload.expiresAt || now >= payload.expiresAt ||
      approval.certificate.payload.deviceId !== request.payload.deviceId ||
      approval.certificate.payload.devicePublicKey !== request.payload.devicePublicKey ||
      approval.certificate.payload.personId !== approval.identity.personId || approval.certificate.payload.canEnrollDevices) {
    throw new Error("Identity device approval does not match this request")
  }
  const exactAppCertificate = canonicalizeJson(approval.certificate)
  if (!approval.certificates.some(value => canonicalizeJson(value) === exactAppCertificate)) {
    throw new Error("Missing app device certificate")
  }
  // A returning app key can have older certificates with the same deviceId in
  // the signed history. Verify the leaf bound by this approval before following
  // issuer hashes; selecting the first matching deviceId can pick stale history.
  const certificateChain = [approval.certificate,
    ...approval.certificates.filter(value => canonicalizeJson(value) !== exactAppCertificate)]
  const appKey = await verifyDeviceCertificateChain(approval.identity, request.payload.deviceId, certificateChain)
  if (appKey !== request.payload.devicePublicKey) throw new Error("App device key mismatch")
  const issuerKey = await verifyDeviceCertificateChain(approval.identity, approval.issuerDeviceId, approval.certificates)
  if (approval.proof.signerKeyId !== approval.issuerDeviceId ||
      !await verifyEnvelope(approval.proof, issuerKey, "MESH-APP-DEVICE-AUTHORIZATION/1")) {
    throw new Error("Invalid Identity device approval signature")
  }
  if (version2) {
    if (!approval.authorityView) throw new Error("Missing Identity authority view")
    const view = await verifyIdentityAuthorityView(approval.authorityView)
    if (view.personId !== approval.identity.personId || view.identityPublicKey !== approval.identity.publicKey ||
        view.viewDigest !== payload.authorityViewDigest ||
        canonicalizeJson(view.revocationHead) !== canonicalizeJson(payload.revocationHead) ||
        !view.certificates.some(value => canonicalizeJson(value) === exactAppCertificate) ||
        await isDeviceBlockedByRevocation(view, request.payload.deviceId)) {
      throw new Error("Application device approval authority view does not match")
    }
  } else if (approval.authorityView) {
    throw new Error("Unexpected Identity authority view on a legacy approval")
  }
  return approval
}

async function isDeviceBlockedByRevocation(view: IdentityAuthorityView, deviceId: string): Promise<boolean> {
  try {
    const { authorizeIdentityDataDevice } = await import("./index")
    await authorizeIdentityDataDevice(await verifyIdentityAuthorityView(view), deviceId)
    return false
  } catch { return true }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}

function isSignedRequest(value: unknown): value is DeviceAuthorizationRequest {
  if (!isRecord(value) || !hasExactKeys(value, ["payload", "signerKeyId", "signature"]) ||
      typeof value.signerKeyId !== "string" || typeof value.signature !== "string" || !isRecord(value.payload)) return false
  return hasExactKeys(value.payload, ["kind", "version", "applicationOrigin", "challenge", "expiresAt", "personId", "deviceId", "devicePublicKey"]) &&
    value.payload.kind === "mesh-device-authorization-request" && value.payload.version === 1 &&
    typeof value.payload.applicationOrigin === "string" && typeof value.payload.challenge === "string" &&
    typeof value.payload.expiresAt === "number" && (value.payload.personId === null || typeof value.payload.personId === "string") &&
    typeof value.payload.deviceId === "string" && typeof value.payload.devicePublicKey === "string"
}

function validOrigin(origin: string): boolean {
  try {
    const value = new URL(origin)
    return value.origin === origin && (value.protocol === "https:" ||
      (value.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(value.hostname)))
  } catch { return false }
}
