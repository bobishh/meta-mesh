import { canonicalizeJson, publicKeyId, signEnvelope, toBase64Url, verifyEnvelope,
  certificateHash, verifyDeviceCertificateChain, sha256Base64Url,
  verifyIdentityDeviceAuthority, authorizeIdentityDevice, authorizeIdentityDataDevice,
  createIdentityAuthorityView, verifyIdentityAuthorityView,
  type DeviceCertificate, type IdentityAuthorityHead, type IdentityAuthorityView,
  type IdentityDeviceRevocation, type LocalProfile, type SignedEnvelope } from "./index"
import { identityProfileRevision, identityProfileValue, identityProfileRustyServicePins, normalizeIdentityRustyServicePins,
  readIdentityProfileStateWithRevocations, type IdentityProfileState, type IdentityRustyServicePin } from "./identityProfile"

type DeviceAuthorizationRequestFields = {
  kind: "mesh-device-authorization-request"
  applicationOrigin: string
  challenge: string
  expiresAt: number
  personId: string | null
  deviceId: string
  devicePublicKey: string
}
export type DeviceAuthorizationRequest = SignedEnvelope<
  (DeviceAuthorizationRequestFields & { version: 1 }) |
  (DeviceAuthorizationRequestFields & { version: 2; rustyServicePins: IdentityRustyServicePin[] })
>

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
type DeviceAuthorizationApprovalPayloadV3 = Omit<DeviceAuthorizationApprovalPayloadV2, "version"> & {
  version: 3
  rustyServicePinsDigest: string
  profileStateDigest: string
}
type DeviceAuthorizationApprovalPayloadV4 = Omit<DeviceAuthorizationApprovalPayloadV3, "version"> & { version: 4 }
export type DeviceAuthorizationApprovalPayload = DeviceAuthorizationApprovalPayloadV1 |
  DeviceAuthorizationApprovalPayloadV2 | DeviceAuthorizationApprovalPayloadV3 | DeviceAuthorizationApprovalPayloadV4

export type DeviceAuthorizationApproval = {
  identity: LocalProfile["identity"]
  issuerDeviceId: string
  certificates: DeviceCertificate[]
  certificate: DeviceCertificate
  authorityView?: IdentityAuthorityView
  rustyServicePins?: IdentityRustyServicePin[]
  profileState?: IdentityProfileState
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
  options: { applicationOrigin: string; challenge: string; expiresAt: number; personId?: string | null;
    rustyServicePins?: readonly IdentityRustyServicePin[] },
): Promise<DeviceAuthorizationRequest> {
  const base = {
    kind: "mesh-device-authorization-request" as const,
    applicationOrigin: options.applicationOrigin, challenge: options.challenge, expiresAt: options.expiresAt,
    personId: options.personId ?? null, deviceId: profile.device.deviceId, devicePublicKey: profile.device.publicKey,
  }
  const pins = options.rustyServicePins === undefined ? [] : await normalizeIdentityRustyServicePins(options.rustyServicePins)
  const payload: DeviceAuthorizationRequest["payload"] = pins.length
    ? { ...base, version: 2, rustyServicePins: pins }
    : { ...base, version: 1 }
  const request = await signEnvelope(profile.privateKeys.devicePrivateKey, payload, payload.deviceId,
    "MESH-DEVICE-AUTHORIZATION/1")
  await verifyDeviceAuthorizationRequest(request, options)
  return request
}

export function encodeDeviceAuthorizationRequest(request: DeviceAuthorizationRequest): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(request)))
}

export async function parseDeviceAuthorizationRequest(encoded: string, now = Date.now()): Promise<DeviceAuthorizationRequest> {
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > 96_000 ||
      !Number.isSafeInteger(now) || !/^[A-Za-z0-9_-]+$/u.test(encoded)) {
    throw new Error("Invalid application device request")
  }
  let value: unknown
  try {
    const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - encoded.length % 4) % 4)
    const binary = atob(base64)
    if (binary.length > 64 * 1024) throw new Error("oversized")
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
  if (!value || !isSignedRequest(request) || value.kind !== "mesh-device-authorization-request" ||
    (value.version !== 1 && value.version !== 2) ||
    value.applicationOrigin !== binding.applicationOrigin || value.challenge !== binding.challenge ||
    !validOrigin(value.applicationOrigin) || !/^[a-f0-9]{64}$/u.test(value.challenge) ||
    !Number.isSafeInteger(value.expiresAt) || !Number.isSafeInteger(now) ||
    value.expiresAt <= now || value.expiresAt > now + 120_000 ||
    !(value.personId === null || (typeof value.personId === "string" && value.personId.length > 0)) ||
    request.signerKeyId !== value.deviceId || await publicKeyId(value.devicePublicKey) !== value.deviceId ||
    !await verifyEnvelope(request, value.devicePublicKey, "MESH-DEVICE-AUTHORIZATION/1")) {
    throw new Error("Invalid or expired application device request")
  }
  if (value.version === 2) {
    const pins = await normalizeIdentityRustyServicePins(value.rustyServicePins)
    if (!pins.length || canonicalizeJson(pins) !== canonicalizeJson(value.rustyServicePins)) {
      throw new Error("Invalid Rusty service pin request")
    }
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
  await options.ensureCurrent?.()
  await verifyDeviceAuthorizationRequest(request, options)
  if (request.payload.personId !== null && request.payload.personId !== identity.personId) {
    throw new Error("Application selected a different person")
  }
  if (await publicKeyId(identity.publicKey) !== identity.personId) throw new Error("Identity key mismatch")
  const chain = Array.from(options.certificates ?? [issuer.certificate])
  const certifiedKey = await verifyDeviceCertificateChain(identity, issuer.device.deviceId, chain)
  if (certifiedKey !== issuer.device.publicKey || issuer.certificate.payload.deviceId !== issuer.device.deviceId ||
      !issuer.certificate.payload.canEnrollDevices ||
      !chain.some(certificate => certificate.payload.deviceId === issuer.device.deviceId &&
        certificate.signature === issuer.certificate.signature)) {
    throw new Error("This Identity device cannot authorize app devices")
  }
  const existingApplicationCertificate = chain.find(certificate => certificate.payload.deviceId === request.payload.deviceId)
  if (existingApplicationCertificate) {
    const existingKey = await verifyDeviceCertificateChain(identity, request.payload.deviceId, chain)
    if (existingKey !== request.payload.devicePublicKey) throw new Error("Existing app certificate does not match this request")
    return structuredClone(existingApplicationCertificate)
  }
  // Bind the app key to the approving Identity device even when this browser
  // also holds the recovery root. Future revocation can then deny this subtree.
  const issuerCertificateHash = await certificateHash(issuer.certificate)
  const signerKey = issuer.privateKeys.devicePrivateKey
  const signerId = issuer.device.deviceId
  const certificate: DeviceCertificate = await signEnvelope(signerKey, {
    kind: "device-certificate" as const, version: 1 as const, personId: identity.personId,
    deviceId: request.payload.deviceId, devicePublicKey: request.payload.devicePublicKey,
    issuerCertificateHash, canEnrollDevices: false,
  }, signerId)
  const certificates = [...chain, certificate]
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
  options: Binding & { ensureCurrent?: () => void | Promise<void>; profileState?: IdentityProfileState; includeProfileState?: boolean;
    revocations?: readonly IdentityDeviceRevocation[] },
): Promise<DeviceAuthorizationApproval> {
  const issuer: LocalProfile = { ...issuerValue, identity: structuredClone(issuerValue.identity),
    device: structuredClone(issuerValue.device), certificate: structuredClone(issuerValue.certificate),
    privateKeys: { ...issuerValue.privateKeys } }
  const request = structuredClone(requestValue)
  if ((request.payload.version === 2 || options.includeProfileState) && (options.profileState === undefined || options.revocations === undefined)) {
    throw new Error("Rusty pin approval requires the current signed Identity profile")
  }
  const certificates = Array.from(options.certificates ?? [], value => structuredClone(value))
  if (!certificates.some(value => value.payload.deviceId === issuer.device.deviceId)) certificates.push(issuer.certificate)
  const currentAuthority = await verifyIdentityDeviceAuthority(issuer.identity,
    { certificates, revocations: Array.from(options.revocations ?? []) })
  await authorizeIdentityDevice(currentAuthority, issuer.device.deviceId)
  const issuerPublicKey = await verifyDeviceCertificateChain(issuer.identity, issuer.device.deviceId, certificates)
  if (issuerPublicKey !== issuer.device.publicKey || issuer.certificate.payload.devicePublicKey !== issuer.device.publicKey) {
    throw new Error("Identity signing device does not match its certificate")
  }
  await options.ensureCurrent?.()
  const certificate = await issueDeviceAuthorization(issuer, request, { ...options, certificates })
  const allCertificates = certificates.some(value => canonicalizeJson(value) === canonicalizeJson(certificate))
    ? certificates : [...certificates, certificate]
  const issuedAt = (options.now ?? Date.now)()
  if (!Number.isSafeInteger(issuedAt) || issuedAt >= request.payload.expiresAt) throw new Error("Application device request expired")
  let authorityView: IdentityAuthorityView | undefined
  let rustyServicePins: IdentityRustyServicePin[] | undefined
  let approvedProfileState: IdentityProfileState | undefined
  let proofPayload: DeviceAuthorizationApprovalPayload
  if (options.profileState !== undefined || options.revocations !== undefined) {
    if (!options.profileState || !options.revocations) throw new Error("Application device approval requires complete Identity authority state")
    const verifiedView = await createIdentityAuthorityView(issuer.identity,
      { certificates: allCertificates, revocations: Array.from(options.revocations) }, options.profileState)
    const approvedApplicationKey = await authorizeIdentityDataDevice(verifiedView, request.payload.deviceId)
    if (approvedApplicationKey !== request.payload.devicePublicKey) throw new Error("Application device is not active in this Identity")
    authorityView = JSON.parse(JSON.stringify(verifiedView)) as IdentityAuthorityView
    if (request.payload.version === 2 || options.includeProfileState) {
      const profile = await readIdentityProfileStateWithRevocations(options.profileState, issuer.identity,
        allCertificates, options.revocations)
      rustyServicePins = identityProfileRustyServicePins(profile)
      const requestedPins = "rustyServicePins" in request.payload ? request.payload.rustyServicePins : []
      if (requestedPins.some(pin => !rustyServicePins!.some(saved => canonicalizeJson(saved) === canonicalizeJson(pin)))) {
        throw new Error("Requested Rusty service pins are not committed to Identity profile history")
      }
      proofPayload = {
        kind: "mesh-device-authorization-approval", version: options.includeProfileState ? 4 : 3, request,
        certificateHash: await certificateHash(certificate), issuedAt, expiresAt: request.payload.expiresAt,
        authorityViewDigest: authorityView.viewDigest, revocationHead: authorityView.revocationHead,
        rustyServicePinsDigest: await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(rustyServicePins))),
        profileStateDigest: await identityProfileRevision(profile),
      }
      if (options.includeProfileState) approvedProfileState = profile
    } else {
      proofPayload = {
        kind: "mesh-device-authorization-approval", version: 2, request,
        certificateHash: await certificateHash(certificate), issuedAt, expiresAt: request.payload.expiresAt,
        authorityViewDigest: authorityView.viewDigest, revocationHead: authorityView.revocationHead,
      }
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
  const signedName = approvedProfileState ? identityProfileValue(approvedProfileState, "name").values[0] : undefined
  const identity = approvedProfileState
    ? { ...issuer.identity, displayName: typeof signedName === "string" ? signedName : "" } : issuer.identity
  const approval: DeviceAuthorizationApproval = { identity, issuerDeviceId: issuer.device.deviceId,
    certificates: allCertificates, certificate, ...(authorityView ? { authorityView } : {}),
    ...(rustyServicePins ? { rustyServicePins } : {}), ...(approvedProfileState ? { profileState: approvedProfileState } : {}), proof }
  if (JSON.stringify(approval).length > 256_000) throw new Error("Identity profile exceeds the browser sign-in size limit")
  return approval
}

/** Decode and verify bounded redirect evidence through the same public protocol seam. */
export async function parseDeviceAuthorizationApproval(encoded: string, request: DeviceAuthorizationRequest,
  options: { now?: () => number } = {}): Promise<DeviceAuthorizationApproval> {
  if (typeof encoded !== "string" || encoded.length > 350_000 || !/^[A-Za-z0-9_-]+$/u.test(encoded)) {
    throw new Error("Invalid Identity device approval")
  }
  let value: unknown
  try {
    const binary = atob(encoded.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - encoded.length % 4) % 4))
    if (binary.length > 256_000) throw new Error("oversized")
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(binary, char => char.charCodeAt(0))))
  } catch { throw new Error("Invalid Identity device approval") }
  return verifyDeviceAuthorizationApproval(value, request, options)
}

/** Validate the redirect payload against the caller's original request. */
export async function verifyDeviceAuthorizationApproval(
  approvalValue: unknown,
  requestValue: DeviceAuthorizationRequest,
  options: { now?: () => number } = {},
): Promise<DeviceAuthorizationApproval> {
  return verifyDeviceAuthorizationApprovalEvidence(approvalValue, requestValue, options, false)
}

/** Reverify retained signed approval evidence after its redirect request expires. */
export async function verifyRetainedDeviceAuthorizationApproval(
  approvalValue: unknown,
  requestValue: DeviceAuthorizationRequest,
): Promise<DeviceAuthorizationApproval> {
  return verifyDeviceAuthorizationApprovalEvidence(approvalValue, requestValue, {}, true)
}

async function verifyDeviceAuthorizationApprovalEvidence(
  approvalValue: unknown,
  requestValue: DeviceAuthorizationRequest,
  options: { now?: () => number },
  retained: boolean,
): Promise<DeviceAuthorizationApproval> {
  const request = structuredClone(requestValue)
  const serialized = JSON.stringify(approvalValue)
  if (!serialized || serialized.length > 256_000) throw new Error("Invalid Identity device approval")
  const approval = JSON.parse(serialized) as DeviceAuthorizationApproval
  if (!isRecord(approval) || !(hasExactKeys(approval, ["identity", "issuerDeviceId", "certificates", "certificate", "proof"]) ||
      hasExactKeys(approval, ["identity", "issuerDeviceId", "certificates", "certificate", "authorityView", "proof"]) ||
      hasExactKeys(approval, ["identity", "issuerDeviceId", "certificates", "certificate", "authorityView", "rustyServicePins", "proof"]) ||
      hasExactKeys(approval, ["identity", "issuerDeviceId", "certificates", "certificate", "authorityView", "rustyServicePins", "profileState", "proof"])) ||
      !isRecord(approval.identity) || !Array.isArray(approval.certificates) || approval.certificates.length < 1 ||
      approval.certificates.length > 32 || typeof approval.issuerDeviceId !== "string" ||
      !isRecord(approval.certificate) || !isRecord(approval.proof) || !isRecord(approval.proof.payload)) {
    throw new Error("Invalid Identity device approval")
  }
  const payload = approval.proof.payload
  const now = retained ? null : (options.now ?? Date.now)()
  const version2 = payload.version === 2 || payload.version === 3 || payload.version === 4
  const version3 = payload.version === 3 || payload.version === 4
  if (!hasExactKeys(payload, version3
      ? ["kind", "version", "request", "certificateHash", "issuedAt", "expiresAt", "authorityViewDigest", "revocationHead", "rustyServicePinsDigest", "profileStateDigest"]
      : version2 ? ["kind", "version", "request", "certificateHash", "issuedAt", "expiresAt", "authorityViewDigest", "revocationHead"]
      : ["kind", "version", "request", "certificateHash", "issuedAt", "expiresAt"]) ||
      payload.kind !== "mesh-device-authorization-approval" || (payload.version !== 1 && payload.version !== 2 && payload.version !== 3 && payload.version !== 4) ||
      canonicalizeJson(payload.request) !== canonicalizeJson(request) ||
      payload.certificateHash !== await certificateHash(approval.certificate) ||
      payload.expiresAt !== request.payload.expiresAt || !Number.isSafeInteger(payload.issuedAt) ||
      (!retained && payload.issuedAt > now! + 30_000) || payload.issuedAt >= payload.expiresAt ||
      (!retained && now! >= payload.expiresAt) ||
      approval.certificate.payload.deviceId !== request.payload.deviceId ||
      approval.certificate.payload.devicePublicKey !== request.payload.devicePublicKey ||
      approval.certificate.payload.personId !== approval.identity.personId || approval.certificate.payload.canEnrollDevices) {
    throw new Error("Identity device approval does not match this request")
  }
  if ((request.payload.version === 2 && !version3) || (request.payload.version === 1 && payload.version === 3)) {
    throw new Error("Identity pin request requires a committed catalog approval")
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
    if (version3) {
      if (!Array.isArray(approval.rustyServicePins) || typeof payload.rustyServicePinsDigest !== "string" ||
          !/^[A-Za-z0-9_-]{43}$/u.test(payload.rustyServicePinsDigest) ||
          typeof payload.profileStateDigest !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(payload.profileStateDigest)) {
        throw new Error("Application device approval is missing its signed Rusty pin catalog")
      }
      const requestedPins = "rustyServicePins" in request.payload ? request.payload.rustyServicePins : []
      const pins = await normalizeIdentityRustyServicePins(approval.rustyServicePins)
      const pinDigest = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(pins)))
      if (canonicalizeJson(pins) !== canonicalizeJson(approval.rustyServicePins) || pinDigest !== payload.rustyServicePinsDigest ||
          !requestedPins.every(pin => pins.some(saved => canonicalizeJson(saved) === canonicalizeJson(pin)))) {
        throw new Error("Application device approval Rusty pin catalog does not match")
      }
      const issuerCertificate = view.certificates.find(value => value.payload.deviceId === approval.issuerDeviceId)
      if (!issuerCertificate?.payload.canEnrollDevices) throw new Error("Rusty pin catalog was not approved by an Identity manager")
      const issuerAuthority = await verifyIdentityDeviceAuthority(approval.identity,
        { certificates: view.certificates, revocations: view.revocations })
      await authorizeIdentityDevice(issuerAuthority, approval.issuerDeviceId)
      if (payload.version === 4) {
        if (!approval.profileState) throw new Error("Identity approval is missing its signed profile")
        const profile = await readIdentityProfileStateWithRevocations(approval.profileState, approval.identity,
          view.certificates, view.revocations)
        if (await identityProfileRevision(profile) !== payload.profileStateDigest) {
          throw new Error("Identity approval profile does not match its signed digest")
        }
        const name = identityProfileValue(profile, "name").values[0]
        if ((typeof name === "string" ? name : "") !== approval.identity.displayName) {
          throw new Error("Identity approval name does not match its signed profile")
        }
      }
    } else if (approval.rustyServicePins !== undefined) {
      throw new Error("Unexpected Rusty pin catalog on a legacy approval")
    }
  } else if (approval.authorityView) {
    throw new Error("Unexpected Identity authority view on a legacy approval")
  } else if (approval.rustyServicePins !== undefined) {
    throw new Error("Unexpected Rusty pin catalog on a legacy approval")
  }
  if (payload.version !== 4 && approval.profileState !== undefined) throw new Error("Unexpected Identity profile on this approval")
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
  const baseKeys = ["kind", "version", "applicationOrigin", "challenge", "expiresAt", "personId", "deviceId", "devicePublicKey"]
  const version = value.payload.version
  const keysMatch = version === 1 ? hasExactKeys(value.payload, baseKeys)
    : version === 2 ? hasExactKeys(value.payload, [...baseKeys, "rustyServicePins"]) && Array.isArray(value.payload.rustyServicePins)
    : false
  return keysMatch &&
    value.payload.kind === "mesh-device-authorization-request" && (version === 1 || version === 2) &&
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
