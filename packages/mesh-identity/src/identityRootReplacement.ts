import { authorizeIdentityDataDevice, authorizeIdentityDevice, canonicalizeJson, certificateHash,
  createIdentityAuthorityView, createIdentityRootSuccession, emptyIdentityProfileState, identityProfileRevision, publicKeyId,
  sha256Base64Url, signEnvelope, verifyDeviceCertificateChain, verifyEnvelope,
  verifyIdentityAuthorityView, verifyIdentityDeviceAuthority,
  type DeviceCertificate, type IdentityAuthorityHead, type IdentityAuthorityView, type LocalProfile,
  type PublicIdentity, type SignedEnvelope } from "./index"
import { verifyIdentityRootSuccession, type IdentityRootSuccession } from "./identityRootSuccession"
import { createIdentityRustyServicePinOperation, identityProfileRustyServicePins, normalizeIdentityRustyServicePins,
  readIdentityProfileState, readIdentityProfileStateWithRevocations, type IdentityProfileState,
  type IdentityRustyServicePin } from "./identityProfile"

const requestDomain = "MESH-DEVICE-AUTHORIZATION/1"
const keyProofDomain = "MESH-IDENTITY-ROOT-REPLACEMENT-KEY/1"
const offerDomain = "MESH-IDENTITY-ROOT-REPLACEMENT/1"

export type IdentityRootReplacementRequester = Pick<LocalProfile, "identity" | "device" | "privateKeys">

export type IdentityRootReplacementRequestPayload = {
  kind: "mesh-identity-root-replacement-request"
  version: 1
  applicationOrigin: string
  challenge: string
  expiresAt: number
  previousPersonId: string
  requesterDeviceId: string
  requesterDevicePublicKey: string
  successorDeviceId: string
  successorDevicePublicKey: string
  rustyServicePins: IdentityRustyServicePin[]
}

export type IdentityRootReplacementKeyProofPayload = {
  kind: "mesh-identity-root-replacement-key-proof"
  version: 1
  requestHash: string
  applicationOrigin: string
  challenge: string
  expiresAt: number
  previousPersonId: string
  requesterDeviceId: string
  successorDeviceId: string
  successorDevicePublicKey: string
}

export type IdentityRootReplacementRequest = {
  authorization: SignedEnvelope<IdentityRootReplacementRequestPayload>
  successorKeyProof: SignedEnvelope<IdentityRootReplacementKeyProofPayload>
}

export type IdentityRootReplacementOfferAuthorization = {
  kind: "mesh-identity-root-replacement-offer"
  version: 1
  requestHash: string
  previousPersonId: string
  previousProfileStateHash: string
  previousAuthorityHead: IdentityAuthorityHead
  previousViewDigest: string
  successorPersonId: string
  successorAuthorityHead: IdentityAuthorityHead
  successorViewDigest: string
  deviceId: string
  devicePublicKey: string
  certificateHash: string
  successorProfileStateHash: string
  transitionHash: string
  issuedAt: number
  expiresAt: number
}

export type IdentityRootReplacementOfferAcceptance = {
  kind: "mesh-identity-root-replacement-acceptance"
  version: 1
  offerHash: string
  previousPersonId: string
  successorPersonId: string
}

export type IdentityRootReplacementOffer = {
  version: 1
  request: IdentityRootReplacementRequest
  previousAuthorityView: IdentityAuthorityView
  previousProfileState: IdentityProfileState
  successorIdentity: PublicIdentity
  certificate: DeviceCertificate
  certificates: DeviceCertificate[]
  authorityView: IdentityAuthorityView
  successorProfileState: IdentityProfileState
  succession: IdentityRootSuccession
  authorization: SignedEnvelope<IdentityRootReplacementOfferAuthorization>
  acceptance: SignedEnvelope<IdentityRootReplacementOfferAcceptance>
}

export type RootReplacementBinding = { applicationOrigin: string; challenge: string; now?: () => number }

/** Bind the old app session and a freshly generated successor app key to one explicit request. */
export async function createIdentityRootReplacementRequest(requester: IdentityRootReplacementRequester,
  options: { successorDevice: { deviceId: string; publicKey: string; privateKey: CryptoKey };
    applicationOrigin: string; challenge: string; expiresAt: number;
    rustyServicePins: IdentityRustyServicePin[] }): Promise<IdentityRootReplacementRequest> {
  const rustyServicePins = await normalizeIdentityRustyServicePins(options.rustyServicePins)
  if (!requester.privateKeys.devicePrivateKey || requester.identity.personId !== await publicKeyId(requester.identity.publicKey) ||
      requester.device.deviceId !== await publicKeyId(requester.device.publicKey) ||
      options.successorDevice.deviceId !== await publicKeyId(options.successorDevice.publicKey) ||
      options.successorDevice.deviceId === requester.device.deviceId || !validOrigin(options.applicationOrigin) ||
      !/^[a-f0-9]{64}$/u.test(options.challenge) || !Number.isSafeInteger(options.expiresAt) ||
      options.expiresAt <= Date.now() || options.expiresAt > Date.now() + 120_000) {
    throw new Error("Invalid Identity root replacement request")
  }
  const payload: IdentityRootReplacementRequestPayload = {
    kind: "mesh-identity-root-replacement-request", version: 1,
    applicationOrigin: options.applicationOrigin, challenge: options.challenge, expiresAt: options.expiresAt,
    previousPersonId: requester.identity.personId,
    requesterDeviceId: requester.device.deviceId,
    requesterDevicePublicKey: requester.device.publicKey, successorDeviceId: options.successorDevice.deviceId,
    successorDevicePublicKey: options.successorDevice.publicKey, rustyServicePins,
  }
  const authorization = await signEnvelope(requester.privateKeys.devicePrivateKey, payload,
    requester.device.deviceId, requestDomain)
  if (!await verifyEnvelope(authorization, requester.device.publicKey, requestDomain)) throw new Error("App device key mismatch")
  const proofPayload: IdentityRootReplacementKeyProofPayload = {
    kind: "mesh-identity-root-replacement-key-proof", version: 1,
    requestHash: await envelopeHash(authorization), applicationOrigin: options.applicationOrigin,
    challenge: options.challenge, expiresAt: options.expiresAt, previousPersonId: requester.identity.personId,
    requesterDeviceId: requester.device.deviceId, successorDeviceId: options.successorDevice.deviceId,
    successorDevicePublicKey: options.successorDevice.publicKey,
  }
  const successorKeyProof = await signEnvelope(options.successorDevice.privateKey, proofPayload,
    options.successorDevice.deviceId, keyProofDomain)
  if (!await verifyEnvelope(successorKeyProof, options.successorDevice.publicKey, keyProofDomain)) {
    throw new Error("Successor app key does not match its public key")
  }
  return { authorization, successorKeyProof }
}

/** Require proof of both the old active session and possession of the fresh successor app key. */
export async function verifyIdentityRootReplacementRequest(requestValue: IdentityRootReplacementRequest,
  previousAuthorityValue: IdentityAuthorityView,
  binding: RootReplacementBinding): Promise<IdentityRootReplacementRequestPayload> {
  const previousAuthority = await verifyIdentityAuthorityView(previousAuthorityValue)
  const request = requestValue
  const authorization = request?.authorization
  const payload = authorization?.payload
  const now = (binding.now ?? Date.now)()
  const requestKeys = ["kind", "version", "applicationOrigin", "challenge", "expiresAt", "previousPersonId",
    "requesterDeviceId", "requesterDevicePublicKey", "successorDeviceId", "successorDevicePublicKey", "rustyServicePins"]
  if (!isRecord(request) || !hasExactKeys(request, ["authorization", "successorKeyProof"]) ||
      !isSignedEnvelope(authorization) || !hasExactKeys(payload, requestKeys) ||
      payload.kind !== "mesh-identity-root-replacement-request" || payload.version !== 1 ||
      payload.applicationOrigin !== binding.applicationOrigin || payload.challenge !== binding.challenge ||
      payload.previousPersonId !== previousAuthority.personId ||
      !validOrigin(payload.applicationOrigin) ||
      !/^[a-f0-9]{64}$/u.test(payload.challenge) || !Number.isSafeInteger(payload.expiresAt) ||
      payload.expiresAt <= now || payload.expiresAt > now + 120_000 ||
      authorization.signerKeyId !== payload.requesterDeviceId ||
      await publicKeyId(payload.requesterDevicePublicKey) !== payload.requesterDeviceId ||
      await publicKeyId(payload.successorDevicePublicKey) !== payload.successorDeviceId ||
      payload.successorDeviceId === payload.requesterDeviceId ||
      !await verifyEnvelope(authorization, payload.requesterDevicePublicKey, requestDomain)) {
    throw new Error("Invalid or expired Identity root replacement request")
  }
  const normalizedPins = await normalizeIdentityRustyServicePins(payload.rustyServicePins)
  if (canonicalizeJson(normalizedPins) !== canonicalizeJson(payload.rustyServicePins)) {
    throw new Error("Identity root replacement request has a non-canonical Rusty service catalog")
  }
  const activeRequesterKey = await authorizeIdentityDataDevice(previousAuthority, payload.requesterDeviceId)
  if (activeRequesterKey !== payload.requesterDevicePublicKey) {
    throw new Error("Root replacement requester is not an active Identity device")
  }
  const proof = request.successorKeyProof
  const proofPayload = proof?.payload
  const expectedProof: IdentityRootReplacementKeyProofPayload = {
    kind: "mesh-identity-root-replacement-key-proof", version: 1,
    requestHash: await envelopeHash(authorization), applicationOrigin: payload.applicationOrigin,
    challenge: payload.challenge, expiresAt: payload.expiresAt, previousPersonId: payload.previousPersonId,
    requesterDeviceId: payload.requesterDeviceId, successorDeviceId: payload.successorDeviceId,
    successorDevicePublicKey: payload.successorDevicePublicKey,
  }
  if (!isSignedEnvelope(proof) || !hasExactKeys(proofPayload, ["kind", "version", "requestHash", "applicationOrigin",
      "challenge", "expiresAt", "previousPersonId", "requesterDeviceId", "successorDeviceId", "successorDevicePublicKey"]) ||
      canonicalizeJson(proofPayload) !== canonicalizeJson(expectedProof) || proof.signerKeyId !== payload.successorDeviceId ||
      !await verifyEnvelope(proof, payload.successorDevicePublicKey, keyProofDomain)) {
    throw new Error("Successor app key proof does not match this request")
  }
  return structuredClone(payload)
}

/** Create a request-bound offer. Recovery keys stay in the Identity origin. */
export async function createIdentityRootReplacementOffer(previous: LocalProfile, successor: LocalProfile,
  requestValue: IdentityRootReplacementRequest, previousAuthorityValue: IdentityAuthorityView,
  previousProfileStateValue: IdentityProfileState,
  options: { successorProfileState?: IdentityProfileState; consentedRustyServicePins: IdentityRustyServicePin[];
    now?: () => number }): Promise<IdentityRootReplacementOffer> {
  const previousAuthority = await verifyIdentityAuthorityView(previousAuthorityValue)
  let previousProfileState = await readIdentityProfileStateWithRevocations(previousProfileStateValue,
    previous.identity, previousAuthority.certificates, previousAuthority.revocations)
  const request = structuredClone(requestValue)
  const requestPayload = request.authorization.payload
  await verifyIdentityRootReplacementRequest(request, previousAuthority, {
    applicationOrigin: requestPayload.applicationOrigin, challenge: requestPayload.challenge, now: options.now,
  })
  const consentedPins = await normalizeIdentityRustyServicePins(options.consentedRustyServicePins)
  if (canonicalizeJson(consentedPins) !== canonicalizeJson(requestPayload.rustyServicePins)) {
    throw new Error("Rusty service pins require explicit consent for this root replacement")
  }
  for (const pin of consentedPins) {
    const operation = await createIdentityRustyServicePinOperation(previous, previousProfileState, pin,
      previousAuthority.certificates)
    if (operation) previousProfileState = await readIdentityProfileState({ ...previousProfileState,
      operations: [...previousProfileState.operations, operation] }, previous.identity, previousAuthority.certificates)
  }
  const acceptedPreviousAuthority = await createIdentityAuthorityView(previous.identity,
    { certificates: previousAuthority.certificates, revocations: previousAuthority.revocations }, previousProfileState)
  const oldRootAuthority = await verifyIdentityDeviceAuthority(previous.identity,
    { certificates: previousAuthority.certificates, revocations: previousAuthority.revocations })
  await authorizeIdentityDevice(oldRootAuthority, previous.device.deviceId)
  if (previous.identity.personId !== previousAuthority.personId || !previous.privateKeys.identityPrivateKey ||
      !successor.privateKeys.identityPrivateKey || successor.identity.personId === previous.identity.personId ||
      successor.identity.personId !== await publicKeyId(successor.identity.publicKey) ||
      successor.device.deviceId === requestPayload.successorDeviceId) {
    throw new Error("A distinct recovery-authorized successor Identity is required")
  }
  const candidateCertificate: DeviceCertificate = await signEnvelope(successor.privateKeys.identityPrivateKey, {
    kind: "device-certificate", version: 1, personId: successor.identity.personId,
    deviceId: requestPayload.successorDeviceId, devicePublicKey: requestPayload.successorDevicePublicKey,
    issuerCertificateHash: null, canEnrollDevices: false,
  }, successor.identity.personId)
  const certificates = [successor.certificate, candidateCertificate]
  let successorProfileState = await readIdentityProfileState(options.successorProfileState ??
    emptyIdentityProfileState(successor.identity.personId), successor.identity, certificates)
  for (const pin of identityProfileRustyServicePins(previousProfileState)) {
    const operation = await createIdentityRustyServicePinOperation(successor, successorProfileState, pin, certificates)
    if (operation) successorProfileState = await readIdentityProfileState({ ...successorProfileState,
      operations: [...successorProfileState.operations, operation] }, successor.identity, certificates)
  }
  const authorityView = await createIdentityAuthorityView(successor.identity,
    { certificates, revocations: [] }, successorProfileState)
  const succession = await createIdentityRootSuccession(previous, successor, acceptedPreviousAuthority)
  const issuedAt = (options.now ?? Date.now)()
  if (!Number.isSafeInteger(issuedAt) || issuedAt >= requestPayload.expiresAt) throw new Error("Root replacement request expired")
  const authorizationPayload: IdentityRootReplacementOfferAuthorization = {
    kind: "mesh-identity-root-replacement-offer", version: 1, requestHash: await envelopeHash(request),
    previousPersonId: previous.identity.personId, previousProfileStateHash: await identityProfileRevision(previousProfileState),
    previousAuthorityHead: structuredClone(acceptedPreviousAuthority.revocationHead), previousViewDigest: acceptedPreviousAuthority.viewDigest,
    successorPersonId: successor.identity.personId,
    successorAuthorityHead: structuredClone(authorityView.revocationHead), successorViewDigest: authorityView.viewDigest,
    deviceId: candidateCertificate.payload.deviceId, devicePublicKey: candidateCertificate.payload.devicePublicKey,
    certificateHash: await certificateHash(candidateCertificate),
    successorProfileStateHash: await identityProfileRevision(successorProfileState),
    transitionHash: await transitionHash(succession),
    issuedAt, expiresAt: requestPayload.expiresAt,
  }
  const authorization = await signEnvelope(previous.privateKeys.identityPrivateKey, authorizationPayload,
    previous.identity.personId, offerDomain)
  const acceptancePayload: IdentityRootReplacementOfferAcceptance = {
    kind: "mesh-identity-root-replacement-acceptance", version: 1,
    offerHash: await envelopeHash(authorization), previousPersonId: previous.identity.personId,
    successorPersonId: successor.identity.personId,
  }
  const acceptance = await signEnvelope(successor.privateKeys.identityPrivateKey, acceptancePayload,
    successor.identity.personId, offerDomain)
  const offer: IdentityRootReplacementOffer = { version: 1, request,
    previousAuthorityView: JSON.parse(JSON.stringify(acceptedPreviousAuthority)) as IdentityAuthorityView,
    previousProfileState: structuredClone(previousProfileState), successorIdentity: structuredClone(successor.identity),
    certificate: candidateCertificate, certificates, authorityView, successorProfileState, succession, authorization, acceptance }
  await verifyIdentityRootReplacementOffer(offer, request, previous.identity, { now: options.now })
  return offer
}

/** Validate the request, both roots, successor authority view, and the fresh candidate app key. */
export async function verifyIdentityRootReplacementOffer(offerValue: unknown,
  requestValue: IdentityRootReplacementRequest, previousIdentity: PublicIdentity,
  options: { now?: () => number } = {}): Promise<{
    previousPersonId: string
    successorPersonId: string
    successorIdentity: PublicIdentity
    certificate: DeviceCertificate
    certificates: DeviceCertificate[]
    authorityView: IdentityAuthorityView
    successorProfileState: IdentityProfileState
    succession: IdentityRootSuccession
  }> {
  const serialized = JSON.stringify(offerValue)
  if (!serialized || serialized.length > 512_000) throw new Error("Invalid Identity root replacement offer")
  const offer = JSON.parse(serialized) as IdentityRootReplacementOffer
  if (!isRecord(offer) || !hasExactKeys(offer, ["version", "request", "previousAuthorityView", "previousProfileState",
      "successorIdentity", "certificate", "certificates",
      "authorityView", "successorProfileState", "succession", "authorization", "acceptance"]) || offer.version !== 1 ||
      !Array.isArray(offer.certificates) || offer.certificates.length < 2 || offer.certificates.length > 512 ||
      !canonicalEqual(offer.request, requestValue)) throw new Error("Identity root replacement offer does not match this request")

  const previousAuthority = await verifyIdentityAuthorityView(offer.previousAuthorityView)
  if (!isRecord(previousIdentity) || previousIdentity.personId !== previousAuthority.personId ||
      previousIdentity.publicKey !== previousAuthority.identityPublicKey ||
      await publicKeyId(previousIdentity.publicKey) !== previousIdentity.personId) {
    throw new Error("Root replacement offer belongs to a different previous Identity")
  }
  const previousProfileState = await readIdentityProfileStateWithRevocations(offer.previousProfileState,
    previousIdentity, previousAuthority.certificates, previousAuthority.revocations)
  const acceptedPins = identityProfileRustyServicePins(previousProfileState)
  for (const requestedPin of requestPins(offer.request)) {
    if (!acceptedPins.some(pin => canonicalizeJson(pin) === canonicalizeJson(requestedPin))) {
      throw new Error("Root replacement offer omitted an app-requested Rusty service pin")
    }
  }
  const request = await verifyIdentityRootReplacementRequest(offer.request, previousAuthority, {
    applicationOrigin: requestValue.authorization.payload.applicationOrigin,
    challenge: requestValue.authorization.payload.challenge, now: options.now,
  })
  const successorAuthority = await verifyIdentityAuthorityView(offer.authorityView)
  if (!isRecord(offer.successorIdentity) || offer.successorIdentity.personId !== successorAuthority.personId ||
      offer.successorIdentity.publicKey !== successorAuthority.identityPublicKey ||
      await publicKeyId(offer.successorIdentity.publicKey) !== offer.successorIdentity.personId ||
      offer.successorIdentity.personId === request.previousPersonId ||
      !offer.certificates.some(certificate => canonicalEqual(certificate, offer.certificate)) ||
      !successorAuthority.certificates.some(certificate => canonicalEqual(certificate, offer.certificate))) {
    throw new Error("Successor Identity certificate catalog does not match the authority view")
  }
  const certificate = offer.certificate
  if (!isRecord(certificate) || certificate.payload.personId !== offer.successorIdentity.personId ||
      certificate.payload.deviceId !== request.successorDeviceId || certificate.payload.devicePublicKey !== request.successorDevicePublicKey ||
      certificate.payload.canEnrollDevices !== false ||
      await verifyDeviceCertificateChain(offer.successorIdentity, request.successorDeviceId, offer.certificates) !== request.successorDevicePublicKey ||
      await authorizeIdentityDataDevice(successorAuthority, request.successorDeviceId) !== request.successorDevicePublicKey) {
    throw new Error("Successor app certificate does not match the signed request")
  }

  const succession = await verifyIdentityRootSuccession(offer.succession, previousAuthority)
  const successorProfileState = await readIdentityProfileStateWithRevocations(offer.successorProfileState,
    offer.successorIdentity, offer.certificates, successorAuthority.revocations)
  const payload = offer.authorization?.payload
  const expected: IdentityRootReplacementOfferAuthorization = {
    kind: "mesh-identity-root-replacement-offer", version: 1,
    requestHash: await envelopeHash(offer.request), previousPersonId: request.previousPersonId,
    previousProfileStateHash: await identityProfileRevision(previousProfileState),
    previousAuthorityHead: structuredClone(previousAuthority.revocationHead), previousViewDigest: previousAuthority.viewDigest,
    successorPersonId: offer.successorIdentity.personId,
    successorAuthorityHead: structuredClone(successorAuthority.revocationHead), successorViewDigest: successorAuthority.viewDigest,
    deviceId: request.successorDeviceId, devicePublicKey: request.successorDevicePublicKey,
    certificateHash: await certificateHash(certificate), successorProfileStateHash: await identityProfileRevision(successorProfileState),
    transitionHash: await transitionHash(offer.succession),
    issuedAt: payload?.issuedAt as number, expiresAt: request.expiresAt,
  }
  const now = (options.now ?? Date.now)()
  if (!isSignedEnvelope(offer.authorization) || !hasExactKeys(payload, ["kind", "version", "requestHash", "previousPersonId",
      "previousProfileStateHash", "previousAuthorityHead", "previousViewDigest", "successorPersonId", "successorAuthorityHead", "successorViewDigest", "deviceId",
      "devicePublicKey", "certificateHash", "successorProfileStateHash", "transitionHash", "issuedAt", "expiresAt"]) ||
      canonicalizeJson(payload) !== canonicalizeJson(expected) ||
      !Number.isSafeInteger(payload.issuedAt) || payload.issuedAt > now + 30_000 || payload.issuedAt >= request.expiresAt ||
      offer.authorization.signerKeyId !== request.previousPersonId ||
      !await verifyEnvelope(offer.authorization, previousAuthority.identityPublicKey, offerDomain)) {
    throw new Error("Invalid old-root root replacement offer signature")
  }
  const acceptancePayload = offer.acceptance?.payload
  const expectedAcceptance: IdentityRootReplacementOfferAcceptance = {
    kind: "mesh-identity-root-replacement-acceptance", version: 1,
    offerHash: await envelopeHash(offer.authorization), previousPersonId: request.previousPersonId,
    successorPersonId: offer.successorIdentity.personId,
  }
  if (!isSignedEnvelope(offer.acceptance) || !hasExactKeys(acceptancePayload, ["kind", "version", "offerHash", "previousPersonId",
      "successorPersonId"]) || canonicalizeJson(acceptancePayload) !== canonicalizeJson(expectedAcceptance) ||
      offer.acceptance.signerKeyId !== offer.successorIdentity.personId ||
      !await verifyEnvelope(offer.acceptance, offer.successorIdentity.publicKey, offerDomain) ||
      succession.previousPersonId !== request.previousPersonId || succession.successorPersonId !== offer.successorIdentity.personId ||
      succession.successorIdentityPublicKey !== offer.successorIdentity.publicKey) {
    throw new Error("Invalid successor root acceptance")
  }
  return { previousPersonId: request.previousPersonId, successorPersonId: offer.successorIdentity.personId,
    successorIdentity: structuredClone(offer.successorIdentity), certificate: structuredClone(certificate),
    certificates: structuredClone(offer.certificates), authorityView: JSON.parse(JSON.stringify(successorAuthority)) as IdentityAuthorityView,
    successorProfileState, succession: structuredClone(offer.succession) }
}

async function transitionHash(value: IdentityRootSuccession): Promise<string> {
  return sha256Base64Url(new TextEncoder().encode(canonicalizeJson(value)))
}

async function envelopeHash(value: unknown): Promise<string> {
  return sha256Base64Url(new TextEncoder().encode(canonicalizeJson(value)))
}

function canonicalEqual(left: unknown, right: unknown): boolean {
  try { return canonicalizeJson(left) === canonicalizeJson(right) } catch { return false }
}

function requestPins(request: IdentityRootReplacementRequest): IdentityRustyServicePin[] {
  return request.authorization.payload.rustyServicePins
}

function isRecord(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
}

function isSignedEnvelope(value: unknown): value is SignedEnvelope<unknown> {
  return isRecord(value) && hasExactKeys(value, ["payload", "signerKeyId", "signature"]) &&
    typeof value.signerKeyId === "string" && typeof value.signature === "string" && isRecord(value.payload)
}

function hasExactKeys(value: unknown, keys: string[]): value is Record<string, any> {
  return isRecord(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}

function validOrigin(value: string): boolean {
  try {
    const parsed = new URL(value)
    return parsed.origin === value && (parsed.protocol === "https:" ||
      parsed.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname))
  } catch { return false }
}
