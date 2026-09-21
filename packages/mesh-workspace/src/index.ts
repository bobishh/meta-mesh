import {
  canonicalizeJson,
  fromBase64Url,
  sha256Base64Url,
  signEnvelope,
  verifyEnvelope,
  type DeviceCertificate,
  type LocalProfile,
  type SignedEnvelope,
} from "@meta-uber/mesh-identity"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"

export type WorkspaceRole = "owner" | "editor" | "visitor"
export type WorkspaceGrant = SignedEnvelope<{
  kind: "workspace-grant"
  version: 1
  grantId: string
  workspaceId: string
  personId: string
  role: WorkspaceRole
}>

export async function certHashDefault(cert: DeviceCertificate): Promise<string> {
  return sha256Base64Url(new TextEncoder().encode(canonicalizeJson(cert)))
}

export async function createDelegatedCertificate(
  delegatorDevicePrivateKey: CryptoKey,
  delegatorDeviceId: string,
  personId: string,
  subjectDeviceId: string,
  subjectDevicePublicKey: string,
  issuerCertificateHash: string,
): Promise<DeviceCertificate> {
  return await signEnvelope(delegatorDevicePrivateKey, {
    kind: "device-certificate" as const,
    version: 1 as const,
    personId,
    deviceId: subjectDeviceId,
    devicePublicKey: subjectDevicePublicKey,
    issuerCertificateHash,
    canEnrollDevices: true as const,
  }, delegatorDeviceId) as DeviceCertificate
}

export async function createWorkspaceGrant(
  profile: LocalProfile,
  workspaceId: string,
  personId: string,
  role: WorkspaceRole,
): Promise<WorkspaceGrant> {
  return await signEnvelope(profile.privateKeys.devicePrivateKey, {
    kind: "workspace-grant" as const,
    version: 1 as const,
    grantId: crypto.randomUUID(),
    workspaceId,
    personId,
    role,
  }, profile.device.deviceId) as WorkspaceGrant
}

export const MAX_PEER_ADVERTISEMENT_SIZE = 65536 // 64 KiB
export const MAX_ENDPOINT_LENGTH = 2048
export const MAX_STRING_LENGTH = 256
export const MAX_FUTURE_TOLERANCE_MS = 5 * 60 * 1000 // 5 minutes
export const MAX_STALE_TOLERANCE_MS = 30 * 24 * 60 * 60 * 1000 // 30 days
export const MAX_CERT_CHAIN_LENGTH = 32
export const MAX_SUCCESSION_EDITORS = 32

export type PeerAdvertisementPayload = {
  kind: "peer-advertisement"
  version: 1
  workspaceId: string
  personId: string
  deviceId: string
  instanceId?: string
  endpoint: string
  issuedAt: string // ISO 8601 string
  routeSequence?: number
  expiresAt?: string
  deviceName?: string
  userAgent?: string
}

export type PeerAdvertisement = SignedEnvelope<PeerAdvertisementPayload>

export type WorkspaceRevocationPayload = {
  kind: "workspace-revocation"
  version: 1
  workspaceId: string
  ownerPersonId: string
  personId: string
  epoch: number
  revokedAt: string
}

export type WorkspaceRevocation = SignedEnvelope<WorkspaceRevocationPayload>

export type WorkspaceAuthority = {
  personId: string
  publicKey: string
  certificates: DeviceCertificate[]
}

export type WorkspaceOwnershipTransferPayload = {
  kind: "workspace-ownership-transfer"
  version: 1
  workspaceId: string
  fromOwnerPersonId: string
  toOwnerPersonId: string
  toOwnerPublicKey: string
  toOwnerCertificates: DeviceCertificate[]
  toOwnerGrant: WorkspaceGrant
  formerOwnerGrant: WorkspaceGrant
  workspaceHeads: string[]
  epoch: number
  transferredAt: string
}

export type WorkspaceOwnershipTransfer = SignedEnvelope<WorkspaceOwnershipTransferPayload>

export type WorkspaceBreakGlassClaim = SignedEnvelope<{
  kind: "workspace-break-glass"
  version: 1
  workspaceId: string
  fromOwnerPersonId: string
  toOwnerPersonId: string
  toOwnerPublicKey: string
  toOwnerCertificates: DeviceCertificate[]
  editorGrant: WorkspaceGrant
  workspaceHeads: string[]
  epoch: number
  claimedAt: string
}>

export function hasConflictingOwnershipTransfers(records: WorkspaceOwnershipTransfer[]): boolean {
  return meshRustRuntime().state.hasConflictingOwnershipTransfers(records)
}

export type WorkspaceSuccessionPolicy = SignedEnvelope<{
  kind: "workspace-succession-policy"; version: 1; workspaceId: string; ownerPersonId: string
  successorPersonId: string | null; eligibleEditorPersonIds: string[]; epoch: number; updatedAt: string
}>
export type WorkspaceSuccessionVote = {
  signed: SignedEnvelope<{
    kind: "workspace-succession-vote"; version: 1; workspaceId: string; ownerPersonId: string
    voterPersonId: string; candidatePersonId: string; policySignature: string; votedAt: string
  }>
  voterPublicKey: string
  voterCertificates: DeviceCertificate[]
  voterGrant: WorkspaceGrant
}
export type WorkspaceSuccessionClaim = SignedEnvelope<{
  kind: "workspace-succession-claim"; version: 1; workspaceId: string; fromOwnerPersonId: string
  toOwnerPersonId: string; toOwnerPublicKey: string; toOwnerCertificates: DeviceCertificate[]
  candidateGrant: WorkspaceGrant; formerOwnerGrant: WorkspaceGrant
  policy: WorkspaceSuccessionPolicy; votes: WorkspaceSuccessionVote[]; workspaceHeads: string[]
  epoch: number; claimedAt: string
}>

export type WorkspaceMemberBundle = {
  advertisement: PeerAdvertisement
  signed?: PeerAdvertisement
  payload?: PeerAdvertisementPayload
  signerKeyId?: string
  signature?: string
  publicKey: string
  certificates: DeviceCertificate[]
  grant?: WorkspaceGrant
  ownerPublicKey?: string
  ownerCertificates?: DeviceCertificate[]
  role?: "owner" | "editor" | "visitor"
}

export type CreatePeerAdvertisementOptions = {
  profile?: LocalProfile
  workspaceId: string
  endpoint: string
  instanceId?: string
  certificates?: DeviceCertificate[]
  grant?: WorkspaceGrant
  ownerPublicKey?: string
  ownerCertificates?: DeviceCertificate[]
  issuedAt?: string
  routeSequence?: number
  expiresAt?: string
  deviceName?: string
  userAgent?: string
}

export type VerifyDeviceChainOptions = {
  personId?: string
  publicKey: string
  deviceId: string
  certificates: DeviceCertificate[]
}

export type VerifyWorkspaceMemberBundleOptions = {
  workspaceId?: string
  ownerPersonId?: string
  ownerPublicKey?: string
  ownerCertificates?: DeviceCertificate[]
  ownerHistory?: WorkspaceAuthority[]
  maxByteLength?: number
  now?: number | Date | string
  allowStaleRoute?: boolean
}

export type VerifiedWorkspaceMember = Omit<
  WorkspaceMemberBundle,
  "payload" | "signed" | "signerKeyId" | "signature"
> & {
  advertisement: PeerAdvertisement
  signed: PeerAdvertisement
  payload: PeerAdvertisementPayload
  signerKeyId: string
  signature: string
  devicePublicKey: string
  role: "owner" | "editor" | "visitor"
}

export async function keyId(key: string): Promise<string> {
  if (typeof key !== "string" || !key) {
    throw new Error("Invalid public key: must be a non-empty string")
  }
  const bytes = fromBase64Url(key)
  if (bytes.byteLength !== 32) {
    throw new Error(`Invalid public key: expected 32 bytes, got ${bytes.byteLength}`)
  }
  return sha256Base64Url(bytes)
}

/**
 * Reusable certificate chain validator that validates that target deviceId is
 * transitively rooted in the provided identity public key via a valid sequence
 * of DeviceCertificates.
 *
 * Returns the target device's public key (base64url) on success.
 */
export async function verifyDeviceChain(
  arg1: string | DeviceCertificate[] | VerifyDeviceChainOptions,
  arg2?: string | DeviceCertificate[],
  arg3?: string | DeviceCertificate[],
  arg4?: DeviceCertificate[]
): Promise<string> {
  let personId: string | undefined
  let publicKey: string
  let deviceId: string
  let certificates: DeviceCertificate[]

  if (typeof arg1 === "object" && !Array.isArray(arg1)) {
    personId = arg1.personId
    publicKey = arg1.publicKey
    deviceId = arg1.deviceId
    certificates = arg1.certificates
  } else if (Array.isArray(arg1)) {
    certificates = arg1
    publicKey = arg2 as string
    deviceId = arg3 as string
  } else if (
    typeof arg1 === "string" &&
    typeof arg2 === "string" &&
    typeof arg3 === "string" &&
    Array.isArray(arg4)
  ) {
    personId = arg1
    publicKey = arg2
    deviceId = arg3
    certificates = arg4
  } else if (typeof arg1 === "string" && typeof arg2 === "string" && Array.isArray(arg3)) {
    publicKey = arg1
    deviceId = arg2
    certificates = arg3
  } else {
    throw new Error("Invalid arguments to verifyDeviceChain")
  }

  if (!publicKey || typeof publicKey !== "string") {
    throw new Error("Invalid public key")
  }
  if (!deviceId || typeof deviceId !== "string") {
    throw new Error("Invalid device ID")
  }
  if (
    !Array.isArray(certificates) ||
    certificates.length === 0 ||
    certificates.length > MAX_CERT_CHAIN_LENGTH
  ) {
    throw new Error(`Invalid certificate chain: expected between 1 and ${MAX_CERT_CHAIN_LENGTH} certificates`)
  }

  // Verify identity hash
  const derivedPersonId = await keyId(publicKey)
  if (personId && personId !== derivedPersonId) {
    throw new Error(`Identity does not match its key: expected ${personId}, derived ${derivedPersonId}`)
  }
  personId = derivedPersonId

  // Build lookup by certificate hash
  const byHash = new Map<string, DeviceCertificate>()
  for (const cert of certificates) {
    const hash = await certHashDefault(cert)
    byHash.set(hash, cert)
  }

  // Find target device certificate
  const first = certificates.find((c) => c?.payload?.deviceId === deviceId)
  if (!first) {
    throw new Error(`Missing device certificate for ${deviceId}`)
  }

  let cert: DeviceCertificate | undefined = first
  const seenCertHashes = new Set<string>()
  let depth = 0

  while (cert) {
    depth++
    if (depth > MAX_CERT_CHAIN_LENGTH) {
      throw new Error(`Certificate chain exceeds depth limit ${MAX_CERT_CHAIN_LENGTH}`)
    }

    const currentCertHash = await certHashDefault(cert)
    if (seenCertHashes.has(currentCertHash)) {
      throw new Error("Cycle detected in certificate chain")
    }
    seenCertHashes.add(currentCertHash)

    const p = cert.payload
    if (
      !p ||
      p.kind !== "device-certificate" ||
      p.version !== 1 ||
      p.personId !== personId ||
      typeof p.devicePublicKey !== "string"
    ) {
      throw new Error("Invalid device certificate payload")
    }

    // Verify exact device hash
    if ((await keyId(p.devicePublicKey)) !== p.deviceId) {
      throw new Error(`Device key does not match deviceId ${p.deviceId}`)
    }

    // Check if root certificate
    if (p.issuerCertificateHash === null) {
      if (cert.signerKeyId !== personId) {
        throw new Error(`Root certificate signerKeyId ${cert.signerKeyId} does not match personId ${personId}`)
      }
      const valid = await verifyEnvelope(cert, publicKey)
      if (!valid) {
        throw new Error("Invalid root certificate signature")
      }
      return first.payload.devicePublicKey
    }

    // Delegated certificate: walk to issuer
    const issuerHash = p.issuerCertificateHash
    const issuer = byHash.get(issuerHash)
    if (!issuer) {
      throw new Error(`Missing issuer certificate for hash ${issuerHash}`)
    }
    if (!issuer.payload.canEnrollDevices) {
      throw new Error("Issuer certificate lacks canEnrollDevices capability")
    }
    if (cert.signerKeyId !== issuer.payload.deviceId) {
      throw new Error("Delegated certificate signerKeyId does not match issuer deviceId")
    }
    const valid = await verifyEnvelope(cert, issuer.payload.devicePublicKey)
    if (!valid) {
      throw new Error("Invalid delegated certificate signature")
    }

    cert = issuer
  }

  throw new Error("Incomplete certificate chain")
}

/**
 * Creates a signed PeerAdvertisement and bundles it with identity public key,
 * certificate chain, and optional WorkspaceGrant.
 */
export async function createPeerAdvertisement(
  profileOrOptions: LocalProfile | (CreatePeerAdvertisementOptions & { profile: LocalProfile }),
  workspaceIdOrOptions?: string | CreatePeerAdvertisementOptions,
  endpoint?: string,
  extraOptions?: Partial<CreatePeerAdvertisementOptions>
): Promise<WorkspaceMemberBundle> {
  let profile: LocalProfile
  let workspaceId: string
  let ep: string
  let certificates: DeviceCertificate[] | undefined
  let grant: WorkspaceGrant | undefined
  let ownerPublicKey: string | undefined
  let ownerCertificates: DeviceCertificate[] | undefined
  let issuedAt: string | undefined
  let routeSequence: number | undefined
  let expiresAt: string | undefined
  let deviceName: string | undefined
  let userAgent: string | undefined
  let instanceId: string | undefined

  if (
    typeof profileOrOptions === "object" &&
    "profile" in profileOrOptions &&
    profileOrOptions.profile
  ) {
    const opts = profileOrOptions as CreatePeerAdvertisementOptions & { profile: LocalProfile }
    profile = opts.profile
    workspaceId = opts.workspaceId
    ep = opts.endpoint
    certificates = opts.certificates
    grant = opts.grant
    ownerPublicKey = opts.ownerPublicKey
    ownerCertificates = opts.ownerCertificates
    issuedAt = opts.issuedAt
    routeSequence = opts.routeSequence
    expiresAt = opts.expiresAt
    deviceName = opts.deviceName
    userAgent = opts.userAgent
    instanceId = opts.instanceId
  } else {
    profile = profileOrOptions as LocalProfile
    if (typeof workspaceIdOrOptions === "object" && workspaceIdOrOptions !== null) {
      workspaceId = workspaceIdOrOptions.workspaceId
      ep = workspaceIdOrOptions.endpoint
      certificates = workspaceIdOrOptions.certificates
      grant = workspaceIdOrOptions.grant
      ownerPublicKey = workspaceIdOrOptions.ownerPublicKey
      ownerCertificates = workspaceIdOrOptions.ownerCertificates
      issuedAt = workspaceIdOrOptions.issuedAt
      routeSequence = workspaceIdOrOptions.routeSequence
      expiresAt = workspaceIdOrOptions.expiresAt
      deviceName = workspaceIdOrOptions.deviceName
      userAgent = workspaceIdOrOptions.userAgent
      instanceId = workspaceIdOrOptions.instanceId
    } else {
      workspaceId = workspaceIdOrOptions as string
      ep = endpoint as string
      if (extraOptions) {
        certificates = extraOptions.certificates
        grant = extraOptions.grant
        ownerPublicKey = extraOptions.ownerPublicKey
        ownerCertificates = extraOptions.ownerCertificates
        issuedAt = extraOptions.issuedAt
        routeSequence = extraOptions.routeSequence
        expiresAt = extraOptions.expiresAt
        deviceName = extraOptions.deviceName
        userAgent = extraOptions.userAgent
        instanceId = extraOptions.instanceId
      }
    }
  }

  if (!profile?.identity?.personId || !profile?.device?.deviceId || !profile?.privateKeys?.devicePrivateKey) {
    throw new Error("Invalid LocalProfile: missing required identity or device keys")
  }
  if (!workspaceId || typeof workspaceId !== "string") {
    throw new Error("Invalid workspaceId: must be a non-empty string")
  }
  if (!ep || typeof ep !== "string") {
    throw new Error("Invalid endpoint: must be a non-empty string")
  }
  if (instanceId !== undefined && (!instanceId || instanceId.length > MAX_STRING_LENGTH)) {
    throw new Error("Invalid instanceId")
  }
  if (routeSequence !== undefined && (!Number.isSafeInteger(routeSequence) || routeSequence < 1)) {
    throw new Error("Invalid routeSequence")
  }
  if (expiresAt !== undefined && (!Number.isFinite(Date.parse(expiresAt)) || new Date(expiresAt).toISOString() !== expiresAt)) {
    throw new Error("Invalid expiresAt")
  }

  const reportedDeviceName = (deviceName ?? profile.device.displayName).trim().slice(0, MAX_STRING_LENGTH)
  const reportedUserAgent = (userAgent ?? (typeof navigator !== "undefined" ? navigator.userAgent : "")).trim().slice(0, MAX_STRING_LENGTH)
  const payload: PeerAdvertisementPayload = {
    kind: "peer-advertisement",
    version: 1,
    workspaceId,
    personId: profile.identity.personId,
    deviceId: profile.device.deviceId,
    ...(instanceId ? { instanceId } : {}),
    endpoint: ep,
    issuedAt: issuedAt ?? new Date().toISOString(),
    ...(routeSequence !== undefined ? { routeSequence } : {}),
    ...(expiresAt ? { expiresAt } : {}),
    ...(reportedDeviceName ? { deviceName: reportedDeviceName } : {}),
    ...(reportedUserAgent ? { userAgent: reportedUserAgent } : {}),
  }

  const advertisement = (await signEnvelope(
    profile.privateKeys.devicePrivateKey,
    payload,
    profile.device.deviceId
  )) as unknown as PeerAdvertisement

  const certChain = certificates ?? [profile.certificate]

  const bundle: WorkspaceMemberBundle = {
    advertisement,
    signed: advertisement,
    payload: advertisement.payload,
    signerKeyId: advertisement.signerKeyId,
    signature: advertisement.signature,
    publicKey: profile.identity.publicKey,
    certificates: certChain,
    grant,
    ownerPublicKey,
    ownerCertificates,
  }

  return bundle
}

export const createWorkspaceMemberBundle = createPeerAdvertisement

/**
 * Verifies a workspace member bundle or peer advertisement:
 * - Bounded serialized size
 * - Exact identity hash
 * - Device certificate chain
 * - Advertisement signature
 * - Workspace / owner / grant role (owner needs no grant)
 * - Root signature or owner device chain for grants
 * - Canonical ISO timestamp within 5 minutes future and max 30 days stale
 */
export async function verifyWorkspaceMemberBundle(
  rawBundle: unknown,
  workspaceIdOrOptions?: string | VerifyWorkspaceMemberBundleOptions,
  ownerPersonIdOrPublicKeyOrOptions?: string | VerifyWorkspaceMemberBundleOptions,
  optionsOrOwnerPublicKey?: string | VerifyWorkspaceMemberBundleOptions,
  maybeOptions?: VerifyWorkspaceMemberBundleOptions
): Promise<VerifiedWorkspaceMember> {
  let opts: VerifyWorkspaceMemberBundleOptions = {}

  if (typeof workspaceIdOrOptions === "object" && workspaceIdOrOptions !== null) {
    opts = workspaceIdOrOptions
  } else if (
    typeof ownerPersonIdOrPublicKeyOrOptions === "object" &&
    ownerPersonIdOrPublicKeyOrOptions !== null
  ) {
    opts = ownerPersonIdOrPublicKeyOrOptions
    if (typeof workspaceIdOrOptions === "string") opts.workspaceId = workspaceIdOrOptions
  } else if (typeof optionsOrOwnerPublicKey === "object" && optionsOrOwnerPublicKey !== null) {
    opts = optionsOrOwnerPublicKey
    if (typeof workspaceIdOrOptions === "string") opts.workspaceId = workspaceIdOrOptions
  } else if (typeof maybeOptions === "object" && maybeOptions !== null) {
    opts = maybeOptions
    if (typeof workspaceIdOrOptions === "string") opts.workspaceId = workspaceIdOrOptions
  } else {
    if (typeof workspaceIdOrOptions === "string") opts.workspaceId = workspaceIdOrOptions
  }

  let ownerKeyOrId: string | undefined
  if (typeof ownerPersonIdOrPublicKeyOrOptions === "string") {
    ownerKeyOrId = ownerPersonIdOrPublicKeyOrOptions
  }
  let secondaryOwnerKeyOrId: string | undefined
  if (typeof optionsOrOwnerPublicKey === "string") {
    secondaryOwnerKeyOrId = optionsOrOwnerPublicKey
  }

  let runtimeOwnerPublicKey = opts.ownerPublicKey
  let runtimeOwnerPersonId = opts.ownerPersonId
  if (ownerKeyOrId) {
    if (!runtimeOwnerPublicKey) {
      runtimeOwnerPublicKey = ownerKeyOrId
      try { runtimeOwnerPersonId ??= await keyId(ownerKeyOrId) }
      catch { runtimeOwnerPersonId ??= ownerKeyOrId }
    }
    if (secondaryOwnerKeyOrId) {
      try {
        if ((await keyId(secondaryOwnerKeyOrId)) === ownerKeyOrId) {
          runtimeOwnerPersonId = ownerKeyOrId
          runtimeOwnerPublicKey = secondaryOwnerKeyOrId
        }
      } catch {}
    }
  }
  const now = typeof opts.now === "number" ? opts.now
    : opts.now instanceof Date ? opts.now.getTime()
      : typeof opts.now === "string" ? Date.parse(opts.now) : Date.now()
  const verified = meshRustRuntime().state.verifyWorkspaceMemberBundle(rawBundle, {
    workspaceId: opts.workspaceId, ownerPersonId: runtimeOwnerPersonId, ownerPublicKey: runtimeOwnerPublicKey,
    ownerCertificates: opts.ownerCertificates ?? [], ownerHistory: opts.ownerHistory ?? [],
    maxByteLength: opts.maxByteLength, allowStaleRoute: opts.allowStaleRoute ?? false,
  }, now) as VerifiedWorkspaceMember & { grant?: WorkspaceGrant | null }
  if (verified.grant === null) delete verified.grant
  if (!(globalThis as { __legacyMeshMemberVerifier?: boolean }).__legacyMeshMemberVerifier) return verified

  // 1. Check bounded serialized size
  const maxByteLength = opts.maxByteLength ?? MAX_PEER_ADVERTISEMENT_SIZE
  const serialized = JSON.stringify(rawBundle)
  if (!serialized || new TextEncoder().encode(serialized).byteLength > maxByteLength) {
    throw new Error("Peer advertisement too large")
  }

  if (!rawBundle || typeof rawBundle !== "object") {
    throw new Error("Invalid peer advertisement bundle: must be an object")
  }

  const bundle = rawBundle as Record<string, unknown>
  const advertisement = (
    bundle.advertisement ??
    bundle.signed ??
    (bundle.payload && bundle.signature ? bundle : undefined)
  ) as PeerAdvertisement | undefined

  if (!advertisement || typeof advertisement !== "object") {
    throw new Error("Missing peer advertisement in bundle")
  }

  const p = advertisement.payload
  if (
    !p ||
    typeof p !== "object" ||
    p.kind !== "peer-advertisement" ||
    p.version !== 1 ||
    typeof p.workspaceId !== "string" ||
    !p.workspaceId ||
    p.workspaceId.length > MAX_STRING_LENGTH ||
    typeof p.personId !== "string" ||
    !p.personId ||
    p.personId.length > MAX_STRING_LENGTH ||
    typeof p.deviceId !== "string" ||
    !p.deviceId ||
    p.deviceId.length > MAX_STRING_LENGTH ||
    (p.instanceId !== undefined && (typeof p.instanceId !== "string" || !p.instanceId || p.instanceId.length > MAX_STRING_LENGTH)) ||
    (p.routeSequence !== undefined && (!Number.isSafeInteger(p.routeSequence) || p.routeSequence < 1)) ||
    (p.expiresAt !== undefined && (typeof p.expiresAt !== "string" || !Number.isFinite(Date.parse(p.expiresAt)) ||
      new Date(p.expiresAt).toISOString() !== p.expiresAt)) ||
    typeof p.endpoint !== "string" ||
    !p.endpoint ||
    p.endpoint.length > MAX_ENDPOINT_LENGTH ||
    (p.deviceName !== undefined && (typeof p.deviceName !== "string" || !p.deviceName.trim() || p.deviceName.length > MAX_STRING_LENGTH)) ||
    (p.userAgent !== undefined && (typeof p.userAgent !== "string" || !p.userAgent.trim() || p.userAgent.length > MAX_STRING_LENGTH))
  ) {
    throw new Error("Invalid peer advertisement payload")
  }

  // 2. Check workspace ID match
  const expectedWorkspaceId = opts.workspaceId
  if (expectedWorkspaceId && p.workspaceId !== expectedWorkspaceId) {
    throw new Error(`Workspace ID ${p.workspaceId} does not match expected workspace ${expectedWorkspaceId}`)
  }

  // 3. Check signer key ID matches device ID
  if (advertisement.signerKeyId !== p.deviceId) {
    throw new Error(`Advertisement signerKeyId ${advertisement.signerKeyId} does not match deviceId ${p.deviceId}`)
  }

  // 4. Validate timestamp: canonical ISO 8601, within 5m future, max 30d stale
  if (
    typeof p.issuedAt !== "string" ||
    !Number.isFinite(Date.parse(p.issuedAt)) ||
    new Date(p.issuedAt).toISOString() !== p.issuedAt
  ) {
    throw new Error("Invalid issuedAt timestamp: must be canonical ISO 8601 string")
  }

  const issuedTime = Date.parse(p.issuedAt)
  const nowTime =
    typeof opts.now === "number"
      ? opts.now
      : opts.now instanceof Date
        ? opts.now.getTime()
        : typeof opts.now === "string"
          ? Date.parse(opts.now)
          : Date.now()

  if (issuedTime > nowTime + MAX_FUTURE_TOLERANCE_MS) {
    throw new Error("Peer advertisement timestamp is in the future (> 5 minutes)")
  }
  if (!opts.allowStaleRoute && issuedTime < nowTime - MAX_STALE_TOLERANCE_MS) {
    throw new Error("Peer advertisement timestamp is stale (> 30 days)")
  }
  if (p.expiresAt && (Date.parse(p.expiresAt) <= issuedTime || Date.parse(p.expiresAt) > issuedTime + 10 * 60 * 1000)) {
    throw new Error("Invalid peer route expiry")
  }

  // 5. Exact identity hash verification
  const memberPublicKey = (bundle.publicKey ?? (bundle.authority as any)?.publicKey) as string | undefined
  if (!memberPublicKey || typeof memberPublicKey !== "string") {
    throw new Error("Missing member identity public key")
  }

  const memberPersonId = await keyId(memberPublicKey)
  if (memberPersonId !== p.personId) {
    throw new Error(`Identity does not match its key: expected ${p.personId}, derived ${memberPersonId}`)
  }

  // 6. Device certificate chain verification
  const certificates = (bundle.certificates ?? (bundle.authority as any)?.certificates) as
    | DeviceCertificate[]
    | undefined
  if (!Array.isArray(certificates) || certificates.length === 0) {
    throw new Error("Missing device certificates in bundle")
  }

  const devicePublicKey = await verifyDeviceChain({
    personId: p.personId,
    publicKey: memberPublicKey,
    deviceId: p.deviceId,
    certificates,
  })

  // 7. Advertisement signature verification
  const adSignatureValid = await verifyEnvelope(advertisement, devicePublicKey)
  if (!adSignatureValid) {
    throw new Error("Invalid advertisement signature")
  }

  // 8. Determine ownerPublicKey and ownerPersonId
  let ownerPublicKey =
    opts.ownerPublicKey ??
    (bundle.ownerPublicKey as string | undefined) ??
    ((bundle.authority as any)?.publicKey as string | undefined)
  let ownerPersonId = opts.ownerPersonId

  if (ownerKeyOrId) {
    if (secondaryOwnerKeyOrId) {
      try {
        if ((await keyId(secondaryOwnerKeyOrId)) === ownerKeyOrId) {
          ownerPersonId = ownerKeyOrId
          ownerPublicKey = secondaryOwnerKeyOrId
        } else if ((await keyId(ownerKeyOrId)) === secondaryOwnerKeyOrId) {
          ownerPersonId = secondaryOwnerKeyOrId
          ownerPublicKey = ownerKeyOrId
        }
      } catch {}
    }

    if (!ownerPublicKey) {
      try {
        const derived = await keyId(ownerKeyOrId)
        ownerPublicKey = ownerKeyOrId
        if (!ownerPersonId) ownerPersonId = derived
      } catch {
        if (!ownerPersonId) ownerPersonId = ownerKeyOrId
      }
    }
  }

  if (ownerPublicKey && !ownerPersonId) {
    ownerPersonId = await keyId(ownerPublicKey)
  }

  // 9. Role and Grant verification
  const grant = (bundle.grant ?? (bundle.authority as any)?.grant) as WorkspaceGrant | undefined
  const isOwner = ownerPersonId ? p.personId === ownerPersonId : !grant
  const embeddedOwnerCertificates = bundle.ownerCertificates ?? (bundle.authority as any)?.certificates
  if (embeddedOwnerCertificates !== undefined && !Array.isArray(embeddedOwnerCertificates)) {
    throw new Error("Invalid owner certificate chain")
  }
  const ownerCertificates = [...new Map([
    ...(opts.ownerCertificates ?? []),
    ...((embeddedOwnerCertificates ?? []) as DeviceCertificate[]),
  ].map(certificate => [certificate?.signature, certificate])).values()]
  if (ownerCertificates.length > MAX_CERT_CHAIN_LENGTH || ownerCertificates.some(certificate => !certificate?.signature)) {
    throw new Error("Invalid owner certificate chain")
  }

  let role: "owner" | "editor" | "visitor" = "owner"

  if (isOwner) {
    // Owner needs no grant
    role = "owner"
    if (!ownerPersonId) ownerPersonId = p.personId
    if (!ownerPublicKey) ownerPublicKey = memberPublicKey
  } else {
    const authorities: WorkspaceAuthority[] = [{
      personId: ownerPersonId!,
      publicKey: ownerPublicKey!,
      certificates: ownerCertificates,
    }, ...(opts.ownerHistory ?? [])]
    let verifiedRole: "owner" | "editor" | "visitor" | undefined
    for (const authority of authorities) {
      try {
        verifiedRole = await verifyWorkspaceGrant(grant, {
          workspaceId: expectedWorkspaceId ?? p.workspaceId, personId: p.personId,
          ownerPersonId: authority.personId, ownerPublicKey: authority.publicKey,
          ownerCertificates: authority.certificates,
        })
        break
      } catch {}
    }
    if (!verifiedRole) throw new Error("Invalid workspace grant signature")
    role = verifiedRole
  }

  return {
    advertisement,
    signed: advertisement,
    payload: advertisement.payload,
    signerKeyId: advertisement.signerKeyId,
    signature: advertisement.signature,
    publicKey: memberPublicKey,
    certificates,
    devicePublicKey,
    role,
    grant,
    ownerPublicKey,
    ownerCertificates,
  }
}

export const verifyPeerAdvertisement = verifyWorkspaceMemberBundle

export async function createWorkspaceRevocation(profile: LocalProfile, workspaceId: string, personId: string, epoch: number,
  revokedAt = new Date().toISOString()): Promise<WorkspaceRevocation> {
  if (!workspaceId || !personId || personId === profile.identity.personId || !Number.isSafeInteger(epoch) || epoch < 2 ||
    !Number.isFinite(Date.parse(revokedAt)) || new Date(revokedAt).toISOString() !== revokedAt) throw new Error("Invalid workspace revocation")
  const key = profile.privateKeys.identityPrivateKey ?? profile.privateKeys.devicePrivateKey
  const signer = profile.privateKeys.identityPrivateKey ? profile.identity.personId : profile.device.deviceId
  return signEnvelope(key, {
    kind: "workspace-revocation", version: 1, workspaceId, ownerPersonId: profile.identity.personId,
    personId, epoch, revokedAt,
  }, signer)
}

export async function verifyWorkspaceRevocation(raw: unknown, workspaceId: string, ownerPersonId: string,
  ownerPublicKey: string, ownerCertificates: DeviceCertificate[], now = Date.now()): Promise<WorkspaceRevocation> {
  return meshRustRuntime().state.verifyWorkspaceRevocation(raw, workspaceId, {
    personId: ownerPersonId, publicKey: ownerPublicKey, certificates: ownerCertificates,
  }, now) as WorkspaceRevocation
}


export async function verifyWorkspaceGrant(grant: WorkspaceGrant | undefined, scope: {
  workspaceId: string; personId: string; ownerPersonId: string; ownerPublicKey: string; ownerCertificates: DeviceCertificate[]
}): Promise<"owner" | "editor" | "visitor"> {
  if (!grant) throw new Error("Missing workspace grant for non-owner member")
  return meshRustRuntime().state.verifyWorkspaceGrant(grant, scope.workspaceId, scope.personId, {
    personId: scope.ownerPersonId, publicKey: scope.ownerPublicKey, certificates: scope.ownerCertificates,
  })
}

export async function createWorkspaceOwnershipTransfer(
  profile: LocalProfile,
  workspaceId: string,
  target: { personId: string; publicKey: string; certificates: DeviceCertificate[] },
  workspaceHeads: string[],
  epoch: number,
  transferredAt = new Date().toISOString(),
): Promise<WorkspaceOwnershipTransfer> {
  if (!workspaceId || !target.personId || target.personId === profile.identity.personId ||
    !Array.isArray(workspaceHeads) || workspaceHeads.length === 0 || workspaceHeads.length > 256 ||
    workspaceHeads.some(head => typeof head !== "string" || !head) || !Number.isSafeInteger(epoch) || epoch < 2 ||
    !Number.isFinite(Date.parse(transferredAt)) || new Date(transferredAt).toISOString() !== transferredAt) {
    throw new Error("Invalid workspace ownership transfer")
  }
  if (await keyId(target.publicKey) !== target.personId) throw new Error("Invalid new owner identity")
  await verifyDeviceChain({ personId: target.personId, publicKey: target.publicKey,
    deviceId: target.certificates[0]?.payload.deviceId, certificates: target.certificates })
  const toOwnerGrant = await createWorkspaceGrant(profile, workspaceId, target.personId, "owner")
  const formerOwnerGrant = await createWorkspaceGrant(profile, workspaceId, profile.identity.personId, "editor")
  return signEnvelope(profile.privateKeys.devicePrivateKey, {
    kind: "workspace-ownership-transfer", version: 1, workspaceId,
    fromOwnerPersonId: profile.identity.personId, toOwnerPersonId: target.personId,
    toOwnerPublicKey: target.publicKey, toOwnerCertificates: target.certificates,
    toOwnerGrant, formerOwnerGrant, workspaceHeads, epoch, transferredAt,
  }, profile.device.deviceId)
}

export async function verifyWorkspaceOwnershipTransfer(
  raw: unknown,
  workspaceId: string,
  authority: WorkspaceAuthority,
  minimumEpoch: number,
  now = Date.now(),
): Promise<WorkspaceOwnershipTransfer> {
  return meshRustRuntime().state.verifyWorkspaceOwnershipTransfer(
    raw, workspaceId, authority, minimumEpoch, now,
  ) as WorkspaceOwnershipTransfer
}

export async function createWorkspaceBreakGlassClaim(
  profile: LocalProfile,
  workspaceId: string,
  fromOwnerPersonId: string,
  editorGrant: WorkspaceGrant,
  workspaceHeads: string[],
  epoch: number,
  claimedAt = new Date().toISOString(),
  certificates: DeviceCertificate[] = [profile.certificate],
): Promise<WorkspaceBreakGlassClaim> {
  if (!workspaceId || !fromOwnerPersonId || fromOwnerPersonId === profile.identity.personId ||
    !Array.isArray(workspaceHeads) || workspaceHeads.length === 0 || workspaceHeads.length > 256 ||
    workspaceHeads.some(head => typeof head !== "string" || !head) || !Number.isSafeInteger(epoch) || epoch < 2 ||
    !validIso(claimedAt) || !Array.isArray(certificates) || !certificates.length || certificates.length > MAX_CERT_CHAIN_LENGTH) {
    throw new Error("Invalid workspace break-glass claim")
  }
  return signEnvelope(profile.privateKeys.devicePrivateKey, {
    kind: "workspace-break-glass", version: 1, workspaceId, fromOwnerPersonId,
    toOwnerPersonId: profile.identity.personId, toOwnerPublicKey: profile.identity.publicKey,
    toOwnerCertificates: certificates, editorGrant, workspaceHeads, epoch, claimedAt,
  }, profile.device.deviceId) as Promise<WorkspaceBreakGlassClaim>
}

export async function verifyWorkspaceBreakGlassClaim(
  raw: unknown,
  workspaceId: string,
  authority: WorkspaceAuthority,
  currentEpoch: number,
  grantAuthorities: WorkspaceAuthority[] = [authority],
): Promise<WorkspaceBreakGlassClaim> {
  const claim = raw as WorkspaceBreakGlassClaim
  const p = claim?.payload
  if (!p || p.kind !== "workspace-break-glass" || p.version !== 1 || p.workspaceId !== workspaceId ||
    p.fromOwnerPersonId !== authority.personId || p.toOwnerPersonId === p.fromOwnerPersonId ||
    p.epoch !== currentEpoch + 1 || !validIso(p.claimedAt) ||
    !Array.isArray(p.workspaceHeads) || !p.workspaceHeads.length || p.workspaceHeads.length > 256 ||
    p.workspaceHeads.some(head => typeof head !== "string" || !head) ||
    !Array.isArray(p.toOwnerCertificates) || !p.toOwnerCertificates.length || p.toOwnerCertificates.length > MAX_CERT_CHAIN_LENGTH ||
    new TextEncoder().encode(JSON.stringify(claim)).byteLength > MAX_PEER_ADVERTISEMENT_SIZE) {
    throw new Error("Invalid workspace break-glass claim")
  }
  if (await keyId(p.toOwnerPublicKey) !== p.toOwnerPersonId) throw new Error("Invalid workspace break-glass identity")
  let role: WorkspaceRole | undefined
  for (const issuer of grantAuthorities) {
    try {
      role = await verifyWorkspaceGrant(p.editorGrant, {
        workspaceId, personId: p.toOwnerPersonId, ownerPersonId: issuer.personId,
        ownerPublicKey: issuer.publicKey, ownerCertificates: issuer.certificates,
      })
      break
    } catch {}
  }
  if (role !== "editor") throw new Error("Workspace break-glass requires an editor grant")
  const deviceKey = await verifyDeviceChain({ personId: p.toOwnerPersonId, publicKey: p.toOwnerPublicKey,
    deviceId: claim.signerKeyId, certificates: p.toOwnerCertificates })
  if (!await verifyEnvelope(claim, deviceKey)) throw new Error("Invalid workspace break-glass signature")
  return claim
}

function validIso(value: unknown, now = Date.now()) {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value &&
    Date.parse(value) <= now + MAX_FUTURE_TOLERANCE_MS
}

export async function createWorkspaceSuccessionPolicy(profile: LocalProfile, workspaceId: string,
  successorPersonId: string | null, eligibleEditorPersonIds: string[], epoch: number,
  updatedAt = new Date().toISOString()): Promise<WorkspaceSuccessionPolicy> {
  const eligible = [...new Set(eligibleEditorPersonIds)].sort()
  if (!workspaceId || !Number.isSafeInteger(epoch) || epoch < 1 || eligible.length > MAX_SUCCESSION_EDITORS ||
    eligible.some(id => typeof id !== "string" || !id || id === profile.identity.personId) ||
    eligible.join("\0") !== eligibleEditorPersonIds.join("\0") ||
    (successorPersonId !== null && !eligible.includes(successorPersonId)) || !validIso(updatedAt)) {
    throw new Error("Invalid workspace succession policy")
  }
  return signEnvelope(profile.privateKeys.devicePrivateKey, {
    kind: "workspace-succession-policy", version: 1, workspaceId, ownerPersonId: profile.identity.personId,
    successorPersonId, eligibleEditorPersonIds: eligible, epoch, updatedAt,
  }, profile.device.deviceId)
}

export async function verifyWorkspaceSuccessionPolicy(raw: unknown, workspaceId: string,
  authority: WorkspaceAuthority, now = Date.now()): Promise<WorkspaceSuccessionPolicy> {
  return meshRustRuntime().state.verifyWorkspaceSuccessionPolicy(
    raw, workspaceId, authority, now,
  ) as WorkspaceSuccessionPolicy
}

export async function createWorkspaceSuccessionVote(profile: LocalProfile, policy: WorkspaceSuccessionPolicy,
  candidatePersonId: string, voterGrant: WorkspaceGrant,
  votedAt = new Date().toISOString(), voterCertificates: DeviceCertificate[] = [profile.certificate]): Promise<WorkspaceSuccessionVote> {
  const p = policy.payload
  if (!candidatePersonId || !p.eligibleEditorPersonIds.includes(profile.identity.personId) ||
    !p.eligibleEditorPersonIds.includes(candidatePersonId) || !validIso(votedAt)) throw new Error("Invalid workspace succession vote")
  return {
    signed: await signEnvelope(profile.privateKeys.devicePrivateKey, {
      kind: "workspace-succession-vote", version: 1, workspaceId: p.workspaceId, ownerPersonId: p.ownerPersonId,
      voterPersonId: profile.identity.personId, candidatePersonId, policySignature: policy.signature, votedAt,
    }, profile.device.deviceId),
    voterPublicKey: profile.identity.publicKey,
    voterCertificates,
    voterGrant,
  }
}

export async function verifyWorkspaceSuccessionVote(raw: unknown, policy: WorkspaceSuccessionPolicy, candidatePersonId: string,
  authority: WorkspaceAuthority, revoked: Set<string>, now: number): Promise<WorkspaceSuccessionVote> {
  return meshRustRuntime().state.verifyWorkspaceSuccessionVote(
    raw, policy, candidatePersonId, authority, [...revoked], now,
  ) as WorkspaceSuccessionVote
}

export async function createWorkspaceSuccessionClaim(profile: LocalProfile, policy: WorkspaceSuccessionPolicy,
  votes: WorkspaceSuccessionVote[], candidateGrant: WorkspaceGrant, workspaceHeads: string[], epoch: number,
  toOwnerCertificates: DeviceCertificate[] = [profile.certificate], claimedAt = new Date().toISOString()): Promise<WorkspaceSuccessionClaim> {
  if (!Array.isArray(workspaceHeads) || !workspaceHeads.length || workspaceHeads.length > 256 ||
    workspaceHeads.some(head => typeof head !== "string" || !head) || !Number.isSafeInteger(epoch) || epoch < 2 ||
    !Array.isArray(toOwnerCertificates) || !toOwnerCertificates.length || toOwnerCertificates.length > MAX_CERT_CHAIN_LENGTH || !validIso(claimedAt)) {
    throw new Error("Invalid workspace succession claim")
  }
  const formerOwnerGrant = await createWorkspaceGrant(profile, policy.payload.workspaceId, policy.payload.ownerPersonId, "editor")
  return signEnvelope(profile.privateKeys.devicePrivateKey, {
    kind: "workspace-succession-claim", version: 1, workspaceId: policy.payload.workspaceId,
    fromOwnerPersonId: policy.payload.ownerPersonId, toOwnerPersonId: profile.identity.personId,
    toOwnerPublicKey: profile.identity.publicKey, toOwnerCertificates, candidateGrant,
    formerOwnerGrant, policy, votes, workspaceHeads, epoch, claimedAt,
  }, profile.device.deviceId)
}

export async function verifyWorkspaceSuccessionClaim(raw: unknown, workspaceId: string, authority: WorkspaceAuthority,
  minimumEpoch: number, revoked: Set<string>, now = Date.now()): Promise<WorkspaceSuccessionClaim> {
  return meshRustRuntime().state.verifyWorkspaceSuccessionClaim(
    raw, workspaceId, authority, minimumEpoch, [...revoked], now,
  ) as WorkspaceSuccessionClaim
}
