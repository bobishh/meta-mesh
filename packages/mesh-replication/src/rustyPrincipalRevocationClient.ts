import {
  authorizeIdentityDataDevice,
  canonicalizeJson,
  publicKeyId,
  sha256Base64Url,
  verifyEnvelope,
  verifyIdentityAuthorityView,
  type IdentityAuthorityView,
  type PublicIdentity,
  type SignedEnvelope,
} from "@meta-uber/mesh-identity"
import { rustyOrigin } from "./rustyReplica"
import type { RustyFetch } from "./rustyDiscovery"
import {
  readRustyScopeAuthorityStatus,
  type ScopeAuthorityValidation,
} from "./rustyScopeAuthorityClient"

const encoder = new TextEncoder()
const idPattern = /^[A-Za-z0-9_-]{1,128}$/u

export type RustyResourcePrincipalRevocationAuthorization = {
  kind: "rusty-resource-principal-revocation"
  version: 1
  serviceId: string
  origin: string
  storageScopeId: string
  workspaceId: string
  grantId: string
  subjectPersonId: string
  policyEpoch: number
  requestHash: string
}

export type RustyResourcePrincipalRevocationReceipt = SignedEnvelope<{
  kind: "rusty-resource-principal-revocation-receipt"
  version: 1
  serviceId: string
  origin: string
  storageScopeId: string
  workspaceId: string
  grantId: string
  subjectPersonId: string
  policyEpoch: number
  requestHash: string
  committedAt: number
}>

export type RustyResourcePrincipalRevocationBinding = {
  origin: string
  servicePublicKey: string
  storageScopeId: string
  workspaceId: string
  grantId: string
  subjectPersonId: string
  policyEpoch: number
}

export type RustyResourcePrincipalRevocationOptions = {
  origin: string
  servicePublicKey: string
  storageScopeId: string
  workspaceId: string
  grantId: string
  subjectPersonId: string
  policyEpoch: number
  identity: PublicIdentity
  authorityView: IdentityAuthorityView
  deviceId: string
  devicePublicKey: string
  fetcher?: RustyFetch
  ensureCurrent?: () => void | Promise<void>
  validateSnapshot: (snapshot: unknown) => ScopeAuthorityValidation
  signAuthorization: (
    payload: RustyResourcePrincipalRevocationAuthorization,
  ) => Promise<SignedEnvelope<RustyResourcePrincipalRevocationAuthorization>>
  now?: () => number
}

/** Revoke one immutable workspace principal grant and verify Rusty's durable receipt. */
export async function revokeRustyResourcePrincipal(
  options: RustyResourcePrincipalRevocationOptions,
): Promise<RustyResourcePrincipalRevocationReceipt> {
  const now = options.now ?? Date.now
  const origin = rustyOrigin(options.origin)
  const { storageScopeId, workspaceId, grantId, subjectPersonId, policyEpoch } = options
  if (![storageScopeId, workspaceId, grantId, subjectPersonId].every((id) => idPattern.test(id)) ||
      !Number.isSafeInteger(policyEpoch) || policyEpoch < 1) {
    throw new Error("Invalid Rusty resource principal revocation binding")
  }

  const serviceId = await publicKeyId(options.servicePublicKey)
  const identity = structuredClone(options.identity)
  const authorityView = await verifyIdentityAuthorityView(options.authorityView)
  if (authorityView.personId !== identity.personId || authorityView.identityPublicKey !== identity.publicKey) {
    throw new Error("Rusty resource principal revocation Identity binding mismatch")
  }
  const activeKey = await authorizeIdentityDataDevice(authorityView, options.deviceId)
  if (activeKey !== options.devicePublicKey || await publicKeyId(activeKey) !== options.deviceId) {
    throw new Error("Rusty resource principal revocation signer is not an active Identity device")
  }

  const accepted = await readRustyScopeAuthorityStatus({
    origin,
    servicePublicKey: options.servicePublicKey,
    scopeId: storageScopeId,
    fetcher: options.fetcher,
    validateSnapshot: options.validateSnapshot,
    now,
  })
  const authority = accepted.authority
  if (!authority || authority.workspaceId !== workspaceId ||
      authority.controllerPersonId !== identity.personId || authority.controllerPublicKey !== identity.publicKey) {
    throw new Error("Rusty resource principal revocation requires the current workspace controller")
  }
  await options.ensureCurrent?.()

  const unsigned = {
    kind: "rusty-resource-principal-revocation" as const,
    version: 1 as const,
    serviceId,
    origin,
    storageScopeId,
    workspaceId,
    grantId,
    subjectPersonId,
    policyEpoch,
  }
  const requestHash = await sha256Base64Url(encoder.encode(canonicalizeJson(unsigned)))
  const authorizationPayload: RustyResourcePrincipalRevocationAuthorization = { ...unsigned, requestHash }
  const authorization = await options.signAuthorization(authorizationPayload)
  if (!hasExactKeys(authorization, ["payload", "signerKeyId", "signature"]) ||
      authorization.signerKeyId !== options.deviceId ||
      canonicalizeJson(authorization.payload) !== canonicalizeJson(authorizationPayload) ||
      !await verifyEnvelope(authorization, activeKey, "MATCH/1")) {
    throw new Error("Invalid Rusty resource principal revocation authorization")
  }
  await options.ensureCurrent?.()

  const fetcher = options.fetcher ?? fetch
  const response = await fetcher(
    `${origin}/v2/scopes/${encodeURIComponent(storageScopeId)}/principals/${encodeURIComponent(grantId)}/revocation`,
    {
      method: "PUT",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ version: 1, authorization }),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    },
  )
  if (!response.ok) {
    await response.body?.cancel()
    throw new Error(`Rusty resource principal revocation failed with HTTP ${response.status}`)
  }
  await options.ensureCurrent?.()
  const body: unknown = await response.json()
  if (!hasExactKeys(body, ["receipt"])) throw new Error("Invalid Rusty resource principal revocation response")
  return await verifyRustyResourcePrincipalRevocationReceipt({
    origin,
    servicePublicKey: options.servicePublicKey,
    storageScopeId,
    workspaceId,
    grantId,
    subjectPersonId,
    policyEpoch,
    receipt: body.receipt,
    now,
  })
}

/** Verify a stored signed receipt against its durable revocation intent. */
export async function verifyRustyResourcePrincipalRevocationReceipt(
  options: RustyResourcePrincipalRevocationBinding & {
    receipt: unknown
    now?: () => number
  },
): Promise<RustyResourcePrincipalRevocationReceipt> {
  const origin = rustyOrigin(options.origin)
  const { storageScopeId, workspaceId, grantId, subjectPersonId, policyEpoch } = options
  if (![storageScopeId, workspaceId, grantId, subjectPersonId].every((id) => idPattern.test(id)) ||
      !Number.isSafeInteger(policyEpoch) || policyEpoch < 1) {
    throw new Error("Invalid Rusty resource principal revocation binding")
  }
  const serviceId = await publicKeyId(options.servicePublicKey)
  const receipt = options.receipt as RustyResourcePrincipalRevocationReceipt
  if (!hasExactKeys(receipt, ["payload", "signerKeyId", "signature"]) || receipt.signerKeyId !== serviceId ||
      !await verifyEnvelope(receipt, options.servicePublicKey, "RUSTY/2")) {
    throw new Error("Invalid Rusty resource principal revocation receipt signature")
  }
  const payload = receipt.payload
  const committedAt = (options.now ?? Date.now)()
  const unsigned = {
    kind: "rusty-resource-principal-revocation" as const,
    version: 1 as const,
    serviceId,
    origin,
    storageScopeId,
    workspaceId,
    grantId,
    subjectPersonId,
    policyEpoch,
  }
  const requestHash = await sha256Base64Url(encoder.encode(canonicalizeJson(unsigned)))
  if (!hasExactKeys(payload, ["kind", "version", "serviceId", "origin", "storageScopeId", "workspaceId", "grantId",
    "subjectPersonId", "policyEpoch", "requestHash", "committedAt"]) ||
      payload.kind !== "rusty-resource-principal-revocation-receipt" || payload.version !== 1 ||
      payload.serviceId !== serviceId || payload.origin !== origin || payload.storageScopeId !== storageScopeId ||
      payload.workspaceId !== workspaceId || payload.grantId !== grantId || payload.subjectPersonId !== subjectPersonId ||
      payload.policyEpoch !== policyEpoch || payload.requestHash !== requestHash ||
      !Number.isSafeInteger(payload.committedAt) || payload.committedAt < 0 || !Number.isSafeInteger(committedAt) ||
      payload.committedAt > committedAt + 120_000) {
    throw new Error("Rusty resource principal revocation receipt does not match this request")
  }
  return receipt
}

function hasExactKeys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key))
}
