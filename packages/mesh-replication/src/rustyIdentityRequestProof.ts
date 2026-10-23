import { authorizeIdentityDataDevice, canonicalizeJson, publicKeyId, sha256Base64Url,
  verifyEnvelope, verifyIdentityAuthorityView, type IdentityAuthorityHead, type IdentityAuthorityView,
  type PublicIdentity, type SignedEnvelope } from "@meta-uber/mesh-identity"
import { rustyOrigin } from "./rustyReplica"

export type RustyIdentityRequestProofPayload = {
  kind: "rusty-identity-request-proof"
  version: 1
  serviceId: string
  origin: string
  personId: string
  deviceId: string
  authorityHead: IdentityAuthorityHead
  viewDigest: string
  resourceKind: "scope"
  resourceId: string
  scopeId: string
  action: "read" | "write"
  grantId: string | null
  policyEpoch: number
  tokenHash: string
  method: string
  path: string
  bodyHash: string
  nonce: string
  issuedAt: number
}

export type CreateRustyIdentityRequestProofOptions = {
  origin: string
  servicePublicKey: string
  identity: PublicIdentity
  view: IdentityAuthorityView
  deviceId: string
  devicePublicKey: string
  scopeId: string
  token: string
  method: string
  /** The exact absolute URL returned to the caller for its fetch. */
  url: string
  /** Exact bytes passed as the fetch body. Empty for requests without a body. */
  bodyBytes: Uint8Array
  action: "read" | "write"
  grantId: string | null
  policyEpoch: number
  signAuthorization: (payload: RustyIdentityRequestProofPayload) => Promise<SignedEnvelope<RustyIdentityRequestProofPayload>>
  now?: () => number
}

export type RustyIdentityRequestProof = {
  url: string
  authorization: SignedEnvelope<RustyIdentityRequestProofPayload>
  headerValue: string
  headers: { authorization: string; "X-Rusty-Identity-Proof": string }
}

const scopePattern = /^[a-zA-Z0-9_-]{1,128}$/u
const encoder = new TextEncoder()

/** Sign one Rusty scope request, binding its service, authority view, bearer, path, method and body. */
export async function createRustyIdentityRequestProof(
  options: CreateRustyIdentityRequestProofOptions,
): Promise<RustyIdentityRequestProof> {
  const origin = rustyOrigin(options.origin)
  const serviceId = await publicKeyId(options.servicePublicKey)
  const identity = structuredClone(options.identity)
  const view = await verifyIdentityAuthorityView(options.view)
  if (view.personId !== identity.personId || view.identityPublicKey !== identity.publicKey) {
    throw new Error("Rusty request authority view belongs to another Identity")
  }
  if (typeof options.token !== "string" || !options.token || options.token.length > 16_384) {
    throw new Error("Invalid Rusty bearer token")
  }
  if (!scopePattern.test(options.scopeId) ||
      (options.grantId !== null && (typeof options.grantId !== "string" || !options.grantId.trim() || options.grantId.length > 512)) ||
      !Number.isSafeInteger(options.policyEpoch) || options.policyEpoch < 0) {
    throw new Error("Invalid Rusty scope authorization binding")
  }
  if (!/^[A-Z]{3,12}$/u.test(options.method) || !(options.bodyBytes instanceof Uint8Array)) {
    throw new Error("Invalid Rusty request method or body")
  }
  const requestUrl = new URL(options.url)
  if (requestUrl.origin !== origin || requestUrl.username || requestUrl.password || requestUrl.hash) {
    throw new Error("Rusty request URL escapes its configured origin")
  }
  const path = `${requestUrl.pathname}${requestUrl.search}`
  if (path !== options.url.slice(origin.length) ||
      !path.startsWith(`/v2/scopes/${options.scopeId}/`)) {
    throw new Error("Rusty request path does not match its configured scope")
  }
  const activeKey = await authorizeIdentityDataDevice(view, options.deviceId)
  if (activeKey !== options.devicePublicKey) {
    throw new Error("Rusty request signer key does not match its active Identity device")
  }
  const now = options.now ?? Date.now
  const issuedAt = now()
  if (!Number.isSafeInteger(issuedAt)) throw new Error("Invalid Rusty request proof time")
  const payload: RustyIdentityRequestProofPayload = {
    kind: "rusty-identity-request-proof", version: 1, serviceId, origin,
    personId: identity.personId, deviceId: options.deviceId,
    authorityHead: structuredClone(view.revocationHead), viewDigest: view.viewDigest,
    resourceKind: "scope", resourceId: options.scopeId, scopeId: options.scopeId,
    action: options.action, grantId: options.grantId, policyEpoch: options.policyEpoch,
    tokenHash: await sha256Base64Url(encoder.encode(options.token)),
    method: options.method, path,
    bodyHash: await sha256Base64Url(new Uint8Array(options.bodyBytes)),
    nonce: randomNonce(), issuedAt,
  }
  const authorization = await options.signAuthorization(payload)
  if (!authorization || authorization.signerKeyId !== options.deviceId ||
      canonicalizeJson(authorization.payload) !== canonicalizeJson(payload) ||
      !await verifyEnvelope(authorization, activeKey, "MATCH/1")) {
    throw new Error("Invalid Rusty Identity request proof signature")
  }
  const headerValue = base64Url(encoder.encode(JSON.stringify(authorization)))
  return {
    url: requestUrl.href,
    authorization,
    headerValue,
    headers: { authorization: `Bearer ${options.token}`, "X-Rusty-Identity-Proof": headerValue },
  }
}

function randomNonce(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(32)))
}

function base64Url(bytes: Uint8Array): string {
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "")
}
