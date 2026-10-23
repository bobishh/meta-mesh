import { canonicalizeJson, publicKeyId, sha256Base64Url, signEnvelope, verifyEnvelope,
  verifyIdentityAuthorityView, type IdentityAuthorityHead, type IdentityAuthorityView,
  type LocalProfile, type SignedEnvelope } from "./index"

export type IdentityRootSuccessionPayload = {
  kind: "mesh-identity-root-succession"
  version: 1
  successionId: string
  previousPersonId: string
  previousIdentityPublicKey: string
  successorPersonId: string
  successorIdentityPublicKey: string
  authorityHead: IdentityAuthorityHead
  authorityViewDigest: string
}

export type IdentityRootSuccessionAcceptancePayload = {
  kind: "mesh-identity-root-succession-acceptance"
  version: 1
  successionHash: string
  previousPersonId: string
  successorPersonId: string
}

export type IdentityRootSuccession = {
  authorization: SignedEnvelope<IdentityRootSuccessionPayload>
  acceptance: SignedEnvelope<IdentityRootSuccessionAcceptancePayload>
}

const domain = "MESH-IDENTITY-ROOT-SUCCESSION/1"

/** Bind an old recovery root to a new root and require both roots to sign the exact transition. */
export async function createIdentityRootSuccession(previous: LocalProfile, successor: LocalProfile,
  authorityView: IdentityAuthorityView): Promise<IdentityRootSuccession> {
  if (!previous.privateKeys.identityPrivateKey || !successor.privateKeys.identityPrivateKey) {
    throw new Error("Both Identity roots are required to authorize root succession")
  }
  const verified = await verifyIdentityAuthorityView(authorityView)
  if (verified.personId !== previous.identity.personId || verified.identityPublicKey !== previous.identity.publicKey ||
      await publicKeyId(previous.identity.publicKey) !== previous.identity.personId ||
      await publicKeyId(successor.identity.publicKey) !== successor.identity.personId ||
      previous.identity.personId === successor.identity.personId) {
    throw new Error("Root succession identities do not match the verified authority")
  }

  const successionId = toBase64Url(crypto.getRandomValues(new Uint8Array(32)))
  const authorizationPayload: IdentityRootSuccessionPayload = {
    kind: "mesh-identity-root-succession", version: 1, successionId,
    previousPersonId: previous.identity.personId, previousIdentityPublicKey: previous.identity.publicKey,
    successorPersonId: successor.identity.personId, successorIdentityPublicKey: successor.identity.publicKey,
    authorityHead: structuredClone(authorityView.revocationHead), authorityViewDigest: authorityView.viewDigest,
  }
  const authorization = await signEnvelope(previous.privateKeys.identityPrivateKey, authorizationPayload,
    previous.identity.personId, domain)
  if (!await verifyEnvelope(authorization, previous.identity.publicKey, domain)) {
    throw new Error("Previous Identity root key does not match its public identity")
  }
  const acceptancePayload: IdentityRootSuccessionAcceptancePayload = {
    kind: "mesh-identity-root-succession-acceptance", version: 1,
    successionHash: await signedEnvelopeHash(authorization),
    previousPersonId: previous.identity.personId, successorPersonId: successor.identity.personId,
  }
  const acceptance = await signEnvelope(successor.privateKeys.identityPrivateKey, acceptancePayload,
    successor.identity.personId, domain)
  if (!await verifyEnvelope(acceptance, successor.identity.publicKey, domain)) {
    throw new Error("Successor Identity root key does not match its public identity")
  }
  return { authorization, acceptance }
}

/** Verify both root signatures and require the exact current old authority view before retirement. */
export async function verifyIdentityRootSuccession(value: IdentityRootSuccession,
  currentPreviousAuthority: IdentityAuthorityView): Promise<{
    previousPersonId: string
    successorPersonId: string
    successorIdentityPublicKey: string
    authorityHead: IdentityAuthorityHead
    authorityViewDigest: string
  }> {
  const verified = await verifyIdentityAuthorityView(currentPreviousAuthority)
  const authorization = value?.authorization
  const payload = authorization?.payload
  if (!isRecord(payload) || !onlyKeys(payload, ["kind", "version", "successionId", "previousPersonId",
    "previousIdentityPublicKey", "successorPersonId", "successorIdentityPublicKey", "authorityHead", "authorityViewDigest"]) ||
      payload.kind !== "mesh-identity-root-succession" || payload.version !== 1 ||
      typeof payload.successionId !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(payload.successionId) ||
      typeof payload.previousPersonId !== "string" || typeof payload.previousIdentityPublicKey !== "string" ||
      typeof payload.successorPersonId !== "string" || typeof payload.successorIdentityPublicKey !== "string" ||
      !isAuthorityHead(payload.authorityHead) || typeof payload.authorityViewDigest !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/u.test(payload.authorityViewDigest) ||
      authorization.signerKeyId !== payload.previousPersonId ||
      payload.previousPersonId !== verified.personId || payload.previousIdentityPublicKey !== verified.identityPublicKey ||
      payload.successorPersonId === payload.previousPersonId ||
      await publicKeyId(payload.previousIdentityPublicKey) !== payload.previousPersonId ||
      await publicKeyId(payload.successorIdentityPublicKey) !== payload.successorPersonId ||
      canonicalizeJson(payload.authorityHead) !== canonicalizeJson(currentPreviousAuthority.revocationHead) ||
      payload.authorityViewDigest !== currentPreviousAuthority.viewDigest ||
      !await verifyEnvelope(authorization, payload.previousIdentityPublicKey, domain)) {
    throw new Error("Identity root succession does not match the current old authority")
  }

  const acceptance = value.acceptance
  const accepted = acceptance?.payload
  if (!isRecord(accepted) || !onlyKeys(accepted, ["kind", "version", "successionHash", "previousPersonId", "successorPersonId"]) ||
      accepted.kind !== "mesh-identity-root-succession-acceptance" || accepted.version !== 1 ||
      accepted.previousPersonId !== payload.previousPersonId || accepted.successorPersonId !== payload.successorPersonId ||
      accepted.successionHash !== await signedEnvelopeHash(authorization) ||
      acceptance.signerKeyId !== payload.successorPersonId ||
      !await verifyEnvelope(acceptance, payload.successorIdentityPublicKey, domain)) {
    throw new Error("Identity root successor did not accept the exact transition")
  }
  return { previousPersonId: payload.previousPersonId, successorPersonId: payload.successorPersonId,
    successorIdentityPublicKey: payload.successorIdentityPublicKey,
    authorityHead: structuredClone(payload.authorityHead), authorityViewDigest: payload.authorityViewDigest }
}

async function signedEnvelopeHash(value: SignedEnvelope<{ kind: string }>): Promise<string> {
  return sha256Base64Url(new TextEncoder().encode(canonicalizeJson(value)))
}

function isAuthorityHead(value: unknown): value is IdentityAuthorityHead {
  if (!isRecord(value) || !onlyKeys(value, ["revision", "recordHash"])) return false
  const head = value as Partial<IdentityAuthorityHead>
  return Number.isSafeInteger(head.revision) && (head.revision ?? -1) >= 0 &&
    typeof head.recordHash === "string" && /^[A-Za-z0-9_-]{43}$/u.test(head.recordHash)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value))
}

function onlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).sort().join(",") === [...keys].sort().join(",")
}

function toBase64Url(value: Uint8Array): string {
  let binary = ""
  for (const byte of value) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "")
}
