import { canonicalizeJson, sha256Base64Url, toBase64Url, signEnvelope,
  type LocalProfile, type PublicIdentity, type DeviceCertificate, type SignedEnvelope } from "@meta-uber/mesh-identity"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"

export const RESOURCE_SIGNATURE_DOMAIN = "MESH-RESOURCE/1"
export const MAX_GRANT_DURATION_MS = 30 * 24 * 60 * 60 * 1000
export type ResourceDescriptor = {
  kind: "mesh-resource"; version: 1; id: string; title: string; issuer: PublicIdentity;
  audience: string; epoch: number; actions: string[]; readScope: string
}
export type ResourceRegistration = Pick<ResourceDescriptor, "id" | "title" | "audience" | "actions" | "readScope">
export type ResourceSignature<T> = SignedEnvelope<T> & { identity: PublicIdentity; deviceId: string; certificates: DeviceCertificate[] }
export type ChallengePayload = {
  kind: "mesh-resource-challenge"; version: 1; requestId: string; nonce: string;
  resourceId: string; resourceEpoch: number; issuerPersonId: string; subjectPersonId: string;
  audience: string; actions: string[]; requestedExpiresAt: number; issuedAt: number; expiresAt: number
}
export type ConnectionPayload = {
  kind: "mesh-resource-connection"; version: 1; requestId: string; challengeHash: string;
  resourceId: string; issuerPersonId: string; subjectPersonId: string; audience: string;
  actions: string[]; requestedExpiresAt: number; issuedAt: number; expiresAt: number
}
export type GrantPayload = {
  kind: "mesh-resource-grant"; version: 1; grantId: string; requestId: string; resourceId: string;
  resourceEpoch: number; issuerPersonId: string; subjectPersonId: string; audience: string;
  actions: string[]; readScope: string; issuedAt: number; expiresAt: number
}
export type OperationPayload = {
  kind: "mesh-resource-operation"; version: 1; nonce: string; grantHash: string;
  resourceId: string; audience: string; action: string; bodyDigest: string; issuedAt: number; expiresAt: number
}
export type ResourceGrant = ResourceSignature<GrantPayload>
export type ResourceOperationProof = ResourceSignature<OperationPayload>
export type ApprovalRequest = ConnectionPayload & { subject: PublicIdentity; readScope: string; resourceTitle: string }
export type AccessDecision = { actions: string[]; expiresAt: number }
export type ConnectionResult = { resource: ResourceDescriptor; grant: ResourceGrant }
export type Authorization = { resourceId: string; subjectPersonId: string; grantId: string; action: string; requestId: string; expiresAt: number }
export type AuthorizeInput = { grant: ResourceGrant; proof: ResourceOperationProof; resourceId: string; action: string; bodyDigest: string }
export type Invitation = {
  kind: "mesh-resource-invitation"; version: 1; invitationId: string; resourceId: string;
  issuerPersonId: string; audience: string; subjectPersonId: string; secret: string; expiresAt: number
}
export type ChallengeOptions = {
  resourceId: string; subjectPersonId: string; requestId: string; actions: string[]; requestedExpiresAt: number;
  invitation?: Invitation
}
export type ResourceConnectionMessage =
  | { kind: "challenge"; options: ChallengeOptions }
  | { kind: "connect"; resourceId: string; challenge: ResourceSignature<ChallengePayload>; request: ResourceSignature<ConnectionPayload> }
export type ResourceConnectionResponse =
  | { kind: "challenge"; challenge: ResourceSignature<ChallengePayload> }
  | { kind: "connected"; grant: ResourceGrant }
  | { kind: "pending" }
  | { kind: "denied" }
export type ResourceConnectionTransport = (message: ResourceConnectionMessage, signal?: AbortSignal) => Promise<ResourceConnectionResponse>
export type PendingConnection = { resource: ResourceDescriptor; options: ChallengeOptions;
  challenge?: ResourceSignature<ChallengePayload>; request?: ResourceSignature<ConnectionPayload> }
/** Durable callers retain the exact signed request before sending it. No identity seeds enter this store. */
export type ResourceConnectionStore = {
  load(requestId: string): Promise<PendingConnection | undefined>
  save(requestId: string, value: PendingConnection): Promise<void>
  remove(requestId: string): Promise<void>
}
export type ResourceState = {
  version: number; resource: ResourceDescriptor; revokedGrants: string[]; revokedDevices: string[];
  connections: Record<string, { optionsHash: string; challenge: ResourceSignature<ChallengePayload>;
    requestHash?: string; request?: ResourceSignature<ConnectionPayload>; decisionHash?: string; status: "open" | "approving" | "denied" | "connected"; grant?: ResourceGrant; invitationId?: string }>;
  invitations: Record<string, { secretHash: string; subjectPersonId: string; actions: string[];
    epoch: number; expiresAt: number; grantExpiresAt: number; consumedBy?: string }>;
  replays: Record<string, number>
}
/** compareAndSwap must be atomic across every provider instance sharing this authority. */
export type ResourceStore = {
  read(key: string): Promise<ResourceState | undefined>
  compareAndSwap(key: string, expectedVersion: number | null, next: ResourceState): Promise<boolean>
}
export function core<T>(input: Record<string, unknown>): T {
  const state = meshRustRuntime().state
  if (typeof state.resourceAccess !== "function") throw new Error("Resource access requires a compatible meta-mesh policy runtime")
  return state.resourceAccess(structuredClone(input)) as T
}
export const randomSecret = () => toBase64Url(crypto.getRandomValues(new Uint8Array(32)))
export const hash = (value: unknown) => sha256Base64Url(new TextEncoder().encode(canonicalizeJson(value)))
export function captureProfile(profile: LocalProfile): LocalProfile {
  return { identity: structuredClone(profile.identity), device: structuredClone(profile.device),
    certificate: structuredClone(profile.certificate), privateKeys: { devicePrivateKey: profile.privateKeys.devicePrivateKey } }
}
export function resourceSigner(profile: LocalProfile, certificates: DeviceCertificate[] = [profile.certificate]) {
  const p = captureProfile(profile), chain = structuredClone(certificates)
  return async <T extends { kind: string }>(payload: T): Promise<ResourceSignature<T>> => {
    const signed = await signEnvelope(p.privateKeys.devicePrivateKey, structuredClone(payload), p.device.deviceId, RESOURCE_SIGNATURE_DOMAIN)
    return { ...signed, identity: structuredClone(p.identity), deviceId: p.device.deviceId, certificates: structuredClone(chain) }
  }
}
export function parseInvitation(code: string): Invitation {
  if (typeof code !== "string" || code.length > 8192 || !code.startsWith("mesh-resource:v1:")) throw new Error("Invalid resource connection code")
  const encoded = code.slice("mesh-resource:v1:".length)
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error("Invalid resource connection code")
  const bytes = Uint8Array.from(atob(encoded.replace(/-/g, "+").replace(/_/g, "/")), character => character.charCodeAt(0))
  const value = JSON.parse(new TextDecoder().decode(bytes)) as Invitation
  const keys = ["kind", "version", "invitationId", "resourceId", "issuerPersonId", "audience", "subjectPersonId", "secret", "expiresAt"]
  if (!value || Object.keys(value).some(key => !keys.includes(key)) || value.kind !== "mesh-resource-invitation" || value.version !== 1 ||
      !keys.filter(key => key !== "version" && key !== "expiresAt").every(key => typeof value[key as keyof Invitation] === "string") ||
      !/^[A-Za-z0-9_-]{43}$/.test(value.secret) || !Number.isSafeInteger(value.expiresAt)) throw new Error("Invalid resource connection code")
  return value
}
