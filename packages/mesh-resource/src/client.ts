import { canonicalizeJson, type DeviceCertificate, type LocalProfile, type PublicIdentity } from "@meta-uber/mesh-identity"
import { core, captureProfile, resourceSigner, randomSecret, parseInvitation, MAX_GRANT_DURATION_MS,
  type ResourceDescriptor, type ResourceGrant, type ResourceOperationProof, type OperationPayload,
  type ResourceConnectionTransport, type PendingConnection, type ResourceConnectionStore,
  type ConnectionPayload, type ConnectionResult, type Invitation } from "./protocol"

export type ConnectResourceOptions = { resource: ResourceDescriptor; actions: string[]; requestId?: string; expiresAt?: number; signal?: AbortSignal }
export class ResourceClient {
  private readonly profile: LocalProfile
  private readonly sign
  private readonly now: () => number
  private readonly transport: ResourceConnectionTransport
  private readonly store: ResourceConnectionStore
  private readonly operations = new Map<string, { fingerprint: string; result: Promise<ConnectionResult> }>()
  constructor(options: { profile: LocalProfile; certificates?: DeviceCertificate[]; now?: () => number;
    transport: ResourceConnectionTransport; store?: ResourceConnectionStore }) {
    this.profile = captureProfile(options.profile); this.sign = resourceSigner(this.profile, options.certificates)
    this.now = options.now ?? Date.now; this.transport = options.transport
    const rows = new Map<string, PendingConnection>()
    this.store = options.store ?? { load: async key => structuredClone(rows.get(key)),
      save: async (key, value) => { rows.set(key, structuredClone(value)) }, remove: async key => { rows.delete(key) } }
  }
  get identity(): PublicIdentity { return structuredClone(this.profile.identity) }
  connectResource(options: ConnectResourceOptions): Promise<ConnectionResult> {
    return this.connect(structuredClone({ ...options, signal: undefined }), options.signal)
  }
  async redeemInvitation(code: string, resource: ResourceDescriptor, signal?: AbortSignal): Promise<ConnectionResult> {
    const invitation = parseInvitation(code)
    if (invitation.subjectPersonId !== this.profile.identity.personId || invitation.resourceId !== resource.id ||
        invitation.issuerPersonId !== resource.issuer.personId || invitation.audience !== resource.audience || invitation.expiresAt <= this.now()) {
      throw new Error("Resource connection code belongs to another identity, resource or time")
    }
    return this.connect({ resource: structuredClone(resource), actions: [], requestId: crypto.randomUUID() }, signal, invitation)
  }
  async signOperation(grant: ResourceGrant, input: { action: string; bodyDigest: string }): Promise<ResourceOperationProof> {
    const payload = core<OperationPayload>({ operation: "operationPayload", grant, ...input, nonce: randomSecret(), now: this.now() })
    return this.sign(payload)
  }
  private connect(options: ConnectResourceOptions, signal?: AbortSignal, invitation?: Invitation): Promise<ConnectionResult> {
    const fingerprint = canonicalizeJson({ resource: options.resource, actions: options.actions,
      expiresAt: options.expiresAt ?? null, invitation: invitation?.invitationId ?? null })
    const key = `${this.profile.identity.personId}:${invitation ? `invitation:${invitation.invitationId}` : options.requestId ? `id:${options.requestId}` : `intent:${fingerprint}`}`
    const retained = this.operations.get(key)
    if (retained) {
      if (retained.fingerprint !== fingerprint) return Promise.reject(new Error("Resource connection request ID was reused with different options"))
      return retained.result
    }
    const pending = this.finishConnection(options, key, signal, invitation)
      .finally(() => { if (this.operations.get(key)?.result === pending) this.operations.delete(key) })
    this.operations.set(key, { fingerprint, result: pending })
    return pending
  }
  private async finishConnection(options: ConnectResourceOptions, key: string, signal?: AbortSignal, invitation?: Invitation): Promise<ConnectionResult> {
    core({ operation: "validateDescriptor", resource: options.resource })
    let pending = await this.store.load(key)
    if (pending && (pending.options.subjectPersonId !== this.profile.identity.personId || canonicalizeJson(pending.resource) !== canonicalizeJson(options.resource) ||
        !invitation && canonicalizeJson(pending.options.actions) !== canonicalizeJson(options.actions) ||
        options.expiresAt !== undefined && pending.options.requestedExpiresAt !== options.expiresAt)) throw new Error("Resource connection request ID was reused with different options")
    const requestId = pending?.options.requestId ?? options.requestId ?? crypto.randomUUID()
    pending ??= { resource: options.resource, options: { resourceId: options.resource.id, subjectPersonId: this.profile.identity.personId,
      requestId, actions: options.actions, requestedExpiresAt: options.expiresAt ?? this.now() + MAX_GRANT_DURATION_MS,
      ...(invitation ? { invitation } : {}) } }
    await this.store.save(key, pending)
    signal?.throwIfAborted()
    if (!pending.challenge) {
      const offered = await this.transport({ kind: "challenge", options: pending.options }, signal)
      signal?.throwIfAborted()
      if (offered.kind !== "challenge") throw new Error("Invalid resource challenge response")
      if (invitation) {
        pending.options.actions = structuredClone(offered.challenge.payload.actions)
        pending.options.requestedExpiresAt = Math.min(pending.options.requestedExpiresAt, offered.challenge.payload.requestedExpiresAt)
      }
      const payload = core<ConnectionPayload>({ operation: "connectionPayload", resource: pending.resource, challenge: offered.challenge,
        subjectPersonId: this.profile.identity.personId, requestId, actions: pending.options.actions,
        requestedExpiresAt: pending.options.requestedExpiresAt, now: this.now() })
      pending.challenge = offered.challenge; pending.request = await this.sign(payload)
      await this.store.save(key, pending)
    }
    if (!pending.request) throw new Error("Incomplete retained resource connection")
    for (let attempt = 0; attempt < 240; attempt++) {
      signal?.throwIfAborted()
      const result = await this.transport({ kind: "connect", resourceId: pending.resource.id, challenge: pending.challenge!, request: pending.request }, signal)
      signal?.throwIfAborted()
      if (result.kind === "denied") { await this.store.remove(key); throw new Error("Resource access denied") }
      if (result.kind === "connected") {
        core({ operation: "verifyGrant", resource: pending.resource, grant: result.grant, now: this.now(), revokedGrants: [], revokedDevices: [] })
        const grant = result.grant.payload
        if (grant.subjectPersonId !== this.profile.identity.personId || grant.requestId !== requestId ||
            grant.expiresAt > pending.options.requestedExpiresAt || grant.actions.some(action => !pending!.options.actions.includes(action))) {
          throw new Error("Resource approval differs from requested access")
        }
        await this.store.remove(key)
        return structuredClone({ resource: pending.resource, grant: result.grant })
      }
      if (result.kind !== "pending") throw new Error("Invalid resource connection response")
      if (pending.challenge!.payload.expiresAt <= this.now()) throw new Error("Resource approval expired")
      await new Promise(resolve => setTimeout(resolve, 250))
    }
    throw new Error("Resource approval is still pending")
  }
}
