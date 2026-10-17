import { canonicalizeJson, toBase64Url, type DeviceCertificate, type LocalProfile } from "@meta-uber/mesh-identity"
import { core, captureProfile, resourceSigner, randomSecret, hash, MAX_GRANT_DURATION_MS,
  type ResourceState, type ResourceStore, type ResourceDescriptor, type ResourceRegistration,
  type ResourceConnectionMessage, type ResourceConnectionResponse, type ResourceSignature, type ChallengePayload,
  type ConnectionPayload, type GrantPayload, type ResourceGrant, type ApprovalRequest, type AccessDecision,
  type ChallengeOptions, type Authorization, type AuthorizeInput, type Invitation } from "./protocol"

const own = <T>(rows: Record<string, T>, key: string): T | undefined => Object.hasOwn(rows, key) ? rows[key] : undefined

export class ResourceProvider {
  private readonly profile: LocalProfile
  private readonly sign
  private readonly now: () => number
  private readonly store: ResourceStore
  private readonly approve?: (request: ApprovalRequest) => Promise<AccessDecision | null>
  private readonly inFlight = new Map<string, Promise<ResourceConnectionResponse>>()
  constructor(options: { profile: LocalProfile; certificates?: DeviceCertificate[]; store: ResourceStore;
    approve?: (request: ApprovalRequest) => Promise<AccessDecision | null>; now?: () => number }) {
    this.profile = captureProfile(options.profile); this.sign = resourceSigner(this.profile, options.certificates)
    this.store = options.store; this.approve = options.approve; this.now = options.now ?? Date.now
  }
  async addResource(input: ResourceRegistration): Promise<ResourceDescriptor> {
    const resource = core<ResourceDescriptor>({ operation: "validateDescriptor", resource: {
      ...structuredClone(input), kind: "mesh-resource", version: 1, issuer: this.profile.identity, epoch: 1 } })
    const key = this.key(resource.id), existing = await this.store.read(key)
    if (existing) {
      const expected = { ...resource, issuer: { ...resource.issuer, displayName: existing.resource.issuer.displayName }, epoch: existing.resource.epoch }
      if (canonicalizeJson(existing.resource) !== canonicalizeJson(expected)) throw new Error("Resource already registered with different authority")
      return structuredClone(existing.resource)
    }
    const initial: ResourceState = { version: 1, resource, revokedGrants: [], revokedDevices: [], connections: {}, invitations: {}, replays: {} }
    if (!await this.store.compareAndSwap(key, null, initial)) return this.addResource(input)
    return structuredClone(resource)
  }
  async getResource(resourceId: string): Promise<ResourceDescriptor> {
    return (await this.read(resourceId)).resource
  }
  async updateResource(input: ResourceRegistration): Promise<ResourceDescriptor> {
    const captured = structuredClone(input)
    return this.mutate(captured.id, row => {
      row.resource = core<ResourceDescriptor>({ operation: "validateDescriptor", resource: {
        ...captured, kind: "mesh-resource", version: 1, issuer: row.resource.issuer, epoch: row.resource.epoch + 1 } })
      return row.resource
    })
  }
  async handleConnection(message: ResourceConnectionMessage): Promise<ResourceConnectionResponse> {
    const captured = structuredClone(message)
    if (!captured || typeof captured !== "object") throw new Error("Invalid resource connection message")
    if (captured.kind === "challenge") return this.challenge(captured.options)
    if (captured.kind !== "connect") throw new Error("Unknown resource connection message")
    const key = await hash(captured)
    const running = this.inFlight.get(key)
    if (running) return running
    const pending = this.accept(captured).finally(() => { if (this.inFlight.get(key) === pending) this.inFlight.delete(key) })
    this.inFlight.set(key, pending); return pending
  }
  async revokeGrant(resourceId: string, grantId: string): Promise<void> {
    await this.mutate(resourceId, row => {
      if (!Object.values(row.connections).some(connection => connection.grant?.payload.grantId === grantId)) throw new Error("Unknown resource grant")
      if (!row.revokedGrants.includes(grantId)) row.revokedGrants.push(grantId)
      return undefined
    })
  }
  async revokeDevice(resourceId: string, deviceId: string): Promise<void> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(deviceId)) throw new Error("Invalid resource device ID")
    await this.mutate(resourceId, row => {
      if (row.revokedDevices.includes(deviceId)) return undefined
      if (row.revokedDevices.length >= 256) throw new Error("Resource device revocation capacity reached")
      row.revokedDevices.push(deviceId)
      return undefined
    })
  }
  async authorize(input: AuthorizeInput): Promise<Authorization> {
    const captured = structuredClone(input)
    return this.mutate(captured.resourceId, row => {
      const authorization = core<Authorization>({ operation: "authorize", resource: row.resource, grant: captured.grant, proof: captured.proof, action: captured.action, bodyDigest: captured.bodyDigest,
        now: this.now(), revokedGrants: row.revokedGrants, revokedDevices: row.revokedDevices })
      if (row.replays[authorization.requestId] !== undefined) throw new Error("Resource operation replay rejected")
      row.replays = Object.fromEntries(Object.entries(row.replays).filter(([, expiresAt]) => expiresAt > this.now()))
      if (Object.keys(row.replays).length >= 4096) throw new Error("Resource replay protection capacity reached")
      row.replays[authorization.requestId] = authorization.expiresAt
      return authorization
    })
  }
  async createInvitation(input: { resourceId: string; subjectPersonId: string; actions: string[]; expiresAt: number; grantExpiresAt?: number }): Promise<string> {
    const captured = structuredClone(input), secret = randomSecret(), invitationId = crypto.randomUUID()
    const secretHash = await hash(secret)
    const invitation = await this.mutate(captured.resourceId, row => {
      const now = this.now(), requestedExpiresAt = captured.grantExpiresAt ?? now + MAX_GRANT_DURATION_MS
      core({ operation: "challengePayload", resource: row.resource, subjectPersonId: captured.subjectPersonId,
        requestId: invitationId, actions: captured.actions, requestedExpiresAt, nonce: secret, now })
      if (!Number.isSafeInteger(captured.expiresAt) || captured.expiresAt <= now || captured.expiresAt > now + 120_000) throw new Error("Invalid connection code expiry")
      row.invitations = Object.fromEntries(Object.entries(row.invitations).filter(([, value]) => value.expiresAt > now))
      if (Object.keys(row.invitations).length >= 128) throw new Error("Resource invitation capacity reached")
      row.invitations[invitationId] = { secretHash, subjectPersonId: captured.subjectPersonId, actions: captured.actions,
        epoch: row.resource.epoch, expiresAt: captured.expiresAt, grantExpiresAt: requestedExpiresAt }
      return { kind: "mesh-resource-invitation", version: 1, invitationId, resourceId: row.resource.id,
        issuerPersonId: row.resource.issuer.personId, audience: row.resource.audience, subjectPersonId: captured.subjectPersonId,
        secret, expiresAt: captured.expiresAt } as Invitation
    })
    return `mesh-resource:v1:${toBase64Url(new TextEncoder().encode(canonicalizeJson(invitation)))}`
  }
  private key(id: string) { return `mesh-resource:${this.profile.identity.personId}:${id}` }
  private async read(id: string): Promise<ResourceState> {
    const row = await this.store.read(this.key(id))
    if (!row || row.resource.id !== id || row.resource.issuer.personId !== this.profile.identity.personId ||
        row.resource.issuer.publicKey !== this.profile.identity.publicKey) throw new Error("Resource is not registered by this issuer")
    if (row.revokedDevices.includes(this.profile.device.deviceId)) throw new Error("Resource provider device revoked")
    core({ operation: "validateDescriptor", resource: row.resource })
    return structuredClone(row)
  }
  private async mutate<T>(id: string, change: (row: ResourceState) => T): Promise<T> {
    for (let attempt = 0; attempt < 8; attempt++) {
      const row = await this.read(id), version = row.version
      const value = change(row); row.version = version + 1
      if (await this.store.compareAndSwap(this.key(id), version, row)) return structuredClone(value)
    }
    throw new Error("Resource authority changed concurrently; retry")
  }
  private async challenge(options: ChallengeOptions): Promise<ResourceConnectionResponse> {
    const input = structuredClone(options), row = await this.read(input.resourceId)
    let invited: ResourceState["invitations"][string] | undefined
    if (input.invitation) {
      invited = row.invitations[input.invitation.invitationId]
      if (!invited || invited.subjectPersonId !== input.subjectPersonId || invited.epoch !== row.resource.epoch ||
          invited.consumedBy || invited.expiresAt <= this.now() || await hash(input.invitation.secret) !== invited.secretHash) throw new Error("Connection code expired, consumed or belongs to another identity")
      input.actions = structuredClone(invited.actions)
      input.requestedExpiresAt = Math.min(input.requestedExpiresAt, invited.grantExpiresAt)
    }
    const safeOptions = { ...input, ...(input.invitation ? { invitation: { ...input.invitation, secret: await hash(input.invitation.secret) } } : {}) }
    const optionsHash = await hash(safeOptions)
    const existing = own(row.connections, input.requestId)
    if (existing) {
      if (existing.optionsHash !== optionsHash) throw new Error("Resource request ID was reused")
      return { kind: "challenge", challenge: existing.challenge }
    }
    const payload = core<ChallengePayload>({ operation: "challengePayload", resource: row.resource, subjectPersonId: input.subjectPersonId,
      requestId: input.requestId, actions: input.actions, requestedExpiresAt: input.requestedExpiresAt, nonce: randomSecret(), now: this.now() })
    const challenge = await this.sign(payload)
    return this.mutate(input.resourceId, current => {
      if (current.resource.epoch !== row.resource.epoch) throw new Error("Resource authority changed during challenge")
      const retained = own(current.connections, input.requestId)
      if (retained) {
        if (retained.optionsHash !== optionsHash) throw new Error("Resource request ID was reused")
        return { kind: "challenge", challenge: retained.challenge } as ResourceConnectionResponse
      }
      current.connections = Object.fromEntries(Object.entries(current.connections).filter(([, c]) => (c.grant?.payload.expiresAt ?? c.challenge.payload.expiresAt) > this.now()))
      if (Object.keys(current.connections).length >= 256) throw new Error("Resource connection capacity reached")
      current.connections = { ...current.connections, [input.requestId]: { optionsHash, challenge, status: "open", ...(input.invitation ? { invitationId: input.invitation.invitationId } : {}) } }
      return { kind: "challenge", challenge } as ResourceConnectionResponse
    })
  }
  private async accept(message: Extract<ResourceConnectionMessage, { kind: "connect" }>): Promise<ResourceConnectionResponse> {
    const requestId = message.request.payload.requestId, requestHash = await hash(message.request)
    const state = await this.mutate(message.resourceId, row => {
      const retained = own(row.connections, requestId)
      if (!retained || canonicalizeJson(retained.challenge) !== canonicalizeJson(message.challenge)) throw new Error("Unknown resource challenge")
      if (retained.requestHash && retained.requestHash !== requestHash) throw new Error("Resource request ID was reused")
      if (retained.status === "connected" && retained.grant) {
        core({ operation: "verifyGrant", resource: row.resource, grant: retained.grant, now: this.now(), revokedGrants: row.revokedGrants, revokedDevices: row.revokedDevices })
        if (row.revokedDevices.includes(message.request.deviceId)) throw new Error("Resource device revoked")
        return { kind: "connected", grant: retained.grant } as const
      }
      core<ConnectionPayload>({ operation: "verifyConnection", resource: row.resource, challenge: message.challenge, request: message.request, now: this.now() })
      if (row.revokedDevices.includes(message.request.deviceId)) throw new Error("Resource device revoked")
      if (retained.status === "denied") return { kind: "denied" } as const
      if (retained.status === "approving") return { kind: "pending" } as const
      retained.requestHash = requestHash; retained.request = message.request; retained.status = "approving"
      return { kind: "approve", resource: row.resource, invitationId: retained.invitationId } as const
    })
    if (state.kind !== "approve") return state
    if (!state.invitationId && !this.approve) return { kind: "pending" }
    let decision: AccessDecision | null
    if (state.invitationId) {
      const row = await this.read(message.resourceId), invitation = row.invitations[state.invitationId]
      if (!invitation || invitation.consumedBy || invitation.expiresAt <= this.now()) throw new Error("Connection code already consumed or expired")
      decision = { actions: invitation.actions, expiresAt: Math.min(invitation.grantExpiresAt, message.request.payload.requestedExpiresAt) }
    } else {
      try { decision = await this.approve!({ ...structuredClone(message.request.payload), subject: structuredClone(message.request.identity),
        readScope: state.resource.readScope, resourceTitle: state.resource.title }) }
      catch (error) { await this.mutate(message.resourceId, row => { own(row.connections, requestId)!.status = "denied" }); throw error }
    }
    return this.approveConnection(message.resourceId, requestId, decision)
  }
  async listPendingRequests(resourceId: string): Promise<ApprovalRequest[]> {
    const row = await this.read(resourceId)
    return Object.values(row.connections).flatMap(connection => {
      if (connection.status !== "approving" || !connection.request || row.revokedDevices.includes(connection.request.deviceId)) return []
      try {
        core({ operation: "verifyConnection", resource: row.resource, challenge: connection.challenge, request: connection.request, now: this.now() })
        return [{ ...connection.request.payload, subject: connection.request.identity, readScope: row.resource.readScope, resourceTitle: row.resource.title }]
      } catch { return [] }
    })
  }
  async approveConnection(resourceId: string, requestId: string, decision: AccessDecision | null): Promise<ResourceConnectionResponse> {
    decision = structuredClone(decision)
    if (!decision) {
      await this.mutate(resourceId, row => {
        const retained = own(row.connections, requestId)
        if (!retained || retained.status === "connected") throw new Error("Resource request cannot be denied; revoke its grant instead")
        retained.status = "denied"
      })
      return { kind: "denied" }
    }
    const decisionHash = await hash(decision)
    const row = await this.read(resourceId), retained = own(row.connections, requestId)
    if (!retained?.request || !retained.requestHash) throw new Error("Unknown resource request")
    if (retained.status === "denied") throw new Error("Resource access denied")
    if (retained.grant && retained.status === "connected") {
      if (retained.decisionHash !== decisionHash) throw new Error("Resource approval changed after issuance")
      core({ operation: "verifyGrant", resource: row.resource, grant: retained.grant, now: this.now(), revokedGrants: row.revokedGrants, revokedDevices: row.revokedDevices })
      return { kind: "connected", grant: retained.grant }
    }
    const message = { resourceId, challenge: retained.challenge, request: retained.request }
    const requestHash = retained.requestHash
    const payload = core<GrantPayload>({ operation: "grantPayload", resource: row.resource, challenge: message.challenge,
      request: message.request, actions: decision.actions, expiresAt: decision.expiresAt, grantId: crypto.randomUUID(), now: this.now() })
    const grant = await this.sign(payload)
    return this.mutate(message.resourceId, current => {
      core({ operation: "verifyGrant", resource: current.resource, grant, now: this.now(), revokedGrants: current.revokedGrants, revokedDevices: current.revokedDevices })
      if (current.revokedDevices.includes(message.request.deviceId)) throw new Error("Resource device revoked during approval")
      const retained = own(current.connections, requestId)
      if (!retained || retained.requestHash !== requestHash) throw new Error("Resource approval changed")
      if (retained.status === "connected" && retained.grant && retained.decisionHash === decisionHash) {
        return { kind: "connected", grant: retained.grant } as ResourceConnectionResponse
      }
      if (retained.status !== "approving") throw new Error("Resource approval changed")
      if (retained.invitationId) {
        const invitation = current.invitations[retained.invitationId]
        if (!invitation || invitation.consumedBy || invitation.expiresAt <= this.now()) throw new Error("Connection code already consumed or expired")
        invitation.consumedBy = requestId
      }
      retained.grant = grant; retained.decisionHash = decisionHash; retained.status = "connected"
      return { kind: "connected", grant } as ResourceConnectionResponse
    })
  }
}
