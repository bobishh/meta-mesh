import * as Automerge from "@automerge/automerge"
import { authorizeIdentityDevice, canonicalizeJson, verifyIdentityDeviceAuthority,
  type DeviceCertificate, type IdentityDeviceRevocation, type LocalProfile, type PublicIdentity } from "@meta-uber/mesh-identity"
import { identityProfileRevision, mergeIdentityProfileState,
  readIdentityProfileStateWithRevocations, type IdentityProfileState } from "@meta-uber/mesh-identity"
import { AutomergeAntiEntropy, receiveAutomergeDeviceSync, syncAutomergeDocumentToDevice,
  type AutomergeAdmission, type AutomergeDeviceSyncRequest, type AutomergeDocumentAdapter } from "./automerge"
import { verifySignedDeviceRoute, verifySignedDurableBatchAck, type DeviceRoute, type DurableBatchAck, type SignedDurableBatchAck } from "./protocol"

export type PersonalIdentityDocument = {
  kind: "mesh-personal-identity"
  version: 2
  personId: string
  identityPublicKey: string
  certificates: DeviceCertificate[]
  revocations: IdentityDeviceRevocation[]
  profileState: IdentityProfileState
}

export type PersonalIdentityReplicaOptions = {
  identity: PublicIdentity
  documentId?: string
  current(): Promise<Automerge.Doc<PersonalIdentityDocument>>
  commit(document: Automerge.Doc<PersonalIdentityDocument>, expectedProfileRevision: string): void | Promise<void>
  authorizePeer?: (remoteDeviceId: string, direction: "send" | "receive") => boolean | Promise<boolean>
}

export type PersonalIdentitySyncStream = {
  send(bytes: Uint8Array): Promise<void>
  /** Identity sync uses raw JSON frames, not newline-delimited pairing frames. */
  readRaw(): Promise<Uint8Array>
  closeSend(): Promise<void>
  /** Cancel this stream without closing its paired-device connection. */
  reset?(): Promise<void>
}

/** Established MetaMesh connection to a paired device. Pairing and dialing stay host-owned. */
export type PersonalIdentitySyncConnection = {
  openStream(): Promise<PersonalIdentitySyncStream>
  acceptStream(): Promise<PersonalIdentitySyncStream>
}

export type PersonalIdentitySyncOptions = {
  profile: LocalProfile
  adapter: AutomergeDocumentAdapter<PersonalIdentityDocument>
}

const maximumCertificates = 256

/** Initial Identity-domain document. Application/resource documents stay separate. */
export function createPersonalIdentityDocument(identity: PublicIdentity,
  certificates: readonly DeviceCertificate[] = []): PersonalIdentityDocument {
  return { kind: "mesh-personal-identity", version: 2, personId: identity.personId,
    identityPublicKey: identity.publicKey, certificates: structuredClone(Array.from(certificates)),
    revocations: [],
    profileState: { version: 1, personId: identity.personId, operations: [], legacy: [] } }
}

/** Adapter for the shared authenticated device anti-entropy engine. Host owns persistence and paired routes. */
export function createPersonalIdentityAdapter(options: PersonalIdentityReplicaOptions): AutomergeDocumentAdapter<PersonalIdentityDocument> {
  const identity = structuredClone(options.identity)
  const scopeId = `mesh-identity:${identity.personId}`
  const documentId = options.documentId ?? scopeId
  return {
    scopeId,
    documentId,
    async current() {
      const document = await options.current()
      return normalizePersonalIdentityDocument(document, identity)
    },
    normalizeCandidate(candidate) {
      return normalizePersonalIdentityDocument(candidate, identity)
    },
    async authorize(remoteDeviceId, _proof, direction) {
      if (options.authorizePeer && !await options.authorizePeer(remoteDeviceId, direction)) return false
      const document = await options.current()
      const value = await validatePersonalIdentityDocument(document, identity)
      try {
        const authority = await verifyIdentityDeviceAuthority(identity,
          { certificates: value.certificates, revocations: value.revocations })
        await authorizeIdentityDevice(authority, remoteDeviceId, "MATCH/1")
        return true
      } catch { return false }
    },
    async validateCandidate(admission: AutomergeAdmission<PersonalIdentityDocument>) {
      await validatePersonalIdentityDocument(admission.candidate, identity)
      if (admission.before.personId !== admission.candidate.personId ||
          admission.before.identityPublicKey !== admission.candidate.identityPublicKey) {
        throw new Error("Identity mesh person cannot change")
      }
    },
    async commit(admission) {
      const before = await readIdentityProfileStateWithRevocations(admission.before.profileState, identity,
        admission.before.certificates, admission.before.revocations)
      let candidate = await normalizePersonalIdentityDocument(admission.candidate, identity)
      let expectedRevision = await identityProfileRevision(before)
      for (let attempt = 0; attempt < 5; attempt += 1) {
        try {
          await options.commit(candidate, expectedRevision)
          return
        } catch (error) {
          const latest = await options.current()
          await validatePersonalIdentityDocument(latest, identity)
          const latestState = await readIdentityProfileStateWithRevocations(latest.profileState, identity,
            latest.certificates, latest.revocations)
          const latestRevision = await identityProfileRevision(latestState)
          if (latestRevision === expectedRevision || attempt === 4) throw error

          // Another direction may commit while this receive is in flight. Rebase the
          // already-validated signed history onto that durable version before retrying.
          candidate = await normalizePersonalIdentityDocument(Automerge.merge(latest, candidate), identity)
          await validatePersonalIdentityDocument(candidate, identity)
          expectedRevision = latestRevision
        }
      }
    },
  }
}

/** Live adapter over the shared MetaMesh device-batch protocol and authenticated peer streams. */
export class PersonalIdentityMeshSync {
  private readonly engine: AutomergeAntiEntropy

  constructor(private readonly options: PersonalIdentitySyncOptions) {
    this.engine = new AutomergeAntiEntropy(options.profile.device.deviceId, Automerge)
  }

  async sync(connection: PersonalIdentitySyncConnection, route: DeviceRoute, targetDeviceId: string,
    signal?: AbortSignal): Promise<{ rounds: number; routeInstanceIds: string[] }> {
    const { profile, adapter } = this.options
    if (route.scopeId !== adapter.scopeId || route.deviceId !== targetDeviceId || route.personId !== profile.identity.personId) {
      throw new Error("Identity route does not match this person and device")
    }
    const current = await adapter.current() as unknown as PersonalIdentityDocument
    const certificate = current.certificates.find(candidate => candidate.payload.deviceId === targetDeviceId)
    if (!certificate) throw new Error("Identity route device is not enrolled")
    const authority = await verifyIdentityDeviceAuthority(profile.identity,
      { certificates: current.certificates, revocations: current.revocations })
    const devicePublicKey = await authorizeIdentityDevice(authority, targetDeviceId, "MATCH/1")
    const signedRoute = { payload: { kind: "mesh-device-route" as const, version: 1 as const, scopeId: route.scopeId,
      personId: route.personId, deviceId: route.deviceId, instanceId: route.instanceId, endpoint: route.endpoint,
      sequence: route.sequence, issuedAt: route.issuedAt, expiresAt: route.expiresAt },
      signerKeyId: route.signerKeyId, signature: route.signature }
    await verifySignedDeviceRoute(signedRoute, devicePublicKey)
    return syncAutomergeDocumentToDevice({ engine: this.engine, adapter, targetDeviceId, routes: [route], signal,
      send: async (_route, request, abortSignal) => {
        if (abortSignal.aborted) throw abortSignal.reason ?? new Error("Identity sync cancelled")
        const stream = await awaitIdentitySyncOperation(() => connection.openStream(), abortSignal, undefined,
          lateStream => resetIdentitySyncStream(lateStream))
        await awaitIdentitySyncOperation(() => stream.send(encodeIdentitySyncFrame(request)), abortSignal,
          () => resetIdentitySyncStream(stream))
        await awaitIdentitySyncOperation(() => stream.closeSend(), abortSignal,
          () => resetIdentitySyncStream(stream))
        const response = await awaitIdentitySyncOperation(() => stream.readRaw(), abortSignal,
          () => resetIdentitySyncStream(stream))
        return decodeIdentitySyncResponse(response)
      },
      verifyAck: async (signedAck: SignedDurableBatchAck): Promise<DurableBatchAck> => {
        const document = await adapter.current() as unknown as PersonalIdentityDocument
        const currentAuthority = await verifyIdentityDeviceAuthority(profile.identity,
          { certificates: document.certificates, revocations: document.revocations })
        const currentDevicePublicKey = await authorizeIdentityDevice(currentAuthority, targetDeviceId, "MATCH/1")
        if (signedAck.signerKeyId !== targetDeviceId ||
            signedAck.payload.receiverDeviceId !== targetDeviceId) throw new Error("Identity sync acknowledgement signer mismatch")
        return verifySignedDurableBatchAck(signedAck, currentDevicePublicKey)
      },
    })
  }

  /** Handle one request stream from an already authenticated paired device. */
  async receiveNext(connection: PersonalIdentitySyncConnection, remoteDeviceId: string): Promise<{ acceptedChanges: number }> {
    const stream = await connection.acceptStream()
    const request = decodeIdentitySyncRequest(await stream.readRaw())
    let acceptedChanges = 0
    const response = await receiveAutomergeDeviceSync({ ...this.options, engine: this.engine,
      adapter: this.options.adapter, remoteDeviceId, request, onReceivedChanges: count => { acceptedChanges = count } })
    await stream.send(encodeIdentitySyncFrame(response))
    await stream.closeSend()
    return { acceptedChanges }
  }
}

function awaitIdentitySyncOperation<T>(operation: () => Promise<T>, signal: AbortSignal,
  onAbort?: () => void, onLateValue?: (value: T) => void): Promise<T> {
  if (signal.aborted) {
    onAbort?.()
    return Promise.reject(signal.reason ?? new Error("Identity sync cancelled"))
  }
  let pending: Promise<T>
  try { pending = Promise.resolve(operation()) }
  catch (error) { pending = Promise.reject(error) }
  return new Promise<T>((resolve, reject) => {
    let settled = false
    const cleanup = () => signal.removeEventListener("abort", abort)
    const abort = () => {
      if (settled) return
      settled = true
      cleanup()
      onAbort?.()
      reject(signal.reason ?? new Error("Identity sync cancelled"))
    }
    signal.addEventListener("abort", abort, { once: true })
    pending.then(value => {
      if (settled) {
        if (onLateValue) void Promise.resolve().then(() => onLateValue(value)).catch(() => undefined)
        return
      }
      settled = true
      cleanup()
      resolve(value)
    }, error => {
      if (settled) return
      settled = true
      cleanup()
      reject(error)
    })
    if (signal.aborted) abort()
  })
}

function resetIdentitySyncStream(stream: PersonalIdentitySyncStream): void {
  if (!stream.reset) return
  try { void Promise.resolve(stream.reset()).catch(() => undefined) }
  catch { /* Cancellation remains authoritative if transport cleanup fails. */ }
}

const maximumIdentitySyncFrameBytes = 16 * 1024 * 1024

function encodeIdentitySyncFrame(value: unknown): Uint8Array {
  const bytes = new TextEncoder().encode(JSON.stringify(value))
  if (bytes.byteLength > maximumIdentitySyncFrameBytes) throw new Error("Identity sync frame exceeds size limit")
  return bytes
}

function decodeIdentitySyncFrame(bytes: Uint8Array): unknown {
  if (bytes.byteLength === 0 || bytes.byteLength > maximumIdentitySyncFrameBytes) {
    throw new Error("Identity sync frame exceeds size limit")
  }
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) }
  catch { throw new Error("Invalid Identity sync frame") }
}

function decodeIdentitySyncRequest(bytes: Uint8Array): AutomergeDeviceSyncRequest {
  const value = decodeIdentitySyncFrame(bytes) as Partial<AutomergeDeviceSyncRequest> | null
  if (!value || value.kind !== "mesh-automerge-device-sync" || value.version !== 1 ||
      typeof value.batchId !== "string" || !value.frame || typeof value.frame !== "object") {
    throw new Error("Invalid Identity sync request")
  }
  return value as AutomergeDeviceSyncRequest
}

function decodeIdentitySyncResponse(bytes: Uint8Array) {
  const value = decodeIdentitySyncFrame(bytes) as { kind?: unknown; version?: unknown; batchId?: unknown; ack?: unknown } | null
  if (!value || value.kind !== "mesh-automerge-device-sync-response" || value.version !== 1 ||
      typeof value.batchId !== "string" || !value.ack || typeof value.ack !== "object") {
    throw new Error("Invalid Identity sync response")
  }
  return value as Awaited<ReturnType<typeof receiveAutomergeDeviceSync>>
}

export async function validatePersonalIdentityDocument(documentValue: unknown, identity: PublicIdentity): Promise<PersonalIdentityDocument> {
  const serialized = JSON.stringify(documentValue)
  if (!serialized || new TextEncoder().encode(serialized).byteLength > 4 * 1024 * 1024) {
    throw new Error("Identity mesh document exceeds the size limit")
  }
  const document = JSON.parse(serialized) as PersonalIdentityDocument
  if (!document || document.kind !== "mesh-personal-identity" || ![1, 2].includes(document.version) ||
      document.personId !== identity.personId || document.identityPublicKey !== identity.publicKey ||
      !Array.isArray(document.certificates) || document.certificates.length > maximumCertificates ||
      (document.version === 2 && !Array.isArray(document.revocations)) ||
      (document.revocations !== undefined && (!Array.isArray(document.revocations) || document.revocations.length > maximumCertificates))) {
    throw new Error("Identity mesh document does not match this person")
  }
  const profileBranches = [document.profileState]
  const certificates = includeProfileOperationCertificates(document.certificates, profileBranches)
  if (certificates.length > maximumCertificates) throw new Error("Identity mesh certificate limit exceeded")
  const seen = new Map<string, string>()
  for (const certificate of certificates) {
    const previous = seen.get(certificate.payload.deviceId)
    const encoded = canonicalizeJson(certificate)
    if (previous && previous !== encoded) throw new Error("Identity mesh device certificate conflict")
    seen.set(certificate.payload.deviceId, encoded)
  }
  const revocations = document.revocations ?? []
  await verifyIdentityDeviceAuthority(identity, { certificates, revocations })
  document.certificates = certificates
  document.version = 2
  document.revocations = revocations
  document.profileState = await readIdentityProfileStateWithRevocations(document.profileState, identity,
    document.certificates, revocations)
  return document
}

/** Fold independent Automerge field branches through the signed Identity domain rules. */
export async function normalizePersonalIdentityDocument(document: Automerge.Doc<PersonalIdentityDocument>,
  identity: PublicIdentity): Promise<Automerge.Doc<PersonalIdentityDocument>> {
  const fields = ["kind", "version", "personId", "identityPublicKey", "certificates", "revocations", "profileState"] as const
  if (!fields.some(field => Object.keys(Automerge.getConflicts(document, field) ?? {}).length > 0)) {
    const validated = await validatePersonalIdentityDocument(document, identity)
    if (document.version === 2 && Array.isArray(document.revocations) &&
        canonicalizeJson(document.profileState) === canonicalizeJson(validated.profileState) &&
        canonicalizeJson(document.certificates) === canonicalizeJson(validated.certificates)) return document
    const writable = Automerge.clone(document)
    const upgraded = Automerge.change(writable, "Normalize Identity authority history", draft => {
      draft.version = 2
      draft.revocations = validated.revocations
      draft.profileState = validated.profileState
      draft.certificates = validated.certificates
    })
    await validatePersonalIdentityDocument(upgraded, identity)
    return upgraded
  }

  const kind = requireSingleFieldValue(document, "kind")
  const versions = fieldBranches(document, "version")
  if (versions.some(value => value !== 1 && value !== 2)) throw new Error("Identity mesh version conflict is invalid")
  const version = versions.includes(2) ? 2 : 1
  const personId = requireSingleFieldValue(document, "personId")
  const identityPublicKey = requireSingleFieldValue(document, "identityPublicKey")
  if (kind !== "mesh-personal-identity" || ![1, 2].includes(version as number) || personId !== identity.personId ||
      identityPublicKey !== identity.publicKey) {
    throw new Error("Identity mesh conflict changes person or document identity")
  }

  const certificateBranches = fieldBranches(document, "certificates")
  const certificatesByDevice = new Map<string, DeviceCertificate>()
  for (const branch of certificateBranches) {
    if (!Array.isArray(branch) || branch.length > maximumCertificates) {
      throw new Error("Identity mesh certificate conflict is invalid")
    }
    for (const certificate of branch as DeviceCertificate[]) {
      const deviceId = certificate?.payload?.deviceId
      if (typeof deviceId !== "string") throw new Error("Identity mesh certificate conflict is invalid")
      const previous = certificatesByDevice.get(deviceId)
      if (previous && canonicalizeJson(previous) !== canonicalizeJson(certificate)) {
        throw new Error("Identity mesh device certificate conflict")
      }
      certificatesByDevice.set(deviceId, structuredClone(certificate))
    }
  }
  let certificates = [...certificatesByDevice.values()]
  if (certificates.length > maximumCertificates) throw new Error("Identity mesh certificate limit exceeded")

  const profileBranches = fieldBranches(document, "profileState")
  if (profileBranches.length === 0) throw new Error("Identity mesh profile state is missing")
  certificates = includeProfileOperationCertificates(certificates, profileBranches)
  if (certificates.length > maximumCertificates) throw new Error("Identity mesh certificate limit exceeded")

  const revocationBranches = fieldBranches(document, "revocations")
  const revocationsByRevision = new Map<number, IdentityDeviceRevocation>()
  for (const branch of revocationBranches) {
    if (branch === undefined) continue
    if (!Array.isArray(branch) || branch.length > maximumCertificates) {
      throw new Error("Identity mesh revocation conflict is invalid")
    }
    for (const record of branch as IdentityDeviceRevocation[]) {
      const revision = record?.payload?.revision
      if (!Number.isSafeInteger(revision) || revision < 1) throw new Error("Identity mesh revocation conflict is invalid")
      const previous = revocationsByRevision.get(revision)
      if (previous && canonicalizeJson(previous) !== canonicalizeJson(record)) {
        throw new Error("Identity mesh revocation history conflict")
      }
      revocationsByRevision.set(revision, structuredClone(record))
    }
  }
  const revocations = [...revocationsByRevision.values()].sort((left, right) => left.payload.revision - right.payload.revision)
  await verifyIdentityDeviceAuthority(identity, { certificates, revocations })

  let profileState = await readIdentityProfileStateWithRevocations(profileBranches[0], identity, certificates, revocations)
  for (const branch of profileBranches.slice(1)) {
    profileState = await mergeIdentityProfileState(profileState,
      await readIdentityProfileStateWithRevocations(branch, identity, certificates, revocations), identity, certificates)
  }

  if (canonicalizeJson(document.certificates) === canonicalizeJson(certificates) &&
      canonicalizeJson(document.revocations ?? []) === canonicalizeJson(revocations) && version === 2 &&
      canonicalizeJson(document.profileState) === canonicalizeJson(profileState)) {
    await validatePersonalIdentityDocument(document, identity)
    return document
  }

  const writable = Automerge.clone(document)
  const normalized = Automerge.change(writable, "Merge concurrent Identity history", draft => {
    draft.version = 2
    draft.certificates = certificates
    draft.revocations = revocations
    draft.profileState = profileState
  })
  await validatePersonalIdentityDocument(normalized, identity)
  return normalized
}

function fieldBranches<K extends keyof PersonalIdentityDocument>(document: Automerge.Doc<PersonalIdentityDocument>,
  field: K): unknown[] {
  const conflicts = Automerge.getConflicts(document, field)
  return [document[field], ...Object.values(conflicts ?? {})]
}

function requireSingleFieldValue<K extends "kind" | "version" | "personId" | "identityPublicKey">(
  document: Automerge.Doc<PersonalIdentityDocument>, field: K): PersonalIdentityDocument[K] {
  const values = fieldBranches(document, field)
  const encoded = values.map(value => canonicalizeJson(value))
  if (encoded.some(value => value !== encoded[0])) {
    throw new Error(`Identity mesh ${field} conflict is invalid`)
  }
  return values[0] as PersonalIdentityDocument[K]
}

function includeProfileOperationCertificates(certificates: readonly DeviceCertificate[], profileStates: readonly unknown[]): DeviceCertificate[] {
  const byDevice = new Map<string, DeviceCertificate>()
  const add = (certificate: unknown) => {
    const deviceId = (certificate as DeviceCertificate | undefined)?.payload?.deviceId
    if (typeof deviceId !== "string") throw new Error("Identity profile operation certificate is invalid")
    const value = certificate as DeviceCertificate
    const previous = byDevice.get(deviceId)
    if (previous && canonicalizeJson(previous) !== canonicalizeJson(value)) {
      throw new Error("Identity profile operation certificate conflicts with device history")
    }
    byDevice.set(deviceId, structuredClone(value))
  }
  for (const certificate of certificates) add(certificate)
  for (const state of profileStates) {
    if (!state || typeof state !== "object" || !Array.isArray((state as { operations?: unknown }).operations)) continue
    const operations = (state as { operations: unknown[] }).operations
    if (operations.length > 512) throw new Error("Identity profile history exceeds the size limit")
    for (const operation of operations) {
      if (!operation || typeof operation !== "object") continue
      const chain = (operation as { certificates?: unknown }).certificates
      if (chain === undefined) continue
      if (!Array.isArray(chain) || chain.length > 32) throw new Error("Identity profile operation certificate chain is invalid")
      for (const certificate of chain) add(certificate)
    }
  }
  return [...byDevice.values()]
}
