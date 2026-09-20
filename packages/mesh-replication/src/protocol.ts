import {
  canonicalizeJson,
  signEnvelope,
  verifyEnvelope,
  sha256Base64Url,
  type LocalProfile,
  type SignedEnvelope,
} from "@meta-uber/mesh-identity"
import { meshRustRuntime, type RustDeviceRouteCatalog } from "./runtime"

export type ReplicaId = string

export type DeviceRoutePayload = {
  kind: "mesh-device-route"
  version: 1
  scopeId: string
  personId: string
  deviceId: ReplicaId
  instanceId: string
  endpoint: string
  sequence: number
  issuedAt: string
  expiresAt: string
}

export type SignedDeviceRoute = SignedEnvelope<DeviceRoutePayload>

export type DeviceRoute = DeviceRoutePayload & {
  signerKeyId: string
  signature: string
  legacyEvidence?: unknown
}

export const MAX_DEVICE_ROUTE_BYTES = 8 * 1024
export const MAX_DEVICE_ROUTE_STRING = 2 * 1024
export const MAX_DEVICE_ROUTE_LIFETIME_MS = 10 * 60 * 1_000
export const MAX_DEVICE_ROUTE_FUTURE_MS = 5 * 60 * 1_000
export const MESH_ROUTE_SIGNATURE_DOMAIN = "META-MESH-ROUTE/1"

type DeviceRouteInput = Omit<DeviceRoutePayload, "kind" | "version" | "personId" | "deviceId">

export async function createSignedDeviceRoute(profile: LocalProfile, input: DeviceRouteInput): Promise<SignedDeviceRoute> {
  const payload: DeviceRoutePayload = {
    kind: "mesh-device-route",
    version: 1,
    personId: profile.identity.personId,
    deviceId: profile.device.deviceId,
    ...input,
  }
  validateDeviceRoutePayload(payload)
  return signEnvelope(profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId, MESH_ROUTE_SIGNATURE_DOMAIN)
}

export async function verifySignedDeviceRoute(
  envelope: SignedDeviceRoute,
  devicePublicKey: string | CryptoKey,
  options: { now?: number; allowExpired?: boolean } = {},
): Promise<DeviceRoute> {
  if (!envelope || typeof envelope !== "object") throw new Error("Invalid signed device route")
  validateDeviceRoutePayload(envelope.payload)
  if (envelope.signerKeyId !== envelope.payload.deviceId) throw new Error("Device route signer does not match device")
  if (typeof envelope.signature !== "string" || envelope.signature.length === 0 || envelope.signature.length > MAX_DEVICE_ROUTE_STRING) {
    throw new Error("Invalid device route signature")
  }
  const bytes = new TextEncoder().encode(canonicalizeJson(envelope)).byteLength
  if (bytes > MAX_DEVICE_ROUTE_BYTES) throw new Error("Device route exceeds size limit")
  const now = options.now ?? Date.now()
  const issuedAt = Date.parse(envelope.payload.issuedAt)
  const expiresAt = Date.parse(envelope.payload.expiresAt)
  if (issuedAt > now + MAX_DEVICE_ROUTE_FUTURE_MS) throw new Error("Device route issued too far in future")
  if (!options.allowExpired && expiresAt <= now) throw new Error("Device route expired")
  if (!await verifyEnvelope(envelope, devicePublicKey, MESH_ROUTE_SIGNATURE_DOMAIN)) throw new Error("Invalid device route signature")
  return { ...envelope.payload, signerKeyId: envelope.signerKeyId, signature: envelope.signature }
}

type VerifiedWorkspaceAdvertisement = SignedEnvelope<{
  kind: "peer-advertisement"
  version: 1
  workspaceId: string
  personId: string
  deviceId: string
  instanceId?: string
  endpoint: string
  issuedAt: string
  routeSequence?: number
  expiresAt?: string
}>

type VerifiedLegacyContactCard = {
  kind: "twang-contact"
  version: 1
  deviceId: string
  endpoint: string
  signed: SignedEnvelope<{
    kind: "contact-card"
    version: 1
    personId: string
    deviceId: string
    endpoint: string
    createdAt: string
  }>
}

type VerifiedRouteContactCard = {
  kind: "twang-contact"
  version: 2
  identity: { personId: string }
  deviceId: string
  instanceId: string
  endpoint: string
  sequence: number
  issuedAt: string
  expiresAt: string
  signed: SignedDeviceRoute
}

type VerifiedContactCard = VerifiedLegacyContactCard | VerifiedRouteContactCard

async function syntheticInstanceId(endpoint: string): Promise<string> {
  const hash = await sha256Base64Url(new TextEncoder().encode(endpoint))
  return `legacy:${hash.slice(0, 22)}`
}

function boundedLegacyExpiry(issuedAt: string, expiresAt?: string): string {
  const issued = Date.parse(issuedAt)
  if (!Number.isFinite(issued) || new Date(issued).toISOString() !== issuedAt) throw new Error("Invalid legacy route timestamp")
  if (expiresAt !== undefined) return expiresAt
  return new Date(issued + MAX_DEVICE_ROUTE_LIFETIME_MS).toISOString()
}

export async function adaptVerifiedWorkspaceAdvertisement(advertisement: VerifiedWorkspaceAdvertisement): Promise<DeviceRoute> {
  const payload = advertisement?.payload
  if (payload?.kind !== "peer-advertisement" || payload.version !== 1 ||
    advertisement.signerKeyId !== payload.deviceId) throw new Error("Invalid verified workspace advertisement")
  const route: DeviceRoute = {
    kind: "mesh-device-route",
    version: 1,
    scopeId: payload.workspaceId,
    personId: payload.personId,
    deviceId: payload.deviceId,
    instanceId: payload.instanceId ?? await syntheticInstanceId(payload.endpoint),
    endpoint: payload.endpoint,
    sequence: payload.routeSequence ?? 1,
    issuedAt: payload.issuedAt,
    expiresAt: boundedLegacyExpiry(payload.issuedAt, payload.expiresAt),
    signerKeyId: advertisement.signerKeyId,
    signature: advertisement.signature,
    legacyEvidence: advertisement,
  }
  validateDeviceRoute(route)
  return route
}

export async function adaptVerifiedContactCard(scopeId: string, card: VerifiedContactCard): Promise<DeviceRoute> {
  if (card?.kind === "twang-contact" && card.version === 2) {
    const payload = card.signed?.payload
    if (payload?.kind !== "mesh-device-route" || payload.version !== 1 || payload.scopeId !== `twang:contact:${card.identity.personId}` ||
      payload.personId !== card.identity.personId || payload.deviceId !== card.deviceId || payload.instanceId !== card.instanceId ||
      payload.endpoint !== card.endpoint || payload.sequence !== card.sequence || payload.issuedAt !== card.issuedAt ||
      payload.expiresAt !== card.expiresAt || card.signed.signerKeyId !== card.deviceId) throw new Error("Invalid verified contact route card")
    const route: DeviceRoute = { ...payload, scopeId, signerKeyId: card.signed.signerKeyId, signature: card.signed.signature,
      legacyEvidence: card }
    validateDeviceRoute(route)
    return route
  }
  const payload = card?.signed?.payload
  if (card?.kind !== "twang-contact" || card.version !== 1 || payload?.kind !== "contact-card" || payload.version !== 1 ||
    card.deviceId !== payload.deviceId || card.endpoint !== payload.endpoint || card.signed.signerKeyId !== card.deviceId) {
    throw new Error("Invalid verified contact card")
  }
  const route: DeviceRoute = {
    kind: "mesh-device-route",
    version: 1,
    scopeId,
    personId: payload.personId,
    deviceId: payload.deviceId,
    instanceId: await syntheticInstanceId(payload.endpoint),
    endpoint: payload.endpoint,
    sequence: 1,
    issuedAt: payload.createdAt,
    expiresAt: boundedLegacyExpiry(payload.createdAt),
    signerKeyId: card.signed.signerKeyId,
    signature: card.signed.signature,
    legacyEvidence: card,
  }
  validateDeviceRoute(route)
  return route
}

export type DeviceChange = {
  hash: string
  bytes: Uint8Array
}

export type DeviceBatch = {
  protocolVersion: 1
  scopeId: string
  documentId: string
  batchId: string
  changes: DeviceChange[]
}

export type DurableBatchAckPayload = {
  kind: "mesh-durable-batch-ack"
  version: 1
  scopeId: string
  documentId: string
  batchId: string
  receiverDeviceId: ReplicaId
  acceptedHashes: string[]
  acceptedHeads: string[]
  committedAt: string
}

export type SignedDurableBatchAck = SignedEnvelope<DurableBatchAckPayload>

export type DurableBatchAck = DurableBatchAckPayload & {
  signerKeyId: string
  signature: string
}

export const MESH_REPLICATION_SIGNATURE_DOMAIN = "META-MESH-REPLICATION/1"
export const MAX_ACK_HASHES = 256
export const MAX_ACK_HEADS = 64
export const MAX_DURABLE_ACK_BYTES = 64 * 1024

type DurableAckInput = Omit<DurableBatchAckPayload, "kind" | "version" | "receiverDeviceId">

export async function createSignedDurableBatchAck(profile: LocalProfile, input: DurableAckInput): Promise<SignedDurableBatchAck> {
  const payload: DurableBatchAckPayload = {
    kind: "mesh-durable-batch-ack",
    version: 1,
    receiverDeviceId: profile.device.deviceId,
    ...input,
  }
  validateDurableAckPayload(payload)
  return signEnvelope(profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId, MESH_REPLICATION_SIGNATURE_DOMAIN)
}

export async function verifySignedDurableBatchAck(
  envelope: SignedDurableBatchAck,
  devicePublicKey: string | CryptoKey,
): Promise<DurableBatchAck> {
  validateDurableAckPayload(envelope?.payload)
  if (envelope.signerKeyId !== envelope.payload.receiverDeviceId) throw new Error("Durable acknowledgement signer mismatch")
  if (!envelope.signature || new TextEncoder().encode(canonicalizeJson(envelope)).byteLength > MAX_DURABLE_ACK_BYTES) {
    throw new Error("Invalid durable acknowledgement envelope")
  }
  if (!await verifyEnvelope(envelope, devicePublicKey, MESH_REPLICATION_SIGNATURE_DOMAIN)) {
    throw new Error("Invalid durable acknowledgement signature")
  }
  return { ...envelope.payload, signerKeyId: envelope.signerKeyId, signature: envelope.signature }
}

export function validateDurableAckPayload(payload: DurableBatchAckPayload): void {
  if (payload?.kind !== "mesh-durable-batch-ack" || payload.version !== 1) throw new Error("Unsupported durable acknowledgement")
  for (const value of [payload.scopeId, payload.documentId, payload.batchId, payload.receiverDeviceId]) required(value, "durable acknowledgement field")
  if (!Array.isArray(payload.acceptedHashes) || payload.acceptedHashes.length > MAX_ACK_HASHES ||
    payload.acceptedHashes.some(hash => typeof hash !== "string" || !hash || hash.length > MAX_DEVICE_ROUTE_STRING)) {
    throw new Error("Invalid durable acknowledgement hashes")
  }
  if (!Array.isArray(payload.acceptedHeads) || payload.acceptedHeads.length > MAX_ACK_HEADS ||
    payload.acceptedHeads.some(head => typeof head !== "string" || !head || head.length > MAX_DEVICE_ROUTE_STRING)) {
    throw new Error("Invalid durable acknowledgement heads")
  }
  const committedAt = Date.parse(payload.committedAt)
  if (!Number.isFinite(committedAt) || new Date(committedAt).toISOString() !== payload.committedAt) {
    throw new Error("Invalid durable acknowledgement commit time")
  }
}

export type RouteBatchSender = (
  route: DeviceRoute,
  batch: DeviceBatch,
  signal: AbortSignal,
) => Promise<DurableBatchAck>

type DeliveryOptions = {
  targetDeviceId: ReplicaId
  routes: readonly DeviceRoute[]
  batch: DeviceBatch
  send: RouteBatchSender
  verifyAck: (ack: DurableBatchAck) => boolean | Promise<boolean>
  fallbackDelayMs?: number
  retryDelaysMs?: readonly number[]
  routeHealth?: (route: DeviceRoute) => number
  trace?: MeshReplicationTrace
  signal?: AbortSignal
}

export type MeshReplicationTrace = (
  event: string,
  fields: Readonly<Record<string, string | number | boolean>>,
) => void

export type DeviceDeliveryResult = {
  route: DeviceRoute
  ack: DurableBatchAck
  attemptedRouteIds: string[]
}

export type DeviceRouteConnection<T> = {
  route: DeviceRoute
  value: T
  attemptedRouteIds: string[]
}

export async function connectToDevice<T>(options: {
  targetDeviceId: ReplicaId
  routes: readonly DeviceRoute[]
  connect: (route: DeviceRoute, signal: AbortSignal) => Promise<T>
  accept?: (value: T, route: DeviceRoute) => boolean | Promise<boolean>
  fallbackDelayMs?: number
  routeHealth?: (route: DeviceRoute) => number
  trace?: MeshReplicationTrace
  signal?: AbortSignal
}): Promise<DeviceRouteConnection<T>> {
  const routes = meshRustRuntime().state.orderDeliveryRoutes(
    options.targetDeviceId,
    options.routes.map(route => ({ route, health: options.routeHealth?.(route) ?? 0 })),
  ) as DeviceRoute[]
  const fallbackDelayMs = options.fallbackDelayMs ?? 250
  if (!Number.isFinite(fallbackDelayMs) || fallbackDelayMs < 0) throw new Error("Invalid fallback delay")
  if (options.signal?.aborted) throw options.signal.reason ?? new Error("Connection aborted")

  return new Promise<DeviceRouteConnection<T>>((resolve, reject) => {
    const controllers = routes.map(() => new AbortController())
    const attemptedRouteIds: string[] = []
    const failures: unknown[] = []
    let next = 0
    let pending = 0
    let settled = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const finishFailure = () => {
      if (!settled && next >= routes.length && pending === 0) {
        settled = true
        reject(new AggregateError(failures, `All routes failed for device ${options.targetDeviceId}`))
      }
    }
    const launch = () => {
      if (settled || next >= routes.length) return finishFailure()
      const index = next++
      const route = routes[index]!
      attemptedRouteIds.push(route.instanceId)
      options.trace?.("route.attempt", { targetDeviceId: options.targetDeviceId, instanceId: route.instanceId, endpoint: route.endpoint })
      pending += 1
      void options.connect(route, controllers[index]!.signal).then(async value => {
        if (options.accept && !await options.accept(value, route)) throw new Error(`Rejected connection from ${route.instanceId}`)
        if (settled) return
        settled = true
        if (timer) clearTimeout(timer)
        controllers.forEach((controller, candidate) => {
          if (candidate !== index) controller.abort(new Error("Another route connected"))
        })
        options.trace?.("route.selected", { targetDeviceId: options.targetDeviceId, instanceId: route.instanceId, endpoint: route.endpoint })
        resolve({ route, value, attemptedRouteIds: [...attemptedRouteIds] })
      }).catch(error => {
        failures.push(error)
        options.trace?.("route.failed", { targetDeviceId: options.targetDeviceId, instanceId: route.instanceId, error: error instanceof Error ? error.message : String(error) })
        if (!settled && next < routes.length) launch()
      }).finally(() => { pending -= 1; finishFailure() })
      if (next < routes.length && !timer) timer = setTimeout(() => { timer = undefined; launch() }, fallbackDelayMs)
    }
    options.signal?.addEventListener("abort", () => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      controllers.forEach(controller => controller.abort(options.signal?.reason))
      reject(options.signal?.reason ?? new Error("Connection aborted"))
    }, { once: true })
    launch()
  })
}

function required(value: string, label: string): void {
  if (value.length === 0) throw new Error(`Invalid ${label}`)
}

export class DeviceRouteCatalog {
  private readonly catalog: RustDeviceRouteCatalog

  constructor() {
    this.catalog = meshRustRuntime().createDeviceRouteCatalog()
  }

  admit(route: DeviceRoute): DeviceRoute {
    return this.catalog.admit(route) as DeviceRoute
  }

  routesFor(scopeId: string, deviceId: ReplicaId): DeviceRoute[] {
    return this.catalog.routesFor(scopeId, deviceId) as DeviceRoute[]
  }
}

export function validateDeviceRoute(route: DeviceRoute): void {
  meshRustRuntime().state.validateDeviceRoute(route)
}

export function validateDeviceRoutePayload(route: DeviceRoutePayload): void {
  if (route.kind !== "mesh-device-route" || route.version !== 1) throw new Error("Unsupported device route version")
  required(route.scopeId, "route scope")
  required(route.personId, "route person")
  required(route.deviceId, "route device")
  required(route.instanceId, "route instance")
  required(route.endpoint, "route endpoint")
  for (const value of [route.scopeId, route.personId, route.deviceId, route.instanceId, route.endpoint]) {
    if (value.length > MAX_DEVICE_ROUTE_STRING) throw new Error("Device route field exceeds size limit")
  }
  if (!Number.isSafeInteger(route.sequence) || route.sequence < 1) throw new Error("Invalid route sequence")
  const issuedAt = Date.parse(route.issuedAt)
  const expiresAt = Date.parse(route.expiresAt)
  if (!Number.isFinite(issuedAt) || new Date(issuedAt).toISOString() !== route.issuedAt ||
    !Number.isFinite(expiresAt) || new Date(expiresAt).toISOString() !== route.expiresAt ||
    expiresAt <= issuedAt || expiresAt - issuedAt > MAX_DEVICE_ROUTE_LIFETIME_MS) {
    throw new Error("Invalid route lifetime")
  }
}

function ackMatches(ack: DurableBatchAck, batch: DeviceBatch, targetDeviceId: ReplicaId): boolean {
  return meshRustRuntime().state.durableAckMatches(ack, batch, targetDeviceId)
}

async function deliverBatchRound(options: DeliveryOptions): Promise<DeviceDeliveryResult> {
  const routes = options.routes
  if (routes.length === 0) throw new Error(`No routes for device ${options.targetDeviceId}`)
  const delay = options.fallbackDelayMs ?? 250
  if (!Number.isFinite(delay) || delay < 0) throw new Error("Invalid fallback delay")
  if (options.signal?.aborted) throw options.signal.reason ?? new Error("Delivery aborted")

  return new Promise<DeviceDeliveryResult>((resolve, reject) => {
    const controllers = routes.map(() => new AbortController())
    const attemptedRouteIds: string[] = []
    const failures: unknown[] = []
    let nextIndex = 0
    let pending = 0
    let settled = false
    let fallbackTimer: ReturnType<typeof setTimeout> | undefined

    const finishFailure = (): void => {
      if (!settled && nextIndex >= routes.length && pending === 0) {
        settled = true
        reject(new AggregateError(failures, `All routes failed for device ${options.targetDeviceId}`))
      }
    }

    const launch = (): void => {
      if (settled || nextIndex >= routes.length) {
        finishFailure()
        return
      }
      const index = nextIndex++
      const route = routes[index]
      attemptedRouteIds.push(route.instanceId)
      options.trace?.("delivery.route.attempt", { targetDeviceId: options.targetDeviceId, instanceId: route.instanceId, batchId: options.batch.batchId })
      pending += 1
      void options.send(route, options.batch, controllers[index].signal).then(async ack => {
        if (!ackMatches(ack, options.batch, options.targetDeviceId) || !await options.verifyAck(ack)) {
          throw new Error(`Invalid durable acknowledgement from ${route.instanceId}`)
        }
        if (settled) return
        settled = true
        if (fallbackTimer) clearTimeout(fallbackTimer)
        controllers.forEach((controller, routeIndex) => {
          if (routeIndex !== index) controller.abort(new Error("Another route acknowledged"))
        })
        options.trace?.("delivery.ack.durable", { targetDeviceId: options.targetDeviceId, instanceId: route.instanceId, batchId: options.batch.batchId, acceptedChanges: ack.acceptedHashes.length })
        resolve({ route, ack, attemptedRouteIds: [...attemptedRouteIds] })
      }).catch(error => {
        failures.push(error)
        options.trace?.("delivery.route.failed", { targetDeviceId: options.targetDeviceId, instanceId: route.instanceId, batchId: options.batch.batchId, error: error instanceof Error ? error.message : String(error) })
        if (!settled && nextIndex < routes.length) launch()
      }).finally(() => {
        pending -= 1
        finishFailure()
      })

      if (nextIndex < routes.length && !fallbackTimer) {
        fallbackTimer = setTimeout(() => {
          fallbackTimer = undefined
          launch()
        }, delay)
      }
    }

    const abort = (): void => {
      if (settled) return
      settled = true
      if (fallbackTimer) clearTimeout(fallbackTimer)
      controllers.forEach(controller => controller.abort(options.signal?.reason))
      reject(options.signal?.reason ?? new Error("Delivery aborted"))
    }
    options.signal?.addEventListener("abort", abort, { once: true })
    launch()
  })
}

function waitForRetry(milliseconds: number, signal?: AbortSignal): Promise<void> {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return Promise.reject(new Error("Invalid retry delay"))
  if (signal?.aborted) return Promise.reject(signal.reason ?? new Error("Delivery aborted"))
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds)
    signal?.addEventListener("abort", () => {
      clearTimeout(timer)
      reject(signal.reason ?? new Error("Delivery aborted"))
    }, { once: true })
  })
}

export async function deliverBatchToDevice(options: DeliveryOptions): Promise<DeviceDeliveryResult> {
  const routes = meshRustRuntime().state.orderDeliveryRoutes(
    options.targetDeviceId,
    options.routes.map(route => ({ route, health: options.routeHealth?.(route) ?? 0 })),
  ) as DeviceRoute[]
  const retryDelays = options.retryDelaysMs ?? []
  const attemptedRouteIds: string[] = []
  const failures: unknown[] = []

  for (let round = 0; round <= retryDelays.length; round += 1) {
    try {
      const result = await deliverBatchRound({ ...options, routes, retryDelaysMs: [] })
      return { ...result, attemptedRouteIds: [...attemptedRouteIds, ...result.attemptedRouteIds] }
    } catch (error) {
      if (options.signal?.aborted) throw options.signal.reason ?? error
      failures.push(error)
      if (round === retryDelays.length) break
      attemptedRouteIds.push(...routes.map(route => route.instanceId))
      await waitForRetry(retryDelays[round], options.signal)
    }
  }
  throw new AggregateError(failures, `Delivery retries exhausted for device ${options.targetDeviceId}`)
}
