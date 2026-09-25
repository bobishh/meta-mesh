import {
  signEnvelope,
  sha256Base64Url,
  toBase64Url,
  type LocalProfile,
  type SignedEnvelope,
} from "@meta-uber/mesh-identity"
import { meshRustRuntime, type RustBatchDeliveryAction, type RustBatchDeliveryFlow, type RustDeviceRouteCatalog } from "./runtime"

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
  return meshRustRuntime().state.verifyDeviceRoute(
    envelope,
    await rustPublicKey(devicePublicKey),
    options.now ?? Date.now(),
    options.allowExpired ?? false,
  ) as DeviceRoute
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

type VerifiedLocatorContactCard = {
  kind: "twang-contact"
  version: 3
  identity: { personId: string }
  deviceId: string
  rendezvousEndpoint: string
  publishedAt: string
  signed: SignedEnvelope<{
    kind: "contact-locator"
    version: 1
    personId: string
    deviceId: string
    rendezvousEndpoint: string
    publishedAt: string
  }>
}

type VerifiedContactCard = VerifiedLegacyContactCard | VerifiedRouteContactCard | VerifiedLocatorContactCard

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
  if (card?.kind === "twang-contact" && card.version === 3) {
    const payload = card.signed?.payload
    if (payload?.kind !== "contact-locator" || payload.version !== 1 || payload.personId !== card.identity.personId ||
      payload.deviceId !== card.deviceId || payload.rendezvousEndpoint !== card.rendezvousEndpoint ||
      payload.publishedAt !== card.publishedAt || card.signed.signerKeyId !== card.deviceId) {
      throw new Error("Invalid verified contact locator card")
    }
    const route: DeviceRoute = {
      kind: "mesh-device-route",
      version: 1,
      scopeId,
      personId: payload.personId,
      deviceId: payload.deviceId,
      instanceId: await syntheticInstanceId(payload.rendezvousEndpoint),
      endpoint: payload.rendezvousEndpoint,
      sequence: 1,
      issuedAt: payload.publishedAt,
      expiresAt: boundedLegacyExpiry(payload.publishedAt),
      signerKeyId: card.signed.signerKeyId,
      signature: card.signed.signature,
      legacyEvidence: card,
    }
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
  return meshRustRuntime().state.verifyDurableAck(
    envelope, await rustPublicKey(devicePublicKey),
  ) as DurableBatchAck
}

export function validateDurableAckPayload(payload: DurableBatchAckPayload): void {
  meshRustRuntime().state.validateDurableAckPayload(payload)
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
  return runBatchDeliveryFlow({
    targetDeviceId: options.targetDeviceId,
    routes: options.routes,
    fallbackDelayMs: options.fallbackDelayMs,
    routeHealth: options.routeHealth,
    signal: options.signal,
    abortMessage: "Connection aborted",
    exhaustedMessage: `All routes failed for device ${options.targetDeviceId}`,
    execute: async (route, signal) => {
      const value = await options.connect(route, signal)
      if (options.accept && !await options.accept(value, route)) throw new Error(`Rejected connection from ${route.instanceId}`)
      return value
    },
    onAttempt: route => options.trace?.("route.attempt", { targetDeviceId: options.targetDeviceId,
      instanceId: route.instanceId, endpoint: route.endpoint }),
    onFailure: (route, error) => options.trace?.("route.failed", { targetDeviceId: options.targetDeviceId,
      instanceId: route.instanceId, error: error instanceof Error ? error.message : String(error) }),
    onSelected: route => options.trace?.("route.selected", { targetDeviceId: options.targetDeviceId,
      instanceId: route.instanceId, endpoint: route.endpoint }),
  })
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
  meshRustRuntime().state.validateDeviceRoutePayload(route)
}

async function rustPublicKey(key: string | CryptoKey): Promise<string> {
  if (typeof key === "string") return key
  return toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", key)))
}

function ackMatches(ack: DurableBatchAck, batch: DeviceBatch, targetDeviceId: ReplicaId): boolean {
  return meshRustRuntime().state.durableAckMatches(ack, batch, targetDeviceId)
}

type RouteFlowOptions<T> = {
  targetDeviceId: ReplicaId
  routes: readonly DeviceRoute[]
  fallbackDelayMs?: number
  retryDelaysMs?: readonly number[]
  routeHealth?: (route: DeviceRoute) => number
  signal?: AbortSignal
  abortMessage: string
  exhaustedMessage?: string
  execute: (route: DeviceRoute, signal: AbortSignal) => Promise<T>
  onAttempt?: (route: DeviceRoute) => void
  onFailure?: (route: DeviceRoute, error: unknown) => void
  onSelected?: (route: DeviceRoute) => void
}

async function runBatchDeliveryFlow<T>(options: RouteFlowOptions<T>): Promise<DeviceRouteConnection<T>> {
  const routes = meshRustRuntime().state.orderDeliveryRoutes(
    options.targetDeviceId,
    options.routes.map(route => ({ route, health: options.routeHealth?.(route) ?? 0 })),
  ) as DeviceRoute[]
  const flow: RustBatchDeliveryFlow = meshRustRuntime().createBatchDeliveryFlow(options.targetDeviceId, routes.map(route => route.instanceId),
    options.fallbackDelayMs ?? 250, [...(options.retryDelaysMs ?? [])])
  if (options.signal?.aborted) {
    flow.abort()
    flow.free?.()
    throw options.signal.reason ?? new Error(options.abortMessage)
  }

  return new Promise<DeviceRouteConnection<T>>((resolve, reject) => {
    const controllers = new Map<string, AbortController>()
    const timers = new Map<string, ReturnType<typeof setTimeout>>()
    const values = new Map<string, { route: DeviceRoute; value: T }>()
    const failures: unknown[] = []
    let settled = false
    const token = (round: number, index: number) => `${round}:${index}`
    const clearTimer = (name: string) => {
      const timer = timers.get(name)
      if (timer !== undefined) clearTimeout(timer)
      timers.delete(name)
    }
    const cleanup = () => {
      for (const timer of timers.values()) clearTimeout(timer)
      timers.clear()
      options.signal?.removeEventListener("abort", onAbort)
      flow.free?.()
    }
    const fail = (error: unknown) => {
      if (settled) return
      settled = true
      cleanup()
      controllers.forEach(controller => controller.abort(error))
      reject(error)
    }
    const finish = (action: RustBatchDeliveryAction) => {
      if (settled) return
      settled = true
      cleanup()
      if (action.kind === "completed") {
        const result = values.get(token(action.round, action.routeIndex))
        if (!result) reject(new Error("Missing route result"))
        else {
          try {
            options.onSelected?.(result.route)
            resolve({ ...result, attemptedRouteIds: action.attemptedRouteIds })
          } catch (error) { reject(error) }
        }
      } else if (action.kind === "exhausted") reject(new AggregateError(failures, options.exhaustedMessage ?? action.message))
      else if (action.kind === "aborted") reject(options.signal?.reason ?? new Error(options.abortMessage))
    }
    const dispatch = (update: { actions: RustBatchDeliveryAction[] }): void => {
      try {
        for (const action of update.actions) {
          if (settled) return
          switch (action.kind) {
          case "launchRoute": {
            const route = routes[action.routeIndex]
            if (!route) {
              const error = new Error("Rust delivery selected unknown route")
              failures.push(error)
              settled = true
              cleanup()
              controllers.forEach(controller => controller.abort(error))
              reject(error)
              return
            }
            const id = token(action.round, action.routeIndex)
            const controller = new AbortController()
            controllers.set(id, controller)
            options.onAttempt?.(route)
            void Promise.resolve().then(() => options.execute(route, controller.signal)).then(value => {
              if (settled) return
              values.set(id, { route, value })
              dispatch(flow.routeResult(action.round, action.routeIndex, true, ""))
            }).catch(error => {
              if (settled) return
              failures.push(error)
              try { options.onFailure?.(route, error) } catch (traceError) { failures.push(traceError) }
              dispatch(flow.routeResult(action.round, action.routeIndex, false,
                error instanceof Error ? error.message : String(error)))
            }).finally(() => controllers.delete(id))
            break
          }
          case "armFallback":
          case "armRetry": {
            const name = `${action.kind === "armFallback" ? "fallback" : "retry"}:${action.round}`
            clearTimer(name)
            timers.set(name, setTimeout(() => {
              timers.delete(name)
              dispatch(action.kind === "armFallback" ? flow.fallbackElapsed(action.round) : flow.retryElapsed(action.round))
            }, action.delayMs))
            break
          }
          case "cancelOtherRoutes":
            clearTimer(`fallback:${action.round}`)
            for (const [id, controller] of controllers) {
              if (id !== token(action.round, action.routeIndex)) controller.abort(new Error("Another route succeeded"))
            }
            break
          case "cancelAllRoutes":
            clearTimer(`fallback:${action.round}`)
            clearTimer(`retry:${action.round}`)
            controllers.forEach(controller => controller.abort(options.signal?.reason))
            break
          case "completed":
          case "exhausted":
          case "aborted":
            finish(action)
            break
          }
        }
      } catch (error) { fail(error) }
    }
    const onAbort = () => dispatch(flow.abort())
    options.signal?.addEventListener("abort", onAbort, { once: true })
    if (options.signal?.aborted) onAbort()
    else dispatch(flow.start())
  })
}

export async function deliverBatchToDevice(options: DeliveryOptions): Promise<DeviceDeliveryResult> {
  const result = await runBatchDeliveryFlow({
    targetDeviceId: options.targetDeviceId,
    routes: options.routes,
    fallbackDelayMs: options.fallbackDelayMs,
    retryDelaysMs: options.retryDelaysMs,
    routeHealth: options.routeHealth,
    signal: options.signal,
    abortMessage: "Delivery aborted",
    onAttempt: route => options.trace?.("delivery.route.attempt", { targetDeviceId: options.targetDeviceId,
      instanceId: route.instanceId, batchId: options.batch.batchId }),
    onFailure: (route, error) => options.trace?.("delivery.route.failed", { targetDeviceId: options.targetDeviceId,
      instanceId: route.instanceId, batchId: options.batch.batchId,
      error: error instanceof Error ? error.message : String(error) }),
    execute: async (route, signal) => {
      const ack = await options.send(route, options.batch, signal)
      const verified = ackMatches(ack, options.batch, options.targetDeviceId) && await options.verifyAck(ack)
      if (!verified) throw new Error(`Invalid durable acknowledgement from ${route.instanceId}`)
      options.trace?.("delivery.ack.durable", { targetDeviceId: options.targetDeviceId,
        instanceId: route.instanceId, batchId: options.batch.batchId, acceptedChanges: ack.acceptedHashes.length })
      return ack
    },
  })
  return { route: result.route, ack: result.value, attemptedRouteIds: result.attemptedRouteIds }
}
