import { expect } from "vitest"
import { deliverBatchToDevice, type DeviceBatch, type DeviceDeliveryResult, type DeviceRoute, type DurableBatchAck, type RouteBatchSender } from "../protocol"
import { deviceBatch, deviceRoute, durableAck, MemoryDurableBatchStore } from "../testing"
import type { ItfState, ItfTrace } from "./itf"

type InFlight = {
  route: DeviceRoute
  batch: DeviceBatch
  signal: AbortSignal
  resolve: (ack: DurableBatchAck) => void
  reject: (err: unknown) => void
}

export class DurableDeliveryMbtDriver {
  readonly store = new MemoryDurableBatchStore()
  readonly targetDeviceId = "device-remote"
  readonly routes: DeviceRoute[]
  readonly batch: DeviceBatch
  readonly inFlight = new Map<string, InFlight>()
  readonly launchedRoutes = new Set<string>()
  readonly abortedRoutes = new Set<string>()

  deliveryPromise?: Promise<DeviceDeliveryResult>
  deliveryResult?: DeviceDeliveryResult
  deliveryError?: unknown

  constructor(routeIds = ["route-a", "route-b", "route-c"], hashes = ["change-1", "change-2"]) {
    this.routes = routeIds.map(id => deviceRoute(id))
    this.batch = deviceBatch("batch-1", hashes)
  }

  private send: RouteBatchSender = (route, batch, signal) => {
    this.launchedRoutes.add(route.instanceId)
    signal.addEventListener("abort", () => {
      this.abortedRoutes.add(route.instanceId)
    })

    return new Promise<DurableBatchAck>((resolve, reject) => {
      this.inFlight.set(route.instanceId, {
        route,
        batch,
        signal,
        resolve,
        reject,
      })
    })
  }

  start(fallbackDelayMs = 20, retryDelaysMs: readonly number[] = [20, 20]): void {
    this.deliveryPromise = deliverBatchToDevice({
      targetDeviceId: this.targetDeviceId,
      routes: this.routes,
      batch: this.batch,
      send: this.send,
      verifyAck: async () => true,
      fallbackDelayMs,
      retryDelaysMs,
    }).then(
      result => {
        this.deliveryResult = result
        return result
      },
      error => {
        this.deliveryError = error
        throw error
      },
    )
  }

  async waitForRouteLaunch(instanceId: string, timeoutMs = 1000): Promise<InFlight> {
    const start = Date.now()
    while (!this.inFlight.has(instanceId)) {
      if (Date.now() - start > timeoutMs) {
        throw new Error(`Timed out waiting for route ${instanceId} to launch`)
      }
      await new Promise(resolve => setTimeout(resolve, 5))
    }
    return this.inFlight.get(instanceId)!
  }

  inferAction(prevState: ItfState, currState: ItfState): { action: string; r?: string } {
    if (currState.actionTaken) {
      const nondet = currState.nondetPicks ?? {}
      const r = (nondet.r as string | undefined) ?? (nondet.route as string | undefined)
      return { action: currState.actionTaken, r }
    }

    const prevActive = (prevState.vars.activeRoutes as Set<string>) ?? new Set()
    const currActive = (currState.vars.activeRoutes as Set<string>) ?? new Set()
    const prevStore = (prevState.vars.targetStore as Set<string>) ?? new Set()
    const currStore = (currState.vars.targetStore as Set<string>) ?? new Set()
    const prevPhase = prevState.vars.phase as string
    const currPhase = currState.vars.phase as string
    const prevRound = (prevState.vars.currentRound as number) ?? 0
    const currRound = (currState.vars.currentRound as number) ?? 0

    if (currPhase === "DELIVERED" && prevPhase !== "DELIVERED") {
      return { action: "routeCommitAndAck", r: currState.vars.winningRoute as string }
    }
    if (currPhase === "FAILED" && prevPhase !== "FAILED") {
      return { action: "exhaustRetries" }
    }
    if (currRound > prevRound) {
      return { action: "retryRound" }
    }

    for (const r of currActive) {
      if (!prevActive.has(r)) {
        return { action: "launchRoute", r }
      }
    }

    for (const r of prevActive) {
      if (!currActive.has(r)) {
        if (currStore.size > prevStore.size) {
          return { action: "routeCommitAndLoseAck", r }
        } else {
          return { action: "routeFailBeforeCommit", r }
        }
      }
    }

    return { action: "stutter" }
  }

  async step(currState: ItfState, prevState?: ItfState): Promise<void> {
    const { action, r } = prevState ? this.inferAction(prevState, currState) : { action: "init" }

    if (action === "init" || action === "stutter") {
      this.assertStateMatches(currState)
      return
    }

    if (action === "launchRoute" && r) {
      await this.waitForRouteLaunch(r)
    } else if (action === "routeCommitAndAck" && r) {
      const flight = await this.waitForRouteLaunch(r)
      const admission = await this.store.admit(this.batch)
      flight.resolve(durableAck(this.batch, this.targetDeviceId, admission.acceptedHashes))
      await new Promise(resolve => setTimeout(resolve, 10))
    } else if (action === "routeCommitAndLoseAck" && r) {
      const flight = await this.waitForRouteLaunch(r)
      await this.store.admit(this.batch)
      flight.reject(new Error(`Route ${r} lost ACK`))
      await new Promise(resolve => setTimeout(resolve, 10))
    } else if (action === "routeFailBeforeCommit" && r) {
      const flight = await this.waitForRouteLaunch(r)
      flight.reject(new Error(`Route ${r} failed before commit`))
      await new Promise(resolve => setTimeout(resolve, 10))
    } else if (action === "retryRound") {
      await new Promise(resolve => setTimeout(resolve, 30))
    } else if (action === "exhaustRetries") {
      try {
        await this.deliveryPromise
      } catch {
        // expected failure
      }
    }

    this.assertStateMatches(currState)
  }

  assertStateMatches(state: ItfState): void {
    const expectedStore = state.vars.targetStore as Set<string> | undefined
    if (expectedStore !== undefined) {
      expect(new Set(this.store.hashes())).toEqual(expectedStore)
    }

    const expectedAdmissions = state.vars.targetAdmissions as number | undefined
    if (expectedAdmissions !== undefined) {
      expect(this.store.admissions.length).toBe(expectedAdmissions)
    }

    const phase = state.vars.phase as string | undefined
    if (phase === "DELIVERED") {
      expect(this.deliveryResult).toBeDefined()
      const winningRoute = state.vars.winningRoute as string
      expect(this.deliveryResult?.route.instanceId).toBe(winningRoute)

      const expectedHashes = state.vars.lastAckAcceptedHashes as Set<string> | undefined
      if (expectedHashes !== undefined) {
        expect(new Set(this.deliveryResult?.ack.acceptedHashes)).toEqual(expectedHashes)
      }
    } else if (phase === "FAILED") {
      expect(this.deliveryError).toBeDefined()
    }
  }

  async replay(trace: ItfTrace): Promise<void> {
    this.start()
    for (let i = 0; i < trace.states.length; i++) {
      await this.step(trace.states[i], trace.states[i - 1])
    }
  }
}
