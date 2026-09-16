import { expect } from "vitest"
import { SparseGossip, type GossipCandidate, type GossipFrame } from "../gossip"
import type { ItfState, ItfTrace } from "./itf"

export class SparseGossipMbtDriver {
  readonly devices: string[]
  readonly stores = new Map<string, Set<string>>()
  readonly engines = new Map<string, SparseGossip>()
  private now = 0

  constructor(devices = ["d1", "d2", "d3"], initialChanges = new Map([["d1", ["c1"]]])) {
    this.devices = devices
    for (const d of devices) {
      const store = new Set<string>(initialChanges.get(d) ?? [])
      this.stores.set(d, store)

      const engine = new SparseGossip(d, {
        now: () => this.now,
        authorize: async () => true,
        hasChange: async (_scope, _doc, hash) => store.has(hash),
        loadChange: async (_scope, _doc, hash) =>
          store.has(hash) ? { hash, bytes: new TextEncoder().encode(hash) } : undefined,
        admitChanges: async (_scope, _doc, changes) => {
          const accepted: string[] = []
          for (const change of changes) {
            if (!store.has(change.hash)) {
              store.add(change.hash)
              accepted.push(change.hash)
            }
          }
          return accepted
        },
      })
      this.engines.set(d, engine)
    }

    // Initialize neighbor topology
    for (const d of devices) {
      const candidates: GossipCandidate[] = devices
        .filter(other => other !== d)
        .map(other => ({ deviceId: other, health: 1 }))
      this.engines.get(d)!.updateScope("scope-1", candidates)
    }
  }

  inferAction(prevState: ItfState, currState: ItfState): {
    action: string
    d?: string
    h?: string
    msg?: { fromDevice: string; toDevice: string; hash: string }
  } {
    if (currState.actionTaken) {
      const nondet = currState.nondetPicks ?? {}
      const d = (nondet.d as string | undefined) ?? (nondet.fromDevice as string | undefined)
      const h = (nondet.h as string | undefined) ?? (nondet.hash as string | undefined)
      const msg = nondet.msg as { fromDevice: string; toDevice: string; hash: string } | undefined
      return { action: currState.actionTaken, d, h, msg }
    }

    const prevFailed = (prevState.vars.failed as Set<string>) ?? new Set()
    const currFailed = (currState.vars.failed as Set<string>) ?? new Set()
    for (const d of currFailed) if (!prevFailed.has(d)) return { action: "markFailed", d }
    for (const d of prevFailed) if (!currFailed.has(d)) return { action: "recoverDevice", d }

    const prevChanges = Array.from((prevState.vars.inFlightChanges as Set<unknown>) ?? [])
    const currChanges = (currState.vars.inFlightChanges as Set<unknown>) ?? new Set()
    for (const rawMsg of prevChanges) {
      const msg = rawMsg as { fromDevice: string; toDevice: string; hash: string }
      const stillPresent = Array.from(currChanges).some(
        c => (c as typeof msg).fromDevice === msg.fromDevice && (c as typeof msg).toDevice === msg.toDevice && (c as typeof msg).hash === msg.hash,
      )
      if (!stillPresent) return { action: "handleChanges", msg }
    }

    const prevWants = Array.from((prevState.vars.inFlightWants as Set<unknown>) ?? [])
    const currWants = (currState.vars.inFlightWants as Set<unknown>) ?? new Set()
    for (const rawMsg of prevWants) {
      const msg = rawMsg as { fromDevice: string; toDevice: string; hash: string }
      const stillPresent = Array.from(currWants).some(
        w => (w as typeof msg).fromDevice === msg.fromDevice && (w as typeof msg).toDevice === msg.toDevice && (w as typeof msg).hash === msg.hash,
      )
      if (!stillPresent) return { action: "handleWant", msg }
    }

    const prevOffers = Array.from((prevState.vars.inFlightOffers as Set<unknown>) ?? [])
    const currOffers = (currState.vars.inFlightOffers as Set<unknown>) ?? new Set()
    for (const rawMsg of prevOffers) {
      const msg = rawMsg as { fromDevice: string; toDevice: string; hash: string }
      const stillPresent = Array.from(currOffers).some(
        o => (o as typeof msg).fromDevice === msg.fromDevice && (o as typeof msg).toDevice === msg.toDevice && (o as typeof msg).hash === msg.hash,
      )
      if (!stillPresent) return { action: "handleOffer", msg }
    }

    // New offers published
    for (const rawMsg of Array.from(currOffers)) {
      const msg = rawMsg as { fromDevice: string; toDevice: string; hash: string }
      const wasPresent = prevOffers.some(
        o => (o as typeof msg).fromDevice === msg.fromDevice && (o as typeof msg).toDevice === msg.toDevice && (o as typeof msg).hash === msg.hash,
      )
      if (!wasPresent) return { action: "publishOffer", d: msg.fromDevice, h: msg.hash }
    }

    return { action: "stutter" }
  }

  async step(currState: ItfState, prevState?: ItfState): Promise<void> {
    const { action, d, h, msg } = prevState
      ? this.inferAction(prevState, currState)
      : { action: "init" }

    if (action === "init" || action === "stutter") {
      this.assertStateMatches(currState)
      return
    }

    if (action === "publishOffer" && d && h) {
      await this.engines.get(d)!.publish("scope-1", "doc-1", [h])
    } else if (action === "handleOffer" && msg) {
      const frame: GossipFrame = {
        version: 1,
        kind: "offer",
        scopeId: "scope-1",
        documentId: "doc-1",
        hashes: [msg.hash],
      }
      await this.engines.get(msg.toDevice)!.receive(msg.fromDevice, frame)
    } else if (action === "handleWant" && msg) {
      const frame: GossipFrame = {
        version: 1,
        kind: "want",
        scopeId: "scope-1",
        documentId: "doc-1",
        hashes: [msg.hash],
      }
      await this.engines.get(msg.toDevice)!.receive(msg.fromDevice, frame)
    } else if (action === "handleChanges" && msg) {
      const frame: GossipFrame = {
        version: 1,
        kind: "changes",
        scopeId: "scope-1",
        documentId: "doc-1",
        changes: [{ hash: msg.hash, bytes: new TextEncoder().encode(msg.hash) }],
      }
      await this.engines.get(msg.toDevice)!.receive(msg.fromDevice, frame)
    } else if (action === "markFailed" && d) {
      for (const [peerId, engine] of this.engines) {
        if (peerId !== d) {
          engine.markFailure("scope-1", d)
        }
      }
    } else if (action === "recoverDevice" && d) {
      this.now += 61_000 // Advance past backoff window
      for (const [peerId, engine] of this.engines) {
        if (peerId !== d) {
          const candidates: GossipCandidate[] = this.devices
            .filter(other => other !== peerId)
            .map(other => ({ deviceId: other, health: 1 }))
          engine.updateScope("scope-1", candidates)
        }
      }
    }

    this.assertStateMatches(currState)
  }

  assertStateMatches(state: ItfState): void {
    const rawStore = state.vars.store
    if (rawStore) {
      const storeMap = rawStore instanceof Map
        ? rawStore
        : new Map(Object.entries(rawStore as Record<string, unknown>))

      for (const d of this.devices) {
        const expected = storeMap.get(d) as Set<string> | undefined
        if (expected !== undefined) {
          expect(this.stores.get(d)).toEqual(expected)
        }
      }
    }
  }

  async replay(trace: ItfTrace): Promise<void> {
    for (let i = 0; i < trace.states.length; i++) {
      await this.step(trace.states[i], trace.states[i - 1])
    }
  }
}
