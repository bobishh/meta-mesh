import * as Automerge from "@automerge/automerge"
import { createDelegatedCertificate, createIdentityEnrollmentDevice, createDeviceRevocation, createIdentityProfileOperation, createRecoverableIdentity, identityProfileValue,
  openIdentityRecoveryEnvelope, canonicalizeJson, sha256Base64Url, identityProfileRevision, mergeIdentityProfileState,
  readIdentityProfileState, readIdentityProfileStateWithRevocations, verifyIdentityDeviceAuthority,
  authorizeIdentityDevice, certificateHash } from "@meta-uber/mesh-identity"
import { describe, expect, it, vi } from "vitest"
import { createSignedDeviceRoute, verifySignedDeviceRoute } from "./protocol"
import { AutomergeAntiEntropy } from "./automerge"
import { createPersonalIdentityAdapter, createPersonalIdentityDocument, PersonalIdentityMeshSync, type PersonalIdentityDocument,
  type PersonalIdentitySyncConnection, type PersonalIdentitySyncStream } from "./identityMesh"
import { normalizePersonalIdentityDocument } from "./identityMesh"

describe("independent personal Identity mesh", () => {
  it("Given simultaneous incoming profile histories, when both receive commits race, then rebase without losing either signed operation", async () => {
    const recovery = await createRecoverableIdentity("better", "Owner")
    const first = recovery.profile
    const second = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
    const initial = Automerge.from<PersonalIdentityDocument>(createPersonalIdentityDocument(first.identity,
      [first.certificate, second.certificate]))
    const leftOperation = await createIdentityProfileOperation(first, initial.profileState, "name", "Left")
    const rightOperation = await createIdentityProfileOperation(second, initial.profileState, "name", "Right")
    const leftCandidate = Automerge.change(Automerge.clone(initial), doc => { doc.profileState.operations.push(leftOperation) })
    const rightCandidate = Automerge.change(Automerge.clone(initial), doc => { doc.profileState.operations.push(rightOperation) })
    let stored = initial
    let tail = Promise.resolve()
    const commit = async (document: Automerge.Doc<PersonalIdentityDocument>, expectedRevision: string) => {
      let release!: () => void
      const previous = tail
      tail = new Promise<void>(resolve => { release = resolve })
      await previous
      try {
        const current = stored
        if (await identityProfileRevision(current.profileState) !== expectedRevision) {
          throw new Error("Identity profile changed during sync; retry from the latest version.")
        }
        stored = document
      } finally { release() }
    }
    const adapter = createPersonalIdentityAdapter({ identity: first.identity, current: async () => stored, commit })
    const [leftBefore, rightBefore] = [initial, initial]
    await Promise.all([
      adapter.commit({ before: leftBefore, candidate: leftCandidate, changes: Automerge.getChanges(initial, leftCandidate),
        remoteDeviceId: second.device.deviceId }),
      adapter.commit({ before: rightBefore, candidate: rightCandidate, changes: Automerge.getChanges(initial, rightCandidate),
        remoteDeviceId: first.device.deviceId }),
    ])
    expect(stored.profileState.operations).toHaveLength(2)
    const state = await readIdentityProfileState(stored.profileState, first.identity, stored.certificates)
    expect(identityProfileValue(state, "name")).toMatchObject({ status: "conflict", values: ["Left", "Right"] })
  })

  it("Given two authorized devices and no application document, when they sync, then signed profile and certificates converge", async () => {
    const recovery = await createRecoverableIdentity("better", "Owner")
    const first = recovery.profile
    const second = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
    const firstCerts = [first.certificate, second.certificate]
    const document = createPersonalIdentityDocument(first.identity, firstCerts)
    const initial = Automerge.from<PersonalIdentityDocument>(document)
    const operation = await createIdentityProfileOperation(first, document.profileState, "name", "Shared Name")
    const leftDoc = Automerge.change(initial, value => { value.profileState.operations.push(operation) })
    const rightDoc = Automerge.clone(initial)
    let leftStored = leftDoc, rightStored = rightDoc
    const leftAdapter = createPersonalIdentityAdapter({ identity: first.identity, current: async () => leftStored,
      commit: async next => { leftStored = next } })
    const rightAdapter = createPersonalIdentityAdapter({ identity: first.identity, current: async () => rightStored,
      commit: async next => { rightStored = next } })
    const leftEngine = new AutomergeAntiEntropy(first.device.deviceId, Automerge)
    const rightEngine = new AutomergeAntiEntropy(second.device.deviceId, Automerge)

    let frame = await leftEngine.generate(leftAdapter, second.device.deviceId)
    for (let round = 0; frame && round < 10; round += 1) {
      const receiving = frame.toDeviceId === second.device.deviceId ? rightEngine : leftEngine
      const adapter = frame.toDeviceId === second.device.deviceId ? rightAdapter : leftAdapter
      frame = (await receiving.receive(adapter, frame.fromDeviceId, frame)).response
    }

    expect(frame).toBeNull()
    expect((rightStored as unknown as PersonalIdentityDocument).profileState.operations).toHaveLength(1)
    expect((rightStored as unknown as PersonalIdentityDocument).certificates).toHaveLength(2)
  })

  it("Given another person's device, when it attempts Identity sync, then deny before merging", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const stranger = (await createRecoverableIdentity("better", "Stranger")).profile
    const ownerDoc = Automerge.from<PersonalIdentityDocument>(createPersonalIdentityDocument(owner.identity, [owner.certificate]))
    const adapter = createPersonalIdentityAdapter({ identity: owner.identity, current: async () => ownerDoc,
      commit: () => {} })

    await expect(adapter.authorize(stranger.device.deviceId, undefined, "receive")).resolves.toBe(false)
  })

  it("Given a paired device and a delegated child, when revocation syncs and reloads, then both lose admission and certificate history remains", async () => {
    const recovery = await createRecoverableIdentity("better", "Owner")
    const owner = recovery.profile
    const removed = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
    const child = await createIdentityEnrollmentDevice("Child")
    const childCertificate = await createDelegatedCertificate(removed.privateKeys.devicePrivateKey,
      removed.device.deviceId, owner.identity.personId, child.device.deviceId, child.device.publicKey,
      await certificateHash(removed.certificate))
    const initial = Automerge.from<PersonalIdentityDocument>(createPersonalIdentityDocument(owner.identity,
      [owner.certificate, removed.certificate, childCertificate]))
    const revokedView = await verifyIdentityDeviceAuthority(owner.identity,
      { certificates: initial.certificates, revocations: initial.revocations })
    const revocation = await createDeviceRevocation(owner, revokedView, removed.device.deviceId, initial.profileState)
    const updated = Automerge.change(initial, draft => { draft.revocations.push(revocation) })
    const serialized = Automerge.save(updated)
    const reloaded = Automerge.load<PersonalIdentityDocument>(serialized)
    const stalePeer = Automerge.from<PersonalIdentityDocument>(createPersonalIdentityDocument(owner.identity,
      initial.certificates))
    const replicated = await normalizePersonalIdentityDocument(Automerge.merge(stalePeer, reloaded), owner.identity)
    const verified = await verifyIdentityDeviceAuthority(owner.identity,
      { certificates: replicated.certificates, revocations: replicated.revocations })
    const adapter = createPersonalIdentityAdapter({ identity: owner.identity, current: async () => replicated,
      commit: () => {} })

    await expect(authorizeIdentityDevice(verified, removed.device.deviceId)).rejects.toThrow(/revoked/i)
    await expect(authorizeIdentityDevice(verified, child.device.deviceId)).rejects.toThrow(/revoked/i)
    await expect(adapter.authorize(removed.device.deviceId, undefined, "receive")).resolves.toBe(false)
    expect(replicated.certificates).toHaveLength(3)
    expect(replicated.revocations).toHaveLength(1)
  })

  it("Given two concurrent revocation branches, when their signed revision numbers collide, then fail closed for explicit retry", async () => {
    const recovery = await createRecoverableIdentity("better", "Owner")
    const owner = recovery.profile
    const peer = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
    const initial = Automerge.from<PersonalIdentityDocument>(createPersonalIdentityDocument(owner.identity,
      [owner.certificate, peer.certificate]))
    const authority = await verifyIdentityDeviceAuthority(owner.identity,
      { certificates: initial.certificates, revocations: initial.revocations })
    const [fromOwner, fromPeer] = await Promise.all([
      createDeviceRevocation(owner, authority, peer.device.deviceId, initial.profileState),
      createDeviceRevocation(peer, authority, owner.device.deviceId, initial.profileState),
    ])
    const left = Automerge.change(Automerge.clone(initial), draft => { draft.revocations.push(fromOwner) })
    const right = Automerge.change(Automerge.clone(initial), draft => { draft.revocations.push(fromPeer) })

    await expect(normalizePersonalIdentityDocument(Automerge.merge(left, right), owner.identity))
      .rejects.toThrow(/revocation/i)
  })

  it("Given a legacy Identity document, when normalized, then upgrade it with an explicit empty revocation history", async () => {
    const owner = (await createRecoverableIdentity("better", "Owner")).profile
    const legacy = { ...createPersonalIdentityDocument(owner.identity, [owner.certificate]), version: 1 }
    delete (legacy as Partial<PersonalIdentityDocument>).revocations
    const normalized = await normalizePersonalIdentityDocument(
      Automerge.from(legacy as unknown as PersonalIdentityDocument), owner.identity)

    expect(normalized.version).toBe(2)
    expect(normalized.revocations).toEqual([])
  })

  it("Given a legacy Identity document, when an enrolled peer asks to sync, then authorize with its normalized authority view", async () => {
    const recovery = await createRecoverableIdentity("better", "Owner")
    const peer = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
    const current = { ...createPersonalIdentityDocument(recovery.profile.identity,
      [recovery.profile.certificate, peer.certificate]), version: 1 as const } as unknown as PersonalIdentityDocument
    delete (current as Partial<PersonalIdentityDocument>).revocations
    const adapter = createPersonalIdentityAdapter({ identity: recovery.profile.identity,
      current: async () => current, commit: () => {} })

    await expect(adapter.authorize(peer.device.deviceId, undefined, "receive")).resolves.toBe(true)
  })

  it("Given a forged cutoff record, when the public revocation-aware reader receives it, then reject the unsigned authority data", async () => {
    const recovery = await createRecoverableIdentity("better", "Owner")
    const owner = recovery.profile
    const peer = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
    const certificates = [owner.certificate, peer.certificate]
    const document = createPersonalIdentityDocument(owner.identity, certificates)
    const authority = await verifyIdentityDeviceAuthority(owner.identity, { certificates, revocations: [] })
    const record = await createDeviceRevocation(owner, authority, peer.device.deviceId, document.profileState)
    const forged = { ...record, payload: { ...record.payload,
      profileOperationHashes: { [peer.device.deviceId]: ["A".repeat(43)] } } }

    await expect(readIdentityProfileStateWithRevocations(document.profileState, owner.identity, certificates, [forged]))
      .rejects.toThrow(/signature/i)
  })

  it("Given a revoked device and observed history, when a forwarder brings later signed operations, then keep only the signed frontier", async () => {
    const recovery = await createRecoverableIdentity("better", "Owner")
    const owner = recovery.profile
    const revoked = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
    const peer = await createIdentityEnrollmentDevice("Independent peer")
    const peerCertificate = await createDelegatedCertificate(owner.privateKeys.devicePrivateKey, owner.device.deviceId,
      owner.identity.personId, peer.device.deviceId, peer.device.publicKey, await certificateHash(owner.certificate))
    const peerProfile = { identity: owner.identity, device: peer.device, certificate: peerCertificate,
      privateKeys: { devicePrivateKey: peer.privateKey } }
    const certificates = [owner.certificate, revoked.certificate, peerCertificate]
    const base = createPersonalIdentityDocument(owner.identity, certificates)
    const before = await createIdentityProfileOperation(revoked, base.profileState, "name", "Observed name", certificates)
    const observed = { ...base.profileState, operations: [before] }
    const authority = await verifyIdentityDeviceAuthority(owner.identity,
      { certificates, revocations: [] })
    const record = await createDeviceRevocation(owner, authority, revoked.device.deviceId, observed)
    expect(record.payload.profileOperationHashes).toEqual({ [revoked.device.deviceId]: [
      await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(before.signed))),
    ] })

    const after = await createIdentityProfileOperation(revoked, observed, "name", "Late name", certificates)
    const peerOperation = await createIdentityProfileOperation(peerProfile, observed, "name", "Peer after observed name", certificates)
    const sameCounterReplay = await createIdentityProfileOperation(revoked, base.profileState,
      "name", "Different operation at observed counter", certificates)
    const futureChild = await createIdentityEnrollmentDevice("Future child")
    const futureChildCertificate = await createDelegatedCertificate(revoked.privateKeys.devicePrivateKey,
      revoked.device.deviceId, owner.identity.personId, futureChild.device.deviceId, futureChild.device.publicKey,
      await certificateHash(revoked.certificate))
    const futureChildProfile = { identity: owner.identity, device: futureChild.device, certificate: futureChildCertificate,
      privateKeys: { devicePrivateKey: futureChild.privateKey } }
    const childOperation = await createIdentityProfileOperation(futureChildProfile, observed, "photo",
      { avatarData: null, changedAt: "2026-10-23T00:00:00.000Z" }, [...certificates, futureChildCertificate])
    const forwarded = Automerge.from<PersonalIdentityDocument>({ ...base, revocations: [record],
      certificates,
      profileState: { ...observed, operations: [...observed.operations, sameCounterReplay, after, peerOperation, childOperation] } })
    const normalized = await normalizePersonalIdentityDocument(forwarded, owner.identity)

    expect(normalized.profileState.operations.map(operation => `${operation.signed.payload.deviceId}:${operation.signed.payload.counter}`).sort())
      .toEqual([before, peerOperation].map(operation => `${operation.signed.payload.deviceId}:${operation.signed.payload.counter}`).sort())
    expect(identityProfileValue(normalized.profileState, "name")).toMatchObject({ status: "value", values: ["Peer after observed name"] })
    expect(normalized.certificates).toHaveLength(4)
  })

  it("Given ten or more observed operations, when creating a revocation cutoff, then hash counters in numeric order", async () => {
    const recovery = await createRecoverableIdentity("better", "Owner")
    const owner = recovery.profile
    const revoked = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
    const certificates = [owner.certificate, revoked.certificate]
    let state: PersonalIdentityDocument["profileState"] = { version: 1, personId: owner.identity.personId, operations: [], legacy: [] }
    for (let index = 1; index <= 12; index += 1) {
      const operation = await createIdentityProfileOperation(revoked, state, "name", `Observed ${index}`, certificates)
      state = { ...state, operations: [...state.operations, operation] }
    }
    const authority = await verifyIdentityDeviceAuthority(owner.identity, { certificates, revocations: [] })
    const record = await createDeviceRevocation(owner, authority, revoked.device.deviceId, state)

    expect(record.payload.profileOperationHashes[revoked.device.deviceId]).toHaveLength(12)
    const forwarded = Automerge.from<PersonalIdentityDocument>({ ...createPersonalIdentityDocument(owner.identity, certificates),
      revocations: [record], profileState: state })
    const normalized = await normalizePersonalIdentityDocument(forwarded, owner.identity)
    expect(normalized.profileState.operations).toHaveLength(12)
  })

  it("Given two paired MetaMesh device streams, when one syncs a personal document, then the other persists verified profile changes", async () => {
    const recovery = await createRecoverableIdentity("better", "Owner")
    const first = recovery.profile
    const second = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
    const third = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
    const initialLeft = createPersonalIdentityDocument(first.identity, [first.certificate, second.certificate, third.certificate])
    const initialRight = createPersonalIdentityDocument(first.identity, [first.certificate, second.certificate])
    const leftOperation = await createIdentityProfileOperation(first, initialLeft.profileState, "name", "Left name")
    const rightOperation = await createIdentityProfileOperation(second, initialRight.profileState, "name", "Right name")
    const leftBase = Automerge.from<PersonalIdentityDocument>(initialLeft, { actor: "00000000000000000000000000000000" })
    const rightBase = Automerge.from<PersonalIdentityDocument>(initialRight, { actor: "ffffffffffffffffffffffffffffffff" })
    let leftStored = Automerge.change(leftBase, doc => {
      doc.profileState.operations.push(leftOperation)
    })
    let rightStored = rightBase
    const conflicted = Automerge.merge(leftStored, rightStored)
    expect(conflicted.profileState.operations).toHaveLength(0)
    const profileConflicts = Object.values(Automerge.getConflicts(conflicted, "profileState") ?? {}) as
      PersonalIdentityDocument["profileState"][]
    expect(profileConflicts.some(state => state.operations.length === 1)).toBe(true)
    expect(conflicted.certificates).toHaveLength(2)
    const certificateConflicts = Object.values(Automerge.getConflicts(conflicted, "certificates") ?? {}) as
      PersonalIdentityDocument["certificates"][]
    expect(certificateConflicts.some(value => value.length === 3)).toBe(true)

    const leftAdapter = createPersonalIdentityAdapter({ identity: first.identity, current: async () => leftStored,
      commit: async next => { leftStored = next } })
    const rightAdapter = createPersonalIdentityAdapter({ identity: first.identity, current: async () => rightStored,
      commit: async next => { rightStored = next } })
    const left = new PersonalIdentityMeshSync({ profile: first, adapter: leftAdapter })
    const right = new PersonalIdentityMeshSync({ profile: second, adapter: rightAdapter })
    const acceptedChanges: number[] = []
    const serverErrors: unknown[] = []
    const connection = linkPersonalIdentityConnections(right, first.device.deviceId, acceptedChanges, serverErrors)
    const signedRoute = await createSignedDeviceRoute(second, { scopeId: leftAdapter.scopeId, instanceId: "second-instance",
      endpoint: "https://peer.invalid", sequence: 1, issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString() })
    const route = await verifySignedDeviceRoute(signedRoute, second.device.publicKey)

    await left.sync(connection.left, route, second.device.deviceId)
    await connection.drain()

    expect(serverErrors).toEqual([])
    expect(acceptedChanges.some(count => count > 0)).toBe(true)
    expect(leftStored.profileState.operations).toHaveLength(1)
    expect(rightStored.profileState.operations).toHaveLength(1)
    expect(leftStored.certificates).toHaveLength(3)
    expect(rightStored.certificates).toHaveLength(3)

    rightStored = Automerge.change(rightStored, doc => { doc.profileState.operations.push(rightOperation) })
    const reverseAcceptedChanges: number[] = []
    const reverseErrors: unknown[] = []
    const reverseConnection = linkPersonalIdentityConnections(left, second.device.deviceId,
      reverseAcceptedChanges, reverseErrors)
    const signedFirstRoute = await createSignedDeviceRoute(first, { scopeId: rightAdapter.scopeId,
      instanceId: "first-instance", endpoint: "https://peer.invalid", sequence: 1,
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString() })
    const firstRoute = await verifySignedDeviceRoute(signedFirstRoute, first.device.publicKey)
    await right.sync(reverseConnection.left, firstRoute, first.device.deviceId)
    await reverseConnection.drain()
    expect(serverErrors).toEqual([])
    expect(reverseErrors).toEqual([])
    expect(reverseAcceptedChanges.some(count => count > 0)).toBe(true)
    expect(leftStored.profileState.operations).toHaveLength(2)
    expect(rightStored.profileState.operations).toHaveLength(2)
    const leftState = await readIdentityProfileState(leftStored.profileState, first.identity, leftStored.certificates)
    const rightState = await readIdentityProfileState(rightStored.profileState, first.identity, rightStored.certificates)
    expect(identityProfileValue(leftState, "name")).toMatchObject({ status: "conflict", values: ["Left name", "Right name"] })
    expect(identityProfileValue(rightState, "name")).toMatchObject({ status: "conflict", values: ["Left name", "Right name"] })

    const reloadedLeft = Automerge.load<PersonalIdentityDocument>(Automerge.save(leftStored))
    const reloadedRight = Automerge.load<PersonalIdentityDocument>(Automerge.save(rightStored))
    for (const document of [reloadedLeft, reloadedRight]) {
      expect(document.profileState.operations).toHaveLength(2)
      expect(document.certificates).toHaveLength(3)
      const state = await readIdentityProfileState(document.profileState, first.identity, document.certificates)
      expect(identityProfileValue(state, "name")).toMatchObject({ status: "conflict", values: ["Left name", "Right name"] })
    }
  })

  it("Given both paired devices start sync together, when one bidirectional exchange runs, then both signed histories converge", async () => {
    const recovery = await createRecoverableIdentity("better", "Owner")
    const first = recovery.profile
    const second = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
    const initial = createPersonalIdentityDocument(first.identity, [first.certificate, second.certificate])
    const initialLeft = Automerge.from<PersonalIdentityDocument>(initial, { actor: "00000000000000000000000000000000" })
    const initialRight = Automerge.from<PersonalIdentityDocument>(initial, { actor: "ffffffffffffffffffffffffffffffff" })
    const leftOperation = await createIdentityProfileOperation(first, initial.profileState, "name", "Left")
    const rightOperation = await createIdentityProfileOperation(second, initial.profileState, "name", "Right")
    const leftStored = createCasIdentityDocument(Automerge.change(initialLeft, doc => {
      doc.profileState.operations.push(leftOperation)
    }), first.identity)
    const rightStored = createCasIdentityDocument(Automerge.change(initialRight, doc => {
      doc.profileState.operations.push(rightOperation)
    }), first.identity)
    const leftAdapter = createPersonalIdentityAdapter({ identity: first.identity, current: leftStored.current,
      commit: leftStored.commit })
    const rightAdapter = createPersonalIdentityAdapter({ identity: first.identity, current: rightStored.current,
      commit: rightStored.commit })
    const left = new PersonalIdentityMeshSync({ profile: first, adapter: leftAdapter })
    const right = new PersonalIdentityMeshSync({ profile: second, adapter: rightAdapter })
    const leftServer = new PersonalIdentityMeshSync({ profile: first, adapter: leftAdapter })
    const rightServer = new PersonalIdentityMeshSync({ profile: second, adapter: rightAdapter })
    const errors: unknown[] = []
    const connection = linkBidirectionalPersonalIdentityConnections(leftServer, rightServer,
      first.device.deviceId, second.device.deviceId, errors)
    const expiresAt = new Date(Date.now() + 60_000).toISOString()
    const [leftRoute, rightRoute] = await Promise.all([
      createSignedDeviceRoute(first, { scopeId: leftAdapter.scopeId, instanceId: "left-instance",
        endpoint: "https://left.invalid", sequence: 1, issuedAt: new Date().toISOString(), expiresAt }),
      createSignedDeviceRoute(second, { scopeId: rightAdapter.scopeId, instanceId: "right-instance",
        endpoint: "https://right.invalid", sequence: 1, issuedAt: new Date().toISOString(), expiresAt }),
    ])
    const [verifiedLeftRoute, verifiedRightRoute] = await Promise.all([
      verifySignedDeviceRoute(leftRoute, first.device.publicKey),
      verifySignedDeviceRoute(rightRoute, second.device.publicKey),
    ])

    await Promise.all([
      left.sync(connection.left, verifiedRightRoute, second.device.deviceId),
      right.sync(connection.right, verifiedLeftRoute, first.device.deviceId),
    ])
    await connection.drain()

    expect(errors).toEqual([])
    expect((await leftStored.current()).profileState.operations).toHaveLength(2)
    expect((await rightStored.current()).profileState.operations).toHaveLength(2)
  })

  it("Given profile sync is blocked reading a response, when its caller aborts, then it resets only that stream", async () => {
    const controller = new AbortController()
    const abortReason = new Error("Owner peer ended")
    let markReadStarted!: () => void
    const readStarted = new Promise<void>(resolve => { markReadStarted = resolve })
    const reset = vi.fn(async () => undefined)
    const stream: PersonalIdentitySyncStream = {
      send: async () => {},
      closeSend: async () => {},
      readRaw: () => { markReadStarted(); return new Promise<Uint8Array>(() => {}) },
      reset,
    }
    const connection: PersonalIdentitySyncConnection & { close: ReturnType<typeof vi.fn> } = {
      openStream: async () => stream,
      acceptStream: async () => { throw new Error("Unexpected inbound stream") },
      close: vi.fn(async () => {}),
    }
    const { sync, route, targetDeviceId } = await createBlockedSyncFixture(connection)

    const syncing = sync.sync(connection, route, targetDeviceId, controller.signal)
    await readStarted
    controller.abort(abortReason)

    await expect(syncing).rejects.toBe(abortReason)
    expect(reset).toHaveBeenCalledOnce()
    expect(connection.close).not.toHaveBeenCalled()
  })

  it("Given profile sync is blocked sending or half-closing, when its caller aborts, then it resets that stream", async () => {
    for (const blockedStage of ["send", "closeSend"] as const) {
      const controller = new AbortController()
      const abortReason = new Error("Owner peer ended")
      let markStageStarted!: () => void
      const stageStarted = new Promise<void>(resolve => { markStageStarted = resolve })
      const never = () => new Promise<void>(() => {})
      const reset = vi.fn(async () => undefined)
      const stream: PersonalIdentitySyncStream = {
        send: () => {
          if (blockedStage === "send") { markStageStarted(); return never() }
          return Promise.resolve()
        },
        closeSend: () => {
          if (blockedStage === "closeSend") { markStageStarted(); return never() }
          return Promise.resolve()
        },
        readRaw: async () => new Uint8Array(),
        reset,
      }
      const connection: PersonalIdentitySyncConnection & { close: ReturnType<typeof vi.fn> } = {
        openStream: async () => stream,
        acceptStream: async () => { throw new Error("Unexpected inbound stream") },
        close: vi.fn(async () => {}),
      }
      const { sync, route, targetDeviceId } = await createBlockedSyncFixture(connection)

      const syncing = sync.sync(connection, route, targetDeviceId, controller.signal)
      await stageStarted
      controller.abort(abortReason)

      await expect(syncing).rejects.toBe(abortReason)
      expect(reset).toHaveBeenCalledOnce()
      expect(connection.close).not.toHaveBeenCalled()
    }
  })

  it("Given stream opening is blocked, when sync aborts before it resolves, then the late stream is reset", async () => {
    const controller = new AbortController()
    const abortReason = new Error("Owner peer ended")
    let markOpenStarted!: () => void
    const openStarted = new Promise<void>(resolve => { markOpenStarted = resolve })
    let resolveOpen!: (stream: PersonalIdentitySyncStream) => void
    const openResult = new Promise<PersonalIdentitySyncStream>(resolve => { resolveOpen = resolve })
    const reset = vi.fn(async () => undefined)
    const send = vi.fn(async () => {})
    const lateStream: PersonalIdentitySyncStream = {
      send,
      closeSend: async () => {},
      readRaw: async () => new Uint8Array(),
      reset,
    }
    const connection: PersonalIdentitySyncConnection & { close: ReturnType<typeof vi.fn> } = {
      openStream: () => { markOpenStarted(); return openResult },
      acceptStream: async () => { throw new Error("Unexpected inbound stream") },
      close: vi.fn(async () => {}),
    }
    const { sync, route, targetDeviceId } = await createBlockedSyncFixture(connection)

    const syncing = sync.sync(connection, route, targetDeviceId, controller.signal)
    await openStarted
    controller.abort(abortReason)
    await expect(syncing).rejects.toBe(abortReason)
    resolveOpen(lateStream)
    await vi.waitFor(() => expect(reset).toHaveBeenCalledOnce())

    expect(send).not.toHaveBeenCalled()
    expect(connection.close).not.toHaveBeenCalled()
  })
})

async function createBlockedSyncFixture(connection: PersonalIdentitySyncConnection) {
  const recovery = await createRecoverableIdentity("better", "Owner")
  const profile = recovery.profile
  const peer = await openIdentityRecoveryEnvelope(recovery.recoveryEnvelope, recovery.recoveryKey, "Owner")
  const initial = createPersonalIdentityDocument(profile.identity, [profile.certificate, peer.certificate])
  const initialDoc = Automerge.from<PersonalIdentityDocument>(initial)
  const operation = await createIdentityProfileOperation(profile, initial.profileState, "name", "Owner")
  const stored = Automerge.change(initialDoc, document => { document.profileState.operations.push(operation) })
  const adapter = createPersonalIdentityAdapter({ identity: profile.identity, current: async () => stored, commit: async () => {} })
  const sync = new PersonalIdentityMeshSync({ profile, adapter })
  const signedRoute = await createSignedDeviceRoute(peer, { scopeId: adapter.scopeId, instanceId: "blocked-peer-instance",
    endpoint: "https://peer.invalid", sequence: 1, issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString() })
  const route = await verifySignedDeviceRoute(signedRoute, peer.device.publicKey)
  return { sync, route, targetDeviceId: peer.device.deviceId }
}

function linkPersonalIdentityConnections(sync: PersonalIdentityMeshSync, remoteDeviceId: string,
  acceptedChanges: number[], errors: unknown[]) {
  const serverTasks: Promise<void>[] = []
  const left: PersonalIdentitySyncConnection = {
    openStream: async () => {
      const [client, server] = duplexStream()
      const task = sync.receiveNext({ openStream: async () => { throw new Error("Unexpected reverse open") },
        acceptStream: async () => server }, remoteDeviceId).then(result => { acceptedChanges.push(result.acceptedChanges) })
        .catch(error => { errors.push(error) })
      serverTasks.push(task)
      return client
    },
    acceptStream: async () => { throw new Error("Unexpected client accept") },
  }
  return { left, drain: async () => { await Promise.all(serverTasks) } }

  function duplexStream(): [PersonalIdentitySyncStream, PersonalIdentitySyncStream] {
    const leftToRight: Uint8Array[] = [], rightToLeft: Uint8Array[] = []
    const leftReaders: Array<(value: Uint8Array) => void> = [], rightReaders: Array<(value: Uint8Array) => void> = []
    const makeSide = (incoming: Uint8Array[], readers: Array<(value: Uint8Array) => void>, outgoing: Uint8Array[], outgoingReaders: Array<(value: Uint8Array) => void>): PersonalIdentitySyncStream => ({
      send: async bytes => { const reader = outgoingReaders.shift(); reader ? reader(bytes) : outgoing.push(bytes) },
      readRaw: async () => incoming.length ? incoming.shift()! : new Promise(resolve => readers.push(resolve)),
      closeSend: async () => {},
    })
    return [makeSide(rightToLeft, rightReaders, leftToRight, leftReaders), makeSide(leftToRight, leftReaders, rightToLeft, rightReaders)]
  }
}

function createCasIdentityDocument(initial: Automerge.Doc<PersonalIdentityDocument>, identity: Awaited<ReturnType<typeof createRecoverableIdentity>>["profile"]["identity"]) {
  let stored = initial
  let tail = Promise.resolve()
  return {
    current: async () => stored,
    commit: async (document: Automerge.Doc<PersonalIdentityDocument>, expectedRevision: string) => {
      let release!: () => void
      const previous = tail
      tail = new Promise<void>(resolve => { release = resolve })
      await previous
      try {
        const current = stored
        if (await identityProfileRevision(current.profileState) !== expectedRevision) {
          throw new Error("Identity profile changed during sync; retry from the latest version.")
        }
        const certificates = [...new Map([...current.certificates, ...document.certificates]
          .map(certificate => [JSON.stringify(certificate), certificate])).values()]
        const merged = Automerge.merge(Automerge.clone(current), document)
        const profileState = await mergeIdentityProfileState(current.profileState, document.profileState,
          identity, certificates)
        stored = canonicalizeJson(merged.certificates) === canonicalizeJson(certificates) &&
          canonicalizeJson(merged.profileState) === canonicalizeJson(profileState)
          ? merged
          : Automerge.change(merged, draft => {
            draft.certificates = certificates
            draft.profileState = profileState
          })
      } finally { release() }
    },
  }
}

function linkBidirectionalPersonalIdentityConnections(leftServer: PersonalIdentityMeshSync, rightServer: PersonalIdentityMeshSync,
  leftDeviceId: string, rightDeviceId: string, errors: unknown[]) {
  const tasks: Promise<unknown>[] = []
  const leftConnection: PersonalIdentitySyncConnection = {
    openStream: async () => {
      const [client, server] = duplexStream()
      tasks.push(rightServer.receiveNext({ openStream: async () => { throw new Error("Unexpected reverse open") },
        acceptStream: async () => server }, leftDeviceId).catch(error => { errors.push(error) }))
      return client
    },
    acceptStream: async () => { throw new Error("Unexpected client accept") },
  }
  const rightConnection: PersonalIdentitySyncConnection = {
    openStream: async () => {
      const [client, server] = duplexStream()
      tasks.push(leftServer.receiveNext({ openStream: async () => { throw new Error("Unexpected reverse open") },
        acceptStream: async () => server }, rightDeviceId).catch(error => { errors.push(error) }))
      return client
    },
    acceptStream: async () => { throw new Error("Unexpected client accept") },
  }
  return { left: leftConnection, right: rightConnection, drain: async () => { await Promise.all(tasks) } }

  function duplexStream(): [PersonalIdentitySyncStream, PersonalIdentitySyncStream] {
    const leftToRight: Uint8Array[] = [], rightToLeft: Uint8Array[] = []
    const leftReaders: Array<(value: Uint8Array) => void> = [], rightReaders: Array<(value: Uint8Array) => void> = []
    const makeSide = (incoming: Uint8Array[], readers: Array<(value: Uint8Array) => void>, outgoing: Uint8Array[], outgoingReaders: Array<(value: Uint8Array) => void>): PersonalIdentitySyncStream => ({
      send: async bytes => { const reader = outgoingReaders.shift(); reader ? reader(bytes) : outgoing.push(bytes) },
      readRaw: async () => incoming.length ? incoming.shift()! : new Promise(resolve => readers.push(resolve)),
      closeSend: async () => {},
    })
    return [makeSide(rightToLeft, rightReaders, leftToRight, leftReaders), makeSide(leftToRight, leftReaders, rightToLeft, rightReaders)]
  }
}
