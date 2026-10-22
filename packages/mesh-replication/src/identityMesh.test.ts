import * as Automerge from "@automerge/automerge"
import { createIdentityProfileOperation, createRecoverableIdentity, identityProfileValue, openIdentityRecoveryEnvelope,
  canonicalizeJson, identityProfileRevision, mergeIdentityProfileState, readIdentityProfileState } from "@meta-uber/mesh-identity"
import { describe, expect, it } from "vitest"
import { createSignedDeviceRoute, verifySignedDeviceRoute } from "./protocol"
import { AutomergeAntiEntropy } from "./automerge"
import { createPersonalIdentityAdapter, createPersonalIdentityDocument, PersonalIdentityMeshSync, type PersonalIdentityDocument,
  type PersonalIdentitySyncConnection, type PersonalIdentitySyncStream } from "./identityMesh"

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
})

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
