export interface MeshInstanceLocks {
  request(
    name: string,
    options: { mode: "exclusive"; ifAvailable: true },
    callback: (lock: unknown | null) => Promise<void>,
  ): Promise<unknown>
}

export type MeshInstanceLease = {
  instanceId: string
  release: () => Promise<void>
}

export type MeshInstanceLeaseOptions = {
  namespace: string
  compatibilityLockNames?: string[]
  locks?: MeshInstanceLocks
  preferredInstanceId?: string | null
  slots?: number
}

export type MeshLeaderLeaseOptions = {
  namespace: string
  name: string
  locks?: MeshInstanceLocks
}

function validNamespace(value: string): string {
  const namespace = value.trim()
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/i.test(namespace)) throw new Error("Invalid mesh instance namespace")
  return namespace
}

export async function acquireMeshInstanceLease(options: MeshInstanceLeaseOptions): Promise<MeshInstanceLease> {
  const namespace = validNamespace(options.namespace)
  const locks = options.locks ?? (typeof navigator !== "undefined" && navigator.locks
    ? navigator.locks as MeshInstanceLocks : undefined)
  if (!locks) return { instanceId: `ephemeral-${crypto.randomUUID()}`, release: async () => {} }

  const count = options.slots ?? 32
  if (!Number.isSafeInteger(count) || count < 1 || count > 256) throw new Error("Invalid mesh instance slot count")
  const preferred = options.preferredInstanceId?.match(/^slot-(\d+)$/)?.[1]
  const slots = [...new Set([
    ...(preferred === undefined ? [] : [Number(preferred)]),
    ...Array.from({ length: count }, (_, index) => index),
  ])].filter(slot => slot >= 0 && slot < count)

  for (const slot of slots) {
    let releaseLock: (() => void) | undefined
    let resolveAttempt!: (acquired: boolean) => void
    const attempted = new Promise<boolean>(resolve => { resolveAttempt = resolve })
    const compatibilityLocks = slot === 0 ? (options.compatibilityLockNames ?? []) : []
    if (compatibilityLocks.some(name => !name || name.length > 128)) throw new Error("Invalid compatibility lock name")
    const lockNames = [...new Set([`${namespace}:mesh-instance:${slot}`, ...compatibilityLocks])]
    const acquireLock = async (index: number): Promise<void> => { await locks.request(
      lockNames[index]!,
      { mode: "exclusive", ifAvailable: true },
      async lock => {
        if (!lock) return resolveAttempt(false)
        if (index + 1 < lockNames.length) {
          await acquireLock(index + 1)
          return
        }
        await new Promise<void>(resolve => {
          releaseLock = resolve
          resolveAttempt(true)
        })
      },
    ) }
    const completion = acquireLock(0)
    if (await attempted) return {
      instanceId: `slot-${slot}`,
      release: async () => {
        releaseLock?.()
        await completion
      },
    }
  }

  return { instanceId: `ephemeral-${crypto.randomUUID()}`, release: async () => {} }
}

export async function tryAcquireMeshLeaderLease(options: MeshLeaderLeaseOptions): Promise<MeshInstanceLease | null> {
  const namespace = validNamespace(options.namespace)
  const name = validNamespace(options.name)
  const locks = options.locks ?? (typeof navigator !== "undefined" && navigator.locks
    ? navigator.locks as MeshInstanceLocks : undefined)
  if (!locks) return { instanceId: "leader", release: async () => {} }

  let releaseLock: (() => void) | undefined
  let resolveAttempt!: (acquired: boolean) => void
  const attempted = new Promise<boolean>(resolve => { resolveAttempt = resolve })
  const completion = locks.request(`${namespace}:mesh-leader:${name}`, { mode: "exclusive", ifAvailable: true }, async lock => {
    if (!lock) return resolveAttempt(false)
    await new Promise<void>(resolve => {
      releaseLock = resolve
      resolveAttempt(true)
    })
  })
  if (!await attempted) return null
  return {
    instanceId: "leader",
    release: async () => {
      releaseLock?.()
      await completion
    },
  }
}

export async function deriveMeshInstanceSeed(
  baseSeed: Uint8Array,
  namespace: string,
  instanceId: string,
): Promise<Uint8Array> {
  if (baseSeed.byteLength < 16) throw new Error("Mesh base seed must contain at least 16 bytes")
  const scope = validNamespace(namespace)
  if (!instanceId || instanceId.length > 128) throw new Error("Invalid mesh instance id")
  const label = new TextEncoder().encode(`\0${scope}\0${instanceId}`)
  const material = new Uint8Array(baseSeed.byteLength + label.byteLength)
  material.set(baseSeed)
  material.set(label, baseSeed.byteLength)
  return new Uint8Array(await crypto.subtle.digest("SHA-256", material))
}
