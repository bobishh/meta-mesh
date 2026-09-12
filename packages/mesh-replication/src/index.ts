export type ReplicaRecord<T> = {
  id: string
  updatedAt: string
  value: T
}

export type ReplicaTombstone = {
  id: string
  deletedAt: string
}

export type ReplicaSet<T> = {
  records: ReplicaRecord<T>[]
  tombstones: ReplicaTombstone[]
}

function timestamp(value: string): number {
  const result = Date.parse(value)
  if (!Number.isFinite(result) || new Date(result).toISOString() !== value) {
    throw new Error("Invalid replica timestamp")
  }
  return result
}

function newer<T extends { id: string }>(current: T | undefined, candidate: T, date: (value: T) => string): T {
  const candidateTime = timestamp(date(candidate))
  if (!current) return candidate
  const currentTime = timestamp(date(current))
  if (candidateTime !== currentTime) return candidateTime > currentTime ? candidate : current
  return JSON.stringify(candidate) > JSON.stringify(current) ? candidate : current
}

export function reconcileReplicaSet<T>(left: ReplicaSet<T>, right: ReplicaSet<T>): ReplicaSet<T> {
  const tombstones = new Map<string, ReplicaTombstone>()
  for (const candidate of [...left.tombstones, ...right.tombstones]) {
    if (!candidate.id) throw new Error("Invalid replica tombstone")
    tombstones.set(candidate.id, newer(tombstones.get(candidate.id), candidate, value => value.deletedAt))
  }

  const records = new Map<string, ReplicaRecord<T>>()
  for (const candidate of [...left.records, ...right.records]) {
    if (!candidate.id) throw new Error("Invalid replica record")
    const deleted = tombstones.get(candidate.id)
    if (deleted && timestamp(deleted.deletedAt) >= timestamp(candidate.updatedAt)) continue
    records.set(candidate.id, newer(records.get(candidate.id), candidate, value => value.updatedAt))
  }

  return {
    records: [...records.values()].sort((a, b) => a.id.localeCompare(b.id)),
    tombstones: [...tombstones.values()].sort((a, b) => a.id.localeCompare(b.id)),
  }
}
