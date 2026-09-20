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

export function reconcileReplicaSet<T>(left: ReplicaSet<T>, right: ReplicaSet<T>): ReplicaSet<T> {
  return meshRustRuntime().state.reconcileReplicaSets(left, right) as ReplicaSet<T>
}

export * from "./protocol"
export * from "./automerge"
export * from "./gossip"
export * from "./runtime"
import { meshRustRuntime } from "./runtime"
