type Limits = { bytes: number; frames: number; headers: number; deadlineMs: number }
type Reservation = { bytes: number; payload: boolean }
type Waiter = { lease: ReadLease; target: Reservation; resolve(): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout> }

/** Header waits reserve bounded bytes, rather than a maximum-size payload that has not arrived. */
export class MeshReadBudget {
  lastUsed = Date.now()
  private bytes = 0
  private frames = 0
  private readonly leases = new Set<ReadLease>()
  private readonly waiting: Waiter[] = []
  constructor(private readonly limits: Limits, private readonly failure: (message: string) => Error) {}
  get idle() { return this.leases.size === 0 }
  create(staged: boolean): ReadLease {
    const sameKind = [...this.leases].filter(lease => lease.staged === staged).length
    if (sameKind >= (staged ? this.limits.headers : this.limits.frames * 2)) {
      throw this.failure("Mesh stream concurrency limit exceeded")
    }
    const lease = new ReadLease(this, staged)
    this.leases.add(lease)
    return lease
  }
  request(lease: ReadLease, target: Reservation): Promise<void> {
    if (!this.leases.has(lease)) return Promise.reject(this.failure("Mesh stream read was cancelled"))
    if (target.bytes > this.limits.bytes) return Promise.reject(this.failure("Mesh frame exceeds peer read budget"))
    if (this.available(lease, target)) { this.assign(lease, target); return Promise.resolve() }
    return new Promise<void>((resolve, reject) => {
      const waiter: Waiter = { lease, target, resolve, reject,
        timer: setTimeout(() => this.cancel(lease, this.failure("Mesh stream read deadline exceeded while queued: stage=stream")), this.limits.deadlineMs * 2) }
      this.waiting.push(waiter)
    })
  }
  cancel(lease: ReadLease, error: Error) {
    for (let index = this.waiting.length - 1; index >= 0; index--) {
      const waiter = this.waiting[index]!
      if (waiter.lease !== lease) continue
      this.waiting.splice(index, 1)
      clearTimeout(waiter.timer)
      waiter.reject(error)
    }
  }
  release(lease: ReadLease) {
    if (!this.leases.delete(lease)) return
    this.cancel(lease, this.failure("Mesh stream read was cancelled"))
    this.bytes -= lease.reservation.bytes
    this.frames -= Number(lease.reservation.payload)
    this.lastUsed = Date.now()
    // A large queued payload must not prevent a bounded heartbeat from progressing.
    for (let index = 0; index < this.waiting.length;) {
      const waiter = this.waiting[index]!
      if (!this.available(waiter.lease, waiter.target)) { index++; continue }
      this.waiting.splice(index, 1)
      clearTimeout(waiter.timer)
      this.assign(waiter.lease, waiter.target)
      waiter.resolve()
    }
  }
  private available(lease: ReadLease, target: Reservation) {
    return this.bytes - lease.reservation.bytes + target.bytes <= this.limits.bytes &&
      this.frames - Number(lease.reservation.payload) + Number(target.payload) <= this.limits.frames
  }
  private assign(lease: ReadLease, target: Reservation) {
    this.bytes += target.bytes - lease.reservation.bytes
    this.frames += Number(target.payload) - Number(lease.reservation.payload)
    lease.reservation = target
    this.lastUsed = Date.now()
  }
}

export class ReadLease {
  reservation: Reservation = { bytes: 0, payload: false }
  constructor(private readonly budget: MeshReadBudget, readonly staged: boolean) {}
  reserve(bytes: number, payload: boolean) { return this.budget.request(this, { bytes, payload }) }
  cancel(error: Error) { this.budget.cancel(this, error) }
  release() { this.budget.release(this) }
}
