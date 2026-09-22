export type BrowserMeshTransferCredential = { workspaceId: string; ownerPersonId: string; epoch: number }
export type BrowserMeshTransferProfile = { personId: string }
export type BrowserMeshTransferPeer = { personId: string; deviceId: string; revokedAt?: string | null }
export type BrowserMeshTransferRecord = {
  payload: { epoch: number; fromOwnerPersonId: string; toOwnerPersonId: string }
}

export type BrowserMeshTransferHost<C extends BrowserMeshTransferCredential, P extends BrowserMeshTransferProfile,
  Peer extends BrowserMeshTransferPeer, Target, Transfer extends BrowserMeshTransferRecord, Session> = {
  profile(): Promise<P>
  credential(workspaceId: string): Promise<C | undefined>
  peers(workspaceId: string): Promise<Peer[]>
  online(peer: Peer, workspaceId: string): boolean
  confirmationSessions(peers: Peer[], workspaceId: string): Session[]
  advertisement(peer: Peer): unknown | undefined
  verifyTarget(credential: C, advertisement: unknown): Promise<Target>
  transfers(credential: C): Transfer[]
  createTransfer(profile: P, credential: C, target: Target): Promise<Transfer>
  persistProposal(credential: C, transfer: Transfer): Promise<void>
  confirmDelivery(sessions: Session[], credential: C): Promise<void>
  merge(credential: C, transfer: Transfer): Promise<void>
  notify(): Promise<void>
  publishAll(): Promise<void>
}

/** Serializes the signed ownership handoff and requires a durable recipient receipt. */
export class BrowserMeshOwnershipTransfer<C extends BrowserMeshTransferCredential, P extends BrowserMeshTransferProfile,
  Peer extends BrowserMeshTransferPeer, Target, Transfer extends BrowserMeshTransferRecord, Session> {
  private queue: Promise<void> = Promise.resolve()

  constructor(private readonly host: BrowserMeshTransferHost<C, P, Peer, Target, Transfer, Session>) {}

  transfer(workspaceId: string, personId: string): Promise<void> {
    const run = () => this.confirmed(workspaceId, personId)
    const result = this.queue.then(() => typeof navigator !== "undefined" && navigator.locks
      ? navigator.locks.request(`mesh-ownership:${workspaceId}`, run) : run())
    this.queue = result.catch(() => undefined)
    return result
  }

  private async confirmed(workspaceId: string, personId: string): Promise<void> {
    const profile = await this.host.profile()
    const credential = await this.host.credential(workspaceId)
    if (!credential || credential.ownerPersonId !== profile.personId) throw new Error("Only the workspace owner can transfer ownership")
    if (personId === profile.personId) throw new Error("You already own this workspace")
    const peers = (await this.host.peers(workspaceId)).filter(peer => peer.personId === personId && !peer.revokedAt)
    if (!peers.length) throw new Error("Select an active mesh member")
    if (!peers.some(peer => this.host.online(peer, workspaceId))) throw new Error("Member must be online to receive ownership")
    const sessions = this.host.confirmationSessions(peers, workspaceId)
    if (!sessions.length) throw new Error("The recipient must reload Match before receiving ownership")
    const advertisement = peers.map(peer => this.host.advertisement(peer)).find(Boolean)
    if (!advertisement) throw new Error("Member identity is unavailable")
    const target = await this.host.verifyTarget(credential, advertisement)
    const pending = this.host.transfers(credential).find(record => record.payload.epoch === credential.epoch + 1 &&
      record.payload.fromOwnerPersonId === profile.personId)
    if (pending && pending.payload.toOwnerPersonId !== personId) {
      throw new Error("An ownership transfer is pending for another member. Reconnect that member to finish it.")
    }
    const transfer = pending ?? await this.host.createTransfer(profile, credential, target)
    if (!pending) await this.host.persistProposal(credential, transfer)
    try { await this.host.confirmDelivery(sessions, credential) }
    catch { throw new Error("Ownership delivery is unconfirmed. Keep both devices open and retry the same recipient.") }
    const current = await this.host.credential(workspaceId)
    if (!current) throw new Error("Workspace mesh credential disappeared")
    await this.host.merge(current, transfer)
    await this.host.notify()
    await this.host.publishAll()
  }
}
