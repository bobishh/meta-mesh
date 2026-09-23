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
    const allPeers = await this.host.peers(workspaceId)
    const transfers = credential ? this.host.transfers(credential) : []
    const advertisements = allPeers.map(peer => this.host.advertisement(peer))
    const selection = meshRustRuntime().state.selectOwnershipTransfer({ localPersonId: profile.personId,
      ownerPersonId: credential?.ownerPersonId ?? null, credentialEpoch: credential?.epoch ?? null,
      targetPersonId: personId, peers: allPeers.map((peer, index) => ({ personId: peer.personId,
        revoked: Boolean(peer.revokedAt), online: this.host.online(peer, workspaceId),
        hasAdvertisement: Boolean(advertisements[index]) })),
      transfers: transfers.map(record => record.payload) })
    const peers = selection.peerIndices.map(index => allPeers[index]!)
    const sessions = this.host.confirmationSessions(peers, workspaceId)
    const advertisement = selection.advertisementIndex === null ? undefined : advertisements[selection.advertisementIndex]
    const pending = selection.pendingIndex === null ? undefined : transfers[selection.pendingIndex]
    const actions = meshRustRuntime().state.planAuthorityCommand({ kind: "transfer", localPersonId: profile.personId,
      ownerPersonId: credential?.ownerPersonId ?? null, targetPersonId: personId, activePeerCount: peers.length,
      targetOnline: selection.targetOnline,
      confirmationSessionCount: sessions.length, hasAdvertisement: Boolean(advertisement),
      pendingTargetPersonId: pending?.payload.toOwnerPersonId ?? null })
    let target!: Target
    let transfer: Transfer = pending!
    let current: C = credential!
    for (const action of actions) {
      switch (action) {
        case "verifyTarget": target = await this.host.verifyTarget(credential!, advertisement); break
        case "createTransfer": transfer = await this.host.createTransfer(profile, credential!, target); break
        case "persistProposal": await this.host.persistProposal(credential!, transfer); break
        case "confirmDelivery":
          try { await this.host.confirmDelivery(sessions, credential!) }
          catch { throw new Error("Ownership delivery is unconfirmed. Keep both devices open and retry the same recipient.") }
          break
        case "reloadCredential":
          current = (await this.host.credential(workspaceId))!
          if (!current) throw new Error("Workspace mesh credential disappeared")
          break
        case "mergeTransfer": await this.host.merge(current, transfer); break
        case "notify": await this.host.notify(); break
        case "publish": await this.host.publishAll(); break
      }
    }
  }
}
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
