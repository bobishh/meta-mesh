export type BrowserMeshCatalogCredential = { workspaceId: string }

export type BrowserMeshCatalogHost<C extends BrowserMeshCatalogCredential, Catalog, Peer> = {
  parse(raw: unknown): Catalog
  credential(workspaceId: string): Promise<C | undefined>
  ownership(credential: C, catalog: Catalog): Promise<C>
  revocations(credential: C, catalog: Catalog): Promise<void>
  succession(credential: C, catalog: Catalog): Promise<C>
  peers(credential: C, catalog: Catalog): Promise<void>
  refreshed(workspaceId: string): Promise<C | undefined>
  notify(): Promise<void>
}

/** Canonical authority-catalog merge order shared by browser and native hosts. */
export class BrowserMeshCatalog<C extends BrowserMeshCatalogCredential, Catalog, Peer = never> {
  constructor(private readonly host: BrowserMeshCatalogHost<C, Catalog, Peer>) {}

  async merge(workspaceId: string, raw: unknown): Promise<void> {
    const catalog = this.host.parse(raw)
    let credential = await this.host.credential(workspaceId)
    if (!credential) return
    for (const action of meshRustRuntime().state.planCatalogMerge()) {
      switch (action) {
        case "ownership": credential = await this.host.ownership(credential, catalog); break
        case "revocations": await this.host.revocations(credential, catalog); break
        case "refreshCredential": credential = await this.host.refreshed(workspaceId) ?? credential; break
        case "succession": credential = await this.host.succession(credential, catalog); break
        case "peers": await this.host.peers(credential, catalog); break
        case "notify": await this.host.notify(); break
      }
    }
  }
}
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"
