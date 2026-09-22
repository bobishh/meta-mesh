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
    credential = await this.host.ownership(credential, catalog)
    await this.host.revocations(credential, catalog)
    credential = await this.host.refreshed(workspaceId) ?? credential
    credential = await this.host.succession(credential, catalog)
    credential = await this.host.refreshed(workspaceId) ?? credential
    await this.host.peers(credential, catalog)
    await this.host.notify()
  }
}
