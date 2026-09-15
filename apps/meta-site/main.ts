import {
  BrowserIdentityStore,
  fromBase64Url,
  chatKeyIsValid,
  normalizeRecoveryPhrase,
  sha256Base64Url,
  signEnvelope,
  toBase64Url,
  verifyDeviceCertificateChain,
  verifyEnvelope,
  type DeviceCertificate,
  type IdentityPassphraseEnvelope,
  type IdentityRecoveryEnvelope,
  type LocalProfile,
  type PublicIdentity,
  type SignedEnvelope,
} from "../../packages/mesh-identity/src/index"
import {
  CONTACT_SIGNATURE_DOMAIN,
  appendContactMessage,
  contactTimeline,
  createContactChannel,
  createContactDecision,
  createContactMessage,
  createContactRequest,
  loadContactChannel,
  mergeContactChannels,
  saveContactChannel,
  verifyContactChannel,
  verifyContactRequest,
  type ContactChannel,
  type ContactRequest,
  addContactParticipantDeviceCertificate,
} from "../../packages/mesh-contact/src/index"
import {
  reconcileReplicaSet,
  type ReplicaRecord,
  type ReplicaTombstone,
} from "../../packages/mesh-replication/src/index"
import * as Automerge from "@automerge/automerge/slim"
import automergeWasmUrl from "@automerge/automerge/automerge.wasm?url"
import { IROH_MODULE_URL, OWNER_ENDPOINT } from "./config"

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

type IrohStream = { send(bytes: Uint8Array): Promise<void>; read(): Promise<Uint8Array>; closeSend(): Promise<void> }
type IrohConnection = { openStream(): Promise<IrohStream>; acceptStream(): Promise<IrohStream>; close(): Promise<void> }
type IrohNode = {
  endpointId: string
  dialRelay(endpoint: string): Promise<IrohConnection>
  accept(): Promise<{ accept(): Promise<IrohConnection | undefined> }>
  close(reason?: string): Promise<void>
}

type SessionPayload = {
  kind: "mesh-session"
  version: 1
  personId: string
  deviceId: string
  nonce: string
  createdAt: string
}

type SessionProof = {
  signed: SignedEnvelope<SessionPayload>
  identity: PublicIdentity
  certificates: DeviceCertificate[]
}

type StoredChannel = {
  channelId: string
  secret: string
  bytes: Uint8Array
  recoveryLocator: string
  recoveryEnvelope: IdentityRecoveryEnvelope
  label?: string
  labelUpdatedAt?: string
}
type PendingRequest = {
  requestId: string
  request: ContactRequest
  recoveryLocator: string
  recoveryEnvelope: IdentityRecoveryEnvelope
}
type OwnerWireChannel = Omit<StoredChannel, "bytes"> & { bytes: string }
type OwnerSnapshot = {
  channels: OwnerWireChannel[]
  pending: PendingRequest[]
  pendingTombstones: ReplicaTombstone[]
}

let irohModule: Promise<any> | undefined

async function loadIroh() {
  return irohModule ??= (async () => {
    const module = await import(/* @vite-ignore */ IROH_MODULE_URL)
    await module.default()
    return module
  })()
}

async function sha256(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", textEncoder.encode(value)))
}

async function startNode(key: string): Promise<IrohNode> {
  const module = await loadIroh()
  return module.BrowserNode.start(await sha256(normalizeRecoveryPhrase(key)))
}

async function startRandomNode(): Promise<IrohNode> {
  const module = await loadIroh()
  return module.BrowserNode.start()
}

function bytesToWire(bytes: Uint8Array): string { return toBase64Url(bytes) }
function wireToBytes(value: string): Uint8Array { return fromBase64Url(value) }

async function request(node: IrohNode, payload: unknown): Promise<any> {
  const operation = (async () => {
    const connection = await node.dialRelay(OWNER_ENDPOINT)
    try {
      const stream = await connection.openStream()
      await stream.send(textEncoder.encode(JSON.stringify(payload)))
      await stream.closeSend()
      const response = JSON.parse(textDecoder.decode(await stream.read()))
      if (response.error) throw new Error(response.error)
      return response
    } finally {
      await connection.close().catch(() => undefined)
    }
  })()
  const timeout = new Promise<never>((_, reject) => window.setTimeout(() => reject(new Error("Peer is offline")), 8_000))
  return Promise.race([operation, timeout])
}

function ownerUnlockError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error)
  if (message === "Wrong key" || (error instanceof DOMException && error.name === "OperationError")) return "Wrong key"
  if (message === "Peer is offline") return "Owner device went offline. Try again."
  return message
}

async function reply(stream: IrohStream, payload: unknown) {
  await stream.send(textEncoder.encode(JSON.stringify(payload)))
  await stream.closeSend()
}

async function sessionProof(profile: LocalProfile): Promise<SessionProof> {
  const payload: SessionPayload = {
    kind: "mesh-session",
    version: 1,
    personId: profile.identity.personId,
    deviceId: profile.device.deviceId,
    nonce: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
  }
  return {
    signed: await signEnvelope(profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId, CONTACT_SIGNATURE_DOMAIN),
    identity: profile.identity,
    certificates: [profile.certificate],
  }
}

async function verifySession(value: SessionProof): Promise<SessionProof> {
  const payload = value?.signed?.payload
  if (!payload || payload.kind !== "mesh-session" || payload.version !== 1 ||
    value.identity?.personId !== payload.personId || value.signed.signerKeyId !== payload.deviceId) {
    throw new Error("Invalid session")
  }
  const timestamp = Date.parse(payload.createdAt)
  if (!Number.isFinite(timestamp) || Math.abs(Date.now() - timestamp) > 5 * 60 * 1000) throw new Error("Expired session")
  const key = await verifyDeviceCertificateChain(value.identity, payload.deviceId, value.certificates)
  if (!await verifyEnvelope(value.signed, key, CONTACT_SIGNATURE_DOMAIN)) throw new Error("Invalid session signature")
  return value
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("meta-mesh-v1", 2)
    request.onupgradeneeded = () => {
      const db = request.result
      for (const name of ["owner-channels", "owner-pending", "owner-pending-tombstones", "visitor-channels", "settings"]) {
        if (!db.objectStoreNames.contains(name)) db.createObjectStore(name)
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

async function idb<T>(store: string, mode: IDBTransactionMode, action: (objectStore: IDBObjectStore) => IDBRequest): Promise<T> {
  const db = await openDatabase()
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(store, mode)
    const req = action(transaction.objectStore(store))
    req.onsuccess = () => resolve(req.result as T)
    req.onerror = () => reject(req.error)
    transaction.oncomplete = () => db.close()
  })
}

const getRecord = <T>(store: string, key: string) => idb<T | undefined>(store, "readonly", value => value.get(key))
const putRecord = (store: string, key: string, value: unknown) => idb<IDBValidKey>(store, "readwrite", object => object.put(value, key))
const deleteRecord = (store: string, key: string) => idb<undefined>(store, "readwrite", object => object.delete(key))
const allRecords = <T>(store: string) => idb<T[]>(store, "readonly", object => object.getAll())
const clearRecords = (store: string) => idb<undefined>(store, "readwrite", object => object.clear())

async function recoveryLocator(recoveryKey: string): Promise<string> {
  const normalized = normalizeRecoveryPhrase(recoveryKey)
  return sha256Base64Url(textEncoder.encode(`meta-mesh/recovery-locator/v1/${normalized}`))
}

async function ownerSnapshot(): Promise<OwnerSnapshot> {
  return {
    channels: (await allRecords<StoredChannel>("owner-channels")).map(channel => ({
      ...channel,
      bytes: bytesToWire(channel.bytes),
    })),
    pending: await allRecords<PendingRequest>("owner-pending"),
    pendingTombstones: await allRecords<ReplicaTombstone>("owner-pending-tombstones"),
  }
}

async function mergeOwnerSnapshot(
  remote: OwnerSnapshot,
  ownerPersonId: string,
  participant?: Pick<LocalProfile, "identity" | "certificate">,
): Promise<void> {
  if (!remote || !Array.isArray(remote.channels) || !Array.isArray(remote.pending) ||
    !Array.isArray(remote.pendingTombstones) || remote.channels.length > 1_000 ||
    remote.pending.length > 1_000 || remote.pendingTombstones.length > 5_000) {
    throw new Error("Invalid owner snapshot")
  }

  const localPending = await allRecords<PendingRequest>("owner-pending")
  const localTombstones = await allRecords<ReplicaTombstone>("owner-pending-tombstones")
  for (const item of remote.pending) {
    const request = await verifyContactRequest(item.request, Date.parse(item.request.signed.payload.createdAt))
    if (item.requestId !== request.signed.payload.requestId) throw new Error("Invalid pending request id")
  }
  const pending = reconcileReplicaSet<PendingRequest>({
    records: localPending.map(item => ({
      id: item.requestId,
      updatedAt: item.request.signed.payload.createdAt,
      value: item,
    })),
    tombstones: localTombstones,
  }, {
    records: remote.pending.map(item => ({
      id: item.requestId,
      updatedAt: item.request.signed.payload.createdAt,
      value: item,
    })),
    tombstones: remote.pendingTombstones,
  })
  const pendingIds = new Set(pending.records.map(item => item.id))
  for (const item of localPending) if (!pendingIds.has(item.requestId)) await deleteRecord("owner-pending", item.requestId)
  for (const item of pending.records) await putRecord("owner-pending", item.id, item.value)
  for (const item of pending.tombstones) await putRecord("owner-pending-tombstones", item.id, item)

  for (const incoming of remote.channels) {
    if (!incoming.channelId || !incoming.secret || typeof incoming.bytes !== "string") {
      throw new Error("Invalid owner channel")
    }
    let remoteChannel = loadContactChannel(wireToBytes(incoming.bytes))
    if (participant) {
      remoteChannel = await addContactParticipantDeviceCertificate(
        remoteChannel,
        participant.identity,
        participant.certificate,
      )
    }
    remoteChannel = await verifyContactChannel(remoteChannel)
    const remoteBytes = saveContactChannel(remoteChannel)
    if (remoteChannel.ownerPersonId !== ownerPersonId || remoteChannel.channelId !== incoming.channelId) {
      throw new Error("Owner channel does not belong to this identity")
    }
    const local = await getRecord<StoredChannel>("owner-channels", incoming.channelId)
    if (!local) {
      await putRecord("owner-channels", incoming.channelId, { ...incoming, bytes: remoteBytes })
      continue
    }
    if (local.secret !== incoming.secret) throw new Error("Owner channel secret conflict")
    const merged = await mergeContactChannels(loadContactChannel(local.bytes), remoteBytes)
    const labels = reconcileReplicaSet<string>({
      records: local.label ? [{ id: local.channelId, updatedAt: local.labelUpdatedAt ?? new Date(0).toISOString(), value: local.label }] : [],
      tombstones: [],
    }, {
      records: incoming.label ? [{ id: incoming.channelId, updatedAt: incoming.labelUpdatedAt ?? new Date(0).toISOString(), value: incoming.label }] : [],
      tombstones: [],
    })
    const label: ReplicaRecord<string> | undefined = labels.records[0]
    await putRecord("owner-channels", local.channelId, {
      ...local,
      bytes: saveContactChannel(merged),
      label: label?.value,
      labelUpdatedAt: label?.updatedAt,
    })
  }
}

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id)
  if (!element) throw new Error(`Missing #${id}`)
  return element as T
}

function setText(id: string, value: string) { byId(id).textContent = value }
function show(id: string, visible: boolean) { byId(id).hidden = !visible }

function submitOnShortcut(textarea: HTMLTextAreaElement, form: HTMLFormElement) {
  textarea.addEventListener("keydown", event => {
    if (event.key !== "Enter" || (!event.metaKey && !event.ctrlKey)) return
    event.preventDefault()
    form.requestSubmit()
  })
}

async function probeOwner(): Promise<boolean> {
  const module = await loadIroh()
  const node: IrohNode = await module.BrowserNode.start()
  try {
    const response = await request(node, { type: "probe" })
    return response.status === "online"
  } catch { return false }
  finally { await node.close("Probe complete").catch(() => undefined) }
}

function renderTimeline(container: HTMLElement, channel: ContactChannel, selfPersonId: string) {
  container.replaceChildren(...contactTimeline(channel).map(item => {
    const article = document.createElement("article")
    article.className = item.authorPersonId === selfPersonId ? "mesh-message mesh-message--mine" : "mesh-message"
    const body = document.createElement("p")
    body.textContent = item.body
    const time = document.createElement("time")
    time.dateTime = item.createdAt
    time.textContent = new Date(item.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    article.append(body, time)
    return article
  }))
  container.scrollTop = container.scrollHeight
}

async function publicApp(openImmediately = false) {
  const dialog = byId<HTMLDialogElement>("mesh-dialog")
  const status = byId("mesh-presence")
  const panelIds = ["mesh-entry", "mesh-offline", "mesh-new", "mesh-existing", "mesh-pending", "mesh-chat"]
  let profile: LocalProfile | undefined
  let node: IrohNode | undefined
  let current: StoredChannel | undefined
  let phrase = ""
  let recoveryEnvelope: IdentityRecoveryEnvelope | undefined
  let pollTimer: number | undefined
  const identityStore = new BrowserIdentityStore({
    storageKey: "meta-mesh.visitor.identity.v1",
    signatureDomain: CONTACT_SIGNATURE_DOMAIN,
  })

  function showPanel(id?: string) {
    for (const panelId of panelIds) show(panelId, panelId === id)
  }

  async function openDialog() {
    dialog.showModal()
    showPanel()
    setText("mesh-presence", "Checking…")
    status.dataset.state = "checking"
    const cachedOnline = await ((window as any).__meshPresence ?? Promise.resolve(false))
    const online = cachedOnline || await probeOwner()
    setText("mesh-presence", online ? "Bogdan is online" : "Bogdan is offline")
    status.dataset.state = online ? "online" : "offline"
    if (!online) return showPanel("mesh-offline")
    if (current) return showChat()
    const savedKey = await getRecord<string>("settings", "visitor-key")
    if (savedKey) {
      try { return await restore(savedKey) }
      catch { await deleteRecord("settings", "visitor-key") }
    }
    showPanel("mesh-entry")
  }

  async function restore(key: string) {
    if (!chatKeyIsValid(key)) throw new Error("That key is not valid")
    const normalized = normalizeRecoveryPhrase(key)
    if (phrase && phrase !== normalized) {
      await node?.close("Switch conversation").catch(() => undefined)
      node = undefined
      profile = undefined
      current = undefined
      recoveryEnvelope = undefined
    }
    phrase = normalized
    node ??= await startRandomNode()
    if (!profile) {
      const savedEnvelope = await getRecord<IdentityRecoveryEnvelope>("settings", "visitor-envelope")
      if (savedEnvelope?.version === 3) {
        try {
          profile = await identityStore.restoreEnvelope(savedEnvelope, phrase)
          recoveryEnvelope = savedEnvelope
        } catch {
          await deleteRecord("settings", "visitor-envelope")
        }
      }
      if (!profile) {
        const envelopeResponse = await request(node, {
          type: "visitor-envelope",
          recoveryLocator: await recoveryLocator(phrase),
        })
        const fetchedEnvelope = envelopeResponse.recoveryEnvelope as IdentityRecoveryEnvelope | undefined
        if (!fetchedEnvelope) throw new Error("No identity envelope found for this key")
        recoveryEnvelope = fetchedEnvelope
        profile = await identityStore.restoreEnvelope(fetchedEnvelope, phrase)
        await putRecord("settings", "visitor-envelope", fetchedEnvelope)
      }
    }
    const response = await request(node, { type: "restore", proof: await sessionProof(profile) })
    if (response.status === "pending") {
      await putRecord("settings", "visitor-key", phrase)
      if (recoveryEnvelope) await putRecord("settings", "visitor-envelope", recoveryEnvelope)
      showPanel("mesh-pending")
      startPolling()
      return
    }
    if (!response.channels?.length) throw new Error("No conversation found for this key")
    const remote = response.channels[0]
    current = {
      channelId: remote.channelId,
      secret: remote.secret,
      bytes: wireToBytes(remote.bytes),
      recoveryLocator: remote.recoveryLocator,
      recoveryEnvelope: remote.recoveryEnvelope,
    }
    await putRecord("visitor-channels", profile.identity.personId, current)
    await putRecord("settings", "visitor-key", phrase)
    if (recoveryEnvelope) await putRecord("settings", "visitor-envelope", recoveryEnvelope)
    showChat()
    startPolling()
  }

  function showChat() {
    if (!profile || !current) return
    showPanel("mesh-chat")
    setText("mesh-chat-key", phrase)
    renderTimeline(byId("mesh-messages"), loadContactChannel(current.bytes), profile.identity.personId)
  }

  async function sync() {
    if (!node || !profile || !current) return
    const response = await request(node, {
      type: "sync",
      proof: await sessionProof(profile),
      channelId: current.channelId,
      secret: current.secret,
      bytes: bytesToWire(current.bytes),
    })
    current.bytes = wireToBytes(response.bytes)
    await putRecord("visitor-channels", profile.identity.personId, current)
    showChat()
    setText("mesh-chat-state", "online")
  }

  function startPolling() {
    window.clearInterval(pollTimer)
    pollTimer = window.setInterval(async () => {
      try {
        if (current) await sync()
        else if (phrase) await restore(phrase)
      } catch { setText("mesh-chat-state", "offline") }
    }, 4_000)
  }

  byId("mesh-open").addEventListener("click", event => { event.preventDefault(); void openDialog() })
  byId("mesh-close").addEventListener("click", () => dialog.close())
  byId("mesh-choose-new").addEventListener("click", () => {
    void (async () => {
      await node?.close("New conversation").catch(() => undefined)
      identityStore.reset()
      const created = await identityStore.createRecoverable("legacy", "Visitor")
      phrase = created.recoveryKey
      recoveryEnvelope = created.recoveryEnvelope
      profile = created.profile
      node = undefined
      current = undefined
      setText("mesh-key", phrase)
      showPanel("mesh-new")
    })().catch(error => {
      setText("mesh-new-error", error instanceof Error ? error.message : String(error))
      showPanel("mesh-new")
    })
  })
  byId("mesh-choose-existing").addEventListener("click", () => {
    showPanel("mesh-existing")
  })
  byId<HTMLButtonElement>("mesh-copy-key").addEventListener("click", async event => {
    await navigator.clipboard.writeText(phrase)
    ;(event.currentTarget as HTMLButtonElement).textContent = "Copied"
  })
  byId<HTMLButtonElement>("mesh-show-chat-key").addEventListener("click", event => {
    const key = byId("mesh-chat-key-panel")
    key.hidden = !key.hidden
    ;(event.currentTarget as HTMLButtonElement).ariaExpanded = String(!key.hidden)
  })
  byId<HTMLButtonElement>("mesh-copy-chat-key").addEventListener("click", async event => {
    await navigator.clipboard.writeText(phrase)
    ;(event.currentTarget as HTMLButtonElement).textContent = "Copied"
  })
  byId<HTMLFormElement>("mesh-existing-form").addEventListener("submit", async event => {
    event.preventDefault()
    try { await restore(byId<HTMLInputElement>("mesh-existing-key").value) }
    catch (error) { setText("mesh-existing-error", error instanceof Error ? error.message : String(error)) }
  })
  byId<HTMLFormElement>("mesh-new-form").addEventListener("submit", async event => {
    event.preventDefault()
    try {
      const name = byId<HTMLInputElement>("mesh-name").value
      if (!profile || !recoveryEnvelope) throw new Error("Create a new key first")
      node = await startRandomNode()
      const requestValue = await createContactRequest(profile, {
        displayName: name,
        firstMessage: byId<HTMLTextAreaElement>("mesh-first-message").value,
      })
      const response = await request(node, {
        type: "contact",
        request: requestValue,
        recoveryLocator: await recoveryLocator(phrase),
        recoveryEnvelope,
      })
      if (response.status !== "pending") throw new Error("Request was not accepted")
      await putRecord("settings", "visitor-key", phrase)
      await putRecord("settings", "visitor-envelope", recoveryEnvelope)
      showPanel("mesh-pending")
      startPolling()
    } catch (error) { setText("mesh-new-error", error instanceof Error ? error.message : String(error)) }
  })
  byId<HTMLFormElement>("mesh-chat-form").addEventListener("submit", async event => {
    event.preventDefault()
    if (!profile || !current) return
    const input = byId<HTMLTextAreaElement>("mesh-chat-input")
    try {
      let channel = loadContactChannel(current.bytes)
      channel = await appendContactMessage(channel, await createContactMessage(profile, current.channelId, input.value))
      current.bytes = saveContactChannel(channel)
      input.value = ""
      await sync()
    } catch (error) { setText("mesh-chat-state", error instanceof Error ? error.message : String(error)) }
  })
  submitOnShortcut(byId("mesh-chat-input"), byId("mesh-chat-form"))
  if (openImmediately) await openDialog()
}

async function ownerApp() {
  let owner: LocalProfile
  let node: IrohNode
  let current: StoredChannel | undefined
  let primary = false
  let ownerEnvelope: IdentityPassphraseEnvelope
  let ownerPollTimer: number | undefined
  let unlocking = false
  const identityStore = new BrowserIdentityStore({
    storageKey: "meta-mesh.owner.identity.v1",
    signatureDomain: CONTACT_SIGNATURE_DOMAIN,
  })

  async function syncOwnerReplica() {
    if (primary) return
    const response = await request(node, {
      type: "owner-sync",
      proof: await sessionProof(owner),
      snapshot: await ownerSnapshot(),
    })
    await mergeOwnerSnapshot(response.snapshot, owner.identity.personId, owner)
    if (current) current = await getRecord<StoredChannel>("owner-channels", current.channelId)
    await refresh()
    if (current) renderOwnerChat()
    setText("oi-status", "linked")
    byId("oi-status").dataset.state = "online"
  }

  function startOwnerPolling() {
    window.clearInterval(ownerPollTimer)
    ownerPollTimer = window.setInterval(async () => {
      try { await syncOwnerReplica() }
      catch {
        setText("oi-status", "primary offline")
        byId("oi-status").dataset.state = "offline"
      }
    }, 4_000)
  }

  async function deletePending(requestId: string) {
    const tombstone: ReplicaTombstone = { id: requestId, deletedAt: new Date().toISOString() }
    await putRecord("owner-pending-tombstones", requestId, tombstone)
    await deleteRecord("owner-pending", requestId)
  }

  async function refresh() {
    const pending = await allRecords<PendingRequest>("owner-pending")
    const channels = await allRecords<StoredChannel>("owner-channels")
    const list = byId("oi-list")
    list.replaceChildren()
    for (const item of pending) {
      const button = document.createElement("button")
      button.className = "oi-chat oi-chat--pending"
      button.textContent = item.request.signed.payload.firstMessage.slice(0, 48)
      button.addEventListener("click", () => renderPending(item))
      list.append(button)
    }
    for (const item of channels) {
      const channel = loadContactChannel(item.bytes)
      const button = document.createElement("button")
      button.className = "oi-chat"
      button.textContent = item.label || channel.request.signed.payload.firstMessage.slice(0, 48)
      button.addEventListener("click", () => { current = item; renderOwnerChat() })
      list.append(button)
    }
    setText("oi-count", `${channels.length} chats · ${pending.length} pending`)
  }

  function renderPending(item: PendingRequest) {
    current = undefined
    show("oi-empty", false)
    show("oi-conversation", false)
    show("oi-request", true)
    setText("oi-request-name", item.request.signed.payload.displayName)
    setText("oi-request-message", item.request.signed.payload.firstMessage)
    byId<HTMLButtonElement>("oi-accept").onclick = async () => {
      const secret = toBase64Url(crypto.getRandomValues(new Uint8Array(32)))
      const decision = await createContactDecision(owner, item.request, true, { channelSecret: secret })
      const channel = await createContactChannel(item.request, decision)
      const stored: StoredChannel = {
        channelId: decision.signed.payload.channelId!,
        secret,
        bytes: saveContactChannel(channel),
        recoveryLocator: item.recoveryLocator,
        recoveryEnvelope: item.recoveryEnvelope,
      }
      await putRecord("owner-channels", stored.channelId, stored)
      await deletePending(item.requestId)
      current = stored
      if (!primary) await syncOwnerReplica()
      await refresh()
      renderOwnerChat()
    }
    byId<HTMLButtonElement>("oi-decline").onclick = async () => {
      await deletePending(item.requestId)
      if (!primary) await syncOwnerReplica()
      await refresh()
      show("oi-request", false)
      show("oi-empty", true)
    }
  }

  function renderOwnerChat() {
    if (!current) return
    const channel = loadContactChannel(current.bytes)
    show("oi-empty", false)
    show("oi-request", false)
    show("oi-conversation", true)
    const name = current.label || channel.request.signed.payload.firstMessage.slice(0, 48)
    setText("oi-chat-title", name)
    byId<HTMLInputElement>("oi-rename").value = name
    renderTimeline(byId("oi-messages"), channel, owner.identity.personId)
  }

  async function handleStream(stream: IrohStream) {
    try {
      const incoming = JSON.parse(textDecoder.decode(await stream.read()))
      if (incoming.type === "probe") return reply(stream, { status: "online" })
      if (incoming.type === "owner-envelope") {
        return reply(stream, { status: "ready", passphraseEnvelope: ownerEnvelope })
      }
      if (incoming.type === "visitor-envelope") {
        const locator = String(incoming.recoveryLocator ?? "")
        const pending = (await allRecords<PendingRequest>("owner-pending"))
          .find(item => item.recoveryLocator === locator)
        const channel = (await allRecords<StoredChannel>("owner-channels"))
          .find(item => item.recoveryLocator === locator)
        const envelope = pending?.recoveryEnvelope ?? channel?.recoveryEnvelope
        return reply(stream, envelope
          ? { status: "ready", recoveryEnvelope: envelope }
          : { status: "missing" })
      }
      if (incoming.type === "contact") {
        const contact = await verifyContactRequest(incoming.request)
        const envelope = incoming.recoveryEnvelope as IdentityRecoveryEnvelope
        const locator = String(incoming.recoveryLocator ?? "")
        if (envelope?.kind !== "mesh-identity-recovery" || envelope.version !== 3 ||
          envelope.personId !== contact.signed.payload.personId || !locator) {
          throw new Error("Invalid identity recovery envelope")
        }
        const item: PendingRequest = {
          requestId: contact.signed.payload.requestId,
          request: contact,
          recoveryLocator: locator,
          recoveryEnvelope: envelope,
        }
        if (!await getRecord<ReplicaTombstone>("owner-pending-tombstones", item.requestId)) {
          await putRecord("owner-pending", item.requestId, item)
        }
        await refresh()
        return reply(stream, { status: "pending" })
      }
      if (incoming.type === "owner-sync") {
        const proof = await verifySession(incoming.proof)
        if (proof.identity.personId !== owner.identity.personId) throw new Error("Owner identity rejected")
        await mergeOwnerSnapshot(incoming.snapshot, owner.identity.personId, {
          identity: proof.identity,
          certificate: proof.certificates[0]!,
        })
        await refresh()
        if (current) {
          current = await getRecord<StoredChannel>("owner-channels", current.channelId)
          if (current) renderOwnerChat()
        }
        return reply(stream, { status: "ready", snapshot: await ownerSnapshot() })
      }
      if (incoming.type === "restore") {
        const proof = await verifySession(incoming.proof)
        const channels: StoredChannel[] = []
        for (const item of await allRecords<StoredChannel>("owner-channels")) {
          let channel = loadContactChannel(item.bytes)
          if (channel.visitorPersonId !== proof.identity.personId) continue
          channel = await addContactParticipantDeviceCertificate(channel, proof.identity, proof.certificates[0]!)
          item.bytes = saveContactChannel(channel)
          await putRecord("owner-channels", item.channelId, item)
          channels.push(item)
        }
        const pending = (await allRecords<PendingRequest>("owner-pending")).some(item =>
          item.request.signed.payload.personId === proof.identity.personId)
        return reply(stream, channels.length ? {
          status: "ready",
          channels: channels.map(item => ({ ...item, bytes: bytesToWire(item.bytes) })),
        } : { status: pending ? "pending" : "missing" })
      }
      if (incoming.type === "sync") {
        const proof = await verifySession(incoming.proof)
        const stored = await getRecord<StoredChannel>("owner-channels", incoming.channelId)
        if (!stored || stored.secret !== incoming.secret) throw new Error("Conversation key rejected")
        let local = loadContactChannel(stored.bytes)
        if (local.visitorPersonId !== proof.identity.personId) throw new Error("Conversation identity rejected")
        local = await addContactParticipantDeviceCertificate(local, proof.identity, proof.certificates[0]!)
        const merged = await mergeContactChannels(local, wireToBytes(incoming.bytes))
        stored.bytes = saveContactChannel(merged)
        await putRecord("owner-channels", stored.channelId, stored)
        if (current?.channelId === stored.channelId) { current = stored; renderOwnerChat() }
        return reply(stream, { status: "ready", bytes: bytesToWire(stored.bytes) })
      }
      throw new Error("Unknown request")
    } catch (error) {
      return reply(stream, { error: error instanceof Error ? error.message : String(error) })
    }
  }

  async function acceptConnections() {
    const acceptor = await node.accept()
    while (true) {
      const connection = await acceptor.accept()
      if (!connection) continue
      void (async () => {
        try {
          while (true) await handleStream(await connection.acceptStream())
        } catch { await connection.close().catch(() => undefined) }
      })()
    }
  }

  byId<HTMLFormElement>("oi-unlock-form").addEventListener("submit", async event => {
    event.preventDefault()
    if (unlocking) return
    const form = event.currentTarget as HTMLFormElement
    const input = byId<HTMLTextAreaElement>("oi-key")
    const submit = byId<HTMLButtonElement>("oi-unlock-submit")
    const key = input.value
    let candidate: IrohNode | undefined
    unlocking = true
    form.ariaBusy = "true"
    input.readOnly = true
    submit.disabled = true
    submit.textContent = "Connecting…"
    setText("oi-error", "")
    try {
      candidate = await startRandomNode()
      let primaryOnline = false
      try { primaryOnline = (await request(candidate, { type: "probe" })).status === "online" }
      catch { primaryOnline = false }
      let savedEnvelope = await getRecord<IdentityPassphraseEnvelope>("settings", "owner-envelope")
      if (primaryOnline) {
        if (savedEnvelope?.version !== 1) {
          const response = await request(candidate, { type: "owner-envelope" })
          savedEnvelope = response.passphraseEnvelope
          if (!savedEnvelope) throw new Error("Owner identity envelope is unavailable")
          await putRecord("settings", "owner-envelope", savedEnvelope)
        }
        ownerEnvelope = savedEnvelope
        owner = await identityStore.restorePassphraseEnvelope(ownerEnvelope, key, "Bogdan")
        node = candidate
        primary = false
        await syncOwnerReplica()
        candidate = undefined
        startOwnerPolling()
      } else {
        await candidate.close("No primary found").catch(() => undefined)
        candidate = await startNode(key)
        if (candidate.endpointId !== OWNER_ENDPOINT) {
          await candidate.close("Wrong owner key")
          candidate = undefined
          throw new Error("Wrong key")
        }
        if (savedEnvelope?.version === 1) {
          ownerEnvelope = savedEnvelope
          owner = await identityStore.restorePassphraseEnvelope(ownerEnvelope, key, "Bogdan")
        } else {
          for (const store of ["owner-channels", "owner-pending", "owner-pending-tombstones"]) {
            await clearRecords(store)
          }
          identityStore.reset()
          const created = await identityStore.createPassphrase(key, "Bogdan")
          owner = created.profile
          ownerEnvelope = created.passphraseEnvelope
          await putRecord("settings", "owner-envelope", ownerEnvelope)
        }
        node = candidate
        candidate = undefined
        primary = true
      }
      show("oi-unlock", false)
      show("oi-app", true)
      await refresh()
      setText("oi-status", primary ? "primary" : "linked")
      if (primary) void acceptConnections()
    } catch (error) {
      await candidate?.close("Owner unlock failed").catch(() => undefined)
      setText("oi-error", ownerUnlockError(error))
    } finally {
      unlocking = false
      form.ariaBusy = "false"
      input.readOnly = false
      submit.disabled = false
      submit.textContent = "Go online"
    }
  })

  byId<HTMLFormElement>("oi-rename-form").addEventListener("submit", async event => {
    event.preventDefault()
    if (!current) return
    current.label = byId<HTMLInputElement>("oi-rename").value.trim()
    current.labelUpdatedAt = new Date().toISOString()
    await putRecord("owner-channels", current.channelId, current)
    if (!primary) await syncOwnerReplica()
    await refresh()
    renderOwnerChat()
  })
  byId<HTMLFormElement>("oi-chat-form").addEventListener("submit", async event => {
    event.preventDefault()
    if (!current) return
    const input = byId<HTMLTextAreaElement>("oi-chat-input")
    let channel = loadContactChannel(current.bytes)
    channel = await appendContactMessage(channel, await createContactMessage(owner, current.channelId, input.value))
    current.bytes = saveContactChannel(channel)
    await putRecord("owner-channels", current.channelId, current)
    input.value = ""
    if (!primary) await syncOwnerReplica()
    renderOwnerChat()
  })
  submitOnShortcut(byId("oi-chat-input"), byId("oi-chat-form"))
}

export async function boot(openPublicImmediately = false) {
  await Automerge.initializeWasm(automergeWasmUrl)
  const page = document.body.dataset.meshPage
  if (page === "public") await publicApp(openPublicImmediately)
  if (page === "owner") await ownerApp()
}
