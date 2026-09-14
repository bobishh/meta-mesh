import { IROH_MODULE_URL, OWNER_ENDPOINT } from "./config"

const page = document.body.dataset.meshPage
const ONLINE_POLL_MS = 15_000
const OFFLINE_POLL_MS = 5_000

type PresenceState = "checking" | "online" | "offline"

let presenceTimer: number | undefined
let presenceCheck: Promise<boolean> | undefined

function updatePresence(state: PresenceState) {
  const trigger = document.getElementById("mesh-open")
  const label = document.getElementById("mesh-home-presence")
  if (trigger) trigger.dataset.state = state
  if (label) label.textContent = state
}

async function checkPresence(): Promise<boolean> {
  updatePresence("checking")
  let node: any
  let connection: any
  try {
    const module = await import(/* @vite-ignore */ IROH_MODULE_URL)
    await module.default()
    node = await module.BrowserNode.start()
    const operation = (async () => {
      connection = await node.dialRelay(OWNER_ENDPOINT)
      const stream = await connection.openStream()
      await stream.send(new TextEncoder().encode(JSON.stringify({ type: "probe" })))
      await stream.closeSend()
      return JSON.parse(new TextDecoder().decode(await stream.read())).status === "online"
    })()
    const timeout = new Promise<boolean>(resolve => window.setTimeout(() => resolve(false), 4_000))
    const online = await Promise.race([operation, timeout])
    updatePresence(online ? "online" : "offline")
    return online
  } catch {
    updatePresence("offline")
    return false
  } finally {
    await connection?.close().catch(() => undefined)
    await node?.close("Presence checked").catch(() => undefined)
  }
}

function schedulePresenceCheck(delay: number) {
  window.clearTimeout(presenceTimer)
  if (document.hidden) return
  presenceTimer = window.setTimeout(() => { void refreshPresence() }, delay)
}

function refreshPresence(): Promise<boolean> {
  if (presenceCheck) return presenceCheck
  presenceCheck = checkPresence()
  ;(window as any).__meshPresence = presenceCheck
  void presenceCheck.then(online => {
    schedulePresenceCheck(online ? ONLINE_POLL_MS : OFFLINE_POLL_MS)
  }).finally(() => { presenceCheck = undefined })
  return presenceCheck
}

function startPresenceMonitor() {
  void refreshPresence()
  document.addEventListener("visibilitychange", () => {
    window.clearTimeout(presenceTimer)
    if (!document.hidden) void refreshPresence()
  })
  window.addEventListener("online", () => { void refreshPresence() })
  window.addEventListener("offline", () => {
    window.clearTimeout(presenceTimer)
    updatePresence("offline")
  })
}

if (page === "owner") {
  void import("./main").then(module => module.boot())
}

if (page === "public") {
  startPresenceMonitor()
  document.getElementById("mesh-open")?.addEventListener("click", event => {
    event.preventDefault()
    void import("./main").then(module => module.boot(true))
  }, { once: true })
}
