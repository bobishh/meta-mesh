import { IROH_MODULE_URL, OWNER_ENDPOINT } from "./config"

const page = document.body.dataset.meshPage

async function checkPresence(): Promise<boolean> {
  const trigger = document.getElementById("mesh-open")
  const label = document.getElementById("mesh-home-presence")
  const update = (state: "checking" | "online" | "offline") => {
    if (trigger) trigger.dataset.state = state
    if (label) label.textContent = state
  }
  update("checking")
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
    update(online ? "online" : "offline")
    return online
  } catch {
    update("offline")
    return false
  } finally {
    await connection?.close().catch(() => undefined)
    await node?.close("Presence checked").catch(() => undefined)
  }
}

if (page === "owner") {
  void import("./main").then(module => module.boot())
}

if (page === "public") {
  ;(window as any).__meshPresence = checkPresence()
  document.getElementById("mesh-open")?.addEventListener("click", event => {
    event.preventDefault()
    void import("./main").then(module => module.boot(true))
  }, { once: true })
}
