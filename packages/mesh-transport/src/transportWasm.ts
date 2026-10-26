import initializeGeneratedTransport, { initSync as initializeGeneratedTransportSync } from "../transport-wasm/meta_mesh.js"

export * from "../transport-wasm/meta_mesh.js"

type TransportExports = Awaited<ReturnType<typeof initializeGeneratedTransport>>

let initialization: Promise<TransportExports> | undefined
let initialized = false

/** Keep concurrent callers on one instance; replacing its memory invalidates live Rust callbacks. */
export default function initializeTransport(
  ...args: Parameters<typeof initializeGeneratedTransport>
): Promise<TransportExports> {
  if (initialized) return initialization ?? initializeGeneratedTransport(...args)
  if (initialization) return initialization

  const pending = initializeGeneratedTransport(...args).then(
    (exports) => {
      initialized = true
      return exports
    },
    (error: unknown) => {
      if (initialization === pending) initialization = undefined
      throw error
    },
  )
  initialization = pending
  return pending
}

export function initSync(
  ...args: Parameters<typeof initializeGeneratedTransportSync>
): ReturnType<typeof initializeGeneratedTransportSync> {
  if (initialization && !initialized) {
    throw new Error("Transport WASM asynchronous initialization is already in progress")
  }

  const exports = initializeGeneratedTransportSync(...args)
  initialized = true
  return exports
}
