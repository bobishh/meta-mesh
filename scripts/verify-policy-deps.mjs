import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { dirname, resolve } from "node:path"

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const result = spawnSync("cargo", [
  "tree",
  "--manifest-path", "Cargo.toml",
  "--locked",
  "--target", "wasm32-unknown-unknown",
  "-p", "meta-mesh-policy",
  "--edges", "normal",
], {
  cwd: root,
  encoding: "utf8",
  timeout: 90_000,
  maxBuffer: 16 * 1024 * 1024,
})

if (result.error) {
  throw new Error(`Could not verify policy dependency tree: ${result.error.message}`)
}
if (result.status !== 0) {
  process.stderr.write(result.stderr)
  throw new Error(`cargo tree failed with status ${result.status}`)
}

const forbidden = /\b(?:iroh|iroh-gossip|iroh-blobs|iroh-webrtc-transport)\b/i
if (forbidden.test(result.stdout)) {
  throw new Error("Policy WASM dependency tree includes Iroh or WebRTC transport")
}

process.stdout.write("Policy WASM dependency tree excludes Iroh and WebRTC transport.\n")
