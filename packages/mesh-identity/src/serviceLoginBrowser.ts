import { toBase64Url } from "./index"
import { encodeServiceLoginRequest } from "./serviceLoginClient"
import type { ServiceLoginApproval, ServiceLoginRequest } from "./serviceLogin"

export type ServiceLoginChallenge = ServiceLoginRequest & { identity_origin: string }

/** Fetch a fresh service challenge and redirect this tab to Identity consent. */
export async function beginServiceLogin(
  issueRequest: () => Promise<ServiceLoginChallenge>,
  location: Location = window.location,
): Promise<void> {
  const challenge = await issueRequest()
  const { identity_origin: identityOrigin, ...request } = challenge
  encodeServiceLoginRequest(request, Date.now())
  const identity = new URL(identityOrigin)
  if (!validOrigin(identity)) throw new Error("Identity sign-in origin is invalid")
  const loginUrl = new URL("/login", identity)
  loginUrl.hash = new URLSearchParams({ request: encodeServiceLoginRequest(request) }).toString()
  location.assign(loginUrl.href)
}

/** Build the fixed same-origin return URL carrying a short-lived signed approval. */
export function serviceLoginApprovalReturnUrl(
  request: ServiceLoginRequest,
  approval: ServiceLoginApproval,
  now = Date.now(),
): string {
  encodeServiceLoginRequest(request, now)
  const callback = new URL(request.return_to)
  const serialized = JSON.stringify(approval)
  if (!serialized || serialized.length > 64_000) throw new Error("Identity approval is too large")
  callback.hash = new URLSearchParams({ mesh_service_login_approval: toBase64Url(new TextEncoder().encode(serialized)) }).toString()
  return callback.href
}

/** Capture the fixed callback proof before app code can send it in another request. */
export async function captureServiceLoginCallback(
  exchange: (challenge: string, approval: ServiceLoginApproval) => Promise<unknown>,
  location: Location = window.location,
  history: History = window.history,
): Promise<boolean> {
  const current = new URL(location.href)
  if (current.pathname !== "/.well-known/mesh-service-login/callback") return false
  const params = new URLSearchParams(current.hash.slice(1))
  const encoded = params.get("mesh_service_login_approval") ?? ""
  history.replaceState(null, "", `${current.pathname}${current.search}`)
  if (!encoded || encoded.length > 96_000 || !/^[A-Za-z0-9_-]+$/u.test(encoded)) {
    throw new Error("Identity approval is missing or invalid")
  }
  let approval: ServiceLoginApproval
  try {
    const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - encoded.length % 4) % 4)
    const binary = atob(base64)
    approval = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(
      Uint8Array.from(binary, character => character.charCodeAt(0)))) as ServiceLoginApproval
  } catch {
    throw new Error("Identity approval is invalid")
  }
  const payload = approval?.proof?.payload
  if (approval?.proof?.payload?.kind !== "mesh-service-login" || payload.version !== 1 ||
      payload.origin !== current.origin || typeof payload.challenge !== "string" || !/^[a-f0-9]{64}$/u.test(payload.challenge)) {
    throw new Error("Identity approval does not match this service")
  }
  await exchange(payload.challenge, approval)
  return true
}

function validOrigin(url: URL): boolean {
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
  return url.origin === url.href.replace(/\/$/u, "") && !url.username && !url.password &&
    (url.protocol === "https:" || (url.protocol === "http:" && loopback))
}
