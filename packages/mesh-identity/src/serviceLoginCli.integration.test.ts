import { spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import { resolve } from "node:path"
import { describe, expect, it } from "vitest"
import { createServiceLoginApproval, profileFromIdentitySeedForDevice, type ServiceLoginRequest } from "./index"

const cliPath = process.env.META_MESH_VERIFY_SERVICE_LOGIN_BIN ??
  resolve(new URL("../../../target/debug/examples/verify_service_login", import.meta.url).pathname)

describe("native service-login verifier CLI", () => {
  it.skipIf(!existsSync(cliPath))("Given an SDK-signed approval, when verified natively, then accept the exact request and reject substitutions", async () => {
    const now = Date.now()
    const request: ServiceLoginRequest = {
      kind: "mesh-service-login-request",
      version: 1,
      origin: "https://acidreflux.example",
      challenge: "a".repeat(64),
      expires_at: Math.floor(now / 1_000) + 90,
    }
    const profile = await profileFromIdentitySeedForDevice(crypto.getRandomValues(new Uint8Array(32)), "Owner")
    const approval = await createServiceLoginApproval(profile, request, { now: () => now })

    const verify = (expectedChallenge: string) => spawnSync(cliPath, [], {
      encoding: "utf8",
      input: `${JSON.stringify({
        identity: approval.identity,
        deviceId: approval.deviceId,
        certificates: approval.certificates,
        proof: approval.proof,
        expectedOrigin: request.origin,
        expectedChallenge,
        expectedExpiresAtMs: request.expires_at * 1_000,
        nowMs: now,
      })}\n`,
      timeout: 5_000,
    })

    const accepted = verify(request.challenge)
    expect(accepted.status).toBe(0)
    expect(JSON.parse(accepted.stdout)).toEqual({
      verified: true,
      personId: profile.identity.personId,
      deviceId: profile.device.deviceId,
    })

    const substituted = verify("b".repeat(64))
    expect(substituted.status).toBe(0)
    expect(JSON.parse(substituted.stdout)).toMatchObject({ verified: false })
  })
})
