import { describe, expect, it } from "vitest"
import { WasmIdentityCrypto } from "@meta-uber/mesh-transport/wasm"
import {
  canonicalizeJson, signEnvelope, signatureInput, toBase64Url, verifyEnvelope,
} from "./index"

const seed = Uint8Array.from({ length: 32 }, (_, index) => index + 1)
const publicKey = WasmIdentityCrypto.publicKeyFromSeed(seed)
const payload = { kind: "canonical-probe", "\uE000": 1, "\u{10000}": 2 }

async function privateKey(): Promise<CryptoKey> {
  const prefix = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])
  return crypto.subtle.importKey(
    "pkcs8", new Uint8Array([...prefix, ...seed]), { name: "Ed25519" }, false, ["sign"],
  )
}

describe("cross-runtime canonical signing", () => {
  it("preserves stored browser canonical bytes for hashes and recovery", () => {
    expect(canonicalizeJson(payload)).toBe('{"kind":"canonical-probe","\u{10000}":2,"\uE000":1}')
  })
  it.each([
    payload,
    { kind: "canonical-probe", nested: [payload], "\u{10ffff}": 1, "\uffff": 2 },
    { kind: "canonical-probe", count: 1e21, small: 1e-7 },
    { kind: "canonical-probe", count: 1e20, small: 1e-6, integral: 1.0, zero: -0 },
  ])("Given Unicode keys or boundary numbers, when Rust signs, then JS verifies: %j", (value) => {
    const native = WasmIdentityCrypto.signEnvelope(seed, value, "probe", "MATCH/1")
    return expect(verifyEnvelope({ ...native, payload: value }, publicKey)).resolves.toBe(true)
  })

  it("Given a Rust Unicode envelope, when verified by JS, then the signature is accepted", async () => {
    const envelope = WasmIdentityCrypto.signEnvelope(seed, payload, "probe", "MATCH/1")
    expect(await verifyEnvelope({ ...envelope, payload }, publicKey)).toBe(true)
  })

  it.each([payload, { kind: "canonical-probe", count: 1e20, small: 1e-6, integral: 1, zero: -0 }])("Given a new JS envelope, when verified by Rust, then the signature is accepted: %j", async (value) => {
    const envelope = await signEnvelope(await privateKey(), value, "probe")
    expect(WasmIdentityCrypto.verifyEnvelope(envelope, publicKey, "MATCH/1")).toBe(true)
  })

  it("Given a saved legacy JS envelope, when verified, then it stays readable but tampering is rejected", async () => {
    // Fixed pre-fix browser bytes use UTF-16 key order, independently of the new canonicalizer.
    const legacyBytes = '{"kind":"canonical-probe","\u{10000}":2,"\uE000":1}'
    const signature = await crypto.subtle.sign(
      { name: "Ed25519" }, await privateKey(), signatureInput(payload.kind, legacyBytes),
    )
    const envelope = { payload, signerKeyId: "probe", signature: toBase64Url(new Uint8Array(signature)) }
    expect(await verifyEnvelope(envelope, publicKey)).toBe(true)
    expect(await verifyEnvelope({ ...envelope, payload: { ...payload, "\uE000": 3 } }, publicKey)).toBe(false)
  })
})
