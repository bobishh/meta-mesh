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

  it("keeps valid JSON signatures byte-compatible with Rust", async () => {
    const rustEnvelope = WasmIdentityCrypto.signEnvelope(seed, payload, "probe", "MATCH/1")
    const javascriptEnvelope = await signEnvelope(await privateKey(), payload, "probe", "MATCH/1")

    expect(javascriptEnvelope.signature).toBe(rustEnvelope.signature)
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

  it("Given optional undefined object members, when signed and JSON-roundtripped, then the envelope verifies", async () => {
    const envelope = await signEnvelope(await privateKey(), {
      kind: "canonical-probe",
      optional: undefined,
      nested: { omitted: undefined, retained: "yes" },
    }, "probe")
    const roundtripped = JSON.parse(JSON.stringify(envelope))

    expect(roundtripped.payload).toEqual({
      kind: "canonical-probe",
      nested: { retained: "yes" },
    })
    expect(await verifyEnvelope(roundtripped, publicKey)).toBe(true)
  })

  it("roundtrips dangerous JSON keys and omits non-enumerable SDK brand metadata", async () => {
    const brand = Symbol("verified-sdk-value")
    const input = JSON.parse('{"kind":"canonical-probe","__proto__":{"polluted":true},"constructor":"own-value","prototype":{"safe":true}}')
    Object.defineProperty(input, brand, { value: true })
    const envelope = await signEnvelope(await privateKey(), input, "probe")
    const roundtripped = JSON.parse(JSON.stringify(envelope))

    expect(Object.hasOwn(envelope.payload, "__proto__")).toBe(true)
    expect(Object.getPrototypeOf(envelope.payload)).toBe(Object.prototype)
    expect(Object.hasOwn(envelope.payload, brand)).toBe(false)
    expect(roundtripped.payload).toEqual(JSON.parse('{"kind":"canonical-probe","__proto__":{"polluted":true},"constructor":"own-value","prototype":{"safe":true}}'))
    expect(await verifyEnvelope(roundtripped, publicKey)).toBe(true)
  })

  it("roundtrips a bounded matrix of JSON trees with optional undefined object members", async () => {
    const leaves: unknown[] = [null, false, true, 0, -1, 1.5, "", "λ", "𐀀"]
    const depthOne = leaves.flatMap(value => [[value], { value }])
    const depthTwo = depthOne.flatMap(value => [[value, null], { nested: value, flag: false }])
    const shared = { leaf: [null, true, "shared"] }
    const trees = [...leaves, ...depthOne, ...depthTwo, { left: shared, right: shared }]
    const key = await privateKey()

    for (const tree of trees) {
      const input = {
        kind: "canonical-probe",
        optional: undefined,
        data: tree,
        nested: { omitted: undefined, retained: tree },
      }
      const before = structuredClone(input)
      const envelope = await signEnvelope(key, input, "probe")
      const roundtripped = JSON.parse(JSON.stringify(envelope))

      expect(input).toEqual(before)
      expect(await verifyEnvelope(roundtripped, publicKey)).toBe(true)
      expect(roundtripped.payload).toEqual({
        kind: "canonical-probe",
        data: tree,
        nested: { retained: tree },
      })
    }
  })

  it("Given a payload mutated while signing, when signing completes, then emitted payload matches signed bytes", async () => {
    const original = { kind: "canonical-probe", nested: { value: "before" } }
    const pending = signEnvelope(await privateKey(), original, "probe")
    original.nested.value = "after"
    const envelope = await pending

    expect(envelope.payload.nested.value).toBe("before")
    expect(await verifyEnvelope(envelope, publicKey)).toBe(true)
  })

  it("rejects values that JSON cannot represent without ambiguity", async () => {
    const key = await privateKey()
    const cycle: { kind: string; self?: unknown } = { kind: "canonical-probe" }
    cycle.self = cycle
    const invalidValues = [
      [undefined], Number.NaN, 1n, cycle, new Date(0), new Uint8Array([1]),
      new Map(), new Set(), key, () => "value", Symbol("value"),
      { kind: "canonical-probe", [Symbol("key")]: "value" },
    ]

    for (const value of invalidValues) {
      await expect(signEnvelope(key, { kind: "canonical-probe", value }, "probe")).rejects.toThrow()
    }
  })

  it("does not treat an added undefined member as unsigned data", async () => {
    const envelope = await signEnvelope(await privateKey(), { kind: "canonical-probe" }, "probe")

    expect(await verifyEnvelope({ ...envelope, payload: { ...envelope.payload, extra: undefined } }, publicKey)).toBe(false)
  })
})
