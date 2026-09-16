import { describe, expect, it } from "vitest"
import * as fs from "node:fs"
import * as path from "node:path"
import { parseItfTrace } from "./itf"

describe("ITF parser", () => {
  it("parses generated durable_delivery trace", () => {
    const root = path.resolve(__dirname, "../../../../quint/traces")
    const raw = fs.readFileSync(path.join(root, "durable_delivery_mbt.itf.json"), "utf-8")
    const trace = parseItfTrace(raw)
    expect(trace.states.length).toBeGreaterThan(0)
    expect(trace.states[0].actionTaken).toBe("init")
    console.log("State 0 vars:", trace.states[0].vars)
    console.log("State 1 action:", trace.states[1].actionTaken, trace.states[1].nondetPicks)
  })
})
