import { expect, it } from "vitest"
import { fromBase64Url } from "@meta-uber/mesh-identity"
import { meshRustRuntime } from "./runtime"
import fixture from "../fixtures/history-control-v2.json"

const cases = fixture.cases as Array<{
  name: string
  control: Record<string, unknown>
  document: string
  allowed: boolean
}>

it("Given original v2 control observations, when a v3 reader loads them, then retain original policy metadata and report the current compiled rules separately", () => {
  expect(fixture.policy).toBe("mesh-causal-admission@2")
  expect(meshRustRuntime().state.causalAdmissionPolicyId()).toBe("mesh-causal-admission@3")
})

it.each(cases)("Given Native history control vector $name, when packaged policy WASM validates it, then match Native authorization", vector => {
  const snapshot = {
    ...vector.control,
    document: Array.from(fromBase64Url(vector.document)),
  }
  let allowed = true
  try {
    meshRustRuntime().state.admitWorkspaceChangeAuthorizations([], snapshot, [], 0)
  } catch {
    allowed = false
  }
  expect(allowed).toBe(vector.allowed)
})
