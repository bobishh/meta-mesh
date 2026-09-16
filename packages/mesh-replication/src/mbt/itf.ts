export type ItfState = {
  meta: { index: number }
  actionTaken?: string
  nondetPicks?: Record<string, unknown>
  vars: Record<string, unknown>
}

export type ItfTrace = {
  source: string
  vars: string[]
  states: ItfState[]
}

export function parseItfValue(val: unknown): unknown {
  if (val === null || val === undefined) return val
  if (typeof val !== "object") return val

  const obj = val as Record<string, unknown>

  if ("#bigint" in obj && typeof obj["#bigint"] === "string") {
    return Number(obj["#bigint"])
  }
  if ("#set" in obj && Array.isArray(obj["#set"])) {
    return new Set(obj["#set"].map(parseItfValue))
  }
  if ("#map" in obj && Array.isArray(obj["#map"])) {
    return new Map((obj["#map"] as [unknown, unknown][]).map(([k, v]) => [parseItfValue(k), parseItfValue(v)]))
  }
  if ("#tup" in obj && Array.isArray(obj["#tup"])) {
    return obj["#tup"].map(parseItfValue)
  }
  if ("tag" in obj && typeof obj.tag === "string") {
    if (obj.tag === "None") return undefined
    if (obj.tag === "Some" && "value" in obj) return parseItfValue(obj.value)
  }

  if (Array.isArray(val)) {
    return val.map(parseItfValue)
  }

  const result: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(obj)) {
    result[k] = parseItfValue(v)
  }
  return result
}

export function parseItfTrace(jsonString: string): ItfTrace {
  const parsed = JSON.parse(jsonString)
  const states: ItfState[] = (parsed.states ?? []).map((rawState: Record<string, unknown>) => {
    const meta = (rawState["#meta"] ?? {}) as { index: number }
    const actionTaken = rawState["mbt::actionTaken"] as string | undefined
    const nondetPicks = rawState["mbt::nondetPicks"] as Record<string, unknown> | undefined

    const vars: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(rawState)) {
      if (k === "#meta" || k === "mbt::actionTaken" || k === "mbt::nondetPicks") continue
      // Simplify variable name by stripping module prefix if present
      const shortKey = k.includes("::") ? k.split("::").pop()! : k
      vars[shortKey] = parseItfValue(v)
    }

    return {
      meta,
      actionTaken,
      nondetPicks: nondetPicks ? (parseItfValue(nondetPicks) as Record<string, unknown>) : undefined,
      vars,
    }
  })

  return {
    source: parsed["#meta"]?.source ?? "",
    vars: parsed.vars ?? [],
    states,
  }
}
