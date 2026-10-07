import { afterEach, beforeEach, describe, expect, it } from "vitest"
import {
  PairingError,
  createPairingInvite,
  decodePairingFrame,
  encodePairingFrame,
  pairingInviteUrl,
  parsePairingInvite,
  createDeviceEnrollmentInvite,
  createWorkspaceJoinInvite,
  invitationUrl,
  parseInvitation,
  inspectPairingFrame,
  installPairingCodec,
} from "./index"

let restoreCodec: (() => void) | undefined

beforeEach(() => {
  restoreCodec = installPairingCodec({
    encode: (type, secret, bytes) => {
      const header = new TextEncoder().encode(`${JSON.stringify({ type, version: "0.0.1", secret })}\n`)
      const frame = new Uint8Array(header.length + bytes.length)
      frame.set(header)
      frame.set(bytes, header.length)
      return frame
    },
    inspect: frame => {
      const separator = frame.indexOf(10)
      if (separator < 0) throw new Error("Pairing frame missing")
      return JSON.parse(new TextDecoder().decode(frame.slice(0, separator)))
    },
    decode: (frame, expectedType, expectedSecret) => {
      const separator = frame.indexOf(10)
      if (separator < 0) throw new Error("Pairing frame missing")
      const header = JSON.parse(new TextDecoder().decode(frame.slice(0, separator)))
      if (header.type !== expectedType || header.version !== "0.0.1" || header.secret !== expectedSecret) {
        throw new Error("Pairing authorization failed")
      }
      return frame.slice(separator + 1)
    },
  })
})

afterEach(() => restoreCodec?.())

describe("pairing protocol", () => {
  it("Given Rust runtime is not installed, when framing starts, then it fails closed", () => {
    const restoreMissingCodec = installPairingCodec(undefined)
    try {
      expect(() => encodePairingFrame("sync-request", "secret-a", new Uint8Array())).toThrow("Rust pairing codec is not installed")
    } finally {
      restoreMissingCodec()
    }
  })

  it("Given a pairing link, when parsed, then it preserves the endpoint and secret", () => {
    const invite = createPairingInvite("endpoint-a", "secret-a")

    expect(parsePairingInvite(pairingInviteUrl("https://match.example", invite))).toEqual(invite)
  })

  it("Given an empty stream, when decoded, then it rejects before merge", () => {
    expect(() => decodePairingFrame(new Uint8Array(), "sync-request", "secret-a")).toThrow(PairingError)
  })

  it("Given a wrong secret, when decoded, then it rejects before merge", () => {
    const frame = encodePairingFrame("sync-request", "wrong-secret", new Uint8Array([1]))

    expect(() => decodePairingFrame(frame, "sync-request", "secret-a")).toThrow("Pairing authorization failed")
  })

  it("Given a mesh handshake, when inspected, then dispatch reads only its framed type and secret", () => {
    const frame = encodePairingFrame("mesh-handshake-request", "workspace-secret", new Uint8Array([7]))
    expect(inspectPairingFrame(frame)).toEqual({ type: "mesh-handshake-request", secret: "workspace-secret" })
  })

  it.each([
    "mesh-automerge-sync",
    "mesh-control-sync",
    "mesh-owner-workspace-offer",
    "mesh-iroh-gossip",
    "mesh-durable-batch",
    "mesh-durable-ack",
    "mesh-handoff-confirmed",
  ] as const)("Given a %s runtime frame, when inspected, then the live session accepts it", (type) => {
    const frame = encodePairingFrame(type, "workspace-secret", new Uint8Array([7]))

    expect(inspectPairingFrame(frame)).toEqual({ type, secret: "workspace-secret" })
  })

  it("Given the Rust codec adapter, when framing data, then the public API delegates all framing operations", () => {
    const calls: string[] = []
    const restore = installPairingCodec({
      encode: (_type, _secret, bytes) => { calls.push("encode"); return new Uint8Array([10, ...bytes]) },
      inspect: () => { calls.push("inspect"); return { type: "sync-request", secret: "secret-a" } },
      decode: (frame) => { calls.push("decode"); return frame.slice(1) },
    })
    try {
      const frame = encodePairingFrame("sync-request", "secret-a", new Uint8Array([7]))
      expect(inspectPairingFrame(frame)).toEqual({ type: "sync-request", secret: "secret-a" })
      expect(decodePairingFrame(frame, "sync-request", "secret-a")).toEqual(new Uint8Array([7]))
      expect(calls).toEqual(["encode", "inspect", "decode"])
    } finally {
      restore()
    }
  })

  describe("Task 3.1: Discriminated v1 invitations", () => {
    const mockProfile = {
      identity: { personId: "person_1" },
      device: { deviceId: "device_1", publicKey: "pubkey_1" },
    }

    it("creates and strictly parses a device-enrollment invitation", () => {
      const now = 1700000000000
      const invite = createDeviceEnrollmentInvite("endpoint_test", "secret_123", mockProfile, now)
      expect(invite.kind).toBe("device-enrollment")
      expect(invite.expiresAt).toBe(new Date(now + 10 * 60 * 1000).toISOString())

      const url = invitationUrl("https://match.test", invite)
      const parsed = parseInvitation(url, now)
      expect(parsed).toEqual(invite)
    })

    it("creates and strictly parses a workspace-join invitation", () => {
      const now = 1700000000000
      const invite = createWorkspaceJoinInvite(
        "endpoint_test",
        "secret_456",
        mockProfile,
        [{ id: "ws_job", title: "Job search" }],
        { now }
      )
      expect(invite.kind).toBe("workspace-join")
      expect(invite.workspaceId).toBe("ws_job")
      expect(invite.role).toBe("visitor")

      const url = invitationUrl("https://match.test", invite)
      const parsed = parseInvitation(url, now)
      expect(parsed).toEqual(invite)
    })

    it("allows a scoped workspace invitation to grant editor access explicitly", () => {
      const now = 1700000000000
      const invite = createWorkspaceJoinInvite(
        "endpoint_test",
        "secret_456",
        mockProfile,
        [{ id: "ws_job", title: "Job search" }],
        { now, role: "editor" }
      )

      expect(invite.role).toBe("editor")
      expect(parseInvitation(invitationUrl("https://match.test", invite), now)).toEqual(invite)
    })

    it("rejects an expired invitation", () => {
      const past = 1700000000000
      const future = past + 11 * 60 * 1000 // 11 minutes later
      const invite = createDeviceEnrollmentInvite("endpoint_test", "secret_123", mockProfile, past)
      const url = invitationUrl("https://match.test", invite)

      expect(() => parseInvitation(url, future)).toThrow(/This invitation has expired/i)
    })

    it("rejects legacy v0 invitation with upgrade message", () => {
      const legacyUrl = "https://match.test/pair#v=0.0.1&endpoint=ep_legacy&secret=sec_legacy"
      expect(() => parseInvitation(legacyUrl)).toThrow(/This sync link was created by an older version of Match\. Please create a new invitation\./i)
    })

    it("rejects device-enrollment with forbidden workspace fields", () => {
      const url = "https://match.test/pair#v=1&kind=device-enrollment&invitationId=inv_1&issuerPersonId=p1&issuerDeviceId=d1&issuerPublicKey=pk1&endpoint=ep1&createdAt=2026-01-01T00:00:00.000Z&expiresAt=2099-01-01T00:00:00.000Z&secret=sec1&workspaceId=ws_illegal"
      expect(() => parseInvitation(url)).toThrow(/wrong-kind/i)
      expect(() => parseInvitation(url.replace("workspaceId=ws_illegal", "workspaceIds=ws_illegal"))).toThrow(/wrong-kind/i)
    })

    it("rejects workspace-join without required workspace fields", () => {
      const url = "https://match.test/pair#v=1&kind=workspace-join&invitationId=inv_1&issuerPersonId=p1&issuerDeviceId=d1&issuerPublicKey=pk1&endpoint=ep1&createdAt=2026-01-01T00:00:00.000Z&expiresAt=2099-01-01T00:00:00.000Z&secret=sec1"
      expect(() => parseInvitation(url)).toThrow(/missing workspace/i)
    })

    it("rejects ambiguous invitation keys and malformed workspace lists", () => {
      const invite = createWorkspaceJoinInvite("ep1", "sec1", mockProfile, [
        { id: "ws_1", title: "One" },
        { id: "ws_2", title: "Two" },
      ], { now: 1700000000000 })
      const validUrl = invitationUrl("https://match.test", invite)
      const duplicatedRole = new URL(validUrl)
      duplicatedRole.hash += "&role=visitor"
      expect(() => parseInvitation(duplicatedRole.toString(), 1700000000000)).toThrow(/invalid pairing link/i)
      const duplicatedKind = new URL(validUrl)
      duplicatedKind.hash += "&kind=device-enrollment"
      expect(() => parseInvitation(duplicatedKind.toString(), 1700000000000)).toThrow(/invalid pairing link/i)

      const duplicateWorkspaceId = new URL(validUrl)
      duplicateWorkspaceId.hash = duplicateWorkspaceId.hash.replace("ws_1%2Cws_2", "ws_1%2Cws_1")
      expect(() => parseInvitation(duplicateWorkspaceId.toString(), 1700000000000)).toThrow(/invalid pairing link/i)

      const mismatchedPrimary = new URL(validUrl)
      mismatchedPrimary.hash = mismatchedPrimary.hash.replace("workspaceId=ws_1", "workspaceId=ws_other")
      expect(() => parseInvitation(mismatchedPrimary.toString(), 1700000000000)).toThrow(/invalid pairing link/i)

      const emptyScopeId = new URL(validUrl)
      emptyScopeId.hash = emptyScopeId.hash.replace("ws_1%2Cws_2", "ws_1%2C%2Cws_2")
      expect(() => parseInvitation(emptyScopeId.toString(), 1700000000000)).toThrow(/invalid pairing link/i)

      const wrongTitleCount = new URL(validUrl)
      const wrongTitleParams = new URLSearchParams(wrongTitleCount.hash.slice(1))
      wrongTitleParams.set("workspaceTitles", "Only one")
      wrongTitleCount.hash = wrongTitleParams.toString()
      expect(() => parseInvitation(wrongTitleCount.toString(), 1700000000000)).toThrow(/invalid pairing link/i)
    })

    it("rejects invalid timestamps and malformed workspace-title escapes", () => {
      const url = "https://match.test/pair#v=1&kind=workspace-join&invitationId=inv_1&issuerPersonId=p1&issuerDeviceId=d1&issuerPublicKey=pk1&endpoint=ep1&createdAt=not-a-date&expiresAt=2099-01-01T00:00:00.000Z&secret=sec1&workspaceId=ws_1&role=editor"
      expect(() => parseInvitation(url)).toThrow(/invalid pairing link/i)
      const reversedDates = url.replace("createdAt=not-a-date", "createdAt=2099-01-02T00:00:00.000Z")
      expect(() => parseInvitation(reversedDates)).toThrow(/invalid pairing link/i)
      const malformedTitle = url.replace("createdAt=not-a-date", "createdAt=2026-01-01T00:00:00.000Z")
        .replace("role=editor", "role=editor&workspaceIds=ws_1&workspaceTitles=%25ZZ")
      expect(() => parseInvitation(malformedTitle)).toThrow(/invalid pairing link/i)
    })

    it("keeps version, identity, and role validation at the invitation boundary", () => {
      const invite = createWorkspaceJoinInvite("ep1", "sec1", mockProfile, [{ id: "ws_1", title: "One" }])
      const validUrl = invitationUrl("https://match.test", invite)
      const invalidVersion = new URL(validUrl)
      invalidVersion.hash = invalidVersion.hash.replace("v=1", "v=2")
      expect(() => parseInvitation(invalidVersion.toString())).toThrow(/invalid pairing link/i)

      const emptyIssuer = new URL(validUrl)
      emptyIssuer.hash = emptyIssuer.hash.replace("issuerPersonId=person_1", "issuerPersonId=")
      expect(() => parseInvitation(emptyIssuer.toString())).toThrow(/invalid pairing link/i)

      const invalidRole = new URL(validUrl)
      invalidRole.hash = invalidRole.hash.replace("role=visitor", "role=admin")
      expect(() => parseInvitation(invalidRole.toString())).toThrow(/valid role/i)
    })

    it("creates and parses a workspace-join invitation for a fixed set of multiple workspaces", () => {
      const now = 1700000000000
      const workspaces = [
        { id: "ws_job", title: "Job search" },
        { id: "ws_reading", title: "Reading list" },
      ]
      const invite = createWorkspaceJoinInvite(
        "endpoint_test",
        "secret_456",
        mockProfile,
        workspaces,
        { now }
      )
      expect(invite.kind).toBe("workspace-join")
      expect(invite.workspaces).toHaveLength(2)
      expect(invite.workspaces[0]).toEqual({ id: "ws_job", title: "Job search" })
      expect(invite.workspaces[1]).toEqual({ id: "ws_reading", title: "Reading list" })
      expect(invite.workspaceId).toBe("ws_job")
      expect(invite.workspaceTitle).toBe("Job search")

      const url = invitationUrl("https://match.test", invite)
      const parsed = parseInvitation(url, now)
      expect(parsed.kind).toBe("workspace-join")
      if (parsed.kind === "workspace-join") {
        expect(parsed.workspaces).toHaveLength(2)
        expect(parsed.workspaces[0]).toEqual({ id: "ws_job", title: "Job search" })
        expect(parsed.workspaces[1]).toEqual({ id: "ws_reading", title: "Reading list" })
        expect(parsed.workspaceId).toBe("ws_job")
      }
    })

    it("preserves backward compatibility with single-workspace invitations without workspaceIds query param", () => {
      const singleUrl = "https://match.test/pair#v=1&kind=workspace-join&invitationId=inv_single&issuerPersonId=p1&issuerDeviceId=d1&issuerPublicKey=pk1&endpoint=ep1&createdAt=2026-01-01T00:00:00.000Z&expiresAt=2099-01-01T00:00:00.000Z&secret=sec1&workspaceId=ws_legacy&workspaceTitle=Legacy+Board&role=editor"
      const parsed = parseInvitation(singleUrl)
      expect(parsed.kind).toBe("workspace-join")
      if (parsed.kind === "workspace-join") {
        expect(parsed.workspaceId).toBe("ws_legacy")
        expect(parsed.workspaceTitle).toBe("Legacy Board")
        expect(parsed.workspaces).toEqual([{ id: "ws_legacy", title: "Legacy Board" }])
      }
    })
  })
})
