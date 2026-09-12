import {
  signEnvelope,
  verifyDeviceCertificateChain,
  verifyEnvelope,
  type LocalProfile,
  type SignedEnvelope,
} from "../../mesh-identity/src/index"
import type { Conversation } from "../../mesh-messaging/src/index"

export const CALL_SIGNATURE_DOMAIN = "MESH-CALLING/1"
export type CallMedia = "audio" | "video"
export type CallSignalKind = "offer" | "answer" | "ice" | "reject" | "end"

export type CallSignalPayload = {
  kind: "call-signal"
  version: 1
  signalKind: CallSignalKind
  callId: string
  roomId: string
  media: CallMedia
  senderPersonId: string
  senderDeviceId: string
  targetPersonId: string
  data: string
  createdAt: string
}

export type CallSignal = SignedEnvelope<CallSignalPayload>

export async function createCallSignal(
  profile: LocalProfile,
  input: Omit<CallSignalPayload, "kind" | "version" | "senderPersonId" | "senderDeviceId" | "createdAt"> & { now?: number },
): Promise<CallSignal> {
  const payload: CallSignalPayload = {
    kind: "call-signal",
    version: 1,
    signalKind: input.signalKind,
    callId: input.callId,
    roomId: input.roomId,
    media: input.media,
    senderPersonId: profile.identity.personId,
    senderDeviceId: profile.device.deviceId,
    targetPersonId: input.targetPersonId,
    data: input.data,
    createdAt: new Date(input.now ?? Date.now()).toISOString(),
  }
  if (!payload.callId || !payload.roomId || !payload.targetPersonId || payload.data.length > 128_000) {
    throw new Error("Invalid call signal")
  }
  return signEnvelope(profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId, CALL_SIGNATURE_DOMAIN)
}

export async function verifyCallSignal(
  signal: CallSignal,
  room: Conversation,
  recipientPersonId: string,
  now = Date.now(),
): Promise<CallSignal> {
  const payload = signal?.payload
  if (!payload || payload.kind !== "call-signal" || payload.version !== 1 ||
    !["offer", "answer", "ice", "reject", "end"].includes(payload.signalKind) ||
    !["audio", "video"].includes(payload.media) || payload.roomId !== room.conversationId ||
    payload.targetPersonId !== recipientPersonId || payload.senderDeviceId !== signal.signerKeyId ||
    !payload.callId || payload.data.length > 128_000) throw new Error("Invalid call signal")
  const timestamp = Date.parse(payload.createdAt)
  if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > 5 * 60 * 1000) throw new Error("Expired call signal")
  const participant = room.participants[payload.senderPersonId]
  if (!participant || !room.participants[recipientPersonId]) throw new Error("Caller is not a room member")
  const key = await verifyDeviceCertificateChain(participant.identity, payload.senderDeviceId, participant.certificates)
  if (!await verifyEnvelope(signal, key, CALL_SIGNATURE_DOMAIN)) throw new Error("Invalid call signature")
  return signal
}
