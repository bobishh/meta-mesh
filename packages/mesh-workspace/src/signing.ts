import { signEnvelope, type DeviceCertificate, type LocalProfile, type SignedEnvelope } from "@meta-uber/mesh-identity"

/** Application-owned verification and live authorization boundary. No application storage enters the SDK. */
export type WorkspaceRecordSigner = {
  readonly personId: string
  readonly deviceId: string
  readonly publicKey: string
  readonly certificates: DeviceCertificate[]
  sign<T extends { kind: string }>(payload: T): Promise<SignedEnvelope<T>>
}

export function workspaceSignerCertificates(profile: LocalProfile, signer?: WorkspaceRecordSigner): DeviceCertificate[] {
  if (!signer) return [profile.certificate]
  if (signer.personId !== profile.identity.personId || signer.deviceId !== profile.device.deviceId ||
    signer.publicKey !== profile.identity.publicKey) throw new Error("Workspace signer belongs to another profile")
  return structuredClone(signer.certificates)
}

export async function signWorkspaceRecord<T extends { kind: string }>(profile: LocalProfile, payload: T,
  signer?: WorkspaceRecordSigner, legacyRootSigner = false): Promise<SignedEnvelope<T>> {
  const snapshot = structuredClone(payload)
  if (signer) {
    workspaceSignerCertificates(profile, signer)
    return signer.sign(snapshot)
  }
  // Detached protocol fixtures and SDK consumers may supply their own key lifecycle.
  const root = legacyRootSigner ? profile.privateKeys.identityPrivateKey : undefined
  return signEnvelope(root ?? profile.privateKeys.devicePrivateKey, snapshot,
    root ? profile.identity.personId : profile.device.deviceId)
}
