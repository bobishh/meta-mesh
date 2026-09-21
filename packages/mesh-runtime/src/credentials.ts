export type RuntimeCredential = {
  workspaceId: string
  ownerPersonId: string
  ownerPublicKey: string
  localGrant?: unknown
}

export type RuntimeProfile = { personId: string; publicKey: string }
export type RuntimeAuthority = { personId: string; publicKey: string; certificates: unknown[] }

export type CredentialIdentityHost<C extends RuntimeCredential> = {
  grant(credential: C): { personId: string } | undefined
  authorities(credential: C): RuntimeAuthority[]
  verifyGrant(grant: unknown, workspaceId: string, personId: string, authority: RuntimeAuthority): Promise<void>
}

/** Shared rule for retaining locally persisted mesh credentials across reloads. */
export async function credentialBelongsToProfile<C extends RuntimeCredential, P extends RuntimeProfile>(
  host: CredentialIdentityHost<C>, credential: C, profile: P,
): Promise<boolean> {
  if (credential.ownerPersonId === profile.personId) return credential.ownerPublicKey === profile.publicKey
  const grant = host.grant(credential)
  if (!grant || grant.personId !== profile.personId) return false
  for (const authority of host.authorities(credential)) {
    try {
      await host.verifyGrant(credential.localGrant, credential.workspaceId, profile.personId, authority)
      return true
    } catch { /* Try verified historical authority keys. */ }
  }
  return false
}

export async function activeCredentialsForProfile<C extends RuntimeCredential, P extends RuntimeProfile>(
  host: CredentialIdentityHost<C>, credentials: C[], profile: P,
): Promise<{ active: C[]; mismatched: C[] }> {
  const active: C[] = []
  const mismatched: C[] = []
  for (const credential of credentials) {
    if (await credentialBelongsToProfile(host, credential, profile)) active.push(credential)
    else mismatched.push(credential)
  }
  return { active, mismatched }
}
