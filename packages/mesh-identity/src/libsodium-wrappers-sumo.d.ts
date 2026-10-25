declare module "libsodium-wrappers-sumo" {
  const sodium: {
    ready: Promise<void>
    crypto_box_seal(message: Uint8Array, publicKey: Uint8Array): Uint8Array
    crypto_box_seal_open(ciphertext: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array): Uint8Array
    crypto_sign_ed25519_pk_to_curve25519(publicKey: Uint8Array): Uint8Array
    crypto_sign_ed25519_sk_to_curve25519(privateKey: Uint8Array): Uint8Array
    crypto_sign_seed_keypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array }
    memcmp(left: Uint8Array, right: Uint8Array): boolean
    memzero(value: Uint8Array): void
  }
  export default sodium
}
