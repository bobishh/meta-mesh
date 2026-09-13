# Mesh

Reusable browser P2P primitives for identity, signed Automerge conversations, and contact bootstrap.

Private workspace packages for now. Publish only after their API stabilizes.

Identity recovery uses a random 256-bit Ed25519 root. A 4, 12, or 24-word recovery phrase derives an AES-256-GCM wrapping key with PBKDF2-HMAC-SHA-256 and 600,000 iterations; it never derives the identity itself. Rewrapping with newly generated words changes recovery strength without changing the person ID. Applications own storage and replication of the encrypted recovery envelope.

Direct-derived v1 identities remain readable. They can be wrapped without changing their person ID, but knowledge of their old phrase remains sufficient to reconstruct the old private key; migration cannot erase that historical weakness.
