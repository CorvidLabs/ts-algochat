---
spec: algochat.spec.md
---

## Context

AlgoChat applications need one interoperable TypeScript package for account material, authenticated message envelopes, on-chain transport, history reconstruction, offline delivery, and optional PSK defense-in-depth. The implementation deliberately separates injectable blockchain boundaries from deterministic protocol logic.

## Design Decisions

- Use fresh X25519 ephemeral keys and ChaCha20-Poly1305 for standard messages.
- Add PSK material through HKDF rather than replacing ECDH, retaining two independent inputs to the symmetric key.
- Keep the wire format compact enough for Algorand note limits.
- Treat public-chain metadata exposure as an explicit limitation, not a security property.
- Keep clients and storage interfaces injectable for offline deterministic tests.
