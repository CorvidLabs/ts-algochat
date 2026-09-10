---
spec: algochat.spec.md
---

## Test Plan

### Native verification

- `bun run tsc` validates every public declaration and implementation under strict TypeScript settings.
- `bun test` runs the deterministic crypto, signature, discovery, indexer, service, mnemonic, conversation, PSK, cache, and queue suite, including Falcon vs Ed25519 scheme recovery.

### Security and compatibility

- Corrupt, truncated, forged, wrong-key, replayed, and oversize inputs must fail closed.
- Network-facing tests use injected fixtures and never require credentials or mutate Algorand networks.
- Cross-implementation protocol vectors remain an independent compatibility boundary where supplied by the protocol repository.
