---
change: CHG-0007-fix-mailboxroutertransport-for-real-algod-arc-4-encode-put-envelopes-include-d
artifact: tasks
---

# Tasks

## Tasks

- [x] Implement `arc4EncodeDynamicBytes` with uint16 big-endian length prefix
- [x] Export it from `src/index.ts` and document it in the spec
- [x] ARC-4-encode put envelopes in `submitPutGroup`
- [x] Include depositor in burn/reclaim foreign accounts
- [x] Unit tests: encoding, put args, burn with/without box, reclaim
- [x] LocalNet e2e round-trip against deployed RavenRouter (app 1002): put/read/burn, 3-leg fan-out, 2049 B negative — 18/18 PASS
