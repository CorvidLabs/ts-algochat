---
change: CHG-0007-fix-mailboxroutertransport-for-real-algod-arc-4-encode-put-envelopes-include-d
artifact: testing
---

# Testing

## Evidence

- `bun test`: full suite green, including new tests for `arc4EncodeDynamicBytes` (length prefix, passthrough), put/fan-out ARC-4 args, burn foreign accounts with an existing box, burn without accounts for an absent mailbox, and reclaim foreign accounts.
- `fledge lanes run verify` (build + test): green.
- LocalNet e2e against deployed RavenRouter (app 1002): put/read/burn round-trip, 3-recipient fan-out, and 2049-byte negative case — 18/18 PASS.

## Requirement evidence map

- `REQ-algochat-024`: `arc4EncodeDynamicBytes` length-prefix tests in `src/blockchain/mailbox.test.ts`; put and fan-out ARC-4 arg assertions in `src/services/mailbox-router.service.test.ts`.
- `REQ-algochat-025`: burn-with-depositor, burn-absent-mailbox, and reclaim foreign-account cases in `src/services/mailbox-router.service.test.ts`.
