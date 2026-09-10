---
change: CHG-0007-fix-mailboxroutertransport-for-real-algod-arc-4-encode-put-envelopes-include-d
artifact: plan
---

# Plan

## Plan

1. Add `arc4EncodeDynamicBytes` to `src/blockchain/mailbox.ts` and export it from `src/index.ts`.
2. Use it for the envelope app arg in `submitPutGroup` (covers both `send` and `sendFanout`).
3. Add `foreignAccountsForRefund` to the transport: read the mailbox box, return the depositor when it exists.
4. Wire foreign accounts into `burn` and `reclaim`.
5. Update unit tests and the spec's Public API table.
