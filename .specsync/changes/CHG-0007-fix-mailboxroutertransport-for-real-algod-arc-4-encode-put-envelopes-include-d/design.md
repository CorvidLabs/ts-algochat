---
change: CHG-0007-fix-mailboxroutertransport-for-real-algod-arc-4-encode-put-envelopes-include-d
artifact: design
---

# Design

## Design

- `arc4EncodeDynamicBytes` lives in `src/blockchain/mailbox.ts` beside the other pure protocol helpers; it throws `MailboxEnvelopeError` above 65535 bytes (uint16 bound).
- `foreignAccountsForRefund` reuses the off-chain `read` so burn/reclaim stay single-call for the user; when the box is absent (idempotent burn) no foreign accounts are attached.
- Static `byte[32]` args (mailbox id, msg key) remain raw per ARC-4.
