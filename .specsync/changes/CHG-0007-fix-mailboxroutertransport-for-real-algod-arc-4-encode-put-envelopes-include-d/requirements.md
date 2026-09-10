---
change: CHG-0007-fix-mailboxroutertransport-for-real-algod-arc-4-encode-put-envelopes-include-d
artifact: requirements
---

# Requirements

## Acceptance Criteria

- Mailbox put and fan-out app args ARC-4-encode the envelope as `uint16_be(len)` followed by the envelope bytes.
- `arc4EncodeDynamicBytes` is exported from the package root and rejects payloads over 65535 bytes with `MailboxEnvelopeError`.
- Burn and reclaim resolve the depositor from the mailbox box header and include it in the foreign accounts array so the inner MBR refund succeeds; absent mailboxes omit foreign accounts (idempotent burn).
- All existing and new unit tests pass, and the fledge verify lane is green.
