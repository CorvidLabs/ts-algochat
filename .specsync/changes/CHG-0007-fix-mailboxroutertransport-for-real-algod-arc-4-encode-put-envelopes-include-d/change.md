---
id: CHG-0007-fix-mailboxroutertransport-for-real-algod-arc-4-encode-put-envelopes-include-d
state: accepted
type: feature
base_commit: 63432d0f56abc1d8641867940f9e0d062da7bf6d
---

# Fix MailboxRouterTransport for real algod: ARC-4-encode put envelopes; include depositor in burn/reclaim foreign accounts for inner refunds

## Intent

Fix MailboxRouterTransport for real algod: ARC-4-encode put envelopes; include depositor in burn/reclaim foreign accounts for inner refunds

## Affected Canonical Specs

- `algochat`

## Acceptance Criteria

- Mailbox put and fan-out app args ARC-4-encode the envelope as uint16_be(len) followed by the bytes; burn and reclaim resolve the depositor from the mailbox box header and include it in foreign accounts so the inner MBR refund succeeds
- omitting accounts when the mailbox is absent; arc4EncodeDynamicBytes is exported and unit-tested; all tests plus the fledge verify lane pass

## No-spec Rationale

Not applicable
