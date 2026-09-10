---
change: CHG-0007-fix-mailboxroutertransport-for-real-algod-arc-4-encode-put-envelopes-include-d
artifact: context
---

# Context

## Why this change exists

CHG-0006 shipped MailboxRouterTransport against a mocked algod. The first run against a real LocalNet algod and the deployed RavenRouter (app 1002) exposed two wire-format bugs:

1. The raven router declares the mailbox envelope parameter as a dynamic ARC-4 `byte[]`. The transport passed raw envelope bytes, so the AVM rejected every real `mailboxPut` call. Dynamic ARC-4 byte arrays must be sent as `uint16_be(length)` followed by the bytes.
2. `mailboxBurn` and `mailboxReclaim` refund the depositor via an inner payment. The AVM requires the refund receiver to be in the foreign accounts array (unless it is the transaction sender), so burns and reclaims failed on real algod.

This change fixes both so the transport works against real algod, verified by a LocalNet round-trip.
