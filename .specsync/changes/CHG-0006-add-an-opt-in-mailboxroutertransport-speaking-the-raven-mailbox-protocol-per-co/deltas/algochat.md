## ADDED

### SPEC SECTION Public API

| Export | Contract |
|---|---|
| `MailboxRouterTransport` | Opt-in raven mailbox transport: put, atomic fan-out put, burn, reclaim, and off-chain box reads against a configured router app id. |
| `MailboxTransportConfig` | Typed transport configuration: injected algod client plus router app id. |
| `MailboxLeg` | One fan-out leg input: view secret, counter, and opaque envelope bytes. |
| `MailboxLegPlan` | Planned leg: derived mailbox id, exact MBR, and envelope. |
| `MailboxSendResult` | Result of a mailbox put: txid, confirmed round, mailbox id, and funded MBR. |
| `MailboxFanoutResult` | Result of an atomic fan-out put: txid, confirmed round, and per-leg plans. |
| `MailboxReadResult` | Off-chain mailbox read: existence flag plus depositor, write round, and envelope when present. |
| `MailboxTxnResult` | Result of a burn or reclaim call: txid and confirmed round. |
| `deriveMsgKey` | Deterministic raven msg_key derivation (HMAC-SHA256, per-counter). |
| `deriveMailboxId` | Deterministic raven mailbox id derivation (SHA-256, domain-separated). |
| `mailboxMbr` | Exact box MBR in microALGO for an envelope length. |
| `planMailboxPut` | Pure single-leg put planning with validation. |
| `planMailboxFanout` | Pure N-leg atomic fan-out planning with validation. |
| `MAILBOX_METHODS` | Canonical ARC-4 signature strings for the router methods. |
| `mailboxMethodSelector` | ARC-4 selector derivation (SHA-512/256, first 4 bytes). |
| `MAILBOX_MAX_ENVELOPE_SIZE` | Published protocol limit: 2048-byte maximum envelope. |
| `MAILBOX_TTL_ROUNDS` | Published protocol value: 2,600,000-round reclaim TTL. |
| `MAILBOX_MAX_FANOUT_LEGS` | Published protocol limit: 8 put legs per atomic group. |
| `MailboxError` | Base typed failure for mailbox protocol and transport operations. |
| `InvalidViewSecretError` | Typed failure for non-32-byte view secrets. |
| `InvalidCounterError` | Typed failure for non-uint32 counters. |
| `InvalidMsgKeyError` | Typed failure for non-32-byte msg keys. |
| `MailboxEnvelopeError` | Typed failure for empty or oversized envelopes. |
| `MailboxFanoutLimitError` | Typed failure for fan-out groups exceeding the consensus limit. |

### REQUIREMENT REQ-algochat-021

Mailbox key derivation SHALL implement the raven router normative construction — `msg_key = HMAC-SHA256(key = view_secret, "raven/mailbox/v1" ‖ counter_be32)` and `mailbox_id = SHA-256("raven/mailbox/v1/id" ‖ msg_key)` — with per-message counter rotation, and SHALL reject malformed secrets, keys, and counters.

Acceptance Criteria
- Derivation tests cross-check byte-identical output against an independent Node crypto implementation across counters including 0 and 2^32−1, verify rotation produces distinct keys, and cover wrong-length view secrets, wrong-length msg keys, and non-integer or out-of-range counters.

### REQUIREMENT REQ-algochat-022

Mailbox put planning SHALL fund every leg with exactly `2500 + 400 × (32 + 40 + envelope_len)` microALGO, SHALL reject empty envelopes and envelopes over 2048 bytes, and SHALL reject fan-out groups larger than the Algorand consensus group limit (8 put legs).

Acceptance Criteria
- Planning tests verify the published MBR table (560 B → 0.2553 ALGO, 878 B → 0.3825 ALGO, 2048 B → 0.8505 ALGO), heterogeneous fan-out legs each funded exactly, and every typed rejection path.

### REQUIREMENT REQ-algochat-023

The mailbox transport SHALL be strictly opt-in — exposed by `AlgorandService` only when configured with a mailbox app id — and SHALL route all chain I/O through the injected algod client so verification requires no credentials, wallets, or public-network mutation.

Acceptance Criteria
- Service tests with a stubbed algod client verify single put, atomic fan-out put, burn, and reclaim group shapes with correct ABI selectors, arguments, and box references; off-chain box reads returning depositor, write round, and envelope; and that the transport is absent unless configured.
