---
spec: algochat.spec.md
---

## User Stories

- As an application developer, I want interoperable encrypted Algorand messaging with typed failures and deterministic local verification.
- As a user, I want message content protected while receiving honest disclosure that blockchain metadata remains public.

## Acceptance Criteria

### REQ-algochat-001

Standard encryption SHALL derive fresh ephemeral X25519 material and authenticate every plaintext with ChaCha20-Poly1305.

Acceptance Criteria
- Round-trip, wrong-key, tampering, empty-message, Unicode, and reply-context tests exercise `encryptMessage`, `encryptReply`, and `decryptMessage`.

### REQ-algochat-002

Standard envelope encoding SHALL be deterministic and SHALL reject invalid version, protocol, length, or truncated input.

Acceptance Criteria
- `encodeEnvelope`, `decodeEnvelope`, and `isChatMessage` tests cover valid and malformed binary data.

### REQ-algochat-003

Encryption-key announcements MAY bind an Ed25519 signing identity to an X25519 public key with Ed25519 signatures. Falcon-1024 senders bind identity through the payment `pqsig` instead.

Acceptance Criteria
- Signature round trips pass and wrong messages, wrong keys, mutations, and invalid key sizes fail for the Ed25519 helper.
- Falcon ChatAccounts still publish and discover X25519 keys via the existing envelope `sender_pubkey` path.

### REQ-algochat-004

Key discovery SHALL scan configured indexer results, validate announcements, and return the newest valid key without accepting malformed or forged notes.

Acceptance Criteria
- Discovery tests cover direct parsing, paginated search, invalid signatures, malformed notes, and no-key results.

### REQ-algochat-005

Message transactions SHALL use the protocol minimum payment, encode the encrypted envelope as a note, and reject notes larger than `MAX_NOTE_SIZE` before submission.

Acceptance Criteria
- Transaction construction exposes `MINIMUM_PAYMENT`, enforces 1,024 bytes, and preserves signed and unsigned transaction types.

### REQ-algochat-006

PSK encryption SHALL combine ephemeral ECDH material with the counter-derived PSK so neither input alone produces the message key.

Acceptance Criteria
- PSK tests cover successful round trips, wrong PSK, wrong recipient key, tampering, and sender-side decryption.

### REQ-algochat-007

The PSK ratchet SHALL derive deterministic session and position keys, with a new session every 100 counters.

Acceptance Criteria
- Boundary tests distinguish positions and sessions and verify `derivePSKAtCounter` against explicit session/position derivation.

### REQ-algochat-008

PSK receive state SHALL reject replays and counters outside its accepted forward window, while send counters advance exactly once per message.

Acceptance Criteria
- State tests cover first receive, out-of-order accepted counters, duplicates, excessive gaps, and immutable send advancement.

### REQ-algochat-009

PSK envelopes and exchange URIs SHALL round-trip all required fields and SHALL reject malformed, unsupported, or unsafe inputs.

Acceptance Criteria
- Binary envelope and `algochat://` URI tests cover valid labels, encoding, malformed keys, versions, protocols, counters, and lengths.

### REQ-algochat-010

`AlgorandService` SHALL compose account creation, key discovery, message encryption, submission, fetching, and reply behavior through injectable clients.

Acceptance Criteria
- Service tests use deterministic mocks to verify send, reply, discovery, fetch, and failure propagation without live network mutation.

### REQ-algochat-024

New ChatAccounts SHALL default to Falcon-1024 authorization. Importing a mnemonic without a scheme SHALL recover the Ed25519 account. Encryption keys SHALL be derived from 32-byte mnemonic entropy for both schemes.

Acceptance Criteria
- `createRandomChatAccount()` returns `scheme: 'falcon-1024'` and a working `txnSigner`.
- `createChatAccountFromMnemonic(mn)` returns `scheme: 'ed25519'` and the classical address.
- `createChatAccountFromMnemonic(mn, { scheme: 'falcon-1024' })` recovers the Falcon address from a Falcon-generated mnemonic.
- The same mnemonic yields identical X25519 keys and different addresses across schemes.
- Falcon payments use at least `minFee * 3`.

### REQ-algochat-011

Mnemonic and address helpers SHALL validate Algorand inputs and SHALL round-trip encryption public keys through base64.

Acceptance Criteria
- Tests cover valid and invalid mnemonics/addresses, random and restored accounts, and base64 conversions.

### REQ-algochat-012

Indexed message retrieval SHALL paginate, filter participants, decrypt supported notes, ignore unrelated or malformed notes, de-duplicate transactions, and sort chronologically.

Acceptance Criteria
- Indexer tests cover multiple pages, participant directions, malformed notes, duplicates, pagination limits, and conversation assembly.

### REQ-algochat-013

Conversation models SHALL retain participant identity and ordered messages and SHALL derive the latest message from the resulting order.

Acceptance Criteria
- Conversation tests cover construction, insertion order, duplicate handling, and last-message updates.

### REQ-algochat-014

Pending-message helpers SHALL return immutable state transitions and enforce the configured retry ceiling.

Acceptance Criteria
- Creation, sending, failure, success, retry-count, and `canRetry` behavior are deterministic.

### REQ-algochat-015

`SendQueue` SHALL persist queued work, process eligible messages in order, emit lifecycle events, and retain failed items for bounded retry.

Acceptance Criteria
- Queue tests cover enqueue, ordering, concurrency exclusion, retries, events, cancellation, restoration, and successful removal.

### REQ-algochat-016

`SyncManager` SHALL expose idle, syncing, and offline states and SHALL coordinate queue processing with connectivity and periodic synchronization.

Acceptance Criteria
- The native build type-checks the public state/events/configuration contract and queue integration.

### REQ-algochat-017

In-memory and file-backed caches SHALL support bounded lookup, update, deletion, and clearing without changing caller-owned message values.

Acceptance Criteria
- Cache tests cover capacity behavior, replacement, lookup, removal, and clearing.

### REQ-algochat-018

File-backed key storage SHALL require a password where configured, authenticate encrypted data, replace files atomically, and distinguish missing, invalid, and undecryptable data.

Acceptance Criteria
- The native suite exercises storage round trips and typed `KeyNotFoundError`, `PasswordRequiredError`, `DecryptionFailedError`, and `InvalidKeyDataError` paths.

### REQ-algochat-019

Public errors SHALL preserve stable machine-readable `ChatErrorCode` classification while retaining contextual human-readable cause information.

Acceptance Criteria
- `isChatError` narrows package errors and `wrapError` preserves existing errors or wraps unknown failures with context.

### REQ-algochat-020

The package SHALL disclose that encryption protects content but not public addresses, timing, or transaction activity.

Acceptance Criteria
- The canonical specification and README security table both state the metadata and traffic-analysis limitation.

## Constraints

- Protocol bytes must remain compatible with AlgoChat v1.0 and its PSK v1.1 extension.
- Verification must not require credentials, live wallets, or mutation of public networks.

## Out of Scope

- Hiding Algorand transaction metadata, operating an indexer, wallet custody, and automatic out-of-band PSK exchange.

### REQ-algochat-021

Mailbox key derivation SHALL implement the raven router normative construction — `msg_key = HMAC-SHA256(key = view_secret, "raven/mailbox/v1" ‖ counter_be32)` and `mailbox_id = SHA-256("raven/mailbox/v1/id" ‖ msg_key)` — with per-message counter rotation, and SHALL reject malformed secrets, keys, and counters.

Acceptance Criteria
- Derivation tests cross-check byte-identical output against an independent Node crypto implementation across counters including 0 and 2^32−1, verify rotation produces distinct keys, and cover wrong-length view secrets, wrong-length msg keys, and non-integer or out-of-range counters.

### REQ-algochat-022

Mailbox put planning SHALL fund every leg with exactly `2500 + 400 × (32 + 40 + envelope_len)` microALGO, SHALL reject empty envelopes and envelopes over 2048 bytes, and SHALL reject fan-out groups larger than the Algorand consensus group limit (8 put legs).

Acceptance Criteria
- Planning tests verify the published MBR table (560 B → 0.2553 ALGO, 878 B → 0.3825 ALGO, 2048 B → 0.8505 ALGO), heterogeneous fan-out legs each funded exactly, and every typed rejection path.

### REQ-algochat-023

The mailbox transport SHALL be strictly opt-in — exposed by `AlgorandService` only when configured with a mailbox app id — and SHALL route all chain I/O through the injected algod client so verification requires no credentials, wallets, or public-network mutation.

Acceptance Criteria
- Service tests with a stubbed algod client verify single put, atomic fan-out put, burn, and reclaim group shapes with correct ABI selectors, arguments, and box references; off-chain box reads returning depositor, write round, and envelope; and that the transport is absent unless configured.

### REQ-algochat-025

Mailbox put envelopes SHALL be transmitted as ARC-4 dynamic byte arrays — `uint16_be(length) ‖ bytes` — for both single puts and fan-out legs, and the encoder SHALL reject payloads longer than 65535 bytes with a typed error.

Acceptance Criteria
- Unit tests verify the big-endian uint16 length prefix and verbatim payload passthrough, and stub-algod tests confirm put and fan-out app args carry the ARC-4-encoded envelope while static `byte[32]` args remain raw.

### REQ-algochat-026

Mailbox burn and reclaim SHALL include the depositor address — parsed from the mailbox box header — in the foreign accounts array so the contract's inner MBR refund succeeds, and SHALL omit foreign accounts when the mailbox box is absent (idempotent burn).

Acceptance Criteria
- Stub-algod tests verify burn includes the depositor for an existing mailbox, omits foreign accounts for an absent mailbox, and reclaim includes the depositor.

