# ts-algochat

[![CI](https://img.shields.io/github/actions/workflow/status/CorvidLabs/ts-algochat/ci.yml?label=CI&branch=main)](https://github.com/CorvidLabs/ts-algochat/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@corvidlabs/ts-algochat)](https://www.npmjs.com/package/@corvidlabs/ts-algochat)
[![License](https://img.shields.io/github/license/CorvidLabs/ts-algochat)](https://github.com/CorvidLabs/ts-algochat/blob/main/LICENSE)
[![Version](https://img.shields.io/github/v/release/CorvidLabs/ts-algochat?display_name=tag)](https://github.com/CorvidLabs/ts-algochat/releases)

> **Pre-1.0 Notice**: This library is under active development. The API may change between minor versions until 1.0.

TypeScript implementation of the AlgoChat protocol for encrypted messaging on Algorand.

## Features

- **End-to-End Encryption** - X25519 + ChaCha20-Poly1305
- **Forward Secrecy** - Per-message ephemeral keys
- **PSK Mode (v1.1)** - Hybrid ECDH + pre-shared key ratcheting for quantum defense-in-depth
- **Bidirectional Decryption** - Sender can decrypt own messages
- **Reply Support** - Thread conversations with context
- **Zero Dependencies** - Uses @noble crypto libraries (audited)
- **TypeScript First** - Full type safety

## Security Properties

| Property | Status |
|----------|--------|
| Message content confidentiality | Protected (E2EE) |
| Message integrity | Protected (authenticated encryption) |
| Forward secrecy | Protected (ephemeral keys per message) |
| Replay attacks | Protected (blockchain uniqueness + PSK counter) |
| Quantum resistance (key exchange) | Optional (PSK mode provides defense-in-depth) |
| PSK session forward secrecy | Optional (100-message session boundaries in PSK mode) |
| Metadata privacy | **Not protected** (addresses, timing visible) |
| Traffic analysis | **Not protected** |

## Installation

```bash
# npm
npm install @corvidlabs/ts-algochat

# bun
bun add @corvidlabs/ts-algochat

# pnpm
pnpm add @corvidlabs/ts-algochat
```

## Quick Start

```typescript
import {
    AlgorandService,
    createChatAccountFromMnemonic,
} from '@corvidlabs/ts-algochat';

// Initialize service
const service = new AlgorandService({
    algodToken: '',
    algodServer: 'https://testnet-api.algonode.cloud',
    indexerToken: '',
    indexerServer: 'https://testnet-idx.algonode.cloud',
});

// Create account from mnemonic
const account = createChatAccountFromMnemonic('your 25 word mnemonic...');

// Discover recipient's encryption key
const recipientKey = await service.discoverPublicKey('RECIPIENT_ADDRESS');

// Send encrypted message
const result = await service.sendMessage(
    account,
    'RECIPIENT_ADDRESS',
    recipientKey,
    'Hello from AlgoChat!'
);

console.log('Transaction ID:', result.txid);

// Fetch messages
const messages = await service.fetchMessages(account, 'RECIPIENT_ADDRESS');
```

## API Reference

### Account Management

```typescript
// Create from mnemonic
const account = createChatAccountFromMnemonic('word1 word2 ...');

// Generate new account
const newAccount = createRandomChatAccount();
console.log('Address:', newAccount.address);
console.log('Mnemonic:', newAccount.mnemonic);

// Validate mnemonic
if (validateMnemonic('word1 word2 ...')) {
    // Valid 25-word mnemonic
}

// Validate address
if (validateAddress('ALGO...')) {
    // Valid Algorand address
}
```

### Sending Messages

```typescript
// Simple message
await service.sendMessage(account, recipient, recipientKey, 'Hello!');

// Reply to a message
await service.sendReply(account, recipient, recipientKey, 'Reply text', {
    txid: 'original-tx-id',
    preview: 'Original message preview...',
});
```

### Fetching Messages

```typescript
// Get all messages with an address
const messages = await service.fetchMessages(account, 'ADDRESS');

// Get all conversations
const conversations = await service.fetchConversations(account);

// Discover public key
const pubKey = await service.discoverPublicKey('ADDRESS');
```

### Low-Level Crypto

```typescript
import {
    deriveEncryptionKeys,
    encryptMessage,
    decryptMessage,
    encodeEnvelope,
    decodeEnvelope,
} from '@corvidlabs/ts-algochat';

// Derive keys from seed
const keys = deriveEncryptionKeys(seed);

// Encrypt message
const envelope = encryptMessage(
    'Hello!',
    senderPrivateKey,
    senderPublicKey,
    recipientPublicKey
);

// Encode for transmission
const bytes = encodeEnvelope(envelope);

// Decode received envelope
const decoded = decodeEnvelope(bytes);

// Decrypt message
const content = decryptMessage(decoded, myPrivateKey, myPublicKey);
```

## Types

```typescript
interface ChatAccount {
    address: string;
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    encryptionKeys: X25519KeyPair;
    mnemonic?: string;
}

interface Message {
    id: string;
    sender: string;
    recipient: string;
    content: string;
    timestamp: Date;
    confirmedRound: number;
    direction: 'sent' | 'received';
    replyContext?: ReplyContext;
}

interface Conversation {
    participant: string;
    participantPublicKey?: Uint8Array;
    messages: Message[];
    lastMessage?: Message;
}
```

## Protocol

This library implements the [AlgoChat Protocol v1](https://github.com/CorvidLabs/protocol-algochat) and the PSK v1.1 extension.

### Wire Format (v1.0 Standard)

```
[version: 1][protocol: 1][sender_pubkey: 32][ephemeral_pubkey: 32][nonce: 12][encrypted_sender_key: 48][ciphertext: variable]
```

### Wire Format (v1.1 PSK)

```
[version: 1][protocol: 2][ratchet_counter: 4][sender_pubkey: 32][ephemeral_pubkey: 32][nonce: 12][encrypted_sender_key: 48][ciphertext: variable]
```

### Cryptographic Primitives

| Function | Algorithm |
|----------|-----------|
| Key Agreement | X25519 ECDH |
| Encryption | ChaCha20-Poly1305 |
| Key Derivation | HKDF-SHA256 |

## PSK v1.1 Protocol

The PSK (Pre-Shared Key) v1.1 protocol adds an additional layer of authentication and security on top of standard ECDH encryption by incorporating a pre-shared key into the key derivation process.

### Features

- **Two-level key ratchet** - Session keys derived per 100 messages, position keys per message
- **Hybrid encryption** - Combines ECDH forward secrecy with PSK authentication
- **Replay protection** - Counter-based sliding window prevents message replay
- **Out-of-band key exchange** - URI scheme for sharing PSK keys (QR code compatible)

### Quantum Defense-in-Depth

PSK mode provides defense against future quantum attacks through **hybrid key derivation**:

```
symmetricKey = HKDF(
  ikm = ephemeralECDH || currentPSK,
  salt = ephemeralPublicKey,
  info = "algochat-psk-v1" || senderPubKey || recipientPubKey
)
```

The encryption key is derived from **both** the ephemeral ECDH shared secret and the ratcheted PSK, concatenated before HKDF. This means an attacker must break **both** layers:

1. **ECDH only broken** (quantum computer): Attacker still needs the PSK
2. **PSK only compromised**: Attacker still cannot break ECDH (per-message ephemeral keys)
3. **Both compromised**: Only then can messages be decrypted

This hybrid approach ensures that even if quantum computers eventually break X25519 ECDH, messages encrypted with PSK mode remain secure as long as the pre-shared key was exchanged securely.

### Two-Level Ratcheting

PSK mode derives per-message keys using a two-level ratchet:

1. **Session derivation**: `sessionPSK = HKDF(initialPSK, sessionIndex)` where `sessionIndex = counter / 100`
2. **Position derivation**: `currentPSK = HKDF(sessionPSK, position)` where `position = counter % 100`

This creates 100-message session boundaries. Compromising a session PSK exposes at most 100 messages.

### Exchange URI Format

PSK exchange URIs are designed for QR code sharing:

```
algochat-psk://v1?addr=<algorand_address>&psk=<base64url>&label=<optional>
```

Use any QR library (e.g., `qrcode`) to encode the URI for easy scanning between devices.

### Usage

```typescript
import {
    derivePSKAtCounter,
    encryptPSKMessage,
    decryptPSKMessage,
    encodePSKEnvelope,
    decodePSKEnvelope,
    isPSKMessage,
    createPSKState,
    advanceSendCounter,
    validateCounter,
    recordReceive,
    createPSKExchangeURI,
    parsePSKExchangeURI,
} from '@corvidlabs/ts-algochat';

// Derive PSK for a specific counter
const psk = derivePSKAtCounter(sharedSecret, counter);

// Encrypt a PSK message
const envelope = encryptPSKMessage(
    'Hello with PSK!',
    senderPublicKey,
    recipientPublicKey,
    psk,
    counter,
);

// Encode for transmission
const bytes = encodePSKEnvelope(envelope);

// Check if received data is a PSK message
if (isPSKMessage(bytes)) {
    const decoded = decodePSKEnvelope(bytes);
    const content = decryptPSKMessage(decoded, myPrivateKey, myPublicKey, psk);
}

// Counter state management
let state = createPSKState();
const { counter: sendCounter, state: newState } = advanceSendCounter(state);
state = newState;

// Exchange URI for out-of-band key sharing
const uri = createPSKExchangeURI('ALGO_ADDRESS', pskBytes, 'My Chat');
const parsed = parsePSKExchangeURI(uri);
```

## Testing

```bash
bun test
```

## Cross-Implementation Compatibility

This implementation is fully compatible with:
- [swift-algochat](https://github.com/CorvidLabs/swift-algochat) (Swift)
- [rs-algochat](https://github.com/CorvidLabs/rs-algochat) (Rust)
- [py-algochat](https://github.com/CorvidLabs/py-algochat) (Python)
- [kt-algochat](https://github.com/CorvidLabs/kt-algochat) (Kotlin)

## License

MIT License - See [LICENSE](LICENSE) for details.
