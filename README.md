# ts-algochat

[![CI](https://img.shields.io/github/actions/workflow/status/CorvidLabs/ts-algochat/ci.yml?label=CI&branch=main)](https://github.com/CorvidLabs/ts-algochat/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/ts-algochat)](https://www.npmjs.com/package/ts-algochat)
[![License](https://img.shields.io/github/license/CorvidLabs/ts-algochat)](https://github.com/CorvidLabs/ts-algochat/blob/main/LICENSE)
[![Version](https://img.shields.io/github/v/release/CorvidLabs/ts-algochat?display_name=tag)](https://github.com/CorvidLabs/ts-algochat/releases)

> **Pre-1.0 Notice**: This library is under active development. The API may change between minor versions until 1.0.

TypeScript implementation of the AlgoChat protocol for encrypted messaging on Algorand.

## Features

- **End-to-End Encryption** - X25519 + ChaCha20-Poly1305
- **Forward Secrecy** - Per-message ephemeral keys
- **Bidirectional Decryption** - Sender can decrypt own messages
- **Reply Support** - Thread conversations with context
- **Zero Dependencies** - Uses @noble crypto libraries (audited)
- **TypeScript First** - Full type safety

## Installation

```bash
# npm
npm install ts-algochat

# bun
bun add ts-algochat

# pnpm
pnpm add ts-algochat
```

## Quick Start

```typescript
import {
    AlgorandService,
    createChatAccountFromMnemonic,
} from 'ts-algochat';

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
} from 'ts-algochat';

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

This library implements the [AlgoChat Protocol v1](https://github.com/CorvidLabs/protocol-algochat).

### Wire Format

```
[version: 1][protocol: 1][sender_pubkey: 32][ephemeral_pubkey: 32][nonce: 12][encrypted_sender_key: 48][ciphertext: variable]
```

### Cryptographic Primitives

| Function | Algorithm |
|----------|-----------|
| Key Agreement | X25519 ECDH |
| Encryption | ChaCha20-Poly1305 |
| Key Derivation | HKDF-SHA256 |

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
