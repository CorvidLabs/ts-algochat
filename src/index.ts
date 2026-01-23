/**
 * AlgoChat Web
 *
 * TypeScript implementation of the AlgoChat protocol for web applications.
 *
 * @example
 * ```typescript
 * import { AlgorandService, createChatAccountFromMnemonic } from '@algochat/web';
 *
 * // Initialize
 * const service = new AlgorandService({
 *   algodToken: 'your-token',
 *   algodServer: 'https://testnet-api.algonode.cloud',
 *   indexerToken: 'your-token',
 *   indexerServer: 'https://testnet-idx.algonode.cloud',
 * });
 *
 * const chatAccount = createChatAccountFromMnemonic('your 25 word mnemonic...');
 *
 * // Discover recipient's key
 * const recipientPubKey = await service.discoverPublicKey('RECIPIENT_ADDRESS...');
 *
 * // Send a message
 * const result = await service.sendMessage(
 *   chatAccount,
 *   'RECIPIENT_ADDRESS...',
 *   recipientPubKey,
 *   'Hello from AlgoChat!'
 * );
 *
 * console.log('Sent:', result.txid);
 *
 * // Fetch messages
 * const messages = await service.fetchMessages(chatAccount, 'RECIPIENT_ADDRESS...');
 * ```
 */

// Core types
export type {
    X25519KeyPair,
    ChatEnvelope,
    DecryptedContent,
    ReplyContext,
    Message,
    MessageDirection,
    Conversation,
    SendResult,
} from './models/types';

export { PROTOCOL } from './models/types';

// Crypto functions
export {
    deriveEncryptionKeys,
    generateEphemeralKeyPair,
    uint8ArrayEquals,
    encryptMessage,
    encryptReply,
    decryptMessage,
    encodeEnvelope,
    decodeEnvelope,
    isChatMessage,
    EncryptionError,
    EnvelopeError,
} from './crypto';

// Services
export {
    AlgorandService,
    type AlgorandConfig,
    type ChatAccount,
    createChatAccountFromMnemonic,
    createRandomChatAccount,
    validateMnemonic,
    validateAddress,
    publicKeyToBase64,
    base64ToPublicKey,
} from './services';
