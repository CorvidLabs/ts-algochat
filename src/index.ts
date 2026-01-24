/**
 * AlgoChat Web
 *
 * TypeScript implementation of the AlgoChat protocol for web applications.
 *
 * @example
 * ```typescript
 * import { AlgorandService, createChatAccountFromMnemonic, SendOptionsPresets } from '@algochat/web';
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
 * // Send a message (with confirmation)
 * const result = await service.sendMessage(
 *   chatAccount,
 *   'RECIPIENT_ADDRESS...',
 *   recipientPubKey,
 *   'Hello from AlgoChat!',
 *   SendOptionsPresets.confirmed
 * );
 *
 * console.log('Sent:', result.txid, 'Round:', result.confirmedRound);
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
    Conversation as ConversationData,
    SendResult,
    SendOptions,
    SendReplyContext,
    DiscoveredKey,
    PendingMessage,
    PendingMessageStatus,
} from './models/types';

export { PROTOCOL, SendOptionsPresets } from './models/types';

// Conversation class
export { Conversation } from './models/Conversation';

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

// Errors
export {
    ChatError,
    ChatErrorCode,
    isChatError,
    wrapError,
} from './errors';

// Caches
export {
    PublicKeyCache,
    type MessageCache,
    InMemoryMessageCache,
} from './cache';

// Queue and sync
export {
    SendQueue,
    InMemorySendQueueStorage,
    type SendQueueStorage,
    type EnqueueOptions,
    SyncManager,
    type SyncState,
    type SyncEvents,
    type SyncManagerConfig,
} from './queue';

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
    MessageIndexer,
    type MessageIndexerConfig,
    type PaginationOptions,
    type WaitForTransactionOptions,
} from './services';
