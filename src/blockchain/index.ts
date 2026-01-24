/**
 * AlgoChat Web - Blockchain Module
 *
 * Abstract interfaces and types for Algorand blockchain integration.
 */

// Types
export type {
    AlgorandConfig,
    TransactionInfo,
    NoteTransaction,
    SuggestedParams,
    AccountInfo,
} from './types';

export {
    localnet,
    testnet,
    mainnet,
    withIndexer,
} from './types';

// Interfaces
export type {
    AlgodClient,
    IndexerClient,
} from './interfaces';

// Discovery
export {
    parseKeyAnnouncement,
    discoverEncryptionKey,
    discoverEncryptionKeyFromMessages,
} from './discovery';

// Message Transaction
export type { UnsignedTransaction, SignedTransaction, ChatAccountLike } from './message-transaction';
export {
    MessageTransaction,
    MessageTooLargeError,
    MAX_NOTE_SIZE,
    MINIMUM_PAYMENT,
} from './message-transaction';

// Message Indexer
export type { ChatAccountLike as IndexerChatAccount } from './message-indexer';
export {
    MessageIndexer,
    PublicKeyNotFoundError,
    DEFAULT_PAGE_SIZE,
    DEFAULT_SEARCH_DEPTH,
} from './message-indexer';
