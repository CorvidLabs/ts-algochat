/**
 * AlgoChat - Storage Module
 *
 * Re-exports all storage interfaces and implementations.
 */

export type { MessageCache } from './message-cache';
export { InMemoryMessageCache } from './message-cache';
export { PublicKeyCache } from './public-key-cache';
export type { EncryptionKeyStorage } from './encryption-key-storage';
export {
    InMemoryKeyStorage,
    KeyNotFoundError,
} from './encryption-key-storage';

// Error types re-exported for compatibility (these don't require Node.js)
export {
    PasswordRequiredError,
    DecryptionFailedError,
    InvalidKeyDataError,
} from './file-key-storage.errors';

// FileKeyStorage is Node.js only - import from 'ts-algochat/node' if needed
