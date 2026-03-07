/**
 * AlgoChat Web - Key Discovery
 *
 * Functions for discovering and verifying encryption keys on the blockchain.
 */

import algosdk from 'algosdk';
import type { DiscoveredKey } from '../models/types';
import type { IndexerClient } from './interfaces';
import { verifyEncryptionKey } from '../crypto';

/**
 * Decodes an Algorand address string to extract the 32-byte Ed25519 public key.
 *
 * Algorand addresses are Base32-encoded: 32 bytes public key + 4 bytes checksum.
 *
 * @param address The Algorand address string (58 characters)
 * @returns The 32-byte Ed25519 public key
 */
function decodeAlgorandAddress(address: string): Uint8Array {
    return algosdk.Address.fromString(address).publicKey;
}

/**
 * Parse a key announcement from a transaction note.
 *
 * Key announcement format:
 * - 32 bytes: X25519 public key
 * - 64 bytes (optional): Ed25519 signature
 *
 * @param note The transaction note field
 * @param ed25519PublicKey The sender's Ed25519 public key (for verification)
 * @returns DiscoveredKey if valid, undefined otherwise
 */
export function parseKeyAnnouncement(
    note: Uint8Array,
    ed25519PublicKey?: Uint8Array
): DiscoveredKey | undefined {
    if (note.length < 32) {
        return undefined;
    }

    const publicKey = note.slice(0, 32);
    let isVerified = false;

    if (note.length >= 96 && ed25519PublicKey) {
        // Has signature, verify it
        const signature = note.slice(32, 96);
        try {
            isVerified = verifyEncryptionKey(publicKey, ed25519PublicKey, signature);
        } catch {
            isVerified = false;
        }
    }

    return { publicKey, isVerified };
}

/**
 * Discover the encryption public key for an Algorand address.
 *
 * This searches the indexer for key announcement transactions from the address.
 * A key announcement is a self-transfer (sender === receiver) with the X25519
 * public key in the note field.
 *
 * When the indexer client supports paginated search, this walks the full
 * transaction history using cursor-based pagination.
 *
 * @param indexer The indexer client to use
 * @param address The Algorand address to find the key for
 * @param maxDepth Maximum transactions to search (default: 0 = exhaustive)
 * @returns DiscoveredKey if found, undefined otherwise
 */
export async function discoverEncryptionKey(
    indexer: IndexerClient,
    address: string,
    maxDepth = 0
): Promise<DiscoveredKey | undefined> {
    // Decode the Ed25519 public key once before the loop; if the address is
    // malformed we can still search but skip signature verification.
    let ed25519PublicKey: Uint8Array | undefined;
    try {
        ed25519PublicKey = decodeAlgorandAddress(address);
    } catch {
        // Invalid address format — continue without verification
    }

    // Use paginated search if available, otherwise fall back to single-call search
    if (indexer.searchTransactionsPaginated) {
        const pageSize = 200;
        let nextToken: string | undefined;
        let searched = 0;

        do {
            const limit = maxDepth > 0 ? Math.min(pageSize, maxDepth - searched) : pageSize;
            const page = await indexer.searchTransactionsPaginated(address, limit, nextToken);

            for (const tx of page.transactions) {
                const key = matchKeyAnnouncement(tx, address, ed25519PublicKey);
                if (key !== undefined) return key;
            }

            searched += page.transactions.length;
            nextToken = page.nextToken;

            if (maxDepth > 0 && searched >= maxDepth) break;
            if (page.transactions.length === 0) break;
        } while (nextToken);
    } else {
        // Fallback: single search with depth limit
        const transactions = await indexer.searchTransactions(address, undefined, maxDepth || 1000);
        for (const tx of transactions) {
            const key = matchKeyAnnouncement(tx, address, ed25519PublicKey);
            if (key !== undefined) return key;
        }
    }

    return undefined;
}

/** Check if a transaction is a key announcement and return the key if so. */
function matchKeyAnnouncement(
    tx: import('./types').NoteTransaction,
    address: string,
    ed25519PublicKey?: Uint8Array
): DiscoveredKey | undefined {
    if (tx.sender !== address) return undefined;
    if (tx.receiver !== address) return undefined;
    if (!tx.note || tx.note.length < 32) return undefined;
    return parseKeyAnnouncement(tx.note, ed25519PublicKey);
}

/**
 * Discover encryption key from a chat message transaction.
 *
 * This extracts the sender's public key from the envelope header of any
 * AlgoChat message they've sent.
 *
 * When the indexer client supports paginated search, this walks the full
 * transaction history using cursor-based pagination.
 *
 * @param indexer The indexer client to use
 * @param address The Algorand address to find the key for
 * @param isChatMessage Function to check if a note is an AlgoChat message
 * @param decodeEnvelope Function to decode envelope and extract public key
 * @param maxDepth Maximum transactions to search (default: 0 = exhaustive)
 * @returns DiscoveredKey if found, undefined otherwise
 */
export async function discoverEncryptionKeyFromMessages(
    indexer: IndexerClient,
    address: string,
    isChatMessage: (note: Uint8Array) => boolean,
    decodeEnvelope: (note: Uint8Array) => { senderPublicKey: Uint8Array },
    maxDepth = 0
): Promise<DiscoveredKey | undefined> {
    const matchMessage = (tx: import('./types').NoteTransaction): DiscoveredKey | undefined => {
        if (tx.sender !== address) return undefined;
        if (!tx.note || tx.note.length === 0) return undefined;
        if (!isChatMessage(tx.note)) return undefined;

        try {
            const envelope = decodeEnvelope(tx.note);
            return {
                publicKey: envelope.senderPublicKey,
                isVerified: false, // Not verified via signature
            };
        } catch {
            return undefined;
        }
    };

    if (indexer.searchTransactionsPaginated) {
        const pageSize = 200;
        let nextToken: string | undefined;
        let searched = 0;

        do {
            const limit = maxDepth > 0 ? Math.min(pageSize, maxDepth - searched) : pageSize;
            const page = await indexer.searchTransactionsPaginated(address, limit, nextToken);

            for (const tx of page.transactions) {
                const key = matchMessage(tx);
                if (key !== undefined) return key;
            }

            searched += page.transactions.length;
            nextToken = page.nextToken;

            if (maxDepth > 0 && searched >= maxDepth) break;
            if (page.transactions.length === 0) break;
        } while (nextToken);
    } else {
        const transactions = await indexer.searchTransactions(address, undefined, maxDepth || 1000);
        for (const tx of transactions) {
            const key = matchMessage(tx);
            if (key !== undefined) return key;
        }
    }

    return undefined;
}
