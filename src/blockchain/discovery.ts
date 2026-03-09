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
 * When the indexer client supports {@link IndexerClient.searchTransactionPages},
 * this paginates through the full transaction history until a key announcement
 * is found. Otherwise it falls back to a single query with the given limit.
 *
 * A key announcement is a self-transfer (sender === receiver) with the X25519
 * public key in the note field.
 *
 * @param indexer The indexer client to use
 * @param address The Algorand address to find the key for
 * @param pageSize Transactions to fetch per page (default: 1000)
 * @returns DiscoveredKey if found, undefined otherwise
 */
export async function discoverEncryptionKey(
    indexer: IndexerClient,
    address: string,
    pageSize = 1000
): Promise<DiscoveredKey | undefined> {
    // Decode the Ed25519 public key once before the loop; if the address is
    // malformed we can still search but skip signature verification.
    let ed25519PublicKey: Uint8Array | undefined;
    try {
        ed25519PublicKey = decodeAlgorandAddress(address);
    } catch {
        // Invalid address format — continue without verification
    }

    // Paginate if the indexer supports it, otherwise single-shot
    if (indexer.searchTransactionPages) {
        let nextToken: string | undefined;
        do {
            const page = await indexer.searchTransactionPages(address, undefined, pageSize, nextToken);
            const result = scanForKeyAnnouncement(page.transactions, address, ed25519PublicKey);
            if (result) return result;
            nextToken = page.nextToken;
        } while (nextToken);
    } else {
        const transactions = await indexer.searchTransactions(address, undefined, pageSize);
        return scanForKeyAnnouncement(transactions, address, ed25519PublicKey);
    }

    return undefined;
}

/** Scan a batch of transactions for a key announcement from the given address. */
function scanForKeyAnnouncement(
    transactions: import('./types').NoteTransaction[],
    address: string,
    ed25519PublicKey?: Uint8Array
): DiscoveredKey | undefined {
    for (const tx of transactions) {
        if (tx.sender !== address) continue;
        if (tx.receiver !== address) continue;
        if (!tx.note || tx.note.length < 32) continue;

        const key = parseKeyAnnouncement(tx.note, ed25519PublicKey);
        if (key !== undefined) return key;
    }
    return undefined;
}

/**
 * Discover encryption key from a chat message transaction.
 *
 * This extracts the sender's public key from the envelope header of any
 * AlgoChat message they've sent. Paginates when the indexer supports it.
 *
 * @param indexer The indexer client to use
 * @param address The Algorand address to find the key for
 * @param isChatMessage Function to check if a note is an AlgoChat message
 * @param decodeEnvelope Function to decode envelope and extract public key
 * @param pageSize Transactions to fetch per page (default: 1000)
 * @returns DiscoveredKey if found, undefined otherwise
 */
export async function discoverEncryptionKeyFromMessages(
    indexer: IndexerClient,
    address: string,
    isChatMessage: (note: Uint8Array) => boolean,
    decodeEnvelope: (note: Uint8Array) => { senderPublicKey: Uint8Array },
    pageSize = 1000
): Promise<DiscoveredKey | undefined> {
    const scan = (transactions: import('./types').NoteTransaction[]) =>
        scanForMessageKey(transactions, address, isChatMessage, decodeEnvelope);

    if (indexer.searchTransactionPages) {
        let nextToken: string | undefined;
        do {
            const page = await indexer.searchTransactionPages(address, undefined, pageSize, nextToken);
            const result = scan(page.transactions);
            if (result) return result;
            nextToken = page.nextToken;
        } while (nextToken);
    } else {
        const transactions = await indexer.searchTransactions(address, undefined, pageSize);
        return scan(transactions);
    }

    return undefined;
}

/** Scan a batch of transactions for a chat message containing a public key. */
function scanForMessageKey(
    transactions: import('./types').NoteTransaction[],
    address: string,
    isChatMessage: (note: Uint8Array) => boolean,
    decodeEnvelope: (note: Uint8Array) => { senderPublicKey: Uint8Array }
): DiscoveredKey | undefined {
    for (const tx of transactions) {
        if (tx.sender !== address) continue;
        if (!tx.note || tx.note.length === 0) continue;
        if (!isChatMessage(tx.note)) continue;

        try {
            const envelope = decodeEnvelope(tx.note);
            return { publicKey: envelope.senderPublicKey, isVerified: false };
        } catch {
            continue;
        }
    }
    return undefined;
}
