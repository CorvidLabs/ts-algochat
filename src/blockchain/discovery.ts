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
 * @param indexer The indexer client to use
 * @param address The Algorand address to find the key for
 * @param searchDepth Maximum transactions to search (default: 100)
 * @returns DiscoveredKey if found, undefined otherwise
 */
export async function discoverEncryptionKey(
    indexer: IndexerClient,
    address: string,
    searchDepth = 100
): Promise<DiscoveredKey | undefined> {
    // Search for transactions from this address
    const transactions = await indexer.searchTransactions(address, undefined, searchDepth);

    // Look for key announcements in the note field
    for (const tx of transactions) {
        // Must be sent by this address
        if (tx.sender !== address) {
            continue;
        }

        // Check if this is a key announcement (self-transfer with note)
        if (tx.receiver !== address) {
            continue;
        }

        // Must have a note
        if (!tx.note || tx.note.length < 32) {
            continue;
        }

        // Decode the Algorand address to get the Ed25519 public key for verification
        const ed25519PublicKey = decodeAlgorandAddress(address);
        const key = parseKeyAnnouncement(tx.note, ed25519PublicKey);
        if (key !== undefined) {
            return key;
        }
    }

    return undefined;
}

/**
 * Discover encryption key from a chat message transaction.
 *
 * This extracts the sender's public key from the envelope header of any
 * AlgoChat message they've sent.
 *
 * @param indexer The indexer client to use
 * @param address The Algorand address to find the key for
 * @param isChatMessage Function to check if a note is an AlgoChat message
 * @param decodeEnvelope Function to decode envelope and extract public key
 * @param searchDepth Maximum transactions to search (default: 200)
 * @returns DiscoveredKey if found, undefined otherwise
 */
export async function discoverEncryptionKeyFromMessages(
    indexer: IndexerClient,
    address: string,
    isChatMessage: (note: Uint8Array) => boolean,
    decodeEnvelope: (note: Uint8Array) => { senderPublicKey: Uint8Array },
    searchDepth = 200
): Promise<DiscoveredKey | undefined> {
    const transactions = await indexer.searchTransactions(address, undefined, searchDepth);

    for (const tx of transactions) {
        // Only look at transactions SENT by this address
        if (tx.sender !== address) {
            continue;
        }

        if (!tx.note || tx.note.length === 0) {
            continue;
        }

        if (!isChatMessage(tx.note)) {
            continue;
        }

        try {
            const envelope = decodeEnvelope(tx.note);
            return {
                publicKey: envelope.senderPublicKey,
                isVerified: false, // Not verified via signature
            };
        } catch {
            // Malformed envelope, continue searching
            continue;
        }
    }

    return undefined;
}
