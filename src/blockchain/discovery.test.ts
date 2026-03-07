/**
 * AlgoChat Web - Key Discovery Tests
 */

import { describe, test, expect } from 'bun:test';
import algosdk from 'algosdk';
import { parseKeyAnnouncement, discoverEncryptionKey } from './discovery';
import { signEncryptionKey, getPublicKey } from '../crypto';
import { deriveEncryptionKeys } from '../crypto/keys';
import type { IndexerClient } from './interfaces';
import type { NoteTransaction, PaginatedTransactions } from './types';

/** Generate a test account and return its seed, ed25519 public key, and address. */
function makeTestAccount() {
    const account = algosdk.generateAccount();
    const seed = account.sk.slice(0, 32);
    const ed25519PublicKey = getPublicKey(seed);
    const encryptionKeys = deriveEncryptionKeys(seed);
    const address = account.addr.toString();
    return { account, seed, ed25519PublicKey, encryptionKeys, address };
}

/** Build a mock IndexerClient that returns the given transactions. */
function mockIndexer(transactions: NoteTransaction[]): IndexerClient {
    return {
        searchTransactions: async () => transactions,
        searchTransactionsBetween: async () => [],
        getTransaction: async () => transactions[0],
        waitForIndexer: async () => transactions[0],
    };
}

describe('parseKeyAnnouncement', () => {
    test('returns undefined for notes shorter than 32 bytes', () => {
        expect(parseKeyAnnouncement(new Uint8Array(31))).toBeUndefined();
        expect(parseKeyAnnouncement(new Uint8Array(0))).toBeUndefined();
    });

    test('returns unverified key for 32-byte note without signature', () => {
        const publicKey = new Uint8Array(32).fill(0xAB);
        const result = parseKeyAnnouncement(publicKey);

        expect(result).toBeDefined();
        expect(result!.publicKey.length).toBe(32);
        expect(result!.isVerified).toBe(false);
    });

    test('returns unverified key when no ed25519PublicKey provided', () => {
        const { seed, encryptionKeys } = makeTestAccount();
        const signature = signEncryptionKey(encryptionKeys.publicKey, seed);

        const note = new Uint8Array(96);
        note.set(encryptionKeys.publicKey, 0);
        note.set(signature, 32);

        const result = parseKeyAnnouncement(note);
        expect(result).toBeDefined();
        expect(result!.isVerified).toBe(false);
    });

    test('returns verified key for valid signature', () => {
        const { seed, ed25519PublicKey, encryptionKeys } = makeTestAccount();
        const signature = signEncryptionKey(encryptionKeys.publicKey, seed);

        const note = new Uint8Array(96);
        note.set(encryptionKeys.publicKey, 0);
        note.set(signature, 32);

        const result = parseKeyAnnouncement(note, ed25519PublicKey);
        expect(result).toBeDefined();
        expect(result!.isVerified).toBe(true);
    });

    test('returns unverified key for invalid signature', () => {
        const { ed25519PublicKey, encryptionKeys } = makeTestAccount();

        const note = new Uint8Array(96);
        note.set(encryptionKeys.publicKey, 0);
        note.set(new Uint8Array(64).fill(0xFF), 32); // bogus signature

        const result = parseKeyAnnouncement(note, ed25519PublicKey);
        expect(result).toBeDefined();
        expect(result!.isVerified).toBe(false);
    });

    test('returns unverified when signature is from a different account', () => {
        const sender = makeTestAccount();
        const other = makeTestAccount();
        const signature = signEncryptionKey(sender.encryptionKeys.publicKey, other.seed);

        const note = new Uint8Array(96);
        note.set(sender.encryptionKeys.publicKey, 0);
        note.set(signature, 32);

        // Verify against sender's key — should fail because other signed it
        const result = parseKeyAnnouncement(note, sender.ed25519PublicKey);
        expect(result).toBeDefined();
        expect(result!.isVerified).toBe(false);
    });
});

describe('discoverEncryptionKey', () => {
    test('returns verified key from valid key announcement', async () => {
        const { seed, encryptionKeys, address } = makeTestAccount();
        const signature = signEncryptionKey(encryptionKeys.publicKey, seed);

        const note = new Uint8Array(96);
        note.set(encryptionKeys.publicKey, 0);
        note.set(signature, 32);

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: address,
                receiver: address,
                note,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const result = await discoverEncryptionKey(indexer, address);
        expect(result).toBeDefined();
        expect(result!.isVerified).toBe(true);
        expect(result!.publicKey.length).toBe(32);
    });

    test('returns unverified key when announcement has no signature', async () => {
        const { encryptionKeys, address } = makeTestAccount();

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: address,
                receiver: address,
                note: encryptionKeys.publicKey, // 32 bytes, no signature
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const result = await discoverEncryptionKey(indexer, address);
        expect(result).toBeDefined();
        expect(result!.isVerified).toBe(false);
    });

    test('skips transactions not sent by the target address', async () => {
        const target = makeTestAccount();
        const other = makeTestAccount();

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: other.address,
                receiver: target.address,
                note: target.encryptionKeys.publicKey,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const result = await discoverEncryptionKey(indexer, target.address);
        expect(result).toBeUndefined();
    });

    test('skips non-self-transfer transactions', async () => {
        const sender = makeTestAccount();
        const other = makeTestAccount();

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: sender.address,
                receiver: other.address, // not self-transfer
                note: sender.encryptionKeys.publicKey,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const result = await discoverEncryptionKey(indexer, sender.address);
        expect(result).toBeUndefined();
    });

    test('skips transactions with notes shorter than 32 bytes', async () => {
        const { address } = makeTestAccount();

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: address,
                receiver: address,
                note: new Uint8Array(16), // too short
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const result = await discoverEncryptionKey(indexer, address);
        expect(result).toBeUndefined();
    });

    test('returns undefined when no transactions match', async () => {
        const { address } = makeTestAccount();
        const indexer = mockIndexer([]);

        const result = await discoverEncryptionKey(indexer, address);
        expect(result).toBeUndefined();
    });

    test('handles malformed address gracefully (falls back to unverified)', async () => {
        const { encryptionKeys } = makeTestAccount();
        const badAddress = 'NOT_A_VALID_ADDRESS';

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: badAddress,
                receiver: badAddress,
                note: encryptionKeys.publicKey,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        // Should not throw — falls back to unverified
        const result = await discoverEncryptionKey(indexer, badAddress);
        expect(result).toBeDefined();
        expect(result!.isVerified).toBe(false);
    });
});

describe('discoverEncryptionKey (paginated)', () => {
    /** Build a mock IndexerClient with paginated search support. */
    function mockPaginatedIndexer(pages: NoteTransaction[][]): IndexerClient {
        let callIndex = 0;
        return {
            searchTransactions: async () => [],
            searchTransactionsBetween: async () => [],
            getTransaction: async () => pages[0][0],
            waitForIndexer: async () => pages[0][0],
            searchTransactionsPaginated: async (
                _address: string,
                _limit?: number,
                _nextToken?: string
            ): Promise<PaginatedTransactions> => {
                const page = pages[callIndex] ?? [];
                callIndex++;
                return {
                    transactions: page,
                    nextToken: callIndex < pages.length ? `token-${callIndex}` : undefined,
                };
            },
        };
    }

    test('finds key in first page', async () => {
        const { encryptionKeys, address } = makeTestAccount();

        const indexer = mockPaginatedIndexer([
            [
                {
                    txid: 'tx1',
                    sender: address,
                    receiver: address,
                    note: encryptionKeys.publicKey,
                    confirmedRound: 100,
                    roundTime: 1700000000,
                },
            ],
        ]);

        const result = await discoverEncryptionKey(indexer, address);
        expect(result).toBeDefined();
        expect(result!.publicKey.length).toBe(32);
    });

    test('finds key in second page after scanning first', async () => {
        const target = makeTestAccount();
        const other = makeTestAccount();

        const indexer = mockPaginatedIndexer([
            // First page: no matching transactions
            [
                {
                    txid: 'tx1',
                    sender: other.address,
                    receiver: target.address,
                    note: target.encryptionKeys.publicKey,
                    confirmedRound: 100,
                    roundTime: 1700000000,
                },
            ],
            // Second page: key announcement
            [
                {
                    txid: 'tx2',
                    sender: target.address,
                    receiver: target.address,
                    note: target.encryptionKeys.publicKey,
                    confirmedRound: 50,
                    roundTime: 1699000000,
                },
            ],
        ]);

        const result = await discoverEncryptionKey(indexer, target.address);
        expect(result).toBeDefined();
        expect(result!.publicKey.length).toBe(32);
    });

    test('returns undefined when all pages exhausted', async () => {
        const { address } = makeTestAccount();
        const other = makeTestAccount();

        const indexer = mockPaginatedIndexer([
            [
                {
                    txid: 'tx1',
                    sender: other.address,
                    receiver: address,
                    note: new Uint8Array(32),
                    confirmedRound: 100,
                    roundTime: 1700000000,
                },
            ],
            [], // Empty page signals end
        ]);

        const result = await discoverEncryptionKey(indexer, address);
        expect(result).toBeUndefined();
    });

    test('respects maxDepth limit across pages', async () => {
        const { address, encryptionKeys } = makeTestAccount();
        const other = makeTestAccount();
        let pagesRequested = 0;

        const indexer: IndexerClient = {
            searchTransactions: async () => [],
            searchTransactionsBetween: async () => [],
            getTransaction: async () => ({} as NoteTransaction),
            waitForIndexer: async () => ({} as NoteTransaction),
            searchTransactionsPaginated: async (): Promise<PaginatedTransactions> => {
                pagesRequested++;
                // Return non-matching transactions with nextToken
                return {
                    transactions: [
                        {
                            txid: `tx${pagesRequested}`,
                            sender: other.address,
                            receiver: address,
                            note: encryptionKeys.publicKey,
                            confirmedRound: 100,
                            roundTime: 1700000000,
                        },
                    ],
                    nextToken: `token-${pagesRequested}`,
                };
            },
        };

        // maxDepth = 2 should stop after searching 2 transactions
        const result = await discoverEncryptionKey(indexer, address, 2);
        expect(result).toBeUndefined();
        expect(pagesRequested).toBeLessThanOrEqual(2);
    });
});

describe('decodeAlgorandAddress (via discoverEncryptionKey)', () => {
    test('correctly extracts Ed25519 public key from a valid address', async () => {
        const { seed, encryptionKeys, address, ed25519PublicKey } = makeTestAccount();
        const signature = signEncryptionKey(encryptionKeys.publicKey, seed);

        const note = new Uint8Array(96);
        note.set(encryptionKeys.publicKey, 0);
        note.set(signature, 32);

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: address,
                receiver: address,
                note,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        // If decodeAlgorandAddress is wrong, verification would fail
        const result = await discoverEncryptionKey(indexer, address);
        expect(result).toBeDefined();
        expect(result!.isVerified).toBe(true);

        // Double-check: the decoded address key matches the known ed25519 public key
        const decodedKey = algosdk.Address.fromString(address).publicKey;
        expect(decodedKey.length).toBe(32);
        expect(
            decodedKey.every((b, i) => b === ed25519PublicKey[i])
        ).toBe(true);
    });
});
