/**
 * AlgoChat Web - Key Discovery Tests
 */

import { describe, test, expect } from 'bun:test';
import algosdk from 'algosdk';
import { parseKeyAnnouncement, discoverEncryptionKey, discoverEncryptionKeyFromMessages } from './discovery';
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

/**
 * Build a mock IndexerClient with paginated search.
 * Pages are provided as an array of arrays; each inner array is one page.
 */
function mockPaginatedIndexer(pages: NoteTransaction[][]): IndexerClient & { callCount: number } {
    let callCount = 0;
    return {
        callCount,
        searchTransactions: async () => pages.flat(),
        searchTransactionsBetween: async () => [],
        getTransaction: async () => pages[0]?.[0],
        waitForIndexer: async () => pages[0]?.[0],
        searchTransactionsPaginated: async (
            _address: string,
            options?: { afterRound?: number; limit?: number; nextToken?: string }
        ): Promise<PaginatedTransactions> => {
            const pageIndex = options?.nextToken ? parseInt(options.nextToken, 10) : 0;
            const page = pages[pageIndex] ?? [];
            callCount++;
            // Update the externally visible callCount
            (mockPaginatedIndexer as any)._lastMock.callCount = callCount;
            const hasMore = pageIndex + 1 < pages.length;
            return {
                transactions: page,
                nextToken: hasMore ? String(pageIndex + 1) : undefined,
            };
        },
    };
}
// Track last created mock for callCount access
(mockPaginatedIndexer as any)._lastMock = null;

/**
 * Simpler paginated mock that tracks call count externally.
 */
function mockPaginatedIndexerWithCounter(pages: NoteTransaction[][]): {
    indexer: IndexerClient;
    getCallCount: () => number;
} {
    let callCount = 0;
    const indexer: IndexerClient = {
        searchTransactions: async () => pages.flat(),
        searchTransactionsBetween: async () => [],
        getTransaction: async () => pages[0]?.[0],
        waitForIndexer: async () => pages[0]?.[0],
        searchTransactionsPaginated: async (
            _address: string,
            options?: { afterRound?: number; limit?: number; nextToken?: string }
        ): Promise<PaginatedTransactions> => {
            const pageIndex = options?.nextToken ? parseInt(options.nextToken, 10) : 0;
            const page = pages[pageIndex] ?? [];
            callCount++;
            const hasMore = pageIndex + 1 < pages.length;
            return {
                transactions: page,
                nextToken: hasMore ? String(pageIndex + 1) : undefined,
            };
        },
    };
    return { indexer, getCallCount: () => callCount };
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

describe('paginated discoverEncryptionKey', () => {
    test('finds key on second page via pagination', async () => {
        const { encryptionKeys, address } = makeTestAccount();
        const other = makeTestAccount();

        // Page 1: irrelevant transactions
        const page1: NoteTransaction[] = [
            {
                txid: 'tx1',
                sender: other.address,
                receiver: address,
                note: new Uint8Array(32).fill(0xFF),
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ];

        // Page 2: the key announcement
        const page2: NoteTransaction[] = [
            {
                txid: 'tx2',
                sender: address,
                receiver: address,
                note: encryptionKeys.publicKey,
                confirmedRound: 50,
                roundTime: 1699999000,
            },
        ];

        const { indexer, getCallCount } = mockPaginatedIndexerWithCounter([page1, page2]);

        const result = await discoverEncryptionKey(indexer, address);
        expect(result).toBeDefined();
        expect(result!.publicKey).toEqual(encryptionKeys.publicKey);
        expect(getCallCount()).toBe(2); // two pages fetched
    });

    test('returns undefined when all pages exhausted without match', async () => {
        const { address } = makeTestAccount();
        const other = makeTestAccount();

        const page1: NoteTransaction[] = [
            {
                txid: 'tx1',
                sender: other.address,
                receiver: address,
                note: new Uint8Array(32).fill(0xFF),
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ];

        const { indexer, getCallCount } = mockPaginatedIndexerWithCounter([page1]);

        const result = await discoverEncryptionKey(indexer, address);
        expect(result).toBeUndefined();
        expect(getCallCount()).toBe(1);
    });

    test('stops at maxDepth even if more pages available', async () => {
        const { address } = makeTestAccount();
        const other = makeTestAccount();

        // 3 pages of 2 transactions each
        const pages: NoteTransaction[][] = [
            [
                { txid: 'tx1', sender: other.address, receiver: address, note: new Uint8Array(32), confirmedRound: 100, roundTime: 1700000000 },
                { txid: 'tx2', sender: other.address, receiver: address, note: new Uint8Array(32), confirmedRound: 101, roundTime: 1700000001 },
            ],
            [
                { txid: 'tx3', sender: other.address, receiver: address, note: new Uint8Array(32), confirmedRound: 102, roundTime: 1700000002 },
                { txid: 'tx4', sender: other.address, receiver: address, note: new Uint8Array(32), confirmedRound: 103, roundTime: 1700000003 },
            ],
            [
                { txid: 'tx5', sender: address, receiver: address, note: new Uint8Array(32).fill(0xAA), confirmedRound: 104, roundTime: 1700000004 },
            ],
        ];

        const { indexer, getCallCount } = mockPaginatedIndexerWithCounter(pages);

        // maxDepth=3 means we should only search 3 transactions (pages 1 and part of 2)
        const result = await discoverEncryptionKey(indexer, address, { maxDepth: 3, pageSize: 2 });
        expect(result).toBeUndefined();
        // Should have fetched 2 pages (2 + 1 = 3 transactions at most)
        expect(getCallCount()).toBe(2);
    });

    test('backward compat: numeric searchDepth still works', async () => {
        const { encryptionKeys, address } = makeTestAccount();

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: address,
                receiver: address,
                note: encryptionKeys.publicKey,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        // Pass numeric depth (backward compat)
        const result = await discoverEncryptionKey(indexer, address, 500);
        expect(result).toBeDefined();
        expect(result!.publicKey).toEqual(encryptionKeys.publicKey);
    });

    test('finds key across many pages (exhaustive search)', async () => {
        const { encryptionKeys, address } = makeTestAccount();
        const other = makeTestAccount();

        // 5 pages of filler, key on page 6
        const pages: NoteTransaction[][] = [];
        for (let i = 0; i < 5; i++) {
            pages.push([
                {
                    txid: `filler-${i}`,
                    sender: other.address,
                    receiver: address,
                    note: new Uint8Array(32).fill(i),
                    confirmedRound: 100 + i,
                    roundTime: 1700000000 + i,
                },
            ]);
        }
        // Page 6: the actual key announcement
        pages.push([
            {
                txid: 'key-tx',
                sender: address,
                receiver: address,
                note: encryptionKeys.publicKey,
                confirmedRound: 200,
                roundTime: 1700001000,
            },
        ]);

        const { indexer, getCallCount } = mockPaginatedIndexerWithCounter(pages);

        const result = await discoverEncryptionKey(indexer, address);
        expect(result).toBeDefined();
        expect(result!.publicKey).toEqual(encryptionKeys.publicKey);
        expect(getCallCount()).toBe(6);
    });
});

describe('paginated discoverEncryptionKeyFromMessages', () => {
    test('finds key from chat message on a later page', async () => {
        const { address } = makeTestAccount();
        const other = makeTestAccount();
        const senderKey = new Uint8Array(32).fill(0xBB);

        // Page 1: non-chat transaction
        const page1: NoteTransaction[] = [
            {
                txid: 'tx1',
                sender: address,
                receiver: other.address,
                note: new Uint8Array(10), // too short to be chat
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ];

        // Page 2: chat message from the target address
        const page2: NoteTransaction[] = [
            {
                txid: 'tx2',
                sender: address,
                receiver: other.address,
                note: new Uint8Array(32).fill(0xCC), // will pass isChatMessage mock
                confirmedRound: 101,
                roundTime: 1700000001,
            },
        ];

        const { indexer } = mockPaginatedIndexerWithCounter([page1, page2]);

        const result = await discoverEncryptionKeyFromMessages(
            indexer,
            address,
            (note) => note.length >= 32,
            (_note) => ({ senderPublicKey: senderKey })
        );

        expect(result).toBeDefined();
        expect(result!.publicKey).toEqual(senderKey);
        expect(result!.isVerified).toBe(false);
    });
});
