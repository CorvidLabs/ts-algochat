/**
 * AlgoChat - Message Indexer Tests
 */

import { describe, test, expect } from 'bun:test';
import algosdk from 'algosdk';
import { MessageIndexer, PublicKeyNotFoundError, DEFAULT_SEARCH_DEPTH } from './message-indexer';
import { signEncryptionKey, getPublicKey } from '../crypto';
import { deriveEncryptionKeys } from '../crypto/keys';
import type { IndexerClient } from './interfaces';
import type { NoteTransaction } from './types';

/** Generate a test account with encryption keys. */
function makeTestAccount() {
    const account = algosdk.generateAccount();
    const seed = account.sk.slice(0, 32);
    const ed25519PublicKey = getPublicKey(seed);
    const encryptionKeys = deriveEncryptionKeys(seed);
    const address = account.addr.toString();
    return { account, seed, ed25519PublicKey, encryptionKeys, address };
}

/** Build a minimal valid AlgoChat envelope note (passes isChatMessage + decodeEnvelope). */
function makeEnvelopeNote(senderPublicKey: Uint8Array): Uint8Array {
    // version(1) + protocolId(1) + senderPubKey(32) + ephemeralPubKey(32) + nonce(12) + encSenderKey(48) + ciphertext(>=16)
    const minSize = 2 + 32 + 32 + 12 + 48 + 16;
    const note = new Uint8Array(minSize);
    note[0] = 0x01; // VERSION
    note[1] = 0x01; // PROTOCOL_ID
    note.set(senderPublicKey, 2);
    // Rest is zeros — good enough for envelope decoding (won't decrypt, but findPublicKey only decodes)
    return note;
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

const dummyAccount = makeTestAccount();
const chatAccount = {
    address: dummyAccount.address,
    encryptionKeys: dummyAccount.encryptionKeys,
};

describe('PublicKeyNotFoundError', () => {
    test('has correct name and message', () => {
        const err = new PublicKeyNotFoundError('SOME_ADDRESS');
        expect(err.name).toBe('PublicKeyNotFoundError');
        expect(err.message).toContain('SOME_ADDRESS');
        expect(err.address).toBe('SOME_ADDRESS');
        expect(err).toBeInstanceOf(Error);
    });
});

describe('MessageIndexer.findPublicKey', () => {
    test('returns isVerified: false for key extracted from message envelope', async () => {
        const target = makeTestAccount();
        const note = makeEnvelopeNote(target.encryptionKeys.publicKey);

        // Regular chat message (not a self-transfer, so NOT a key announcement)
        const indexer = mockIndexer([
            {
                txid: 'tx-msg',
                sender: target.address,
                receiver: dummyAccount.address, // not self-transfer
                note,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const mi = new MessageIndexer(indexer, chatAccount);
        const result = await mi.findPublicKey(target.address);

        expect(result.publicKey.length).toBe(32);
        expect(result.isVerified).toBe(false);
    });

    test('returns isVerified: true for key from signed key announcement', async () => {
        const target = makeTestAccount();
        const signature = signEncryptionKey(target.encryptionKeys.publicKey, target.seed);

        // Build signed key announcement (self-transfer with 96-byte note)
        const announcementNote = new Uint8Array(96);
        announcementNote.set(target.encryptionKeys.publicKey, 0);
        announcementNote.set(signature, 32);

        const indexer = mockIndexer([
            {
                txid: 'tx-announce',
                sender: target.address,
                receiver: target.address, // self-transfer
                note: announcementNote,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const mi = new MessageIndexer(indexer, chatAccount);
        const result = await mi.findPublicKey(target.address);

        expect(result.publicKey.length).toBe(32);
        expect(result.isVerified).toBe(true);
    });

    test('prefers signed key announcement over message envelope', async () => {
        const target = makeTestAccount();
        const signature = signEncryptionKey(target.encryptionKeys.publicKey, target.seed);

        // Key announcement (self-transfer)
        const announcementNote = new Uint8Array(96);
        announcementNote.set(target.encryptionKeys.publicKey, 0);
        announcementNote.set(signature, 32);

        // Regular message envelope
        const messageNote = makeEnvelopeNote(target.encryptionKeys.publicKey);

        const indexer = mockIndexer([
            {
                txid: 'tx-msg',
                sender: target.address,
                receiver: dummyAccount.address,
                note: messageNote,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
            {
                txid: 'tx-announce',
                sender: target.address,
                receiver: target.address,
                note: announcementNote,
                confirmedRound: 101,
                roundTime: 1700000001,
            },
        ]);

        const mi = new MessageIndexer(indexer, chatAccount);
        const result = await mi.findPublicKey(target.address);

        // Should pick the signed announcement (isVerified: true)
        expect(result.isVerified).toBe(true);
    });

    test('falls back to message envelope when no signed announcement exists', async () => {
        const target = makeTestAccount();
        const note = makeEnvelopeNote(target.encryptionKeys.publicKey);

        // Only a regular message, no key announcement
        const indexer = mockIndexer([
            {
                txid: 'tx-msg',
                sender: target.address,
                receiver: dummyAccount.address,
                note,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const mi = new MessageIndexer(indexer, chatAccount);
        const result = await mi.findPublicKey(target.address);

        expect(result.publicKey).toEqual(target.encryptionKeys.publicKey);
        expect(result.isVerified).toBe(false);
    });

    test('throws PublicKeyNotFoundError when no transactions exist', async () => {
        const indexer = mockIndexer([]);
        const mi = new MessageIndexer(indexer, chatAccount);

        expect(mi.findPublicKey('SOME_ADDRESS')).rejects.toThrow(PublicKeyNotFoundError);
    });

    test('skips transactions not sent by the target address', async () => {
        const target = makeTestAccount();
        const other = makeTestAccount();
        const note = makeEnvelopeNote(target.encryptionKeys.publicKey);

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: other.address, // not sent by target
                receiver: target.address,
                note,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const mi = new MessageIndexer(indexer, chatAccount);
        expect(mi.findPublicKey(target.address)).rejects.toThrow(PublicKeyNotFoundError);
    });

    test('skips transactions without note field', async () => {
        const target = makeTestAccount();

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: target.address,
                receiver: dummyAccount.address,
                note: new Uint8Array(0), // empty note
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const mi = new MessageIndexer(indexer, chatAccount);
        expect(mi.findPublicKey(target.address)).rejects.toThrow(PublicKeyNotFoundError);
    });

    test('skips non-AlgoChat messages', async () => {
        const target = makeTestAccount();

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: target.address,
                receiver: dummyAccount.address,
                note: new Uint8Array([0xFF, 0xFF, ...new Array(140).fill(0)]), // wrong protocol
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const mi = new MessageIndexer(indexer, chatAccount);
        expect(mi.findPublicKey(target.address)).rejects.toThrow(PublicKeyNotFoundError);
    });

    test('uses default search depth', async () => {
        expect(DEFAULT_SEARCH_DEPTH).toBe(200);
    });

    test('returns unverified key when announcement has invalid signature', async () => {
        const target = makeTestAccount();

        // Key announcement with bogus signature (self-transfer)
        const announcementNote = new Uint8Array(96);
        announcementNote.set(target.encryptionKeys.publicKey, 0);
        announcementNote.set(new Uint8Array(64).fill(0xFF), 32); // bogus signature

        // Also include a message envelope so we have a fallback
        const messageNote = makeEnvelopeNote(target.encryptionKeys.publicKey);

        const indexer = mockIndexer([
            {
                txid: 'tx-announce',
                sender: target.address,
                receiver: target.address,
                note: announcementNote,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
            {
                txid: 'tx-msg',
                sender: target.address,
                receiver: dummyAccount.address,
                note: messageNote,
                confirmedRound: 101,
                roundTime: 1700000001,
            },
        ]);

        const mi = new MessageIndexer(indexer, chatAccount);
        const result = await mi.findPublicKey(target.address);

        // discoverEncryptionKey returns the key but with isVerified: false
        // since the signature is bogus
        expect(result.isVerified).toBe(false);
    });
});

describe('MessageIndexer.fetchMessages', () => {
    test('returns empty array when no transactions', async () => {
        const indexer = mockIndexer([]);
        const mi = new MessageIndexer(indexer, chatAccount);

        const messages = await mi.fetchMessages('OTHER_ADDRESS');
        expect(messages).toEqual([]);
    });

    test('skips non-chat transactions', async () => {
        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: dummyAccount.address,
                receiver: 'OTHER',
                note: new Uint8Array([0xFF, 0x00]), // not AlgoChat
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const mi = new MessageIndexer(indexer, chatAccount);
        const messages = await mi.fetchMessages('OTHER');
        expect(messages).toEqual([]);
    });

    test('skips transactions with empty notes', async () => {
        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: dummyAccount.address,
                receiver: 'OTHER',
                note: new Uint8Array(0),
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const mi = new MessageIndexer(indexer, chatAccount);
        const messages = await mi.fetchMessages('OTHER');
        expect(messages).toEqual([]);
    });
});

describe('MessageIndexer.fetchConversations', () => {
    test('returns empty array when no transactions', async () => {
        const indexer = mockIndexer([]);
        const mi = new MessageIndexer(indexer, chatAccount);

        const conversations = await mi.fetchConversations();
        expect(conversations).toEqual([]);
    });
});

describe('MessageIndexer.waitForTransaction', () => {
    test('returns true when transaction is found immediately', async () => {
        const indexer = mockIndexer([
            {
                txid: 'target-tx',
                sender: dummyAccount.address,
                receiver: 'OTHER',
                note: new Uint8Array(0),
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const mi = new MessageIndexer(indexer, chatAccount);
        const found = await mi.waitForTransaction('target-tx', 5000);
        expect(found).toBe(true);
    });

    test('returns false on timeout when transaction not found', async () => {
        const indexer = mockIndexer([]);
        const mi = new MessageIndexer(indexer, chatAccount);

        // Use very short timeout to avoid slow test
        const found = await mi.waitForTransaction('missing-tx', 50, 10, 20);
        expect(found).toBe(false);
    });

    test('returns true when transaction appears after initial miss', async () => {
        let callCount = 0;
        const indexer: IndexerClient = {
            searchTransactions: async () => {
                callCount++;
                if (callCount >= 2) {
                    return [
                        {
                            txid: 'delayed-tx',
                            sender: dummyAccount.address,
                            receiver: 'OTHER',
                            note: new Uint8Array(0),
                            confirmedRound: 100,
                            roundTime: 1700000000,
                        },
                    ];
                }
                return [];
            },
            searchTransactionsBetween: async () => [],
            getTransaction: async () => ({
                txid: '',
                sender: '',
                receiver: '',
                note: new Uint8Array(0),
                confirmedRound: 0,
                roundTime: 0,
            }),
            waitForIndexer: async () => ({
                txid: '',
                sender: '',
                receiver: '',
                note: new Uint8Array(0),
                confirmedRound: 0,
                roundTime: 0,
            }),
        };

        const mi = new MessageIndexer(indexer, chatAccount);
        const found = await mi.waitForTransaction('delayed-tx', 5000, 10, 50);
        expect(found).toBe(true);
        expect(callCount).toBeGreaterThanOrEqual(2);
    });
});
