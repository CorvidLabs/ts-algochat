/**
 * AlgoChat - MessageIndexer Tests
 *
 * Tests for the blockchain MessageIndexer, focusing on the findPublicKey()
 * method and its isVerified behavior.
 */

import { describe, test, expect } from 'bun:test';
import { MessageIndexer, PublicKeyNotFoundError } from './message-indexer';
import { encodeEnvelope } from '../crypto/envelope';
import { PROTOCOL, type ChatEnvelope } from '../models/types';
import type { IndexerClient } from './interfaces';
import type { NoteTransaction } from './types';

const SENDER_ADDRESS = 'SENDER_ADDRESS';
const OTHER_ADDRESS = 'OTHER_ADDRESS';

/** Build a valid AlgoChat envelope note (binary) for testing. */
function makeEnvelopeNote(): Uint8Array {
    const envelope: ChatEnvelope = {
        version: PROTOCOL.VERSION,
        protocolId: PROTOCOL.PROTOCOL_ID,
        senderPublicKey: new Uint8Array(32).fill(0xAA),
        ephemeralPublicKey: new Uint8Array(32).fill(0xBB),
        nonce: new Uint8Array(12).fill(0xCC),
        encryptedSenderKey: new Uint8Array(48).fill(0xDD),
        ciphertext: new Uint8Array(32).fill(0xEE),
    };
    return encodeEnvelope(envelope);
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

/** Build a mock ChatAccountLike for the MessageIndexer constructor. */
function mockChatAccount() {
    return {
        address: 'MY_ADDRESS',
        encryptionKeys: {
            publicKey: new Uint8Array(32).fill(0x11),
            privateKey: new Uint8Array(32).fill(0x22),
        },
    };
}

describe('MessageIndexer.findPublicKey', () => {
    test('returns isVerified: false for keys extracted from envelope senderPublicKey', async () => {
        const note = makeEnvelopeNote();

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: SENDER_ADDRESS,
                receiver: OTHER_ADDRESS,
                note,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const messageIndexer = new MessageIndexer(indexer, mockChatAccount());
        const result = await messageIndexer.findPublicKey(SENDER_ADDRESS);

        expect(result).toBeDefined();
        expect(result.isVerified).toBe(false);
        expect(result.publicKey.length).toBe(32);
    });

    test('returns the correct senderPublicKey from the envelope', async () => {
        const note = makeEnvelopeNote();

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: SENDER_ADDRESS,
                receiver: OTHER_ADDRESS,
                note,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const messageIndexer = new MessageIndexer(indexer, mockChatAccount());
        const result = await messageIndexer.findPublicKey(SENDER_ADDRESS);

        // The key should be the 0xAA-filled bytes we set in makeEnvelopeNote
        expect(result.publicKey.every((b) => b === 0xAA)).toBe(true);
    });

    test('skips transactions not sent by the target address', async () => {
        const note = makeEnvelopeNote();

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: OTHER_ADDRESS,
                receiver: SENDER_ADDRESS,
                note,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const messageIndexer = new MessageIndexer(indexer, mockChatAccount());

        await expect(
            messageIndexer.findPublicKey(SENDER_ADDRESS)
        ).rejects.toThrow(PublicKeyNotFoundError);
    });

    test('skips transactions with notes too short to be AlgoChat messages', async () => {
        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: SENDER_ADDRESS,
                receiver: OTHER_ADDRESS,
                note: new Uint8Array(1), // too short
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const messageIndexer = new MessageIndexer(indexer, mockChatAccount());

        await expect(
            messageIndexer.findPublicKey(SENDER_ADDRESS)
        ).rejects.toThrow(PublicKeyNotFoundError);
    });

    test('skips transactions with non-AlgoChat notes', async () => {
        const nonAlgoChatNote = new Uint8Array(200).fill(0x00); // wrong version/protocol

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: SENDER_ADDRESS,
                receiver: OTHER_ADDRESS,
                note: nonAlgoChatNote,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const messageIndexer = new MessageIndexer(indexer, mockChatAccount());

        await expect(
            messageIndexer.findPublicKey(SENDER_ADDRESS)
        ).rejects.toThrow(PublicKeyNotFoundError);
    });

    test('throws PublicKeyNotFoundError when no transactions match', async () => {
        const indexer = mockIndexer([]);

        const messageIndexer = new MessageIndexer(indexer, mockChatAccount());

        await expect(
            messageIndexer.findPublicKey(SENDER_ADDRESS)
        ).rejects.toThrow(PublicKeyNotFoundError);
    });

    test('PublicKeyNotFoundError contains the address', async () => {
        const indexer = mockIndexer([]);

        const messageIndexer = new MessageIndexer(indexer, mockChatAccount());

        try {
            await messageIndexer.findPublicKey(SENDER_ADDRESS);
            expect(true).toBe(false); // should not reach
        } catch (err) {
            expect(err).toBeInstanceOf(PublicKeyNotFoundError);
            expect((err as PublicKeyNotFoundError).address).toBe(SENDER_ADDRESS);
        }
    });

    test('finds key from second transaction when first is not from target', async () => {
        const note = makeEnvelopeNote();

        const indexer = mockIndexer([
            {
                txid: 'tx1',
                sender: OTHER_ADDRESS,
                receiver: SENDER_ADDRESS,
                note,
                confirmedRound: 99,
                roundTime: 1699999999,
            },
            {
                txid: 'tx2',
                sender: SENDER_ADDRESS,
                receiver: OTHER_ADDRESS,
                note,
                confirmedRound: 100,
                roundTime: 1700000000,
            },
        ]);

        const messageIndexer = new MessageIndexer(indexer, mockChatAccount());
        const result = await messageIndexer.findPublicKey(SENDER_ADDRESS);

        expect(result).toBeDefined();
        expect(result.isVerified).toBe(false);
    });
});
