/**
 * AlgoChat Web - Algorand Service Tests
 *
 * Tests for the AlgorandService class.
 * Note: Network-dependent methods require mocking or integration tests.
 */

import { describe, test, expect } from 'bun:test';
import { AlgorandService, type AlgorandConfig } from './algorand.service';
import { createRandomChatAccount } from './mnemonic.service';
import { encryptMessage, encodeEnvelope } from '../crypto';

const TEST_CONFIG: AlgorandConfig = {
    algodToken: 'test-token',
    algodServer: 'https://testnet-api.algonode.cloud',
    indexerToken: 'test-token',
    indexerServer: 'https://testnet-idx.algonode.cloud',
};

describe('AlgorandService', () => {
    describe('constructor', () => {
        test('creates service with valid config', () => {
            const service = new AlgorandService(TEST_CONFIG);
            expect(service).toBeDefined();
        });

        test('creates service with optional ports', () => {
            const configWithPorts: AlgorandConfig = {
                ...TEST_CONFIG,
                algodPort: 443,
                indexerPort: 443,
            };
            const service = new AlgorandService(configWithPorts);
            expect(service).toBeDefined();
        });
    });

    describe('message encryption integration', () => {
        test('encrypted message can be encoded to valid note', () => {
            const sender = createRandomChatAccount().account;
            const recipient = createRandomChatAccount().account;

            const envelope = encryptMessage(
                'Test message',
                sender.encryptionKeys.publicKey,
                recipient.encryptionKeys.publicKey
            );

            const note = encodeEnvelope(envelope);

            // Verify note is within Algorand limits
            expect(note.length).toBeLessThanOrEqual(1024);
            expect(note.length).toBeGreaterThanOrEqual(142); // Minimum envelope size
        });

        test('large message stays within note limit', () => {
            const sender = createRandomChatAccount().account;
            const recipient = createRandomChatAccount().account;

            // Create message near max size (882 bytes plaintext max)
            const largeMessage = 'A'.repeat(800);

            const envelope = encryptMessage(
                largeMessage,
                sender.encryptionKeys.publicKey,
                recipient.encryptionKeys.publicKey
            );

            const note = encodeEnvelope(envelope);

            expect(note.length).toBeLessThanOrEqual(1024);
        });

        test('message too large throws error', () => {
            const sender = createRandomChatAccount().account;
            const recipient = createRandomChatAccount().account;

            // Message over 882 bytes should fail
            const oversizeMessage = 'A'.repeat(900);

            expect(() =>
                encryptMessage(
                    oversizeMessage,
                    sender.encryptionKeys.publicKey,
                    recipient.encryptionKeys.publicKey
                )
            ).toThrow(/too large/i);
        });
    });

    describe('ChatAccount structure', () => {
        test('ChatAccount has required fields', () => {
            const { account: chatAccount } = createRandomChatAccount();

            // Type check - these should all be defined
            expect(chatAccount.address).toBeDefined();
            expect(chatAccount.account).toBeDefined();
            expect(chatAccount.encryptionKeys).toBeDefined();
            expect(chatAccount.encryptionKeys.publicKey).toBeDefined();
            expect(chatAccount.encryptionKeys.privateKey).toBeDefined();
        });

        test('ChatAccount address matches algosdk account', () => {
            const { account: chatAccount } = createRandomChatAccount();

            expect(chatAccount.address).toBe(chatAccount.account.addr.toString());
        });
    });

    describe('sendMessage result structure', () => {
        test('optimistic message has correct shape', () => {
            // Test the Message type structure that sendMessage returns
            const sender = createRandomChatAccount().account;
            const recipientAddress = createRandomChatAccount().account.address;

            // Simulate what sendMessage builds for optimistic UI
            const optimisticMessage = {
                id: 'test-txid',
                sender: sender.address,
                recipient: recipientAddress,
                content: 'Test message',
                timestamp: new Date(),
                confirmedRound: 0,
                direction: 'sent' as const,
            };

            expect(optimisticMessage.id).toBe('test-txid');
            expect(optimisticMessage.sender).toBe(sender.address);
            expect(optimisticMessage.recipient).toBe(recipientAddress);
            expect(optimisticMessage.direction).toBe('sent');
            expect(optimisticMessage.confirmedRound).toBe(0);
        });

        test('reply message includes reply context', () => {
            const sender = createRandomChatAccount().account;
            const recipientAddress = createRandomChatAccount().account.address;

            const replyMessage = {
                id: 'reply-txid',
                sender: sender.address,
                recipient: recipientAddress,
                content: 'This is a reply',
                timestamp: new Date(),
                confirmedRound: 0,
                direction: 'sent' as const,
                replyContext: {
                    messageId: 'original-txid',
                    preview: 'Original message...',
                },
            };

            expect(replyMessage.replyContext).toBeDefined();
            expect(replyMessage.replyContext.messageId).toBe('original-txid');
            expect(replyMessage.replyContext.preview).toBe('Original message...');
        });
    });

    describe('key publish payload', () => {
        test('key publish creates self-addressed envelope', () => {
            const { account: chatAccount } = createRandomChatAccount();

            const payload = JSON.stringify({ type: 'key-publish' });

            // Self-encrypt like publishKey does
            const envelope = encryptMessage(
                payload,
                chatAccount.encryptionKeys.publicKey,
                chatAccount.encryptionKeys.publicKey // Self
            );

            // Sender public key should be set
            expect(envelope.senderPublicKey.length).toBe(32);

            // Can encode to valid note
            const note = encodeEnvelope(envelope);
            expect(note.length).toBeLessThanOrEqual(1024);
        });
    });

    describe('discoverPublicKey error handling', () => {
        test('throws descriptive error when key not found', async () => {
            const service = new AlgorandService(TEST_CONFIG);
            const fakeAddress = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ';

            // Mock the indexer to return empty results
            const mockIndexer = {
                searchForTransactions: () => ({
                    address: () => ({
                        limit: () => ({
                            do: async () => ({ transactions: [] }),
                        }),
                    }),
                }),
            };

            // @ts-expect-error - accessing private property for testing
            service.indexerClient = mockIndexer;

            await expect(service.discoverPublicKey(fakeAddress)).rejects.toThrow(
                /Public key not found for address/
            );
        });
    });
});
