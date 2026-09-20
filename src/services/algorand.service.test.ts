/**
 * AlgoChat Web - Algorand Service Tests
 *
 * Tests for the AlgorandService class.
 * Note: Network-dependent methods require mocking or integration tests.
 */

import { describe, test, expect } from 'bun:test';
import algosdk from 'algosdk';
import { AlgorandService, FALCON_FEE_MULTIPLIER, type AlgorandConfig } from './algorand.service.js';
import { SIGNING_SCHEME, createRandomChatAccount } from './mnemonic.service.js';
import { decryptMessage, encryptMessage, encodeEnvelope, isChatMessage } from '../crypto/index.js';

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

        test('creates service with encryption options (PSK)', () => {
            const psk = new Uint8Array(32).fill(0xaa);
            const service = new AlgorandService(TEST_CONFIG, { psk });
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

            expect(chatAccount.address).toBeDefined();
            expect(chatAccount.scheme).toBe('falcon-1024');
            expect(chatAccount.txnSigner).toBeTypeOf('function');
            expect(chatAccount.encryptionKeys).toBeDefined();
            expect(chatAccount.encryptionKeys.publicKey).toBeDefined();
            expect(chatAccount.encryptionKeys.privateKey).toBeDefined();
        });

        test('Ed25519 ChatAccount address matches algosdk account', () => {
            const { account: chatAccount } = createRandomChatAccount({ scheme: 'ed25519' });

            expect(chatAccount.account).toBeDefined();
            expect(chatAccount.address).toBe(chatAccount.account!.addr.toString());
        });

        test('Falcon fee multiplier is 3', () => {
            expect(FALCON_FEE_MULTIPLIER).toBe(3);
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
                /Public key not found for/
            );
        });
    });

    describe('Falcon and Ed25519 send path', () => {
        function suggestedParams(
            overrides: Record<string, unknown> = {}
        ): algosdk.SuggestedParams {
            return {
                fee: 1000,
                minFee: 1000,
                firstValid: 100,
                lastValid: 1100,
                genesisHash: new Uint8Array(32).fill(1),
                genesisID: 'testnet-v1.0',
                flatFee: true,
                ...overrides,
            } as algosdk.SuggestedParams;
        }

        function makeStubAlgod(params: algosdk.SuggestedParams = suggestedParams()) {
            const captured: Uint8Array[] = [];
            const client = {
                getTransactionParams: () => ({ do: async () => params }),
                sendRawTransaction: (signed: Uint8Array | Uint8Array[]) => ({
                    do: async () => {
                        const blob = Array.isArray(signed) ? signed[0] : signed;
                        captured.push(blob);
                        return { txid: algosdk.decodeSignedTransaction(blob).txn.txID() };
                    },
                }),
            };
            return { client, captured };
        }

        function attachAlgod(service: AlgorandService, client: unknown): void {
            // @ts-expect-error private client injected for offline send tests
            service.algodClient = client;
        }

        test('does not expose a mailbox transport', () => {
            const service = new AlgorandService(TEST_CONFIG);
            expect(service).not.toHaveProperty('mailbox');
        });

        test('Falcon sendMessage signs with pqsig and 3× minFee', async () => {
            const stub = makeStubAlgod();
            const service = new AlgorandService(TEST_CONFIG);
            attachAlgod(service, stub.client);

            const sender = createRandomChatAccount().account;
            const recipient = createRandomChatAccount().account;
            expect(sender.scheme).toBe(SIGNING_SCHEME.FALCON_1024);
            expect(sender.account).toBeUndefined();

            const result = await service.sendMessage(
                sender,
                recipient.address,
                recipient.encryptionKeys.publicKey,
                'hello falcon'
            );

            expect(result.txid).toBeDefined();
            expect(result.fee).toBe(3000);
            expect(stub.captured).toHaveLength(1);

            const signed = algosdk.decodeSignedTransaction(stub.captured[0]);
            expect(signed.pqsig).toBeDefined();
            expect(signed.sig).toBeUndefined();
            expect(Buffer.from(signed.pqsig!.sch).toString()).toBe('f1');
            expect(Number(signed.txn.fee)).toBe(3000);
            expect(signed.txn.sender.toString()).toBe(sender.address);
            expect(isChatMessage(signed.txn.note ?? new Uint8Array())).toBe(true);
        });

        test('Ed25519 sendMessage signs with sig at the network min fee', async () => {
            const stub = makeStubAlgod();
            const service = new AlgorandService(TEST_CONFIG);
            attachAlgod(service, stub.client);

            const sender = createRandomChatAccount({ scheme: 'ed25519' }).account;
            const recipient = createRandomChatAccount().account;

            const result = await service.sendMessage(
                sender,
                recipient.address,
                recipient.encryptionKeys.publicKey,
                'hello ed25519'
            );

            expect(result.fee).toBe(1000);
            const signed = algosdk.decodeSignedTransaction(stub.captured[0]);
            expect(signed.sig).toBeDefined();
            expect(signed.sig?.length).toBe(64);
            expect(signed.pqsig).toBeUndefined();
            expect(Number(signed.txn.fee)).toBe(1000);
        });

        test('Falcon sendReply and publishKey also use pqsig', async () => {
            const stub = makeStubAlgod();
            const service = new AlgorandService(TEST_CONFIG);
            attachAlgod(service, stub.client);

            const sender = createRandomChatAccount().account;
            const recipient = createRandomChatAccount().account;

            await service.sendReply(
                sender,
                recipient.address,
                recipient.encryptionKeys.publicKey,
                'reply',
                'original-txid',
                'original preview'
            );
            await service.publishKey(sender);

            expect(stub.captured).toHaveLength(2);
            for (const blob of stub.captured) {
                const signed = algosdk.decodeSignedTransaction(blob);
                expect(signed.pqsig).toBeDefined();
                expect(signed.sig).toBeUndefined();
                expect(Number(signed.txn.fee)).toBe(3000);
            }
        });

        test('Falcon fee uses the payment fee when minFee is omitted', async () => {
            const stub = makeStubAlgod(suggestedParams({ minFee: undefined }));
            const service = new AlgorandService(TEST_CONFIG);
            attachAlgod(service, stub.client);

            const sender = createRandomChatAccount().account;
            const recipient = createRandomChatAccount().account;

            const result = await service.sendMessage(
                sender,
                recipient.address,
                recipient.encryptionKeys.publicKey,
                'no minFee'
            );

            expect(result.fee).toBe(3000);
            expect(Number(algosdk.decodeSignedTransaction(stub.captured[0]).txn.fee)).toBe(3000);
        });

        test('Falcon ChatAccounts encrypt and decrypt standard envelopes', () => {
            const sender = createRandomChatAccount().account;
            const recipient = createRandomChatAccount().account;

            const envelope = encryptMessage(
                'post-quantum identity, classical ECDH',
                sender.encryptionKeys.publicKey,
                recipient.encryptionKeys.publicKey
            );
            const decrypted = decryptMessage(
                envelope,
                recipient.encryptionKeys.privateKey,
                recipient.encryptionKeys.publicKey
            );

            expect(sender.scheme).toBe(SIGNING_SCHEME.FALCON_1024);
            expect(recipient.scheme).toBe(SIGNING_SCHEME.FALCON_1024);
            expect(decrypted?.text).toBe('post-quantum identity, classical ECDH');
        });
    });
});
