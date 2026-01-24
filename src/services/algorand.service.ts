/**
 * AlgoChat Web - Algorand Blockchain Service
 *
 * Handles sending messages and querying the blockchain.
 */

import algosdk from 'algosdk';
import type { Message, Conversation, SendResult, SendOptions, X25519KeyPair, DiscoveredKey } from '../models/types';
import { encryptMessage, encryptReply, decryptMessage, encodeEnvelope, decodeEnvelope, isChatMessage } from '../crypto';
import { ChatError } from '../errors/ChatError';

export interface AlgorandConfig {
    algodToken: string;
    algodServer: string;
    algodPort?: number;
    indexerToken: string;
    indexerServer: string;
    indexerPort?: number;
}

export interface ChatAccount {
    address: string;
    account: algosdk.Account;
    encryptionKeys: X25519KeyPair;
}

/** Indexer transaction response shape (subset of fields we use) */
interface IndexerTransaction {
    id: string;
    sender: string;
    txType: string;
    note?: string;
    roundTime?: number;
    confirmedRound?: number;
    paymentTransaction?: {
        receiver?: string;
        amount?: number;
    };
}

interface IndexerSearchResponse {
    transactions?: IndexerTransaction[];
}

export class AlgorandService {
    private algodClient: algosdk.Algodv2;
    private indexerClient: algosdk.Indexer;

    constructor(config: AlgorandConfig) {
        // Pass empty string for port when not specified to avoid algosdk defaulting to 8080
        this.algodClient = new algosdk.Algodv2(
            config.algodToken,
            config.algodServer,
            config.algodPort ?? ''
        );

        this.indexerClient = new algosdk.Indexer(
            config.indexerToken,
            config.indexerServer,
            config.indexerPort ?? ''
        );
    }

    /**
     * Sends an encrypted message to a recipient
     *
     * @param chatAccount - The sender's chat account
     * @param recipientAddress - Recipient's Algorand address
     * @param recipientPublicKey - Recipient's encryption public key
     * @param message - Message content
     * @param options - Send options (waitForConfirmation, waitForIndexer, etc.)
     */
    async sendMessage(
        chatAccount: ChatAccount,
        recipientAddress: string,
        recipientPublicKey: Uint8Array,
        message: string,
        options: SendOptions = {}
    ): Promise<SendResult> {
        // Encrypt message
        const envelope = encryptMessage(
            message,
            chatAccount.encryptionKeys.publicKey,
            recipientPublicKey
        );

        // Encode to bytes
        const note = encodeEnvelope(envelope);

        // Get transaction parameters
        const params = await this.algodClient.getTransactionParams().do();

        // Build payment transaction
        const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
            sender: chatAccount.address,
            receiver: recipientAddress,
            amount: options?.amount ?? 1000, // 0.001 ALGO minimum
            note,
            suggestedParams: params,
        });

        // Sign and submit
        const signedTxn = txn.signTxn(chatAccount.account.sk);
        const { txid } = await this.algodClient.sendRawTransaction(signedTxn).do();

        // Build optimistic message for UI
        const sentMessage: Message = {
            id: txid,
            sender: chatAccount.address,
            recipient: recipientAddress,
            content: message,
            timestamp: new Date(),
            confirmedRound: 0,
            direction: 'sent',
            replyContext: options.replyContext,
            amount: options?.amount ?? 1000,
        };

        const result: SendResult = { txid, message: sentMessage };

        // Wait for confirmation if requested
        if (options.waitForConfirmation) {
            const timeout = options.timeout ?? 10;
            const confirmation = await algosdk.waitForConfirmation(this.algodClient, txid, timeout);
            result.confirmedRound = Number(confirmation.confirmedRound);
            sentMessage.confirmedRound = result.confirmedRound;
        }

        // Wait for indexer if requested
        if (options.waitForIndexer) {
            const indexed = await this.waitForIndexer(txid, options.indexerTimeout ?? 30000);
            if (!indexed) {
                throw ChatError.timeout('waitForIndexer', options.indexerTimeout ?? 30000);
            }
        }

        return result;
    }

    /**
     * Sends a reply to a message
     *
     * @param chatAccount - The sender's chat account
     * @param recipientAddress - Recipient's Algorand address
     * @param recipientPublicKey - Recipient's encryption public key
     * @param message - Message content
     * @param replyToTxid - Transaction ID of the message being replied to
     * @param replyToPreview - Preview text of the message being replied to
     * @param options - Send options (waitForConfirmation, waitForIndexer, etc.)
     */
    async sendReply(
        chatAccount: ChatAccount,
        recipientAddress: string,
        recipientPublicKey: Uint8Array,
        message: string,
        replyToTxid: string,
        replyToPreview: string,
        options: SendOptions = {}
    ): Promise<SendResult> {
        const envelope = encryptReply(
            message,
            replyToTxid,
            replyToPreview,
            chatAccount.encryptionKeys.publicKey,
            recipientPublicKey
        );

        const note = encodeEnvelope(envelope);
        const params = await this.algodClient.getTransactionParams().do();

        const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
            sender: chatAccount.address,
            receiver: recipientAddress,
            amount: options?.amount ?? 1000,
            note,
            suggestedParams: params,
        });

        const signedTxn = txn.signTxn(chatAccount.account.sk);
        const { txid } = await this.algodClient.sendRawTransaction(signedTxn).do();

        const replyContext = {
            messageId: replyToTxid,
            preview: replyToPreview,
        };

        const sentMessage: Message = {
            id: txid,
            sender: chatAccount.address,
            recipient: recipientAddress,
            content: message,
            timestamp: new Date(),
            confirmedRound: 0,
            direction: 'sent',
            replyContext,
            amount: options?.amount ?? 1000,
        };

        const result: SendResult = { txid, message: sentMessage };

        // Wait for confirmation if requested
        if (options.waitForConfirmation) {
            const timeout = options.timeout ?? 10;
            const confirmation = await algosdk.waitForConfirmation(this.algodClient, txid, timeout);
            result.confirmedRound = Number(confirmation.confirmedRound);
            sentMessage.confirmedRound = result.confirmedRound;
        }

        // Wait for indexer if requested
        if (options.waitForIndexer) {
            const indexed = await this.waitForIndexer(txid, options.indexerTimeout ?? 30000);
            if (!indexed) {
                throw ChatError.timeout('waitForIndexer', options.indexerTimeout ?? 30000);
            }
        }

        return result;
    }

    /**
     * Fetches messages with a participant
     */
    async fetchMessages(
        chatAccount: ChatAccount,
        participantAddress: string,
        afterRound?: number,
        limit = 50
    ): Promise<Message[]> {
        const messages: Message[] = [];

        // Query transactions
        let query = this.indexerClient
            .searchForTransactions()
            .address(chatAccount.address)
            .limit(limit);

        if (afterRound) {
            query = query.minRound(afterRound);
        }

        const response = await query.do() as IndexerSearchResponse;

        for (const tx of response.transactions ?? []) {
            // Filter: payment transactions with notes
            if (tx.txType !== 'pay' || !tx.note) {
                continue;
            }

            // Decode note from base64
            const noteBytes = base64ToBytes(tx.note);

            // Filter: AlgoChat messages
            if (!isChatMessage(noteBytes)) {
                continue;
            }

            // Determine direction and filter by participant
            const sender: string = tx.sender;
            const receiver: string | undefined = tx.paymentTransaction?.receiver;

            if (!receiver) continue;

            let direction: 'sent' | 'received';

            if (sender === chatAccount.address) {
                if (receiver !== participantAddress) continue;
                direction = 'sent';
            } else {
                if (sender !== participantAddress) continue;
                if (receiver !== chatAccount.address) continue;
                direction = 'received';
            }

            // Decrypt message
            try {
                const envelope = decodeEnvelope(noteBytes);
                const decrypted = decryptMessage(
                    envelope,
                    chatAccount.encryptionKeys.privateKey,
                    chatAccount.encryptionKeys.publicKey
                );

                if (!decrypted) continue; // Key-publish, skip

                messages.push({
                    id: tx.id,
                    sender,
                    recipient: receiver,
                    content: decrypted.text,
                    timestamp: new Date((tx.roundTime ?? 0) * 1000),
                    confirmedRound: tx.confirmedRound ?? 0,
                    direction,
                    replyContext: decrypted.replyToId
                        ? {
                              messageId: decrypted.replyToId,
                              preview: decrypted.replyToPreview || '',
                          }
                        : undefined,
                    amount: tx.paymentTransaction?.amount,
                });
            } catch (error) {
                // Log decryption failures for debugging - may indicate
                // corrupted data or messages we can't decrypt
                console.warn(`[AlgoChat] Failed to decrypt message ${tx.id}:`, error);
                continue;
            }
        }

        return messages.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    }

    /**
     * Discovers a user's encryption public key from their transaction history
     *
     * @param address - Algorand address to discover key for
     * @param searchDepth - Maximum transactions to search (default: 200)
     */
    async discoverPublicKey(address: string, searchDepth = 200): Promise<Uint8Array> {
        const result = await this.discoverPublicKeyWithMetadata(address, searchDepth);
        return result.publicKey;
    }

    /**
     * Discovers a user's encryption public key with full metadata
     *
     * @param address - Algorand address to discover key for
     * @param searchDepth - Maximum transactions to search (default: 200)
     */
    async discoverPublicKeyWithMetadata(address: string, searchDepth = 200): Promise<DiscoveredKey> {
        const response = await this.indexerClient
            .searchForTransactions()
            .address(address)
            .limit(searchDepth)
            .do() as IndexerSearchResponse;

        for (const tx of response.transactions ?? []) {
            // Only look at transactions SENT by this address
            if (tx.sender !== address) continue;
            if (!tx.note) continue;

            const noteBytes = base64ToBytes(tx.note);

            if (!isChatMessage(noteBytes)) continue;

            try {
                const envelope = decodeEnvelope(noteBytes);
                return {
                    publicKey: envelope.senderPublicKey,
                    address,
                    discoveredInTx: tx.id,
                    discoveredAtRound: tx.confirmedRound ?? 0,
                    discoveredAt: new Date((tx.roundTime ?? 0) * 1000),
                };
            } catch (error) {
                // Log but continue searching - this transaction may be malformed
                console.warn(`[AlgoChat] Failed to decode envelope from ${tx.id}:`, error);
                continue;
            }
        }

        throw ChatError.publicKeyNotFound(address, searchDepth);
    }

    /**
     * Publishes the account's encryption key to the blockchain
     */
    async publishKey(chatAccount: ChatAccount): Promise<string> {
        const payload = JSON.stringify({ type: 'key-publish' });

        // Self-encrypt
        const envelope = encryptMessage(
            payload,
            chatAccount.encryptionKeys.publicKey,
            chatAccount.encryptionKeys.publicKey // Self
        );

        const note = encodeEnvelope(envelope);
        const params = await this.algodClient.getTransactionParams().do();

        // Zero-amount self-payment
        const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
            sender: chatAccount.address,
            receiver: chatAccount.address,
            amount: 0,
            note,
            suggestedParams: params,
        });

        const signedTxn = txn.signTxn(chatAccount.account.sk);
        const { txid } = await this.algodClient.sendRawTransaction(signedTxn).do();

        return txid;
    }

    /**
     * Gets account balance in microAlgos
     */
    async getBalance(address: string): Promise<bigint> {
        const info = await this.algodClient.accountInformation(address).do();
        return info.amount;
    }

    /**
     * Fetches all conversations for an account
     *
     * Scans transaction history and groups messages by participant.
     * Returns conversations sorted by most recent message.
     */
    async fetchConversations(
        chatAccount: ChatAccount,
        limit = 100
    ): Promise<Conversation[]> {
        const response = await this.indexerClient
            .searchForTransactions()
            .address(chatAccount.address)
            .limit(limit)
            .do() as IndexerSearchResponse;

        const conversationsMap = new Map<string, Conversation>();

        for (const tx of response.transactions ?? []) {
            if (tx.txType !== 'pay' || !tx.note) continue;

            const noteBytes = base64ToBytes(tx.note);
            if (!isChatMessage(noteBytes)) continue;

            const sender: string = tx.sender;
            const receiver: string | undefined = tx.paymentTransaction?.receiver;
            if (!receiver) continue;

            try {
                const envelope = decodeEnvelope(noteBytes);
                const decrypted = decryptMessage(
                    envelope,
                    chatAccount.encryptionKeys.privateKey,
                    chatAccount.encryptionKeys.publicKey
                );

                if (!decrypted) continue;

                // Skip key-publish transactions (self-tx with key-publish payload)
                if (sender === receiver) {
                    try {
                        const parsed = JSON.parse(decrypted.text);
                        if (parsed.type === 'key-publish') continue;
                    } catch {
                        // Not JSON, check plain text
                        if (decrypted.text === 'key-publish') continue;
                    }
                }

                const otherParty = sender === chatAccount.address ? receiver : sender;
                const direction: 'sent' | 'received' = sender === chatAccount.address ? 'sent' : 'received';

                const message: Message = {
                    id: tx.id,
                    sender,
                    recipient: receiver,
                    content: decrypted.text,
                    timestamp: new Date((tx.roundTime ?? 0) * 1000),
                    confirmedRound: tx.confirmedRound ?? 0,
                    direction,
                    replyContext: decrypted.replyToId
                        ? { messageId: decrypted.replyToId, preview: decrypted.replyToPreview || '' }
                        : undefined,
                    amount: tx.paymentTransaction?.amount,
                };

                if (!conversationsMap.has(otherParty)) {
                    conversationsMap.set(otherParty, {
                        participant: otherParty,
                        messages: [],
                    });
                }

                const conv = conversationsMap.get(otherParty)!;
                conv.messages.push(message);

                // Store public key from received messages
                if (direction === 'received') {
                    conv.participantPublicKey = envelope.senderPublicKey;
                }

                // Track the latest round
                const round = tx.confirmedRound ?? 0;
                if (!conv.lastFetchedRound || round > conv.lastFetchedRound) {
                    conv.lastFetchedRound = round;
                }
            } catch {
                continue;
            }
        }

        // Sort messages within each conversation
        const conversations = Array.from(conversationsMap.values());
        for (const conv of conversations) {
            conv.messages.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
        }

        // Sort conversations by most recent message
        conversations.sort((a, b) => {
            const aLast = a.messages[a.messages.length - 1]?.timestamp.getTime() ?? 0;
            const bLast = b.messages[b.messages.length - 1]?.timestamp.getTime() ?? 0;
            return bLast - aLast;
        });

        return conversations;
    }

    /**
     * Waits for transaction confirmation
     *
     * @param txid - Transaction ID to wait for
     * @param timeout - Timeout in rounds (default: 10)
     * @returns Confirmed round number
     */
    async waitForConfirmation(txid: string, timeout = 10): Promise<number> {
        const result = await algosdk.waitForConfirmation(this.algodClient, txid, timeout);
        return Number(result.confirmedRound);
    }

    /**
     * Waits for a transaction to be indexed
     *
     * Uses exponential backoff with jitter for efficient polling.
     *
     * @param txid - Transaction ID to wait for
     * @param timeout - Timeout in milliseconds (default: 30000)
     * @param initialInterval - Initial polling interval (default: 500ms)
     * @param maxInterval - Maximum polling interval (default: 5000ms)
     * @param backoffMultiplier - Backoff multiplier (default: 1.5)
     * @returns true if indexed, false if timeout
     */
    async waitForIndexer(
        txid: string,
        timeout = 30000,
        initialInterval = 500,
        maxInterval = 5000,
        backoffMultiplier = 1.5
    ): Promise<boolean> {
        const deadline = Date.now() + timeout;
        let interval = initialInterval;

        while (Date.now() < deadline) {
            try {
                await this.indexerClient.lookupTransactionByID(txid).do();
                return true;
            } catch {
                // Transaction not yet indexed, continue waiting
            }

            // Calculate remaining time
            const remaining = deadline - Date.now();
            if (remaining <= 0) {
                break;
            }

            // Apply jitter (0.8x to 1.2x)
            const jitter = 0.8 + Math.random() * 0.4;
            const sleepTime = Math.min(interval * jitter, remaining);

            await sleep(sleepTime);

            // Exponential backoff
            interval = Math.min(interval * backoffMultiplier, maxInterval);
        }

        return false;
    }

    /**
     * Checks if a transaction exists in the indexer
     *
     * @param txid - Transaction ID to check
     */
    async transactionExists(txid: string): Promise<boolean> {
        try {
            await this.indexerClient.lookupTransactionByID(txid).do();
            return true;
        } catch {
            return false;
        }
    }
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Decodes base64 or base64url string to Uint8Array
 *
 * The Algorand indexer returns notes as base64url encoded strings,
 * so we need to handle both standard base64 and base64url formats.
 */
function base64ToBytes(input: string | Uint8Array): Uint8Array {
    // If already Uint8Array, return as-is
    if (input instanceof Uint8Array) {
        return input;
    }

    if (typeof input !== 'string') {
        return new Uint8Array(0);
    }

    // Convert base64url to standard base64
    const standardBase64 = input.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding if needed
    const padded = standardBase64 + '='.repeat((4 - (standardBase64.length % 4)) % 4);

    const binaryString = atob(padded);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}
