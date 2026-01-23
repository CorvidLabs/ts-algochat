/**
 * AlgoChat Web - Algorand Blockchain Service
 *
 * Handles sending messages and querying the blockchain.
 */

import algosdk from 'algosdk';
import type { Message, SendResult, X25519KeyPair } from '../models/types';
import { encryptMessage, encryptReply, decryptMessage, encodeEnvelope, decodeEnvelope, isChatMessage } from '../crypto';

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
        this.algodClient = new algosdk.Algodv2(
            config.algodToken,
            config.algodServer,
            config.algodPort
        );

        this.indexerClient = new algosdk.Indexer(
            config.indexerToken,
            config.indexerServer,
            config.indexerPort
        );
    }

    /**
     * Sends an encrypted message to a recipient
     */
    async sendMessage(
        chatAccount: ChatAccount,
        recipientAddress: string,
        recipientPublicKey: Uint8Array,
        message: string
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
            amount: 1000, // 0.001 ALGO minimum
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
        };

        return { txid, message: sentMessage };
    }

    /**
     * Sends a reply to a message
     */
    async sendReply(
        chatAccount: ChatAccount,
        recipientAddress: string,
        recipientPublicKey: Uint8Array,
        message: string,
        replyToTxid: string,
        replyToPreview: string
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
            amount: 1000,
            note,
            suggestedParams: params,
        });

        const signedTxn = txn.signTxn(chatAccount.account.sk);
        const { txid } = await this.algodClient.sendRawTransaction(signedTxn).do();

        const sentMessage: Message = {
            id: txid,
            sender: chatAccount.address,
            recipient: recipientAddress,
            content: message,
            timestamp: new Date(),
            confirmedRound: 0,
            direction: 'sent',
            replyContext: {
                messageId: replyToTxid,
                preview: replyToPreview,
            },
        };

        return { txid, message: sentMessage };
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
     */
    async discoverPublicKey(address: string, searchDepth = 200): Promise<Uint8Array> {
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
                return envelope.senderPublicKey;
            } catch (error) {
                // Log but continue searching - this transaction may be malformed
                console.warn(`[AlgoChat] Failed to decode envelope from ${tx.id}:`, error);
                continue;
            }
        }

        throw new Error(`Public key not found for address: ${address}`);
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
     * Waits for transaction confirmation
     */
    async waitForConfirmation(txid: string, timeout = 10): Promise<void> {
        await algosdk.waitForConfirmation(this.algodClient, txid, timeout);
    }
}

/**
 * Decodes base64 string to Uint8Array
 */
function base64ToBytes(base64: string): Uint8Array {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}
