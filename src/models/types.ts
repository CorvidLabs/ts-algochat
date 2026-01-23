/**
 * AlgoChat Web - Core Types
 */

/** 32-byte X25519 key pair */
export interface X25519KeyPair {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
}

/** Parsed message envelope from transaction note */
export interface ChatEnvelope {
    version: number;
    protocolId: number;
    senderPublicKey: Uint8Array;
    ephemeralPublicKey: Uint8Array;
    nonce: Uint8Array;
    encryptedSenderKey: Uint8Array;
    ciphertext: Uint8Array;
}

/** Decrypted message content */
export interface DecryptedContent {
    text: string;
    replyToId?: string;
    replyToPreview?: string;
}

/** Reply context for threaded messages */
export interface ReplyContext {
    messageId: string;
    preview: string;
}

/** Message direction relative to current user */
export type MessageDirection = 'sent' | 'received';

/** A chat message */
export interface Message {
    id: string;
    sender: string;
    recipient: string;
    content: string;
    timestamp: Date;
    confirmedRound: number;
    direction: MessageDirection;
    replyContext?: ReplyContext;
}

/** A conversation with another user */
export interface Conversation {
    participant: string;
    participantPublicKey?: Uint8Array;
    messages: Message[];
    lastFetchedRound?: number;
}

/** Result of sending a message */
export interface SendResult {
    txid: string;
    message: Message;
}

/** Protocol constants */
export const PROTOCOL = {
    VERSION: 0x01,
    PROTOCOL_ID: 0x01,
    HEADER_SIZE: 126,
    TAG_SIZE: 16,
    ENCRYPTED_SENDER_KEY_SIZE: 48,
    MAX_PAYLOAD_SIZE: 882,
    MIN_PAYMENT: 1000,
} as const;
