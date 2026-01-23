/**
 * AlgoChat Web - Message Encryption/Decryption
 *
 * Implements ChaCha20-Poly1305 encryption with ephemeral key ECDH
 * and bidirectional decryption support.
 */

import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { ChatEnvelope, DecryptedContent, PROTOCOL } from '../models/types';
import { generateEphemeralKeyPair, x25519ECDH, uint8ArrayEquals } from './keys';

const ENCRYPTION_INFO_PREFIX = new TextEncoder().encode('AlgoChatV1');
const SENDER_KEY_INFO_PREFIX = new TextEncoder().encode('AlgoChatV1-SenderKey');

export class EncryptionError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'EncryptionError';
    }
}

/**
 * Encrypts a message for a recipient with forward secrecy
 */
export function encryptMessage(
    plaintext: string,
    _senderPrivateKey: Uint8Array,
    senderPublicKey: Uint8Array,
    recipientPublicKey: Uint8Array
): ChatEnvelope {
    const messageBytes = new TextEncoder().encode(plaintext);

    if (messageBytes.length > PROTOCOL.MAX_PAYLOAD_SIZE) {
        throw new EncryptionError(`Message too large: ${messageBytes.length} bytes, max ${PROTOCOL.MAX_PAYLOAD_SIZE}`);
    }

    // Step 1: Generate ephemeral key pair
    const ephemeral = generateEphemeralKeyPair();

    // Step 2: Derive symmetric key for recipient
    const sharedSecret = x25519ECDH(ephemeral.privateKey, recipientPublicKey);

    const info = concatBytes(ENCRYPTION_INFO_PREFIX, senderPublicKey, recipientPublicKey);
    const symmetricKey = hkdf(sha256, sharedSecret, ephemeral.publicKey, info, 32);

    // Step 3: Generate random nonce
    const nonce = randomBytes(12);

    // Step 4: Encrypt message
    const cipher = chacha20poly1305(symmetricKey, nonce);
    const ciphertextWithTag = cipher.encrypt(messageBytes);

    // Step 5: Encrypt symmetric key for sender (bidirectional decryption)
    const senderSharedSecret = x25519ECDH(ephemeral.privateKey, senderPublicKey);

    const senderInfo = concatBytes(SENDER_KEY_INFO_PREFIX, senderPublicKey);
    const senderEncryptionKey = hkdf(sha256, senderSharedSecret, ephemeral.publicKey, senderInfo, 32);

    const senderCipher = chacha20poly1305(senderEncryptionKey, nonce);
    const encryptedSenderKey = senderCipher.encrypt(symmetricKey);

    return {
        version: PROTOCOL.VERSION,
        protocolId: PROTOCOL.PROTOCOL_ID,
        senderPublicKey,
        ephemeralPublicKey: ephemeral.publicKey,
        nonce,
        encryptedSenderKey,
        ciphertext: ciphertextWithTag,
    };
}

/**
 * Encrypts a reply message
 */
export function encryptReply(
    text: string,
    replyToTxid: string,
    replyToPreview: string,
    senderPrivateKey: Uint8Array,
    senderPublicKey: Uint8Array,
    recipientPublicKey: Uint8Array
): ChatEnvelope {
    // Truncate preview to 80 chars
    const preview = replyToPreview.length > 80 ? replyToPreview.slice(0, 77) + '...' : replyToPreview;

    const payload = JSON.stringify({
        text,
        replyTo: {
            txid: replyToTxid,
            preview,
        },
    });

    return encryptMessage(payload, senderPrivateKey, senderPublicKey, recipientPublicKey);
}

/**
 * Decrypts a message envelope
 *
 * Automatically detects if we're the sender or recipient
 * and uses the appropriate decryption path.
 */
export function decryptMessage(
    envelope: ChatEnvelope,
    myPrivateKey: Uint8Array,
    myPublicKey: Uint8Array
): DecryptedContent | null {
    const weAreSender = uint8ArrayEquals(myPublicKey, envelope.senderPublicKey);

    let plaintext: Uint8Array;

    if (weAreSender) {
        plaintext = decryptAsSender(envelope, myPrivateKey, myPublicKey);
    } else {
        plaintext = decryptAsRecipient(envelope, myPrivateKey, myPublicKey);
    }

    // Check for key-publish payload
    if (isKeyPublishPayload(plaintext)) {
        return null;
    }

    return parseMessagePayload(plaintext);
}

/**
 * Decrypts as the message recipient
 */
function decryptAsRecipient(
    envelope: ChatEnvelope,
    recipientPrivateKey: Uint8Array,
    recipientPublicKey: Uint8Array
): Uint8Array {
    // Derive symmetric key
    const sharedSecret = x25519ECDH(recipientPrivateKey, envelope.ephemeralPublicKey);

    const info = concatBytes(ENCRYPTION_INFO_PREFIX, envelope.senderPublicKey, recipientPublicKey);
    const symmetricKey = hkdf(sha256, sharedSecret, envelope.ephemeralPublicKey, info, 32);

    // Decrypt message
    const cipher = chacha20poly1305(symmetricKey, envelope.nonce);
    return cipher.decrypt(envelope.ciphertext);
}

/**
 * Decrypts as the message sender (bidirectional decryption)
 */
function decryptAsSender(
    envelope: ChatEnvelope,
    senderPrivateKey: Uint8Array,
    senderPublicKey: Uint8Array
): Uint8Array {
    // Step 1: Derive key to decrypt the symmetric key
    const sharedSecret = x25519ECDH(senderPrivateKey, envelope.ephemeralPublicKey);

    const senderInfo = concatBytes(SENDER_KEY_INFO_PREFIX, senderPublicKey);
    const senderDecryptionKey = hkdf(sha256, sharedSecret, envelope.ephemeralPublicKey, senderInfo, 32);

    // Step 2: Decrypt the symmetric key
    const senderCipher = chacha20poly1305(senderDecryptionKey, envelope.nonce);
    const symmetricKey = senderCipher.decrypt(envelope.encryptedSenderKey);

    // Step 3: Decrypt message using recovered symmetric key
    const cipher = chacha20poly1305(symmetricKey, envelope.nonce);
    return cipher.decrypt(envelope.ciphertext);
}

/**
 * Checks if payload is a key-publish message
 */
function isKeyPublishPayload(data: Uint8Array): boolean {
    if (data.length === 0 || data[0] !== 0x7b) {
        // 0x7b = '{'
        return false;
    }

    try {
        const json = JSON.parse(new TextDecoder().decode(data));
        return json.type === 'key-publish';
    } catch {
        return false;
    }
}

/**
 * Parses decrypted message payload
 */
function parseMessagePayload(data: Uint8Array): DecryptedContent {
    const text = new TextDecoder().decode(data);

    // Try JSON first
    if (text.startsWith('{')) {
        try {
            const json = JSON.parse(text);
            if (typeof json.text === 'string') {
                return {
                    text: json.text,
                    replyToId: json.replyTo?.txid,
                    replyToPreview: json.replyTo?.preview,
                };
            }
        } catch {
            // Fall through to plain text
        }
    }

    // Plain text (legacy format)
    return { text };
}

/**
 * Concatenates multiple Uint8Arrays
 */
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}
