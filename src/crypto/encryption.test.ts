/**
 * AlgoChat Web - Encryption Tests
 */

import { describe, test, expect } from 'bun:test';
import { deriveEncryptionKeys, generateEphemeralKeyPair, uint8ArrayEquals } from './keys';
import { encryptMessage, decryptMessage } from './encryption';
import { encodeEnvelope, decodeEnvelope, isChatMessage } from './envelope';

describe('Key Derivation', () => {
    test('derives consistent keys from same seed', () => {
        const seed = new Uint8Array(32).fill(42);

        const keys1 = deriveEncryptionKeys(seed);
        const keys2 = deriveEncryptionKeys(seed);

        expect(uint8ArrayEquals(keys1.privateKey, keys2.privateKey)).toBe(true);
        expect(uint8ArrayEquals(keys1.publicKey, keys2.publicKey)).toBe(true);
    });

    test('derives different keys from different seeds', () => {
        const seed1 = new Uint8Array(32).fill(1);
        const seed2 = new Uint8Array(32).fill(2);

        const keys1 = deriveEncryptionKeys(seed1);
        const keys2 = deriveEncryptionKeys(seed2);

        expect(uint8ArrayEquals(keys1.privateKey, keys2.privateKey)).toBe(false);
    });

    test('public key is 32 bytes', () => {
        const seed = new Uint8Array(32).fill(0);
        const keys = deriveEncryptionKeys(seed);

        expect(keys.publicKey.length).toBe(32);
        expect(keys.privateKey.length).toBe(32);
    });
});

describe('Ephemeral Keys', () => {
    test('generates unique keys each time', () => {
        const pair1 = generateEphemeralKeyPair();
        const pair2 = generateEphemeralKeyPair();

        expect(uint8ArrayEquals(pair1.privateKey, pair2.privateKey)).toBe(false);
    });
});

describe('Envelope Encoding', () => {
    test('encodes and decodes envelope correctly', () => {
        const original = {
            version: 0x01,
            protocolId: 0x01,
            senderPublicKey: new Uint8Array(32).fill(0xaa),
            ephemeralPublicKey: new Uint8Array(32).fill(0xbb),
            nonce: new Uint8Array(12).fill(0xcc),
            encryptedSenderKey: new Uint8Array(48).fill(0xdd),
            ciphertext: new Uint8Array(100).fill(0xee),
        };

        const encoded = encodeEnvelope(original);
        const decoded = decodeEnvelope(encoded);

        expect(decoded.version).toBe(original.version);
        expect(decoded.protocolId).toBe(original.protocolId);
        expect(uint8ArrayEquals(decoded.senderPublicKey, original.senderPublicKey)).toBe(true);
        expect(uint8ArrayEquals(decoded.ephemeralPublicKey, original.ephemeralPublicKey)).toBe(true);
        expect(uint8ArrayEquals(decoded.nonce, original.nonce)).toBe(true);
        expect(uint8ArrayEquals(decoded.encryptedSenderKey, original.encryptedSenderKey)).toBe(true);
        expect(uint8ArrayEquals(decoded.ciphertext, original.ciphertext)).toBe(true);
    });

    test('isChatMessage returns true for valid messages', () => {
        const data = new Uint8Array([0x01, 0x01, ...new Array(140).fill(0)]);
        expect(isChatMessage(data)).toBe(true);
    });

    test('isChatMessage returns false for invalid messages', () => {
        expect(isChatMessage(new Uint8Array([0x02, 0x01]))).toBe(false);
        expect(isChatMessage(new Uint8Array([0x01, 0x02]))).toBe(false);
        expect(isChatMessage(new Uint8Array([0x01]))).toBe(false);
        expect(isChatMessage(new Uint8Array([]))).toBe(false);
    });
});

describe('Message Encryption', () => {
    test('recipient can decrypt message', () => {
        const senderKeys = deriveEncryptionKeys(new Uint8Array(32).fill(1));
        const recipientKeys = deriveEncryptionKeys(new Uint8Array(32).fill(2));

        const original = 'Hello, AlgoChat!';

        const envelope = encryptMessage(
            original,
            senderKeys.privateKey,
            senderKeys.publicKey,
            recipientKeys.publicKey
        );

        const decrypted = decryptMessage(envelope, recipientKeys.privateKey, recipientKeys.publicKey);

        expect(decrypted).not.toBeNull();
        expect(decrypted?.text).toBe(original);
    });

    test('sender can decrypt their own message (bidirectional)', () => {
        const senderKeys = deriveEncryptionKeys(new Uint8Array(32).fill(1));
        const recipientKeys = deriveEncryptionKeys(new Uint8Array(32).fill(2));

        const original = 'Hello, AlgoChat!';

        const envelope = encryptMessage(
            original,
            senderKeys.privateKey,
            senderKeys.publicKey,
            recipientKeys.publicKey
        );

        const decrypted = decryptMessage(envelope, senderKeys.privateKey, senderKeys.publicKey);

        expect(decrypted).not.toBeNull();
        expect(decrypted?.text).toBe(original);
    });

    test('ephemeral keys are unique per message', () => {
        const senderKeys = deriveEncryptionKeys(new Uint8Array(32).fill(1));
        const recipientKeys = deriveEncryptionKeys(new Uint8Array(32).fill(2));

        const envelope1 = encryptMessage('Message 1', senderKeys.privateKey, senderKeys.publicKey, recipientKeys.publicKey);
        const envelope2 = encryptMessage('Message 2', senderKeys.privateKey, senderKeys.publicKey, recipientKeys.publicKey);

        expect(uint8ArrayEquals(envelope1.ephemeralPublicKey, envelope2.ephemeralPublicKey)).toBe(false);
    });

    test('nonces are unique per message', () => {
        const senderKeys = deriveEncryptionKeys(new Uint8Array(32).fill(1));
        const recipientKeys = deriveEncryptionKeys(new Uint8Array(32).fill(2));

        const envelope1 = encryptMessage('Message 1', senderKeys.privateKey, senderKeys.publicKey, recipientKeys.publicKey);
        const envelope2 = encryptMessage('Message 2', senderKeys.privateKey, senderKeys.publicKey, recipientKeys.publicKey);

        expect(uint8ArrayEquals(envelope1.nonce, envelope2.nonce)).toBe(false);
    });

    test('handles unicode correctly', () => {
        const senderKeys = deriveEncryptionKeys(new Uint8Array(32).fill(1));
        const recipientKeys = deriveEncryptionKeys(new Uint8Array(32).fill(2));

        const original = 'Hello! Bonjour! Hallo! Ciao! Hola!';

        const envelope = encryptMessage(
            original,
            senderKeys.privateKey,
            senderKeys.publicKey,
            recipientKeys.publicKey
        );

        const decrypted = decryptMessage(envelope, recipientKeys.privateKey, recipientKeys.publicKey);

        expect(decrypted?.text).toBe(original);
    });

    test('key-publish payload returns null', () => {
        const senderKeys = deriveEncryptionKeys(new Uint8Array(32).fill(1));

        // Self-encrypt key-publish payload
        const envelope = encryptMessage(
            '{"type":"key-publish"}',
            senderKeys.privateKey,
            senderKeys.publicKey,
            senderKeys.publicKey
        );

        const decrypted = decryptMessage(envelope, senderKeys.privateKey, senderKeys.publicKey);

        expect(decrypted).toBeNull();
    });
});

describe('Full Round-Trip', () => {
    test('message survives encode/decode/decrypt cycle', () => {
        const senderKeys = deriveEncryptionKeys(new Uint8Array(32).fill(1));
        const recipientKeys = deriveEncryptionKeys(new Uint8Array(32).fill(2));

        const original = 'This is a test message for the full round-trip!';

        // Encrypt
        const envelope = encryptMessage(
            original,
            senderKeys.privateKey,
            senderKeys.publicKey,
            recipientKeys.publicKey
        );

        // Encode to bytes (as would be stored in transaction note)
        const encoded = encodeEnvelope(envelope);

        // Verify it's a chat message
        expect(isChatMessage(encoded)).toBe(true);

        // Decode from bytes
        const decoded = decodeEnvelope(encoded);

        // Decrypt
        const decrypted = decryptMessage(decoded, recipientKeys.privateKey, recipientKeys.publicKey);

        expect(decrypted?.text).toBe(original);
    });
});
