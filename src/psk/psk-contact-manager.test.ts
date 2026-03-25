/**
 * AlgoChat Web - PSK Contact Manager Tests
 */

import { describe, test, expect } from 'bun:test';
import { deriveEncryptionKeys } from '../crypto/keys';
import { PSKContactManager } from './psk-contact-manager';
import { isPSKMessage } from './envelope';

// Deterministic test seeds
const ALICE_SEED = new Uint8Array(32).fill(0x01);
const BOB_SEED = new Uint8Array(32).fill(0x02);
const TEST_PSK = new Uint8Array(32).fill(0xaa);

const alice = deriveEncryptionKeys(ALICE_SEED);
const bob = deriveEncryptionKeys(BOB_SEED);

const ALICE_ADDRESS = 'ALICE_TEST_ADDRESS_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const BOB_ADDRESS = 'BOB_TEST_ADDRESS_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

describe('PSKContactManager - Contact CRUD', () => {
    test('addContact registers a contact', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        const contact = mgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob');

        expect(contact.address).toBe(BOB_ADDRESS);
        expect(contact.label).toBe('Bob');
        expect(contact.state.sendCounter).toBe(0);
        expect(contact.state.peerLastCounter).toBe(0);
        expect(mgr.contactCount).toBe(1);
    });

    test('addContact rejects invalid PSK length', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        expect(() => mgr.addContact(BOB_ADDRESS, new Uint8Array(16))).toThrow('PSK must be 32 bytes');
    });

    test('addContact overwrites existing contact', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        mgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob v1');

        const newPSK = new Uint8Array(32).fill(0xbb);
        const updated = mgr.addContact(BOB_ADDRESS, newPSK, 'Bob v2');

        expect(mgr.contactCount).toBe(1);
        expect(updated.label).toBe('Bob v2');
        expect(updated.state.sendCounter).toBe(0); // Reset
    });

    test('removeContact removes and returns true', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        mgr.addContact(BOB_ADDRESS, TEST_PSK);

        expect(mgr.removeContact(BOB_ADDRESS)).toBe(true);
        expect(mgr.contactCount).toBe(0);
        expect(mgr.hasContact(BOB_ADDRESS)).toBe(false);
    });

    test('removeContact returns false for unknown address', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        expect(mgr.removeContact('UNKNOWN')).toBe(false);
    });

    test('getContact returns contact or undefined', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        mgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob');

        expect(mgr.getContact(BOB_ADDRESS)?.label).toBe('Bob');
        expect(mgr.getContact('UNKNOWN')).toBeUndefined();
    });

    test('listContacts returns all contacts', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        mgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob');
        mgr.addContact(ALICE_ADDRESS, TEST_PSK, 'Alice');

        const contacts = mgr.listContacts();
        expect(contacts.length).toBe(2);
    });

    test('hasContact checks registration', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        expect(mgr.hasContact(BOB_ADDRESS)).toBe(false);
        mgr.addContact(BOB_ADDRESS, TEST_PSK);
        expect(mgr.hasContact(BOB_ADDRESS)).toBe(true);
    });

    test('setContactPublicKey updates key', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        mgr.addContact(BOB_ADDRESS, TEST_PSK);

        mgr.setContactPublicKey(BOB_ADDRESS, bob.publicKey);
        expect(mgr.getContact(BOB_ADDRESS)?.publicKey).toEqual(bob.publicKey);
    });

    test('setContactPublicKey throws for unknown contact', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        expect(() => mgr.setContactPublicKey('UNKNOWN', bob.publicKey)).toThrow('No PSK contact');
    });
});

describe('PSKContactManager - Send', () => {
    test('send encrypts and advances counter', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        mgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob', bob.publicKey);

        const result = mgr.send(BOB_ADDRESS, 'Hello Bob!');

        expect(result.counter).toBe(0);
        expect(result.envelope).toBeInstanceOf(Uint8Array);
        expect(isPSKMessage(result.envelope)).toBe(true);
        expect(mgr.getSendCounter(BOB_ADDRESS)).toBe(1);
    });

    test('send advances counter on each call', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        mgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob', bob.publicKey);

        const r0 = mgr.send(BOB_ADDRESS, 'Message 0');
        const r1 = mgr.send(BOB_ADDRESS, 'Message 1');
        const r2 = mgr.send(BOB_ADDRESS, 'Message 2');

        expect(r0.counter).toBe(0);
        expect(r1.counter).toBe(1);
        expect(r2.counter).toBe(2);
        expect(mgr.getSendCounter(BOB_ADDRESS)).toBe(3);
    });

    test('send throws without registered contact', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        expect(() => mgr.send('UNKNOWN', 'Hello')).toThrow('No PSK contact');
    });

    test('send throws without public key', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        mgr.addContact(BOB_ADDRESS, TEST_PSK);

        expect(() => mgr.send(BOB_ADDRESS, 'Hello')).toThrow('No public key');
    });

    test('send with reply context', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        mgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob', bob.publicKey);

        const result = mgr.send(BOB_ADDRESS, 'Replying!', {
            replyToId: 'TX123',
            replyToPreview: 'Original message',
        });

        expect(result.envelope).toBeInstanceOf(Uint8Array);
        expect(result.counter).toBe(0);
    });
});

describe('PSKContactManager - Receive', () => {
    test('receive decrypts and updates counter state', () => {
        // Alice sends to Bob; Bob receives
        const aliceMgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        const bobMgr = new PSKContactManager(bob.publicKey, bob.privateKey);

        aliceMgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob', bob.publicKey);
        bobMgr.addContact(ALICE_ADDRESS, TEST_PSK, 'Alice', alice.publicKey);

        const { envelope } = aliceMgr.send(BOB_ADDRESS, 'Hello from Alice!');
        const result = bobMgr.receive(envelope, ALICE_ADDRESS);

        expect(result).not.toBeNull();
        expect(result!.text).toBe('Hello from Alice!');
        expect(bobMgr.getPeerLastCounter(ALICE_ADDRESS)).toBe(0);
    });

    test('receive rejects replay', () => {
        const aliceMgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        const bobMgr = new PSKContactManager(bob.publicKey, bob.privateKey);

        aliceMgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob', bob.publicKey);
        bobMgr.addContact(ALICE_ADDRESS, TEST_PSK, 'Alice', alice.publicKey);

        const { envelope } = aliceMgr.send(BOB_ADDRESS, 'Message');
        bobMgr.receive(envelope, ALICE_ADDRESS);

        // Replay same message
        expect(() => bobMgr.receive(envelope, ALICE_ADDRESS)).toThrow('replay');
    });

    test('receive handles out-of-order delivery', () => {
        const aliceMgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        const bobMgr = new PSKContactManager(bob.publicKey, bob.privateKey);

        aliceMgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob', bob.publicKey);
        bobMgr.addContact(ALICE_ADDRESS, TEST_PSK, 'Alice', alice.publicKey);

        // Send 3 messages
        const msg0 = aliceMgr.send(BOB_ADDRESS, 'Message 0');
        const msg1 = aliceMgr.send(BOB_ADDRESS, 'Message 1');
        const msg2 = aliceMgr.send(BOB_ADDRESS, 'Message 2');

        // Receive out of order: 2, 0, 1
        const r2 = bobMgr.receive(msg2.envelope, ALICE_ADDRESS);
        expect(r2!.text).toBe('Message 2');

        const r0 = bobMgr.receive(msg0.envelope, ALICE_ADDRESS);
        expect(r0!.text).toBe('Message 0');

        const r1 = bobMgr.receive(msg1.envelope, ALICE_ADDRESS);
        expect(r1!.text).toBe('Message 1');
    });

    test('receive throws for unknown contact', () => {
        const bobMgr = new PSKContactManager(bob.publicKey, bob.privateKey);
        expect(() => bobMgr.receive(new Uint8Array(150), 'UNKNOWN')).toThrow('No PSK contact');
    });

    test('receive throws for non-PSK data', () => {
        const mgr = new PSKContactManager(bob.publicKey, bob.privateKey);
        mgr.addContact(ALICE_ADDRESS, TEST_PSK, 'Alice');

        // Standard protocol 0x01, not PSK 0x02
        const fakeBuf = new Uint8Array(150);
        fakeBuf[0] = 0x01;
        fakeBuf[1] = 0x01;

        expect(() => mgr.receive(fakeBuf, ALICE_ADDRESS)).toThrow('Not a PSK message');
    });
});

describe('PSKContactManager - Bidirectional Conversation', () => {
    test('full conversation between Alice and Bob', () => {
        const aliceMgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        const bobMgr = new PSKContactManager(bob.publicKey, bob.privateKey);

        aliceMgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob', bob.publicKey);
        bobMgr.addContact(ALICE_ADDRESS, TEST_PSK, 'Alice', alice.publicKey);

        // Alice -> Bob
        const m1 = aliceMgr.send(BOB_ADDRESS, 'Hi Bob!');
        expect(bobMgr.receive(m1.envelope, ALICE_ADDRESS)!.text).toBe('Hi Bob!');

        // Bob -> Alice
        const m2 = bobMgr.send(ALICE_ADDRESS, 'Hey Alice!');
        expect(aliceMgr.receive(m2.envelope, BOB_ADDRESS)!.text).toBe('Hey Alice!');

        // Alice -> Bob
        const m3 = aliceMgr.send(BOB_ADDRESS, 'How are you?');
        expect(bobMgr.receive(m3.envelope, ALICE_ADDRESS)!.text).toBe('How are you?');

        // Counters: Alice sent 2, Bob sent 1
        expect(aliceMgr.getSendCounter(BOB_ADDRESS)).toBe(2);
        expect(bobMgr.getSendCounter(ALICE_ADDRESS)).toBe(1);

        // Peer counters: Bob saw Alice at 1, Alice saw Bob at 0
        expect(bobMgr.getPeerLastCounter(ALICE_ADDRESS)).toBe(1);
        expect(aliceMgr.getPeerLastCounter(BOB_ADDRESS)).toBe(0);
    });

    test('sender can decrypt own messages (bidirectional)', () => {
        const aliceMgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        aliceMgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob', bob.publicKey);

        const { envelope } = aliceMgr.send(BOB_ADDRESS, 'Self-readable');

        // Alice decrypts her own message using low-level decrypt
        const result = aliceMgr.decrypt(envelope, TEST_PSK);
        expect(result).not.toBeNull();
        expect(result!.text).toBe('Self-readable');
    });
});

describe('PSKContactManager - Low-level encrypt/decrypt', () => {
    test('encrypt and decrypt without contact state', () => {
        const aliceMgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        const bobMgr = new PSKContactManager(bob.publicKey, bob.privateKey);

        const encrypted = aliceMgr.encrypt('Low level test', bob.publicKey, TEST_PSK, 42);
        expect(isPSKMessage(encrypted)).toBe(true);

        const decrypted = bobMgr.decrypt(encrypted, TEST_PSK);
        expect(decrypted).not.toBeNull();
        expect(decrypted!.text).toBe('Low level test');
    });

    test('decrypt throws for non-PSK data', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        expect(() => mgr.decrypt(new Uint8Array(10), TEST_PSK)).toThrow('Not a PSK message');
    });
});

describe('PSKContactManager - Counter queries', () => {
    test('getSendCounter returns current value', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        mgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob', bob.publicKey);

        expect(mgr.getSendCounter(BOB_ADDRESS)).toBe(0);
        mgr.send(BOB_ADDRESS, 'msg');
        expect(mgr.getSendCounter(BOB_ADDRESS)).toBe(1);
    });

    test('getSendCounter throws for unknown contact', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        expect(() => mgr.getSendCounter('UNKNOWN')).toThrow('No PSK contact');
    });

    test('getPeerLastCounter throws for unknown contact', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        expect(() => mgr.getPeerLastCounter('UNKNOWN')).toThrow('No PSK contact');
    });
});

describe('PSKContactManager - Unicode and edge cases', () => {
    test('handles unicode messages', () => {
        const aliceMgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        const bobMgr = new PSKContactManager(bob.publicKey, bob.privateKey);

        aliceMgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob', bob.publicKey);
        bobMgr.addContact(ALICE_ADDRESS, TEST_PSK, 'Alice', alice.publicKey);

        const { envelope } = aliceMgr.send(BOB_ADDRESS, 'Bonjour! 🇫🇷 Привет мир 日本語');
        const result = bobMgr.receive(envelope, ALICE_ADDRESS);

        expect(result!.text).toBe('Bonjour! 🇫🇷 Привет мир 日本語');
    });

    test('handles empty messages', () => {
        const aliceMgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        const bobMgr = new PSKContactManager(bob.publicKey, bob.privateKey);

        aliceMgr.addContact(BOB_ADDRESS, TEST_PSK, 'Bob', bob.publicKey);
        bobMgr.addContact(ALICE_ADDRESS, TEST_PSK, 'Alice', alice.publicKey);

        const { envelope } = aliceMgr.send(BOB_ADDRESS, '');
        const result = bobMgr.receive(envelope, ALICE_ADDRESS);

        expect(result!.text).toBe('');
    });

    test('copies PSK bytes on addContact (no aliasing)', () => {
        const mgr = new PSKContactManager(alice.publicKey, alice.privateKey);
        const pskCopy = new Uint8Array(TEST_PSK);

        mgr.addContact(BOB_ADDRESS, pskCopy);

        // Mutate the original
        pskCopy[0] = 0xff;

        // Contact should retain original value
        expect(mgr.getContact(BOB_ADDRESS)!.psk[0]).toBe(0xaa);
    });
});
