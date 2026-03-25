/**
 * AlgoChat Web - PSK Contact Manager
 *
 * High-level manager for PSK contacts and their state. Handles contact
 * registration, automatic counter management, and replay protection.
 *
 * Mirrors the Python SDK's `AlgoChat.add_psk_contact()`, `send_psk()`,
 * and `receive_psk()` functionality.
 */

import type { PSKState } from './types';
import type { DecryptedContent } from '../models/types';
import { createPSKState, validateCounter, recordReceive, advanceSendCounter } from './state';
import { derivePSKAtCounter } from './ratchet';
import { encryptPSKMessage, decryptPSKMessage } from './encryption';
import { encodePSKEnvelope, decodePSKEnvelope, isPSKMessage } from './envelope';

/** A registered PSK contact */
export interface PSKContact {
    /** Algorand address of the contact */
    address: string;
    /** The initial 32-byte pre-shared key */
    psk: Uint8Array;
    /** Counter state for replay protection */
    state: PSKState;
    /** Optional human-readable label */
    label?: string;
    /** Contact's X25519 encryption public key (set when known) */
    publicKey?: Uint8Array;
}

/** Result of a PSK send operation */
export interface PSKSendResult {
    /** Encoded PSK envelope bytes ready for transmission */
    envelope: Uint8Array;
    /** The ratchet counter used for this message */
    counter: number;
}

/** Options for PSK message encryption */
export interface PSKSendOptions {
    /** Reply-to transaction ID for threaded messages */
    replyToId?: string;
    /** Preview text of the replied message */
    replyToPreview?: string;
}

/**
 * Manages PSK contacts and provides high-level send/receive with
 * automatic counter state management and replay protection.
 */
export class PSKContactManager {
    private contacts = new Map<string, PSKContact>();

    /**
     * Creates a new PSKContactManager.
     *
     * @param senderPublicKey - Our X25519 public key (32 bytes)
     * @param senderPrivateKey - Our X25519 private key (32 bytes)
     */
    constructor(
        private readonly senderPublicKey: Uint8Array,
        private readonly senderPrivateKey: Uint8Array,
    ) {}

    /**
     * Registers a PSK contact.
     *
     * If a contact with this address already exists, updates the PSK
     * and resets the counter state.
     *
     * @param address - Algorand address of the contact
     * @param psk - The 32-byte pre-shared key
     * @param label - Optional human-readable label
     * @param publicKey - Contact's X25519 encryption public key (if known)
     * @returns The registered contact
     */
    addContact(address: string, psk: Uint8Array, label?: string, publicKey?: Uint8Array): PSKContact {
        if (psk.length !== 32) {
            throw new Error(`PSK must be 32 bytes, got ${psk.length}`);
        }

        const contact: PSKContact = {
            address,
            psk: new Uint8Array(psk),
            state: createPSKState(),
            label,
            publicKey: publicKey ? new Uint8Array(publicKey) : undefined,
        };

        this.contacts.set(address, contact);
        return contact;
    }

    /**
     * Removes a PSK contact.
     *
     * @param address - Algorand address to remove
     * @returns true if the contact existed and was removed
     */
    removeContact(address: string): boolean {
        return this.contacts.delete(address);
    }

    /**
     * Gets a PSK contact by address.
     *
     * @param address - Algorand address to look up
     * @returns The contact, or undefined if not registered
     */
    getContact(address: string): PSKContact | undefined {
        return this.contacts.get(address);
    }

    /**
     * Lists all registered PSK contacts.
     */
    listContacts(): PSKContact[] {
        return Array.from(this.contacts.values());
    }

    /**
     * Checks if an address has a registered PSK contact.
     */
    hasContact(address: string): boolean {
        return this.contacts.has(address);
    }

    /**
     * Updates a contact's public key.
     *
     * @param address - Algorand address
     * @param publicKey - X25519 public key (32 bytes)
     */
    setContactPublicKey(address: string, publicKey: Uint8Array): void {
        const contact = this.contacts.get(address);
        if (!contact) {
            throw new Error(`No PSK contact registered for ${address}`);
        }
        contact.publicKey = new Uint8Array(publicKey);
    }

    /**
     * Encrypts a PSK message for a contact, automatically advancing the
     * send counter.
     *
     * @param address - Recipient's Algorand address
     * @param message - Plaintext message to encrypt
     * @param options - Optional send options (reply context)
     * @returns Encoded envelope bytes and counter used
     * @throws Error if no contact or no public key
     */
    send(address: string, message: string, options?: PSKSendOptions): PSKSendResult {
        const contact = this.contacts.get(address);
        if (!contact) {
            throw new Error(`No PSK contact registered for ${address}`);
        }
        if (!contact.publicKey) {
            throw new Error(`No public key set for PSK contact ${address}`);
        }

        // Advance counter atomically
        const { counter, state: newState } = advanceSendCounter(contact.state);
        contact.state = newState;

        // Build message payload (with optional reply context)
        const payload = formatPayload(message, options?.replyToId, options?.replyToPreview);

        // Derive PSK for this counter and encrypt
        const currentPSK = derivePSKAtCounter(contact.psk, counter);
        const pskEnvelope = encryptPSKMessage(
            payload,
            this.senderPublicKey,
            contact.publicKey,
            currentPSK,
            counter,
        );

        const envelope = encodePSKEnvelope(pskEnvelope);

        return { envelope, counter };
    }

    /**
     * Decrypts a PSK message from a contact, with automatic counter
     * validation and state update.
     *
     * @param data - Encoded PSK envelope bytes
     * @param senderAddress - The sender's Algorand address
     * @returns Decrypted content, or null for key-publish payloads
     * @throws Error if no contact, replay detected, or decryption fails
     */
    receive(data: Uint8Array, senderAddress: string): DecryptedContent | null {
        const contact = this.contacts.get(senderAddress);
        if (!contact) {
            throw new Error(`No PSK contact registered for ${senderAddress}`);
        }

        if (!isPSKMessage(data)) {
            throw new Error('Not a PSK message');
        }

        const envelope = decodePSKEnvelope(data);

        // Validate counter for replay protection
        if (!validateCounter(contact.state, envelope.ratchetCounter)) {
            throw new Error(
                `Invalid counter ${envelope.ratchetCounter}: replay or out of window`,
            );
        }

        // Derive PSK and decrypt
        const currentPSK = derivePSKAtCounter(contact.psk, envelope.ratchetCounter);
        const result = decryptPSKMessage(
            envelope,
            this.senderPrivateKey,
            this.senderPublicKey,
            currentPSK,
        );

        // Record counter after successful decryption
        contact.state = recordReceive(contact.state, envelope.ratchetCounter);

        return result;
    }

    /**
     * Low-level PSK encryption without contact management.
     *
     * Derives the ratcheted PSK at the given counter and encrypts.
     * Does not advance any counter state.
     *
     * @param message - Plaintext message
     * @param recipientPublicKey - Recipient's X25519 public key
     * @param psk - Initial 32-byte PSK
     * @param counter - Ratchet counter to use
     * @returns Encoded PSK envelope bytes
     */
    encrypt(message: string, recipientPublicKey: Uint8Array, psk: Uint8Array, counter: number): Uint8Array {
        const currentPSK = derivePSKAtCounter(psk, counter);
        const pskEnvelope = encryptPSKMessage(
            message,
            this.senderPublicKey,
            recipientPublicKey,
            currentPSK,
            counter,
        );
        return encodePSKEnvelope(pskEnvelope);
    }

    /**
     * Low-level PSK decryption without contact management.
     *
     * Derives the ratcheted PSK from the envelope's counter and decrypts.
     * Does not validate or update any counter state.
     *
     * @param data - Encoded PSK envelope bytes
     * @param psk - Initial 32-byte PSK
     * @returns Decrypted content, or null for key-publish payloads
     */
    decrypt(data: Uint8Array, psk: Uint8Array): DecryptedContent | null {
        if (!isPSKMessage(data)) {
            throw new Error('Not a PSK message');
        }

        const envelope = decodePSKEnvelope(data);
        const currentPSK = derivePSKAtCounter(psk, envelope.ratchetCounter);
        return decryptPSKMessage(
            envelope,
            this.senderPrivateKey,
            this.senderPublicKey,
            currentPSK,
        );
    }

    /**
     * Gets the current send counter for a contact (without advancing it).
     *
     * @param address - Algorand address
     * @returns Current send counter value
     */
    getSendCounter(address: string): number {
        const contact = this.contacts.get(address);
        if (!contact) {
            throw new Error(`No PSK contact registered for ${address}`);
        }
        return contact.state.sendCounter;
    }

    /**
     * Gets the peer's last seen counter for a contact.
     *
     * @param address - Algorand address
     * @returns Peer's last counter value
     */
    getPeerLastCounter(address: string): number {
        const contact = this.contacts.get(address);
        if (!contact) {
            throw new Error(`No PSK contact registered for ${address}`);
        }
        return contact.state.peerLastCounter;
    }

    /**
     * Gets the number of registered contacts.
     */
    get contactCount(): number {
        return this.contacts.size;
    }
}

/**
 * Formats a message payload with optional reply context.
 */
function formatPayload(text: string, replyToId?: string, replyToPreview?: string): string {
    if (!replyToId) {
        return text;
    }

    const payload: { text: string; replyTo?: { txid: string; preview?: string } } = {
        text,
        replyTo: {
            txid: replyToId,
            preview: replyToPreview,
        },
    };

    return JSON.stringify(payload);
}
