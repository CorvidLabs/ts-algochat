/**
 * AlgoChat Web - PSK (Pre-Shared Key) Protocol Types
 *
 * Constants and interfaces for PSK v1.1 protocol support.
 */

/** PSK protocol constants */
export const PSK_PROTOCOL = {
    VERSION: 0x01,
    PROTOCOL_ID: 0x02,
    HEADER_SIZE: 130,
    TAG_SIZE: 16,
    ENCRYPTED_SENDER_KEY_SIZE: 48,
    MAX_PAYLOAD_SIZE: 878,
    SESSION_SIZE: 100,
    COUNTER_WINDOW: 200,
} as const;

/** PSK envelope wire format */
export interface PSKEnvelope {
    version: number;
    protocolId: number;
    ratchetCounter: number;
    senderPublicKey: Uint8Array;
    ephemeralPublicKey: Uint8Array;
    nonce: Uint8Array;
    encryptedSenderKey: Uint8Array;
    ciphertext: Uint8Array;
}

/** Counter state for replay protection */
export interface PSKState {
    sendCounter: number;
    peerLastCounter: number;
    seenCounters: Set<number>;
}
