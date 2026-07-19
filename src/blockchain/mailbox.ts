/**
 * AlgoChat - Raven Mailbox Protocol (pure layer)
 *
 * Deterministic, I/O-free implementation of the raven router mailbox
 * protocol (RFC 0001; reference contract: CorvidLabs/raven
 * `contracts/router/src/router.algo.ts`).
 *
 * Key derivation (normative):
 *   msg_key    = HMAC-SHA256(key = view_secret, "raven/mailbox/v1" ‖ counter_be32)
 *   mailbox_id = SHA-256("raven/mailbox/v1/id" ‖ msg_key)
 *
 * The contract never sees the view secret. Burning a mailbox reveals only
 * one counter's msg_key, which is useless afterwards — rotate the counter
 * per message. Counter ownership stays with the caller.
 *
 * This module performs no network or signing operations; see
 * `MailboxRouterTransport` in services for the chain-bound layer.
 */

import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { sha512_256 } from '@noble/hashes/sha512';

/** Domain separator HMACed (with the counter) into msg keys. */
export const MAILBOX_MSG_KEY_DOMAIN = 'raven/mailbox/v1';

/** Domain separator hashed in front of msg_key to form mailbox ids. */
export const MAILBOX_ID_DOMAIN = 'raven/mailbox/v1/id';

/** Maximum envelope size accepted by the contract, in bytes. */
export const MAILBOX_MAX_ENVELOPE_SIZE = 2048;

/** Rounds an unclaimed box must age before the depositor may reclaim. */
export const MAILBOX_TTL_ROUNDS = 2_600_000;

/** Consensus flat box MBR, in microALGO. */
export const MAILBOX_BOX_FLAT_MBR = 2500;

/** Consensus per-byte box MBR, in microALGO. */
export const MAILBOX_BOX_BYTE_MBR = 400;

/** Box value header prepended by the contract: 32B depositor + 8B round. */
export const MAILBOX_HEADER_SIZE = 40;

/** Fee charged to the released MBR on every refund inner-transaction. */
export const MAILBOX_REFUND_FEE = 1000;

/** Algorand consensus maximum transactions per atomic group. */
export const MAILBOX_MAX_GROUP_SIZE = 16;

/** Maximum put legs per atomic fan-out group (2 transactions per leg). */
export const MAILBOX_MAX_FANOUT_LEGS = 8;

/** Required view secret length, in bytes. */
export const VIEW_SECRET_SIZE = 32;

/** Msg key length, in bytes. */
export const MSG_KEY_SIZE = 32;

/** Mailbox id length, in bytes. */
export const MAILBOX_ID_SIZE = 32;

/** Largest valid counter value (uint32, big-endian encoded). */
export const MAX_COUNTER = 0xffffffff;

/** Base error for all mailbox protocol and transport failures. */
export class MailboxError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'MailboxError';
    }
}

/** Thrown when a view secret is not exactly 32 bytes. */
export class InvalidViewSecretError extends MailboxError {
    actualSize: number;

    constructor(actualSize: number) {
        super(`Invalid view secret: ${actualSize} bytes (expected ${VIEW_SECRET_SIZE})`);
        this.name = 'InvalidViewSecretError';
        this.actualSize = actualSize;
    }
}

/** Thrown when a msg key is not exactly 32 bytes. */
export class InvalidMsgKeyError extends MailboxError {
    actualSize: number;

    constructor(actualSize: number) {
        super(`Invalid msg key: ${actualSize} bytes (expected ${MSG_KEY_SIZE})`);
        this.name = 'InvalidMsgKeyError';
        this.actualSize = actualSize;
    }
}

/** Thrown when a counter is not an integer in [0, 2^32 - 1]. */
export class InvalidCounterError extends MailboxError {
    actualValue: number;

    constructor(actualValue: number) {
        super(`Invalid counter: ${actualValue} (expected integer 0..${MAX_COUNTER})`);
        this.name = 'InvalidCounterError';
        this.actualValue = actualValue;
    }
}

/** Thrown when an envelope is empty or exceeds MAILBOX_MAX_ENVELOPE_SIZE. */
export class MailboxEnvelopeError extends MailboxError {
    actualSize: number;

    constructor(actualSize: number) {
        super(
            actualSize === 0
                ? 'Empty envelope: mailbox envelopes must carry at least 1 byte'
                : `Envelope too large: ${actualSize} bytes (max ${MAILBOX_MAX_ENVELOPE_SIZE})`
        );
        this.name = 'MailboxEnvelopeError';
        this.actualSize = actualSize;
    }
}

/** Thrown when a fan-out group would exceed the consensus group limit. */
export class MailboxFanoutLimitError extends MailboxError {
    actualLegs: number;

    constructor(actualLegs: number) {
        super(
            `Fan-out of ${actualLegs} legs exceeds the limit of ${MAILBOX_MAX_FANOUT_LEGS} ` +
            `(${MAILBOX_MAX_GROUP_SIZE} transactions per atomic group, 2 per leg)`
        );
        this.name = 'MailboxFanoutLimitError';
        this.actualLegs = actualLegs;
    }
}

/**
 * Canonical ARC-4 method signatures of the raven router contract.
 * Selectors are derived from these strings; do not edit casually.
 */
export const MAILBOX_METHODS = {
    mailboxPut: 'mailboxPut(pay,byte[32],byte[])void',
    mailboxBurn: 'mailboxBurn(byte[32],byte[32])void',
    mailboxReclaim: 'mailboxReclaim(byte[32])void',
    mailboxStatus: 'mailboxStatus(byte[32])(bool,byte[],uint64)',
} as const;

/**
 * Computes the ARC-4 method selector for a signature: the first 4 bytes of
 * SHA-512/256 over the UTF-8 signature string.
 *
 * @param signature - Canonical ARC-4 signature (see MAILBOX_METHODS)
 * @returns 4-byte selector
 */
export function mailboxMethodSelector(signature: string): Uint8Array {
    return sha512_256(new TextEncoder().encode(signature)).slice(0, 4);
}

/**
 * Derives the per-message msg key from a shared view secret and counter.
 *
 * `msg_key = HMAC-SHA256(key = view_secret, "raven/mailbox/v1" ‖ counter_be32)`
 *
 * @param viewSecret - 32-byte secret shared sender↔recipient
 * @param counter - uint32 rotation counter (advance per message)
 * @returns 32-byte msg key
 * @throws InvalidViewSecretError if the secret is not 32 bytes
 * @throws InvalidCounterError if the counter is not a uint32
 */
export function deriveMsgKey(viewSecret: Uint8Array, counter: number): Uint8Array {
    if (viewSecret.length !== VIEW_SECRET_SIZE) {
        throw new InvalidViewSecretError(viewSecret.length);
    }
    if (!Number.isInteger(counter) || counter < 0 || counter > MAX_COUNTER) {
        throw new InvalidCounterError(counter);
    }
    const message = new Uint8Array(MAILBOX_MSG_KEY_DOMAIN.length + 4);
    const encoded = new TextEncoder().encodeInto(MAILBOX_MSG_KEY_DOMAIN, message);
    const view = new DataView(message.buffer);
    view.setUint32(encoded.written, counter, false);
    return hmac(sha256, viewSecret, message.subarray(0, encoded.written + 4));
}

/**
 * Derives the on-chain mailbox id for a msg key.
 *
 * `mailbox_id = SHA-256("raven/mailbox/v1/id" ‖ msg_key)`
 *
 * @param msgKey - 32-byte msg key from deriveMsgKey
 * @returns 32-byte mailbox id (the box name)
 * @throws InvalidMsgKeyError if the key is not 32 bytes
 */
export function deriveMailboxId(msgKey: Uint8Array): Uint8Array {
    if (msgKey.length !== MSG_KEY_SIZE) {
        throw new InvalidMsgKeyError(msgKey.length);
    }
    const prefix = new TextEncoder().encode(MAILBOX_ID_DOMAIN);
    const message = new Uint8Array(prefix.length + msgKey.length);
    message.set(prefix, 0);
    message.set(msgKey, prefix.length);
    return sha256(message);
}

/**
 * Computes the exact box MBR the contract requires for an envelope, in
 * microALGO: `2500 + 400 × (32 + 40 + envelope_len)`.
 *
 * @param envelopeLength - Envelope size in bytes
 * @returns Required minimum balance in microALGO
 * @throws MailboxEnvelopeError if the length is invalid for the contract
 */
export function mailboxMbr(envelopeLength: number): number {
    validateEnvelopeLength(envelopeLength);
    return MAILBOX_BOX_FLAT_MBR + MAILBOX_BOX_BYTE_MBR * (32 + MAILBOX_HEADER_SIZE + envelopeLength);
}

/**
 * One fan-out leg input: the recipient channel's view secret, the message
 * counter, and the opaque (already encrypted) envelope bytes.
 */
export interface MailboxLeg {
    /** 32-byte secret shared with this recipient */
    viewSecret: Uint8Array;
    /** uint32 rotation counter for this message */
    counter: number;
    /** 1..2048 opaque envelope bytes */
    envelope: Uint8Array;
}

/**
 * A validated put leg: derived mailbox id, exact MBR, and the envelope.
 */
export interface MailboxLegPlan {
    /** 32-byte box name the envelope will be stored under */
    mailboxId: Uint8Array;
    /** Exact MBR the leg's payment must fund, in microALGO */
    mbr: number;
    /** The envelope bytes (passed through untouched) */
    envelope: Uint8Array;
}

function validateEnvelopeLength(length: number): void {
    if (!Number.isInteger(length) || length <= 0 || length > MAILBOX_MAX_ENVELOPE_SIZE) {
        throw new MailboxEnvelopeError(Number.isInteger(length) ? length : -1);
    }
}

/**
 * Validates and plans a single mailbox put.
 *
 * @param viewSecret - 32-byte secret shared with the recipient
 * @param counter - uint32 rotation counter
 * @param envelope - 1..2048 opaque envelope bytes
 * @returns The leg plan (mailbox id, exact MBR, envelope)
 */
export function planMailboxPut(
    viewSecret: Uint8Array,
    counter: number,
    envelope: Uint8Array
): MailboxLegPlan {
    validateEnvelopeLength(envelope.length);
    const msgKey = deriveMsgKey(viewSecret, counter);
    return {
        mailboxId: deriveMailboxId(msgKey),
        mbr: mailboxMbr(envelope.length),
        envelope,
    };
}

/**
 * Validates and plans an atomic fan-out: N independent put legs that must
 * ride in one AVM group (all-or-nothing delivery).
 *
 * @param legs - 1..MAILBOX_MAX_FANOUT_LEGS legs
 * @returns One plan per leg, in input order
 * @throws MailboxFanoutLimitError if more than 8 legs (or zero) are given
 */
export function planMailboxFanout(legs: MailboxLeg[]): MailboxLegPlan[] {
    if (legs.length === 0 || legs.length > MAILBOX_MAX_FANOUT_LEGS) {
        throw new MailboxFanoutLimitError(legs.length);
    }
    return legs.map((leg) => planMailboxPut(leg.viewSecret, leg.counter, leg.envelope));
}
