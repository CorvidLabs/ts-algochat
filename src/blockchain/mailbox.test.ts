/**
 * AlgoChat - Raven Mailbox Protocol Tests (pure layer)
 *
 * Cross-checks the noble-based derivation against an independent
 * node:crypto implementation, verifies the published MBR table, and
 * exercises every validation path. Fully offline.
 */

import { describe, test, expect } from 'bun:test';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import algosdk from 'algosdk';
import {
    MAILBOX_MSG_KEY_DOMAIN,
    MAILBOX_ID_DOMAIN,
    MAILBOX_MAX_ENVELOPE_SIZE,
    MAILBOX_MAX_FANOUT_LEGS,
    MAILBOX_REFUND_FEE,
    MAILBOX_TTL_ROUNDS,
    MAILBOX_METHODS,
    MAX_COUNTER,
    MailboxEnvelopeError,
    MailboxFanoutLimitError,
    InvalidCounterError,
    InvalidMsgKeyError,
    InvalidViewSecretError,
    deriveMailboxId,
    deriveMsgKey,
    mailboxMbr,
    mailboxMethodSelector,
    planMailboxFanout,
    planMailboxPut,
} from './mailbox.js';

/** Independent reference implementation (node:crypto) — must match byte-for-byte. */
function refMsgKey(viewSecret: Uint8Array, counter: number): Uint8Array {
    const msg = Buffer.concat([
        Buffer.from(MAILBOX_MSG_KEY_DOMAIN, 'utf8'),
        (() => { const b = Buffer.alloc(4); b.writeUInt32BE(counter); return b; })(),
    ]);
    return createHmac('sha256', Buffer.from(viewSecret)).update(msg).digest();
}

function refMailboxId(msgKey: Uint8Array): Uint8Array {
    return createHash('sha256')
        .update(Buffer.from(MAILBOX_ID_DOMAIN, 'utf8'))
        .update(msgKey)
        .digest();
}

function refMbr(envelopeLength: number): number {
    return 2500 + 400 * (32 + 40 + envelopeLength);
}

describe('mailbox key derivation', () => {
    test('deriveMsgKey matches node:crypto HMAC-SHA256 across counters', () => {
        const secret = randomBytes(32);
        for (const counter of [0, 1, 2, 99, 100, 65_535, 65_536, MAX_COUNTER]) {
            const derived = deriveMsgKey(secret, counter);
            expect(derived.length).toBe(32);
            expect(Buffer.from(derived).equals(Buffer.from(refMsgKey(secret, counter)))).toBe(true);
        }
    });

    test('deriveMailboxId matches node:crypto SHA-256 domain construction', () => {
        const msgKey = randomBytes(32);
        const derived = deriveMailboxId(msgKey);
        expect(derived.length).toBe(32);
        expect(Buffer.from(derived).equals(Buffer.from(refMailboxId(msgKey)))).toBe(true);
    });

    test('derivation is deterministic', () => {
        const secret = randomBytes(32);
        const a = deriveMailboxId(deriveMsgKey(secret, 7));
        const b = deriveMailboxId(deriveMsgKey(secret, 7));
        expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
    });

    test('counter rotation produces distinct msg keys and mailbox ids', () => {
        const secret = randomBytes(32);
        const id0 = deriveMailboxId(deriveMsgKey(secret, 0));
        const id1 = deriveMailboxId(deriveMsgKey(secret, 1));
        expect(Buffer.from(id0).equals(Buffer.from(id1))).toBe(false);
    });

    test('different view secrets produce different mailbox ids at the same counter', () => {
        const idA = deriveMailboxId(deriveMsgKey(randomBytes(32), 0));
        const idB = deriveMailboxId(deriveMsgKey(randomBytes(32), 0));
        expect(Buffer.from(idA).equals(Buffer.from(idB))).toBe(false);
    });

    test('rejects wrong-length view secrets', () => {
        for (const bad of [0, 16, 31, 33, 64]) {
            expect(() => deriveMsgKey(randomBytes(bad), 0)).toThrow(InvalidViewSecretError);
        }
    });

    test('rejects non-integer and out-of-range counters', () => {
        const secret = randomBytes(32);
        for (const bad of [-1, 0.5, Number.NaN, MAX_COUNTER + 1, Number.MAX_SAFE_INTEGER]) {
            expect(() => deriveMsgKey(secret, bad)).toThrow(InvalidCounterError);
        }
    });

    test('rejects wrong-length msg keys', () => {
        for (const bad of [0, 31, 33]) {
            expect(() => deriveMailboxId(randomBytes(bad))).toThrow(InvalidMsgKeyError);
        }
    });
});

describe('mailbox MBR planning', () => {
    test('matches the raven implementation-verified table', () => {
        expect(mailboxMbr(560)).toBe(255_300);   // 0.2553 ALGO
        expect(mailboxMbr(878)).toBe(382_500);   // 0.3825 ALGO
        expect(mailboxMbr(2048)).toBe(850_500);  // 0.8505 ALGO
    });

    test('matches the reference formula across sizes', () => {
        for (const len of [1, 2, 100, 560, 1024, 2047, MAILBOX_MAX_ENVELOPE_SIZE]) {
            expect(mailboxMbr(len)).toBe(refMbr(len));
        }
    });

    test('rejects empty and oversized envelopes', () => {
        expect(() => mailboxMbr(0)).toThrow(MailboxEnvelopeError);
        expect(() => mailboxMbr(MAILBOX_MAX_ENVELOPE_SIZE + 1)).toThrow(MailboxEnvelopeError);
    });
});

describe('mailbox put planning', () => {
    test('planMailboxPut derives the mailbox id and exact MBR', () => {
        const secret = randomBytes(32);
        const envelope = randomBytes(560);
        const plan = planMailboxPut(secret, 3, envelope);
        expect(Buffer.from(plan.mailboxId).equals(Buffer.from(refMailboxId(refMsgKey(secret, 3))))).toBe(true);
        expect(plan.mbr).toBe(255_300);
        expect(plan.envelope).toBe(envelope);
    });

    test('planMailboxPut rejects empty and oversized envelopes', () => {
        const secret = randomBytes(32);
        expect(() => planMailboxPut(secret, 0, new Uint8Array(0))).toThrow(MailboxEnvelopeError);
        expect(() => planMailboxPut(secret, 0, randomBytes(2049))).toThrow(MailboxEnvelopeError);
    });

    test('planMailboxFanout plans heterogeneous legs independently', () => {
        const legs = [
            { viewSecret: randomBytes(32), counter: 0, envelope: randomBytes(128) },
            { viewSecret: randomBytes(32), counter: 1, envelope: randomBytes(560) },
            { viewSecret: randomBytes(32), counter: 2, envelope: randomBytes(1024) },
        ];
        const plans = planMailboxFanout(legs);
        expect(plans.length).toBe(3);
        for (let i = 0; i < legs.length; i++) {
            expect(plans[i].mbr).toBe(refMbr(legs[i].envelope.length));
            expect(
                Buffer.from(plans[i].mailboxId).equals(
                    Buffer.from(refMailboxId(refMsgKey(legs[i].viewSecret, legs[i].counter)))
                )
            ).toBe(true);
        }
        // distinct recipients → distinct mailboxes
        expect(Buffer.from(plans[0].mailboxId).equals(Buffer.from(plans[1].mailboxId))).toBe(false);
    });

    test('planMailboxFanout accepts exactly 8 legs and rejects 0 and 9', () => {
        const leg = () => ({ viewSecret: randomBytes(32), counter: 0, envelope: randomBytes(16) });
        expect(planMailboxFanout(Array.from({ length: MAILBOX_MAX_FANOUT_LEGS }, leg)).length).toBe(8);
        expect(() => planMailboxFanout([])).toThrow(MailboxFanoutLimitError);
        expect(() => planMailboxFanout(Array.from({ length: 9 }, leg))).toThrow(MailboxFanoutLimitError);
    });
});

describe('ARC-4 selectors', () => {
    test('mailboxMethodSelector matches algosdk for every router method', () => {
        const expectations: Array<[string, algosdk.ABIMethodParams]> = [
            [MAILBOX_METHODS.mailboxPut, { name: 'mailboxPut', args: [{ type: 'pay' }, { type: 'byte[32]' }, { type: 'byte[]' }], returns: { type: 'void' } }],
            [MAILBOX_METHODS.mailboxBurn, { name: 'mailboxBurn', args: [{ type: 'byte[32]' }, { type: 'byte[32]' }], returns: { type: 'void' } }],
            [MAILBOX_METHODS.mailboxReclaim, { name: 'mailboxReclaim', args: [{ type: 'byte[32]' }], returns: { type: 'void' } }],
            [MAILBOX_METHODS.mailboxStatus, { name: 'mailboxStatus', args: [{ type: 'byte[32]' }], returns: { type: '(bool,byte[],uint64)' } }],
        ];
        for (const [signature, params] of expectations) {
            const selector = mailboxMethodSelector(signature);
            expect(selector.length).toBe(4);
            expect(Buffer.from(selector).equals(Buffer.from(new algosdk.ABIMethod(params).getSelector()))).toBe(true);
        }
    });
});

describe('published protocol constants', () => {
    test('match the deployed contract constants', () => {
        expect(MAILBOX_MAX_ENVELOPE_SIZE).toBe(2048);
        expect(MAILBOX_TTL_ROUNDS).toBe(2_600_000);
        expect(MAILBOX_REFUND_FEE).toBe(1000);
        expect(MAILBOX_MAX_FANOUT_LEGS).toBe(8);
    });
});
