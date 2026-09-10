/**
 * AlgoChat - Mailbox Router Transport Tests
 *
 * Exercises the transport against a stubbed algod client: every submission
 * is captured, decoded, and asserted structurally (group shape, amounts,
 * ABI args, box references). No network, credentials, or wallets involved.
 */

import { describe, test, expect } from 'bun:test';
import algosdk from 'algosdk';
import { MailboxRouterTransport, type MailboxReadResult } from './mailbox-router.service.js';
import { AlgorandService } from './algorand.service.js';
import {
    MAILBOX_METHODS,
    MAILBOX_MAX_ENVELOPE_SIZE,
    MailboxError,
    MailboxFanoutLimitError,
    arc4EncodeDynamicBytes,
    mailboxMbr,
    mailboxMethodSelector,
    planMailboxPut,
} from '../blockchain/mailbox.js';

const APP_ID = 1234n;
const PUT_SELECTOR = mailboxMethodSelector(MAILBOX_METHODS.mailboxPut);
const BURN_SELECTOR = mailboxMethodSelector(MAILBOX_METHODS.mailboxBurn);
const RECLAIM_SELECTOR = mailboxMethodSelector(MAILBOX_METHODS.mailboxReclaim);

function suggestedParams() {
    return {
        fee: 1000,
        firstValid: 100,
        lastValid: 1100,
        genesisHash: new Uint8Array(32).fill(1),
        genesisID: 'testnet-v1.0',
        flatFee: true,
    };
}

/** A stub algod client capturing every submitted signed group. */
function makeStubAlgod(boxes: Map<string, Uint8Array> = new Map()) {
    const captured: Uint8Array[][] = [];
    const client = {
        getTransactionParams: () => ({ do: async () => suggestedParams() }),
        sendRawTransaction: (signed: Uint8Array | Uint8Array[]) => ({
            do: async () => {
                const group = Array.isArray(signed) ? signed : [signed];
                captured.push(group);
                const first = algosdk.decodeSignedTransaction(group[0]);
                return { txid: first.txn.txID() };
            },
        }),
        status: () => ({ do: async () => ({ lastRound: 100n }) }),
        statusAfterBlock: () => ({ do: async () => ({ lastRound: 101n }) }),
        pendingTransactionInformation: () => ({
            do: async () => ({ confirmedRound: 101n, poolError: '' }),
        }),
        getApplicationBoxByName: (_appId: number | bigint, name: Uint8Array) => ({
            do: async () => {
                const key = Buffer.from(name).toString('hex');
                const value = boxes.get(key);
                if (value === undefined) {
                    const error = new Error('no application box found') as Error & { status?: number };
                    error.status = 404;
                    throw error;
                }
                return { name, value };
            },
        }),
    };
    return { client: client as unknown as algosdk.Algodv2, captured, boxes };
}

function makeTransport(stub: ReturnType<typeof makeStubAlgod>) {
    return new MailboxRouterTransport({ algodClient: stub.client, appId: APP_ID });
}

function decodeGroup(signed: Uint8Array[]) {
    return signed.map((bytes) => algosdk.decodeSignedTransaction(bytes).txn);
}

describe('MailboxRouterTransport construction', () => {
    test('derives the application address from the app id', () => {
        const stub = makeStubAlgod();
        const transport = makeTransport(stub);
        expect(transport.appId).toBe(APP_ID);
        expect(transport.appAddress).toBe(algosdk.getApplicationAddress(APP_ID).toString());
    });

    test('rejects a missing app id', () => {
        const stub = makeStubAlgod();
        expect(
            () => new MailboxRouterTransport({ algodClient: stub.client, appId: undefined as unknown as number })
        ).toThrow(MailboxError);
    });
});

describe('MailboxRouterTransport.send', () => {
    test('submits a [pay, appl] group funding exactly the box MBR', async () => {
        const account = algosdk.generateAccount();
        const stub = makeStubAlgod();
        const transport = makeTransport(stub);

        const viewSecret = new Uint8Array(32).fill(7);
        const envelope = new Uint8Array(560).fill(3);
        const result = await transport.send(account, viewSecret, 0, envelope);

        const expected = planMailboxPut(viewSecret, 0, envelope);
        expect(result.mbr).toBe(255_300);
        expect(result.confirmedRound).toBe(101);
        expect(Buffer.from(result.mailboxId).equals(Buffer.from(expected.mailboxId))).toBe(true);

        expect(stub.captured.length).toBe(1);
        const [pay, call] = decodeGroup(stub.captured[0]);

        expect(pay.type).toBe(algosdk.TransactionType.pay);
        expect(pay.payment?.amount).toBe(BigInt(expected.mbr));
        expect(pay.payment?.receiver.toString()).toBe(transport.appAddress);
        expect(pay.sender.toString()).toBe(account.addr.toString());

        expect(call.type).toBe(algosdk.TransactionType.appl);
        expect(call.applicationCall?.appIndex).toBe(APP_ID);
        expect(call.applicationCall?.onComplete).toBe(algosdk.OnApplicationComplete.NoOpOC);
        const args = call.applicationCall?.appArgs ?? [];
        expect(args.length).toBe(3);
        expect(Buffer.from(args[0]).equals(Buffer.from(PUT_SELECTOR))).toBe(true);
        expect(Buffer.from(args[1]).equals(Buffer.from(expected.mailboxId))).toBe(true);
        expect(Buffer.from(args[2]).equals(Buffer.from(arc4EncodeDynamicBytes(envelope)))).toBe(true);

        const boxes = call.applicationCall?.boxes ?? [];
        expect(boxes.length).toBe(1);
        expect(Number(boxes[0].appIndex)).toBe(0);
        expect(Buffer.from(boxes[0].name).equals(Buffer.from(expected.mailboxId))).toBe(true);

        // one shared group id across both legs
        expect(Buffer.from(pay.group ?? []).equals(Buffer.from(call.group ?? []))).toBe(true);
    });

    test('validates before any network call', async () => {
        const account = algosdk.generateAccount();
        const stub = makeStubAlgod();
        const transport = makeTransport(stub);
        await expect(
            transport.send(account, new Uint8Array(32), 0, new Uint8Array(MAILBOX_MAX_ENVELOPE_SIZE + 1))
        ).rejects.toThrow(/too large/);
        expect(stub.captured.length).toBe(0);
    });
});

describe('MailboxRouterTransport.sendFanout', () => {
    test('submits one atomic group with an exact-MBR leg per recipient', async () => {
        const account = algosdk.generateAccount();
        const stub = makeStubAlgod();
        const transport = makeTransport(stub);

        const legs = [
            { viewSecret: new Uint8Array(32).fill(1), counter: 0, envelope: new Uint8Array(128).fill(1) },
            { viewSecret: new Uint8Array(32).fill(2), counter: 0, envelope: new Uint8Array(560).fill(2) },
            { viewSecret: new Uint8Array(32).fill(3), counter: 1, envelope: new Uint8Array(1024).fill(3) },
        ];
        const result = await transport.sendFanout(account, legs);

        expect(result.legs.length).toBe(3);
        expect(stub.captured.length).toBe(1);
        const group = decodeGroup(stub.captured[0]);
        expect(group.length).toBe(6); // 2 transactions per leg

        const groupIds = group.map((txn) => Buffer.from(txn.group ?? []).toString('hex'));
        expect(new Set(groupIds).size).toBe(1); // one atomic group

        for (let i = 0; i < legs.length; i++) {
            const pay = group[i * 2];
            const call = group[i * 2 + 1];
            const plan = result.legs[i];
            expect(pay.type).toBe(algosdk.TransactionType.pay);
            expect(pay.payment?.amount).toBe(BigInt(mailboxMbr(legs[i].envelope.length)));
            expect(call.type).toBe(algosdk.TransactionType.appl);
            const args = call.applicationCall?.appArgs ?? [];
            expect(Buffer.from(args[0]).equals(Buffer.from(PUT_SELECTOR))).toBe(true);
            expect(Buffer.from(args[1]).equals(Buffer.from(plan.mailboxId))).toBe(true);
            expect(Buffer.from(args[2]).equals(Buffer.from(arc4EncodeDynamicBytes(legs[i].envelope)))).toBe(true);
        }
        // distinct recipients, distinct mailboxes
        const ids = result.legs.map((leg) => Buffer.from(leg.mailboxId).toString('hex'));
        expect(new Set(ids).size).toBe(3);
    });

    test('rejects more than 8 legs before any network call', async () => {
        const account = algosdk.generateAccount();
        const stub = makeStubAlgod();
        const transport = makeTransport(stub);
        const legs = Array.from({ length: 9 }, (_, i) => ({
            viewSecret: new Uint8Array(32).fill(i),
            counter: 0,
            envelope: new Uint8Array(16).fill(1),
        }));
        await expect(transport.sendFanout(account, legs)).rejects.toThrow(MailboxFanoutLimitError);
        expect(stub.captured.length).toBe(0);
    });
});

describe('MailboxRouterTransport burn and reclaim', () => {
    test('burn submits the proof with the mailbox box reference and depositor account', async () => {
        const account = algosdk.generateAccount();
        const depositor = algosdk.generateAccount();
        const stub = makeStubAlgod();
        const transport = makeTransport(stub);

        const plan = planMailboxPut(new Uint8Array(32).fill(7), 4, new Uint8Array(64).fill(1));
        const header = new Uint8Array(40);
        header.set(algosdk.decodeAddress(depositor.addr.toString()).publicKey, 0);
        new DataView(header.buffer).setBigUint64(32, 100n, false);
        const value = new Uint8Array(40 + 64);
        value.set(header, 0);
        stub.boxes.set(Buffer.from(plan.mailboxId).toString('hex'), value);

        const msgKey = new Uint8Array(32).fill(11);
        const result = await transport.burn(account, plan.mailboxId, msgKey);
        expect(result.confirmedRound).toBe(101);

        const [call] = decodeGroup(stub.captured[0]);
        expect(call.type).toBe(algosdk.TransactionType.appl);
        const args = call.applicationCall?.appArgs ?? [];
        expect(args.length).toBe(3);
        expect(Buffer.from(args[0]).equals(Buffer.from(BURN_SELECTOR))).toBe(true);
        expect(Buffer.from(args[1]).equals(Buffer.from(plan.mailboxId))).toBe(true);
        expect(Buffer.from(args[2]).equals(Buffer.from(msgKey))).toBe(true);
        expect(Buffer.from((call.applicationCall?.boxes ?? [])[0].name).equals(Buffer.from(plan.mailboxId))).toBe(true);
        const foreign = (call.applicationCall?.accounts ?? []).map((entry) => entry.toString());
        expect(foreign).toContain(depositor.addr.toString());
    });

    test('burn omits foreign accounts when the mailbox is already absent', async () => {
        const account = algosdk.generateAccount();
        const stub = makeStubAlgod();
        const transport = makeTransport(stub);
        const mailboxId = new Uint8Array(32).fill(9);
        await transport.burn(account, mailboxId, new Uint8Array(32).fill(11));
        const [call] = decodeGroup(stub.captured[0]);
        expect(call.applicationCall?.accounts ?? []).toHaveLength(0);
    });

    test('reclaim submits depositor-only call with the mailbox box reference', async () => {
        const account = algosdk.generateAccount();
        const stub = makeStubAlgod();
        const transport = makeTransport(stub);

        const mailboxId = new Uint8Array(32).fill(21);
        const header = new Uint8Array(40);
        header.set(algosdk.decodeAddress(account.addr.toString()).publicKey, 0);
        new DataView(header.buffer).setBigUint64(32, 100n, false);
        stub.boxes.set(Buffer.from(mailboxId).toString('hex'), header);

        await transport.reclaim(account, mailboxId);

        const [call] = decodeGroup(stub.captured[0]);
        const args = call.applicationCall?.appArgs ?? [];
        expect(args.length).toBe(2);
        expect(Buffer.from(args[0]).equals(Buffer.from(RECLAIM_SELECTOR))).toBe(true);
        expect(Buffer.from(args[1]).equals(Buffer.from(mailboxId))).toBe(true);
        expect(Buffer.from((call.applicationCall?.boxes ?? [])[0].name).equals(Buffer.from(mailboxId))).toBe(true);
        const foreign = (call.applicationCall?.accounts ?? []).map((entry) => entry.toString());
        expect(foreign).toContain(account.addr.toString());
    });
});

describe('MailboxRouterTransport.read', () => {
    test('parses the box header and returns the envelope verbatim', async () => {
        const stub = makeStubAlgod();
        const transport = makeTransport(stub);

        const depositor = algosdk.generateAccount();
        const envelope = new Uint8Array(200).fill(5);
        const mailboxId = new Uint8Array(32).fill(31);
        const header = new Uint8Array(40);
        header.set(algosdk.decodeAddress(depositor.addr.toString()).publicKey, 0);
        new DataView(header.buffer).setBigUint64(32, 424242n, false);
        const value = new Uint8Array(40 + envelope.length);
        value.set(header, 0);
        value.set(envelope, 40);
        stub.boxes.set(Buffer.from(mailboxId).toString('hex'), value);

        const result: MailboxReadResult = await transport.read(mailboxId);
        expect(result.exists).toBe(true);
        expect(result.depositor).toBe(depositor.addr.toString());
        expect(result.writeRound).toBe(424242);
        expect(Buffer.from(result.envelope ?? []).equals(Buffer.from(envelope))).toBe(true);
    });

    test('maps a box 404 to exists: false', async () => {
        const stub = makeStubAlgod();
        const transport = makeTransport(stub);
        const result = await transport.read(new Uint8Array(32).fill(99));
        expect(result.exists).toBe(false);
        expect(result.envelope).toBeUndefined();
    });
});

describe('AlgorandService mailbox opt-in', () => {
    const config = {
        algodToken: '',
        algodServer: 'http://localhost',
        indexerToken: '',
        indexerServer: 'http://localhost',
    };

    test('exposes no mailbox transport unless configured', () => {
        const service = new AlgorandService(config);
        expect(service.mailbox).toBeUndefined();
    });

    test('exposes a mailbox transport when configured with an app id', () => {
        const service = new AlgorandService({ ...config, mailboxAppId: 1234 });
        expect(service.mailbox).toBeInstanceOf(MailboxRouterTransport);
        expect(service.mailbox?.appId).toBe(1234);
    });
});
