/**
 * AlgoChat - Mailbox Router Transport
 *
 * Opt-in transport speaking the raven router mailbox protocol
 * (RFC 0001; contract: CorvidLabs/raven `contracts/router`). Delivery is a
 * dead-drop: the sender writes the encrypted envelope into an on-chain box
 * keyed by a derived mailbox id, and the recipient reads the box off-chain —
 * the recipient never appears in any transaction.
 *
 * This transport is strictly opt-in. `AlgorandService` only exposes it when
 * constructed with a `mailboxAppId`, and direct construction requires an
 * explicit app id. The referenced contract is pre-audit; do not point this
 * transport at a MainNet deployment until raven RFC 0001 Phase 3 completes.
 *
 * Security notes:
 * - The view secret is passed per call and never stored.
 * - Counter ownership stays with the caller; rotate per message.
 * - Burning is idempotent on-chain; re-claiming an absent mailbox is a no-op.
 */

import algosdk from 'algosdk';
import {
    MAILBOX_HEADER_SIZE,
    MAILBOX_METHODS,
    mailboxMethodSelector,
    planMailboxFanout,
    planMailboxPut,
    MailboxError,
    type MailboxLeg,
    type MailboxLegPlan,
} from '../blockchain/mailbox.js';

/** Transport configuration: an algod client plus the router app id. */
export interface MailboxTransportConfig {
    /** Injected algod client (all chain I/O flows through it) */
    algodClient: algosdk.Algodv2;
    /** Application id of the deployed raven router contract */
    appId: number | bigint;
}

/** Per-call submission options. */
export interface MailboxSubmitOptions {
    /** Rounds to wait for confirmation (default: 10) */
    waitRounds?: number;
}

/** Result of a mailbox put. */
export interface MailboxSendResult {
    txid: string;
    confirmedRound: number;
    /** 32-byte box name the envelope was stored under */
    mailboxId: Uint8Array;
    /** MBR funded into the app for this mailbox, in microALGO */
    mbr: number;
}

/** Result of an atomic fan-out put. */
export interface MailboxFanoutResult {
    txid: string;
    confirmedRound: number;
    /** One entry per leg, in input order */
    legs: MailboxLegPlan[];
}

/** Result of a burn or reclaim call. */
export interface MailboxTxnResult {
    txid: string;
    confirmedRound: number;
}

/** Off-chain mailbox read result. */
export interface MailboxReadResult {
    exists: boolean;
    /** Depositor address (from the box header) when the mailbox exists */
    depositor?: string;
    /** Write round (from the box header) when the mailbox exists */
    writeRound?: number;
    /** The stored envelope bytes when the mailbox exists */
    envelope?: Uint8Array;
}

const PUT_SELECTOR = mailboxMethodSelector(MAILBOX_METHODS.mailboxPut);
const BURN_SELECTOR = mailboxMethodSelector(MAILBOX_METHODS.mailboxBurn);
const RECLAIM_SELECTOR = mailboxMethodSelector(MAILBOX_METHODS.mailboxReclaim);

/** Default rounds to wait for confirmation after submission. */
const DEFAULT_WAIT_ROUNDS = 10;

/**
 * Transport for the raven router mailbox contract.
 *
 * All methods build, sign, and submit Algorand transaction groups through
 * the injected algod client. Nothing is sent over the network at
 * construction time, and validation happens before any network call.
 */
export class MailboxRouterTransport {
    private readonly algodClient: algosdk.Algodv2;

    /** Application id of the router contract this transport talks to. */
    readonly appId: number | bigint;

    /** Escrow address of the router application (MBR payments go here). */
    readonly appAddress: string;

    constructor(config: MailboxTransportConfig) {
        if (config.appId === undefined || config.appId === null) {
            throw new MailboxError('MailboxRouterTransport requires a router app id');
        }
        this.algodClient = config.algodClient;
        this.appId = config.appId;
        this.appAddress = algosdk.getApplicationAddress(config.appId).toString();
    }

    /**
     * Deposits one envelope into a mailbox: an atomic `[payment, app-call]`
     * group where the payment funds exactly the box MBR.
     *
     * @param account - The depositor (pays the MBR; may reclaim after TTL)
     * @param viewSecret - 32-byte secret shared with the recipient
     * @param counter - uint32 rotation counter (advance per message)
     * @param envelope - 1..2048 opaque envelope bytes
     * @param options - Submission options
     */
    async send(
        account: algosdk.Account,
        viewSecret: Uint8Array,
        counter: number,
        envelope: Uint8Array,
        options: MailboxSubmitOptions = {}
    ): Promise<MailboxSendResult> {
        const plan = planMailboxPut(viewSecret, counter, envelope);
        const txid = await this.submitPutGroup(account, [plan], options.waitRounds ?? DEFAULT_WAIT_ROUNDS);
        return { ...txid, mailboxId: plan.mailboxId, mbr: plan.mbr };
    }

    /**
     * Atomic fan-out: deposits N envelopes into N independent mailboxes in a
     * single group. The AVM executes all legs or none — a failed leg (for
     * example an occupied mailbox or insufficient MBR) aborts the whole
     * fan-out, so delivery is never partial.
     *
     * @param account - The depositor for every leg
     * @param legs - 1..8 legs (16-transaction group limit, 2 per leg)
     * @param options - Submission options
     */
    async sendFanout(
        account: algosdk.Account,
        legs: MailboxLeg[],
        options: MailboxSubmitOptions = {}
    ): Promise<MailboxFanoutResult> {
        const plans = planMailboxFanout(legs);
        const txid = await this.submitPutGroup(account, plans, options.waitRounds ?? DEFAULT_WAIT_ROUNDS);
        return { ...txid, legs: plans };
    }

    /**
     * Claims a mailbox by revealing the msg key for its counter. Any key
     * holder may burn; the contract refunds the depositor's MBR minus the
     * inner-txn fee. Idempotent: burning an absent mailbox is a no-op.
     *
     * @param account - The claiming account (pays the outer call fee)
     * @param mailboxId - 32-byte box name
     * @param msgKey - 32-byte preimage proving knowledge of the view secret
     * @param options - Submission options
     */
    async burn(
        account: algosdk.Account,
        mailboxId: Uint8Array,
        msgKey: Uint8Array,
        options: MailboxSubmitOptions = {}
    ): Promise<MailboxTxnResult> {
        const call = algosdk.makeApplicationCallTxnFromObject({
            sender: account.addr,
            appIndex: this.appId,
            onComplete: algosdk.OnApplicationComplete.NoOpOC,
            appArgs: [BURN_SELECTOR, mailboxId, msgKey],
            boxes: [{ appIndex: 0, name: mailboxId }],
            suggestedParams: await this.algodClient.getTransactionParams().do(),
        });
        return this.signAndSubmit(account, [call], options.waitRounds ?? DEFAULT_WAIT_ROUNDS);
    }

    /**
     * Reclaims an unclaimed mailbox's MBR after the TTL matures. Only the
     * original depositor may reclaim; the contract enforces it.
     *
     * @param account - The original depositor
     * @param mailboxId - 32-byte box name
     * @param options - Submission options
     */
    async reclaim(
        account: algosdk.Account,
        mailboxId: Uint8Array,
        options: MailboxSubmitOptions = {}
    ): Promise<MailboxTxnResult> {
        const call = algosdk.makeApplicationCallTxnFromObject({
            sender: account.addr,
            appIndex: this.appId,
            onComplete: algosdk.OnApplicationComplete.NoOpOC,
            appArgs: [RECLAIM_SELECTOR, mailboxId],
            boxes: [{ appIndex: 0, name: mailboxId }],
            suggestedParams: await this.algodClient.getTransactionParams().do(),
        });
        return this.signAndSubmit(account, [call], options.waitRounds ?? DEFAULT_WAIT_ROUNDS);
    }

    /**
     * Reads a mailbox off-chain via algod — free, no transaction. Parses the
     * 40-byte box header into depositor and write round and returns the
     * stored envelope verbatim.
     *
     * @param mailboxId - 32-byte box name
     */
    async read(mailboxId: Uint8Array): Promise<MailboxReadResult> {
        let value: Uint8Array;
        try {
            const box = await this.algodClient.getApplicationBoxByName(this.appId, mailboxId).do();
            value = box.value;
        } catch (error) {
            if (isBoxNotFound(error)) {
                return { exists: false };
            }
            throw error;
        }

        const depositor = algosdk.encodeAddress(value.subarray(0, 32));
        const roundView = new DataView(value.buffer, value.byteOffset + 32, 8);
        const writeRound = Number(roundView.getBigUint64(0, false));
        const envelope = value.subarray(MAILBOX_HEADER_SIZE);
        return { exists: true, depositor, writeRound, envelope };
    }

    /**
     * Builds and submits one `[pay, appl]*` put group for the given plans.
     */
    private async submitPutGroup(
        account: algosdk.Account,
        plans: MailboxLegPlan[],
        waitRounds: number
    ): Promise<MailboxTxnResult> {
        const params = await this.algodClient.getTransactionParams().do();
        const txns: algosdk.Transaction[] = [];
        for (const plan of plans) {
            txns.push(
                algosdk.makePaymentTxnWithSuggestedParamsFromObject({
                    sender: account.addr,
                    receiver: this.appAddress,
                    amount: plan.mbr,
                    suggestedParams: params,
                }),
                algosdk.makeApplicationCallTxnFromObject({
                    sender: account.addr,
                    appIndex: this.appId,
                    onComplete: algosdk.OnApplicationComplete.NoOpOC,
                    appArgs: [PUT_SELECTOR, plan.mailboxId, plan.envelope],
                    boxes: [{ appIndex: 0, name: plan.mailboxId }],
                    suggestedParams: params,
                })
            );
        }
        return this.signAndSubmit(account, txns, waitRounds);
    }

    /**
     * Groups, signs, submits, and confirms a set of transactions.
     */
    private async signAndSubmit(
        account: algosdk.Account,
        txns: algosdk.Transaction[],
        waitRounds: number
    ): Promise<MailboxTxnResult> {
        if (txns.length > 1) {
            algosdk.assignGroupID(txns);
        }
        const signed = txns.map((txn) => txn.signTxn(account.sk));
        const { txid } = await this.algodClient.sendRawTransaction(signed).do();
        const confirmation = await algosdk.waitForConfirmation(this.algodClient, txid, waitRounds);
        return { txid, confirmedRound: Number(confirmation.confirmedRound ?? 0) };
    }
}

/** Detects the algod 404 returned for an absent application box. */
function isBoxNotFound(error: unknown): boolean {
    if (typeof error !== 'object' || error === null) {
        return false;
    }
    const candidate = error as { status?: number; message?: string };
    if (candidate.status === 404) {
        return true;
    }
    return typeof candidate.message === 'string' && /404|box.*(not|does not) (found|exist)/i.test(candidate.message);
}
