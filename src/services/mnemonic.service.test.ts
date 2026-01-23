/**
 * AlgoChat Web - Mnemonic Service Tests
 */

import { describe, test, expect } from 'bun:test';
import {
    createChatAccountFromMnemonic,
    createRandomChatAccount,
    validateMnemonic,
    validateAddress,
    publicKeyToBase64,
    base64ToPublicKey,
} from './mnemonic.service';
import { uint8ArrayEquals } from '../crypto/keys';

// Test mnemonic (DO NOT USE IN PRODUCTION - this is for testing only)
const TEST_MNEMONIC =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest';

describe('MnemonicService', () => {
    describe('createChatAccountFromMnemonic', () => {
        test('creates account with valid address', () => {
            const chatAccount = createChatAccountFromMnemonic(TEST_MNEMONIC);

            expect(chatAccount.address).toBeDefined();
            expect(chatAccount.address.length).toBe(58); // Algorand addresses are 58 chars
        });

        test('creates account with encryption keys', () => {
            const chatAccount = createChatAccountFromMnemonic(TEST_MNEMONIC);

            expect(chatAccount.encryptionKeys).toBeDefined();
            expect(chatAccount.encryptionKeys.publicKey.length).toBe(32);
            expect(chatAccount.encryptionKeys.privateKey.length).toBe(32);
        });

        test('creates account with algosdk Account', () => {
            const chatAccount = createChatAccountFromMnemonic(TEST_MNEMONIC);

            expect(chatAccount.account).toBeDefined();
            expect(chatAccount.account.sk).toBeDefined();
            expect(chatAccount.account.sk.length).toBe(64); // Ed25519 secret key
        });

        test('same mnemonic produces same keys', () => {
            const account1 = createChatAccountFromMnemonic(TEST_MNEMONIC);
            const account2 = createChatAccountFromMnemonic(TEST_MNEMONIC);

            expect(account1.address).toBe(account2.address);
            expect(uint8ArrayEquals(account1.encryptionKeys.publicKey, account2.encryptionKeys.publicKey)).toBe(true);
            expect(uint8ArrayEquals(account1.encryptionKeys.privateKey, account2.encryptionKeys.privateKey)).toBe(true);
        });

        test('different mnemonics produce different keys', () => {
            const { mnemonic: otherMnemonic } = createRandomChatAccount();
            const account1 = createChatAccountFromMnemonic(TEST_MNEMONIC);
            const account2 = createChatAccountFromMnemonic(otherMnemonic);

            expect(account1.address).not.toBe(account2.address);
            expect(uint8ArrayEquals(account1.encryptionKeys.publicKey, account2.encryptionKeys.publicKey)).toBe(false);
        });

        test('throws on invalid mnemonic', () => {
            expect(() => createChatAccountFromMnemonic('invalid mnemonic')).toThrow();
        });
    });

    describe('createRandomChatAccount', () => {
        test('creates account with valid address', () => {
            const { account } = createRandomChatAccount();

            expect(account.address).toBeDefined();
            expect(account.address.length).toBe(58);
        });

        test('creates account with encryption keys', () => {
            const { account } = createRandomChatAccount();

            expect(account.encryptionKeys.publicKey.length).toBe(32);
            expect(account.encryptionKeys.privateKey.length).toBe(32);
        });

        test('returns valid mnemonic', () => {
            const { mnemonic } = createRandomChatAccount();

            expect(mnemonic).toBeDefined();
            expect(mnemonic.split(' ').length).toBe(25); // Algorand uses 25-word mnemonics
            expect(validateMnemonic(mnemonic)).toBe(true);
        });

        test('mnemonic can recreate same account', () => {
            const { account: original, mnemonic } = createRandomChatAccount();
            const recreated = createChatAccountFromMnemonic(mnemonic);

            expect(recreated.address).toBe(original.address);
            expect(uint8ArrayEquals(recreated.encryptionKeys.publicKey, original.encryptionKeys.publicKey)).toBe(true);
        });

        test('generates unique accounts each time', () => {
            const { account: account1 } = createRandomChatAccount();
            const { account: account2 } = createRandomChatAccount();

            expect(account1.address).not.toBe(account2.address);
        });
    });

    describe('validateMnemonic', () => {
        test('returns true for valid mnemonic', () => {
            expect(validateMnemonic(TEST_MNEMONIC)).toBe(true);
        });

        test('returns true for generated mnemonic', () => {
            const { mnemonic } = createRandomChatAccount();
            expect(validateMnemonic(mnemonic)).toBe(true);
        });

        test('returns false for invalid mnemonic', () => {
            expect(validateMnemonic('invalid')).toBe(false);
            expect(validateMnemonic('')).toBe(false);
            expect(validateMnemonic('word '.repeat(25).trim())).toBe(false);
        });

        test('returns false for wrong word count', () => {
            expect(validateMnemonic('abandon '.repeat(24).trim())).toBe(false);
            expect(validateMnemonic('abandon '.repeat(12).trim())).toBe(false);
        });
    });

    describe('validateAddress', () => {
        test('returns true for valid address', () => {
            const { account } = createRandomChatAccount();
            expect(validateAddress(account.address)).toBe(true);
        });

        test('returns false for invalid address', () => {
            expect(validateAddress('invalid')).toBe(false);
            expect(validateAddress('')).toBe(false);
            expect(validateAddress('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')).toBe(false);
        });

        test('returns false for address with wrong length', () => {
            expect(validateAddress('ABC123')).toBe(false);
        });
    });

    describe('publicKeyToBase64 / base64ToPublicKey', () => {
        test('round-trip conversion preserves data', () => {
            const { account } = createRandomChatAccount();
            const original = account.encryptionKeys.publicKey;

            const base64 = publicKeyToBase64(original);
            const recovered = base64ToPublicKey(base64);

            expect(uint8ArrayEquals(original, recovered)).toBe(true);
        });

        test('produces valid base64 string', () => {
            const { account } = createRandomChatAccount();
            const base64 = publicKeyToBase64(account.encryptionKeys.publicKey);

            // Base64 for 32 bytes should be 44 chars (with padding)
            expect(base64.length).toBe(44);
            expect(/^[A-Za-z0-9+/]+=*$/.test(base64)).toBe(true);
        });

        test('handles known values', () => {
            const knownBytes = new Uint8Array(32).fill(0xAA);
            const base64 = publicKeyToBase64(knownBytes);
            const recovered = base64ToPublicKey(base64);

            expect(uint8ArrayEquals(knownBytes, recovered)).toBe(true);
        });
    });
});
