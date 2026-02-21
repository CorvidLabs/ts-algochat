/**
 * AlgoChat Web - Mnemonic/Account Service
 *
 * Handles Algorand mnemonic decoding and account creation.
 */

import algosdk from 'algosdk';
import { deriveEncryptionKeys } from '../crypto';
import { getPublicKey } from '../crypto/signature';
import type { ChatAccount } from './algorand.service';

/**
 * Creates a ChatAccount from an Algorand mnemonic
 */
export function createChatAccountFromMnemonic(mnemonic: string): ChatAccount {
    // Recover Algorand account from mnemonic
    const account = algosdk.mnemonicToSecretKey(mnemonic);

    // Extract the 32-byte seed from the secret key
    // The secret key is 64 bytes: first 32 are the seed, last 32 are the public key
    const seed = account.sk.slice(0, 32);

    // Derive X25519 encryption keys
    const encryptionKeys = deriveEncryptionKeys(seed);

    // Derive the Ed25519 public key from the seed
    const ed25519PublicKey = getPublicKey(seed);

    return {
        address: account.addr.toString(),
        account,
        encryptionKeys,
        ed25519PublicKey,
    };
}

/**
 * Creates a new random ChatAccount
 */
export function createRandomChatAccount(): { account: ChatAccount; mnemonic: string } {
    const account = algosdk.generateAccount();
    const mnemonic = algosdk.secretKeyToMnemonic(account.sk);

    const seed = account.sk.slice(0, 32);
    const encryptionKeys = deriveEncryptionKeys(seed);

    // Derive the Ed25519 public key from the seed
    const ed25519PublicKey = getPublicKey(seed);

    return {
        account: {
            address: account.addr.toString(),
            account,
            encryptionKeys,
            ed25519PublicKey,
        },
        mnemonic,
    };
}

/**
 * Validates an Algorand mnemonic
 */
export function validateMnemonic(mnemonic: string): boolean {
    try {
        algosdk.mnemonicToSecretKey(mnemonic);
        return true;
    } catch {
        return false;
    }
}

/**
 * Validates an Algorand address
 */
export function validateAddress(address: string): boolean {
    return algosdk.isValidAddress(address);
}

/**
 * Converts public key bytes to base64 for display/storage
 */
export function publicKeyToBase64(publicKey: Uint8Array): string {
    return Buffer.from(publicKey).toString('base64');
}

/**
 * Converts base64 to public key bytes
 */
export function base64ToPublicKey(base64: string): Uint8Array {
    return new Uint8Array(Buffer.from(base64, 'base64'));
}
