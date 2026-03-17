/**
 * Local storage management for user keys.
 * Private keys are stored in browser localStorage.
 * WARNING: In production, consider using IndexedDB with encryption or hardware security.
 */
import type { IdentityKeyPair, EphemeralKeyPair } from './crypto';
import { bytesToHex, hexToBytes } from './crypto';

interface StoredKeys {
  identityPrivateKey: string; // hex
  identityPublicKey: string;  // hex
  ephemeralPrivateKey: string; // hex
  ephemeralPublicKey: string;  // hex
  userId?: string;
}

const STORAGE_KEY = 'e2ee_keys';

export function saveKeys(
  identity: IdentityKeyPair,
  ephemeral: EphemeralKeyPair,
  userId?: string
): void {
  const keys: StoredKeys = {
    identityPrivateKey: bytesToHex(identity.privateKey),
    identityPublicKey: bytesToHex(identity.publicKey),
    ephemeralPrivateKey: bytesToHex(ephemeral.privateKey),
    ephemeralPublicKey: bytesToHex(ephemeral.publicKey),
    userId,
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(keys));
}

export function loadKeys(): {
  identity: IdentityKeyPair;
  ephemeral: EphemeralKeyPair;
  userId?: string;
} | null {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (!stored) return null;

  try {
    const keys: StoredKeys = JSON.parse(stored);
    return {
      identity: {
        privateKey: hexToBytes(keys.identityPrivateKey),
        publicKey: hexToBytes(keys.identityPublicKey),
      },
      ephemeral: {
        privateKey: hexToBytes(keys.ephemeralPrivateKey),
        publicKey: hexToBytes(keys.ephemeralPublicKey),
      },
      userId: keys.userId,
    };
  } catch (error) {
    console.error('Failed to load keys:', error);
    return null;
  }
}

export function clearKeys(): void {
  localStorage.removeItem(STORAGE_KEY);
}

export function hasKeys(): boolean {
  return localStorage.getItem(STORAGE_KEY) !== null;
}
