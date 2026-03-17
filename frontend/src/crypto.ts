/**
 * Cryptography utilities for E2EE messaging.
 * All encryption/decryption happens client-side.
 * Server never sees private keys or plaintext.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { x25519 } from '@noble/curves/ed25519';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

// Use native Web Crypto API
export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

// Convert between different encodings
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  if (!base64) {
    throw new Error('base64 string is empty or undefined');
  }
  // Remove any whitespace or newlines
  const cleaned = base64.replace(/\s/g, '');
  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// Ed25519 Identity Key Pair (for signing/authentication)
export interface IdentityKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateIdentityKeyPair(): IdentityKeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function signMessage(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey);
}

export function verifySignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): boolean {
  return ed25519.verify(signature, message, publicKey);
}

// X25519 Ephemeral Key Pair (for key exchange)
export interface EphemeralKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateEphemeralKeyPair(): EphemeralKeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

// Derive shared secret using X25519
export function deriveSharedSecret(
  myPrivateKey: Uint8Array,
  theirPublicKey: Uint8Array
): Uint8Array {
  return x25519.getSharedSecret(myPrivateKey, theirPublicKey);
}

// Derive encryption key from shared secret using HKDF
export function deriveEncryptionKey(
  sharedSecret: Uint8Array,
  salt?: Uint8Array
): Uint8Array {
  const actualSalt = salt || new Uint8Array(32); // Use empty salt if not provided
  return hkdf(sha256, sharedSecret, actualSalt, undefined, 32);
}

// Encrypt message using XChaCha20-Poly1305
export interface EncryptedMessage {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

export function encryptMessage(
  plaintext: string,
  key: Uint8Array
): EncryptedMessage {
  const nonce = randomBytes(24); // XChaCha20 uses 24-byte nonce
  const plaintextBytes = new TextEncoder().encode(plaintext);
  
  const cipher = xchacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(plaintextBytes);
  
  return { ciphertext, nonce };
}

export function decryptMessage(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
): string {
  const cipher = xchacha20poly1305(key, nonce);
  const plaintextBytes = cipher.decrypt(ciphertext);
  return new TextDecoder().decode(plaintextBytes);
}

// High-level encryption for sending messages
export function encryptForRecipient(
  plaintext: string,
  myEphemeralPrivateKey: Uint8Array,
  recipientEphemeralPublicKey: Uint8Array,
  myIdentityPrivateKey: Uint8Array
): { ciphertext: string; nonce: string; signature: string } {
  // 1. Derive shared secret
  const sharedSecret = deriveSharedSecret(myEphemeralPrivateKey, recipientEphemeralPublicKey);
  
  // 2. Derive encryption key
  const encryptionKey = deriveEncryptionKey(sharedSecret);
  
  // 3. Encrypt the message
  const { ciphertext, nonce } = encryptMessage(plaintext, encryptionKey);
  
  // 4. Sign the ciphertext for authenticity
  const signature = signMessage(myIdentityPrivateKey, ciphertext);
  
  return {
    ciphertext: bytesToBase64(ciphertext),
    nonce: bytesToBase64(nonce),
    signature: bytesToBase64(signature),
  };
}

// High-level decryption for receiving messages
export function decryptFromSender(
  ciphertextB64: string,
  nonceB64: string,
  signatureB64: string,
  myEphemeralPrivateKey: Uint8Array,
  senderEphemeralPublicKey: Uint8Array,
  senderIdentityPublicKey: Uint8Array
): string {
  const ciphertext = base64ToBytes(ciphertextB64);
  const nonce = base64ToBytes(nonceB64);
  const signature = base64ToBytes(signatureB64);
  
  // 1. Verify signature
  const isValid = verifySignature(senderIdentityPublicKey, ciphertext, signature);
  if (!isValid) {
    throw new Error('Invalid signature - message may be tampered');
  }
  
  // 2. Derive shared secret
  const sharedSecret = deriveSharedSecret(myEphemeralPrivateKey, senderEphemeralPublicKey);
  
  // 3. Derive encryption key
  const encryptionKey = deriveEncryptionKey(sharedSecret);
  
  // 4. Decrypt the message
  return decryptMessage(ciphertext, nonce, encryptionKey);
}
