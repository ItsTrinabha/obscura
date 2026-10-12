/**
 * Thin, typed wrappers around audited primitives. Obscura never implements a
 * cipher, curve or hash itself; every primitive comes from the @noble
 * libraries (pure TypeScript, independently audited, zero dependencies).
 *
 *   X25519            key agreement                @noble/curves
 *   Ed25519           signatures                   @noble/curves
 *   ML-KEM-768        post-quantum KEM (FIPS 203)   @noble/post-quantum
 *   XChaCha20-Poly1305 AEAD                         @noble/ciphers
 *   HKDF / HMAC / SHA-2                            @noble/hashes
 */
import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 as nobleSha256, sha512 as nobleSha512 } from '@noble/hashes/sha2.js';
import { randomBytes as nobleRandom } from '@noble/hashes/utils.js';
import { equalBytes, utf8 } from './bytes.js';

export const X25519_LEN = 32;
export const ED25519_PUB_LEN = 32;
export const ED25519_SIG_LEN = 64;
export const KEM_PUB_LEN = 1184;
export const KEM_SECRET_LEN = 2400;
export const KEM_CT_LEN = 1088;
export const KEY_LEN = 32;
export const NONCE_LEN = 24;
export const TAG_LEN = 16;

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** CSPRNG: crypto.getRandomValues (WebCrypto) in both browsers and Node. */
export function randomBytes(n: number): Uint8Array {
  if (n <= 65536) return nobleRandom(n);
  const out = new Uint8Array(n); // getRandomValues is capped at 64 KiB per call
  for (let off = 0; off < n; off += 65536) out.set(nobleRandom(Math.min(65536, n - off)), off);
  return out;
}

export const sha256 = (b: Uint8Array): Uint8Array => nobleSha256(b);
export const sha512 = (b: Uint8Array): Uint8Array => nobleSha512(b);
export const hmacSha256 = (key: Uint8Array, msg: Uint8Array): Uint8Array => hmac(nobleSha256, key, msg);

export function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string, length: number): Uint8Array {
  return nobleHkdf(nobleSha256, ikm, salt, utf8(info), length);
}

// ---------- X25519 ----------
export const dhKeyPair = (): KeyPair => x25519.keygen();

export function dh(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const out = x25519.getSharedSecret(secretKey, publicKey);
  // Reject low-order points: an all-zero output means the peer key contributed nothing.
  if (equalBytes(out, new Uint8Array(32))) throw new Error('invalid X25519 public key');
  return out;
}

// ---------- Ed25519 ----------
export const signKeyPair = (): KeyPair => ed25519.keygen();
export const sign = (secretKey: Uint8Array, msg: Uint8Array): Uint8Array => ed25519.sign(msg, secretKey);
export function verify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    // zip215:false => strict RFC 8032 verification (rejects malleable/non-canonical signatures).
    return ed25519.verify(sig, msg, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

// ---------- ML-KEM-768 ----------
export const kemKeyPair = (): KeyPair => ml_kem768.keygen();
export function kemEncapsulate(publicKey: Uint8Array): { ct: Uint8Array; ss: Uint8Array } {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  return { ct: cipherText, ss: sharedSecret };
}
export function kemDecapsulate(ct: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (ct.length !== KEM_CT_LEN) throw new Error('invalid ML-KEM ciphertext length');
  return ml_kem768.decapsulate(ct, secretKey);
}

// ---------- AEAD ----------
export function seal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, ad?: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, nonce, ad).encrypt(plaintext);
}

export class DecryptError extends Error {
  constructor(msg = 'decryption failed') {
    super(msg);
    this.name = 'DecryptError';
  }
}

export function open(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, ad?: Uint8Array): Uint8Array {
  try {
    return xchacha20poly1305(key, nonce, ad).decrypt(ciphertext);
  } catch {
    throw new DecryptError();
  }
}

/** Seal with a fresh random 192-bit nonce, which is safe to pick at random (XChaCha). Output: nonce || ct. */
export function sealRandom(key: Uint8Array, plaintext: Uint8Array, ad?: Uint8Array): Uint8Array {
  const nonce = randomBytes(NONCE_LEN);
  const ct = seal(key, nonce, plaintext, ad);
  const out = new Uint8Array(NONCE_LEN + ct.length);
  out.set(nonce);
  out.set(ct, NONCE_LEN);
  return out;
}

export function openRandom(key: Uint8Array, box: Uint8Array, ad?: Uint8Array): Uint8Array {
  if (box.length < NONCE_LEN + TAG_LEN) throw new DecryptError('ciphertext too short');
  return open(key, box.subarray(0, NONCE_LEN), box.subarray(NONCE_LEN), ad);
}
