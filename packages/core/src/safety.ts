/**
 * Safety numbers, following Signal's NumericFingerprint design: each party's
 * identity is hashed 5200 times with SHA-512 and rendered as 30 digits; the two
 * halves are sorted so both people see the same 60-digit number. If you compare
 * it in person (or scan the QR), nobody can be sitting in the middle.
 */
import { concat, utf8 } from './bytes.js';
import { PublicIdentity } from './keys.js';
import { sha512 } from './primitives.js';

const ITERATIONS = 5200;

export function fingerprintDigits(identity: PublicIdentity, accountId: string): string {
  const key = concat(identity.sigPub, identity.dhPub);
  let h = sha512(concat(Uint8Array.of(0, 1), key, utf8(accountId)));
  for (let i = 0; i < ITERATIONS; i++) h = sha512(concat(h, key));
  let digits = '';
  for (let i = 0; i < 6; i++) {
    const c = h.subarray(i * 5, i * 5 + 5);
    const n = c[0] * 2 ** 32 + c[1] * 2 ** 24 + c[2] * 2 ** 16 + c[3] * 2 ** 8 + c[4];
    digits += String(n % 100000).padStart(5, '0');
  }
  return digits;
}

export function safetyNumber(a: PublicIdentity, aId: string, b: PublicIdentity, bId: string): string {
  const fa = fingerprintDigits(a, aId);
  const fb = fingerprintDigits(b, bId);
  return fa < fb ? fa + fb : fb + fa;
}

export const formatSafetyNumber = (n: string): string[] => n.match(/.{5}/g) ?? [];
