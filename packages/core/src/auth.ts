/**
 * Passwordless server authentication. There are no passwords, tokens or
 * cookies: every authenticated request is signed with the account's Ed25519
 * identity key. The signature covers method, path, a timestamp, a random nonce
 * and the SHA-256 of the body, so requests cannot be replayed or altered.
 */
import { concat, fromB64, toB64, toHex, utf8 } from './bytes.js';
import { randomBytes, sha256, sign, verify } from './primitives.js';

export const AUTH_HEADER = 'x-obscura-auth';
export const AUTH_MAX_SKEW_MS = 120_000;

function authMessage(method: string, path: string, ts: number, nonce: string, body: Uint8Array): Uint8Array {
  return utf8(`OBSCURA-AUTH-v1\n${method.toUpperCase()}\n${path}\n${ts}\n${nonce}\n${toHex(sha256(body))}`);
}

export function signRequest(
  accountId: string,
  sigSecret: Uint8Array,
  method: string,
  path: string,
  body: Uint8Array = new Uint8Array(0),
  now = Date.now(),
): string {
  const nonce = toB64(randomBytes(16));
  const sig = sign(sigSecret, authMessage(method, path, now, nonce, body));
  return `${accountId}.${now}.${nonce}.${toB64(sig)}`;
}

export interface ParsedAuth {
  accountId: string;
  ts: number;
  nonce: string;
  sig: Uint8Array;
}

export function parseAuthHeader(h: string | undefined): ParsedAuth | null {
  if (!h) return null;
  const parts = h.split('.');
  if (parts.length !== 4) return null;
  const [accountId, ts, nonce, sig] = parts;
  if (!/^[a-z2-7]{32}$/.test(accountId) || !/^\d{1,15}$/.test(ts) || !/^[A-Za-z0-9_-]{22}$/.test(nonce)) return null;
  try {
    return { accountId, ts: Number(ts), nonce, sig: fromB64(sig) };
  } catch {
    return null;
  }
}

export function verifyRequest(
  p: ParsedAuth,
  sigPub: Uint8Array,
  method: string,
  path: string,
  body: Uint8Array,
  now = Date.now(),
): boolean {
  if (Math.abs(now - p.ts) > AUTH_MAX_SKEW_MS) return false;
  return verify(sigPub, authMessage(method, path, p.ts, p.nonce, body), p.sig);
}

/** WebSocket login: the server sends a random challenge, the client signs it. */
export const wsChallengeMessage = (challenge: Uint8Array): Uint8Array => concat(utf8('OBSCURA-WS-v1\n'), challenge);
