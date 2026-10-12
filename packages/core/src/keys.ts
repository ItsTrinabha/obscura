/**
 * Long-term identity keys and prekeys.
 *
 * An identity is an Ed25519 signing key plus an X25519 key-agreement key. The
 * X25519 key is signed by the Ed25519 key so the two are cryptographically
 * bound; the account ID is a hash of the signing key, so nobody (including the
 * server) can register an ID that belongs to someone else's key.
 */
import { concat, fromB64, toB32, toB64, u32be, utf8 } from './bytes.js';
import {
  dhKeyPair,
  kemKeyPair,
  KeyPair,
  sha256,
  sign,
  signKeyPair,
  verify,
  X25519_LEN,
  ED25519_PUB_LEN,
  ED25519_SIG_LEN,
  KEM_PUB_LEN,
} from './primitives.js';

export interface IdentityKeyPair {
  sig: KeyPair; // Ed25519
  dh: KeyPair; // X25519
  dhSig: Uint8Array; // Ed25519 signature binding dh.publicKey to sig.publicKey
}

export interface PublicIdentity {
  sigPub: Uint8Array;
  dhPub: Uint8Array;
  dhSig: Uint8Array;
}

export interface SignedPreKey {
  id: number;
  keyPair: KeyPair;
  signature: Uint8Array;
  createdAt: number;
}

export interface PqPreKey {
  id: number;
  keyPair: KeyPair; // ML-KEM-768
  signature: Uint8Array;
  lastResort: boolean;
}

export interface OneTimePreKey {
  id: number;
  keyPair: KeyPair;
}

/** What the server hands out to someone who wants to start a session with us. */
export interface PreKeyBundle {
  identity: PublicIdentity;
  signedPreKey: { id: number; publicKey: Uint8Array; signature: Uint8Array };
  pqPreKey: { id: number; publicKey: Uint8Array; signature: Uint8Array; lastResort: boolean };
  oneTimePreKey?: { id: number; publicKey: Uint8Array };
}

const IDK_DOMAIN = utf8('OBSCURA-IDENTITY-DH-v1');
const SPK_DOMAIN = utf8('OBSCURA-SIGNED-PREKEY-v1');
const PQPK_DOMAIN = utf8('OBSCURA-PQ-PREKEY-v1');
const ID_DOMAIN = utf8('OBSCURA-ACCOUNT-ID-v1');

export function generateIdentity(): IdentityKeyPair {
  const sig = signKeyPair();
  const dh = dhKeyPair();
  const dhSig = sign(sig.secretKey, concat(IDK_DOMAIN, dh.publicKey));
  return { sig, dh, dhSig };
}

export function publicIdentity(id: IdentityKeyPair): PublicIdentity {
  return { sigPub: id.sig.publicKey, dhPub: id.dh.publicKey, dhSig: id.dhSig };
}

export function verifyIdentity(p: PublicIdentity): boolean {
  return (
    p.sigPub.length === ED25519_PUB_LEN &&
    p.dhPub.length === X25519_LEN &&
    p.dhSig.length === ED25519_SIG_LEN &&
    verify(p.sigPub, concat(IDK_DOMAIN, p.dhPub), p.dhSig)
  );
}

/** 32-character base32 account ID = first 160 bits of SHA-256(domain || Ed25519 public key). */
export function accountId(sigPub: Uint8Array): string {
  return toB32(sha256(concat(ID_DOMAIN, sigPub)).subarray(0, 20));
}

export function generateSignedPreKey(identity: IdentityKeyPair, id: number): SignedPreKey {
  const keyPair = dhKeyPair();
  const signature = sign(identity.sig.secretKey, concat(SPK_DOMAIN, u32be(id), keyPair.publicKey));
  return { id, keyPair, signature, createdAt: Date.now() };
}

export function generatePqPreKey(identity: IdentityKeyPair, id: number, lastResort: boolean): PqPreKey {
  const keyPair = kemKeyPair();
  const signature = sign(
    identity.sig.secretKey,
    concat(PQPK_DOMAIN, Uint8Array.of(lastResort ? 1 : 0), u32be(id), keyPair.publicKey),
  );
  return { id, keyPair, signature, lastResort };
}

export function generateOneTimePreKeys(startId: number, count: number): OneTimePreKey[] {
  const out: OneTimePreKey[] = [];
  for (let i = 0; i < count; i++) out.push({ id: (startId + i) >>> 0, keyPair: dhKeyPair() });
  return out;
}

export function verifySignedPreKey(sigPub: Uint8Array, spk: PreKeyBundle['signedPreKey']): boolean {
  return spk.publicKey.length === X25519_LEN && verify(sigPub, concat(SPK_DOMAIN, u32be(spk.id), spk.publicKey), spk.signature);
}

export function verifyPqPreKey(sigPub: Uint8Array, pq: PreKeyBundle['pqPreKey']): boolean {
  return (
    pq.publicKey.length === KEM_PUB_LEN &&
    verify(sigPub, concat(PQPK_DOMAIN, Uint8Array.of(pq.lastResort ? 1 : 0), u32be(pq.id), pq.publicKey), pq.signature)
  );
}

// ---------- JSON wire forms (base64url) ----------

export interface PublicIdentityJSON {
  sigPub: string;
  dhPub: string;
  dhSig: string;
}

export interface PreKeyBundleJSON {
  identity: PublicIdentityJSON;
  signedPreKey: { id: number; publicKey: string; signature: string };
  pqPreKey: { id: number; publicKey: string; signature: string; lastResort: boolean };
  oneTimePreKey?: { id: number; publicKey: string } | null;
}

export const identityToJSON = (p: PublicIdentity): PublicIdentityJSON => ({
  sigPub: toB64(p.sigPub),
  dhPub: toB64(p.dhPub),
  dhSig: toB64(p.dhSig),
});

export const identityFromJSON = (j: PublicIdentityJSON): PublicIdentity => ({
  sigPub: fromB64(j.sigPub),
  dhPub: fromB64(j.dhPub),
  dhSig: fromB64(j.dhSig),
});

export function bundleFromJSON(j: PreKeyBundleJSON): PreKeyBundle {
  return {
    identity: identityFromJSON(j.identity),
    signedPreKey: { id: j.signedPreKey.id, publicKey: fromB64(j.signedPreKey.publicKey), signature: fromB64(j.signedPreKey.signature) },
    pqPreKey: {
      id: j.pqPreKey.id,
      publicKey: fromB64(j.pqPreKey.publicKey),
      signature: fromB64(j.pqPreKey.signature),
      lastResort: !!j.pqPreKey.lastResort,
    },
    oneTimePreKey: j.oneTimePreKey ? { id: j.oneTimePreKey.id, publicKey: fromB64(j.oneTimePreKey.publicKey) } : undefined,
  };
}

export function bundleToJSON(b: PreKeyBundle): PreKeyBundleJSON {
  return {
    identity: identityToJSON(b.identity),
    signedPreKey: { id: b.signedPreKey.id, publicKey: toB64(b.signedPreKey.publicKey), signature: toB64(b.signedPreKey.signature) },
    pqPreKey: {
      id: b.pqPreKey.id,
      publicKey: toB64(b.pqPreKey.publicKey),
      signature: toB64(b.pqPreKey.signature),
      lastResort: b.pqPreKey.lastResort,
    },
    oneTimePreKey: b.oneTimePreKey ? { id: b.oneTimePreKey.id, publicKey: toB64(b.oneTimePreKey.publicKey) } : null,
  };
}

/** Associated data binding a session to both identities, initiator first (PQXDH §3.3 "AD"). */
export function sessionAD(initiator: PublicIdentity, responder: PublicIdentity): Uint8Array {
  return concat(initiator.sigPub, initiator.dhPub, responder.sigPub, responder.dhPub);
}
