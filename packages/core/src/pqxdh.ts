/**
 * PQXDH: Signal's post-quantum extension of X3DH
 * (https://signal.org/docs/specifications/pqxdh/), instantiated with
 * X25519, SHA-256 and ML-KEM-768.
 *
 *   DH1 = DH(IK_A, SPK_B)   DH2 = DH(EK_A, IK_B)
 *   DH3 = DH(EK_A, SPK_B)   DH4 = DH(EK_A, OPK_B)   (if a one-time prekey was available)
 *   (CT, SS) = ML-KEM-768.Encaps(PQPK_B)
 *   SK = HKDF(F || DH1 || DH2 || DH3 [|| DH4] || SS)
 *
 * An attacker must break BOTH X25519 and ML-KEM to recover SK, which defeats
 * "harvest now, decrypt later" collection by a future quantum adversary.
 */
import { concat, Reader, Writer } from './bytes.js';
import {
  IdentityKeyPair,
  PreKeyBundle,
  PublicIdentity,
  publicIdentity,
  sessionAD,
  verifyIdentity,
  verifyPqPreKey,
  verifySignedPreKey,
} from './keys.js';
import {
  DecryptError,
  dh,
  dhKeyPair,
  hkdf,
  kemDecapsulate,
  kemEncapsulate,
  KeyPair,
  ED25519_PUB_LEN,
  ED25519_SIG_LEN,
  KEM_CT_LEN,
  X25519_LEN,
} from './primitives.js';
import { initInitiator, initResponder, RatchetState } from './ratchet.js';
import { wipe } from './bytes.js';

const PQXDH_INFO = 'OBSCURA_PQXDH_CURVE25519_SHA-256_ML-KEM-768_v1';
const F = new Uint8Array(32).fill(0xff); // curve25519 "F" prefix from the X3DH/PQXDH spec
const NO_OPK = 0xffffffff;

export interface PreKeyHeader {
  identity: PublicIdentity;
  ephemeral: Uint8Array;
  signedPreKeyId: number;
  oneTimePreKeyId: number | null;
  pqPreKeyId: number;
  kemCt: Uint8Array;
}

export function encodePreKeyHeader(h: PreKeyHeader): Uint8Array {
  return new Writer()
    .u8(1)
    .fixed(h.identity.sigPub, ED25519_PUB_LEN)
    .fixed(h.identity.dhPub, X25519_LEN)
    .fixed(h.identity.dhSig, ED25519_SIG_LEN)
    .fixed(h.ephemeral, X25519_LEN)
    .u32(h.signedPreKeyId)
    .u32(h.oneTimePreKeyId ?? NO_OPK)
    .u32(h.pqPreKeyId)
    .fixed(h.kemCt, KEM_CT_LEN)
    .finish();
}

export function decodePreKeyHeader(b: Uint8Array): PreKeyHeader {
  const r = new Reader(b);
  if (r.u8() !== 1) throw new DecryptError('unsupported prekey message version');
  const identity = { sigPub: r.fixed(ED25519_PUB_LEN), dhPub: r.fixed(X25519_LEN), dhSig: r.fixed(ED25519_SIG_LEN) };
  const ephemeral = r.fixed(X25519_LEN);
  const signedPreKeyId = r.u32();
  const opk = r.u32();
  const pqPreKeyId = r.u32();
  const kemCt = r.fixed(KEM_CT_LEN);
  r.done();
  return { identity, ephemeral, signedPreKeyId, oneTimePreKeyId: opk === NO_OPK ? null : opk, pqPreKeyId, kemCt };
}

function deriveSK(parts: Uint8Array[]): Uint8Array {
  const ikm = concat(F, ...parts);
  const sk = hkdf(ikm, new Uint8Array(32), PQXDH_INFO, 32);
  wipe(ikm, ...parts);
  return sk;
}

/** Alice: verify Bob's bundle, run PQXDH, and return the initial ratchet state + header to send. */
export function pqxdhInitiate(
  ours: IdentityKeyPair,
  bundle: PreKeyBundle,
): { state: RatchetState; header: PreKeyHeader } {
  const theirs = bundle.identity;
  if (!verifyIdentity(theirs)) throw new Error('bundle identity signature invalid');
  if (!verifySignedPreKey(theirs.sigPub, bundle.signedPreKey)) throw new Error('signed prekey signature invalid');
  if (!verifyPqPreKey(theirs.sigPub, bundle.pqPreKey)) throw new Error('post-quantum prekey signature invalid');

  const ek: KeyPair = dhKeyPair();
  const spk = bundle.signedPreKey.publicKey;
  const parts = [dh(ours.dh.secretKey, spk), dh(ek.secretKey, theirs.dhPub), dh(ek.secretKey, spk)];
  if (bundle.oneTimePreKey) parts.push(dh(ek.secretKey, bundle.oneTimePreKey.publicKey));
  const { ct, ss } = kemEncapsulate(bundle.pqPreKey.publicKey);
  parts.push(ss);
  const sk = deriveSK(parts);
  wipe(ek.secretKey);

  const me = publicIdentity(ours);
  const state = initInitiator(sk, spk, sessionAD(me, theirs));
  wipe(sk);
  return {
    state,
    header: {
      identity: me,
      ephemeral: ek.publicKey,
      signedPreKeyId: bundle.signedPreKey.id,
      oneTimePreKeyId: bundle.oneTimePreKey?.id ?? null,
      pqPreKeyId: bundle.pqPreKey.id,
      kemCt: ct,
    },
  };
}

export interface PreKeyLookup {
  signedPreKey(id: number): KeyPair | undefined;
  oneTimePreKey(id: number): KeyPair | undefined;
  pqPreKey(id: number): KeyPair | undefined;
}

/** Bob: recompute SK from an incoming prekey header. The caller deletes one-time keys only after the first message decrypts. */
export function pqxdhRespond(ours: IdentityKeyPair, keys: PreKeyLookup, h: PreKeyHeader): RatchetState {
  if (!verifyIdentity(h.identity)) throw new DecryptError('sender identity signature invalid');
  const spk = keys.signedPreKey(h.signedPreKeyId);
  if (!spk) throw new DecryptError('unknown signed prekey');
  const pq = keys.pqPreKey(h.pqPreKeyId);
  if (!pq) throw new DecryptError('unknown post-quantum prekey');
  const parts = [dh(spk.secretKey, h.identity.dhPub), dh(ours.dh.secretKey, h.ephemeral), dh(spk.secretKey, h.ephemeral)];
  if (h.oneTimePreKeyId !== null) {
    const opk = keys.oneTimePreKey(h.oneTimePreKeyId);
    if (!opk) throw new DecryptError('one-time prekey already used or unknown');
    parts.push(dh(opk.secretKey, h.ephemeral));
  }
  parts.push(kemDecapsulate(h.kemCt, pq.secretKey));
  const sk = deriveSK(parts);
  const state = initResponder(sk, spk, sessionAD(h.identity, publicIdentity(ours)));
  wipe(sk);
  return state;
}
