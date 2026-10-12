/**
 * Hybrid post-quantum Double Ratchet.
 *
 * This is the Signal Double Ratchet (https://signal.org/docs/specifications/doubleratchet/)
 * with one change: every DH ratchet step also runs an ML-KEM-768 encapsulation
 * to the peer's current ratchet KEM key, and the KEM shared secret is mixed
 * into the root KDF together with the X25519 output.
 *
 *   root_key', chain_key = HKDF(salt = root_key, ikm = X25519(...) || ML-KEM-ss)
 *
 * Consequences:
 *  - Forward secrecy: every message has its own key, deleted after use.
 *  - Post-compromise security: a stolen state heals after one round trip.
 *  - Quantum resistance of the healing: an attacker recording traffic today
 *    with a future quantum computer cannot recompute later root keys, because
 *    each step also depends on a fresh ML-KEM secret, not only on X25519.
 *
 * All state transitions happen on a copy and are committed only after the AEAD
 * tag verifies, so a forged or corrupted message can never desynchronise a session.
 */
import { concat, equalBytes, fromB64, Reader, toB64, toHex, utf8, wipe, Writer } from './bytes.js';
import {
  DecryptError,
  dh,
  dhKeyPair,
  hkdf,
  hmacSha256,
  kemDecapsulate,
  kemEncapsulate,
  kemKeyPair,
  KeyPair,
  open,
  seal,
  KEM_CT_LEN,
  KEM_PUB_LEN,
  X25519_LEN,
} from './primitives.js';

export const RATCHET_VERSION = 1;
/** Max message keys we will derive and stash for a single gap (Signal recommends a bound). */
export const MAX_SKIP = 1000;
/** Max skipped keys held across all chains; oldest are evicted first. */
export const MAX_SKIPPED_TOTAL = 2000;

export interface RatchetState {
  rk: Uint8Array;
  dhs: KeyPair;
  dhr: Uint8Array | null;
  kems: KeyPair | null;
  kemr: Uint8Array | null;
  /** ML-KEM ciphertext that seeded our current sending chain; repeated in every header of the chain. */
  sendCt: Uint8Array | null;
  cks: Uint8Array | null;
  ckr: Uint8Array | null;
  ns: number;
  nr: number;
  pn: number;
  skipped: Map<string, Uint8Array>;
  ad: Uint8Array;
  /** Only a fresh responder may accept one classical (no-KEM) step: the initiator's first chain, already PQ-protected by PQXDH. */
  allowClassicStep: boolean;
  /** Number of DH+KEM ratchet steps taken (for UI / diagnostics). */
  steps: number;
}

export interface Header {
  dh: Uint8Array;
  kem: Uint8Array;
  kemCt: Uint8Array | null;
  pn: number;
  n: number;
}

export interface MessageInfo {
  n: number;
  pn: number;
  ratchetStep: number;
  pqStep: boolean;
}

export function encodeHeader(h: Header): Uint8Array {
  const w = new Writer().u8(RATCHET_VERSION).fixed(h.dh, X25519_LEN).fixed(h.kem, KEM_PUB_LEN);
  if (h.kemCt) w.u8(1).fixed(h.kemCt, KEM_CT_LEN);
  else w.u8(0);
  return w.u32(h.pn).u32(h.n).finish();
}

export function decodeHeader(b: Uint8Array): Header {
  const r = new Reader(b);
  if (r.u8() !== RATCHET_VERSION) throw new DecryptError('unsupported ratchet version');
  const dhPub = r.fixed(X25519_LEN);
  const kem = r.fixed(KEM_PUB_LEN);
  const flag = r.u8();
  if (flag > 1) throw new DecryptError('bad header');
  const kemCt = flag === 1 ? r.fixed(KEM_CT_LEN) : null;
  const pn = r.u32();
  const n = r.u32();
  r.done();
  return { dh: dhPub, kem, kemCt, pn, n };
}

function kdfRk(rk: Uint8Array, dhOut: Uint8Array, kemSs: Uint8Array | null): [Uint8Array, Uint8Array] {
  const ikm = kemSs ? concat(dhOut, kemSs) : dhOut;
  const info = kemSs ? 'OBSCURA_RATCHET_HYBRID_X25519_MLKEM768_v1' : 'OBSCURA_RATCHET_CLASSIC_X25519_v1';
  const out = hkdf(ikm, rk, info, 64);
  wipe(ikm, dhOut, kemSs);
  return [out.slice(0, 32), out.slice(32, 64)];
}

function kdfCk(ck: Uint8Array): [Uint8Array, Uint8Array] {
  const mk = hmacSha256(ck, Uint8Array.of(0x01));
  const next = hmacSha256(ck, Uint8Array.of(0x02));
  return [next, mk];
}

function messageKeys(mk: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const out = hkdf(mk, new Uint8Array(32), 'OBSCURA_MESSAGE_KEYS_v1', 56);
  return { key: out.slice(0, 32), nonce: out.slice(32, 56) };
}

/** Initiator (Alice) state after PQXDH. `sk` already contains the ML-KEM secret from PQXDH. */
export function initInitiator(sk: Uint8Array, responderSpk: Uint8Array, ad: Uint8Array): RatchetState {
  const dhs = dhKeyPair();
  const [rk, cks] = kdfRk(sk, dh(dhs.secretKey, responderSpk), null);
  return {
    rk,
    dhs,
    dhr: responderSpk,
    kems: kemKeyPair(),
    kemr: null,
    sendCt: null,
    cks,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: new Map(),
    ad,
    allowClassicStep: false,
    steps: 0,
  };
}

/** Responder (Bob) state after PQXDH: our signed prekey is the first ratchet key. */
export function initResponder(sk: Uint8Array, spk: KeyPair, ad: Uint8Array): RatchetState {
  return {
    rk: sk.slice(),
    dhs: { publicKey: spk.publicKey.slice(), secretKey: spk.secretKey.slice() },
    dhr: null,
    kems: null,
    kemr: null,
    sendCt: null,
    cks: null,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: new Map(),
    ad,
    allowClassicStep: true,
    steps: 0,
  };
}

export function canSend(s: RatchetState): boolean {
  return s.cks !== null && s.kems !== null;
}

export function ratchetEncrypt(s: RatchetState, plaintext: Uint8Array): { message: Uint8Array; info: MessageInfo } {
  if (!s.cks || !s.kems) throw new Error('session cannot send yet');
  const [cks, mk] = kdfCk(s.cks);
  const header: Header = { dh: s.dhs.publicKey, kem: s.kems.publicKey, kemCt: s.sendCt, pn: s.pn, n: s.ns };
  const hb = encodeHeader(header);
  const { key, nonce } = messageKeys(mk);
  const ct = seal(key, nonce, plaintext, concat(s.ad, hb));
  wipe(key, nonce, mk, s.cks);
  s.cks = cks;
  const info: MessageInfo = { n: s.ns, pn: s.pn, ratchetStep: s.steps, pqStep: s.sendCt !== null };
  s.ns += 1;
  return { message: new Writer().bytes(hb).bytes(ct).finish(), info };
}

function cloneState(s: RatchetState): RatchetState {
  const c = (b: Uint8Array | null) => (b ? b.slice() : null);
  return {
    rk: s.rk.slice(),
    dhs: { publicKey: s.dhs.publicKey.slice(), secretKey: s.dhs.secretKey.slice() },
    dhr: c(s.dhr),
    kems: s.kems ? { publicKey: s.kems.publicKey.slice(), secretKey: s.kems.secretKey.slice() } : null,
    kemr: c(s.kemr),
    sendCt: c(s.sendCt),
    cks: c(s.cks),
    ckr: c(s.ckr),
    ns: s.ns,
    nr: s.nr,
    pn: s.pn,
    skipped: new Map([...s.skipped].map(([k, v]) => [k, v.slice()])),
    ad: s.ad,
    allowClassicStep: s.allowClassicStep,
    steps: s.steps,
  };
}

function commit(target: RatchetState, src: RatchetState) {
  Object.assign(target, src);
}

const skipKey = (dhPub: Uint8Array, n: number) => `${toHex(dhPub)}:${n}`;

function skipMessageKeys(s: RatchetState, until: number) {
  if (!s.ckr || !s.dhr) return;
  if (until - s.nr > MAX_SKIP) throw new DecryptError('too many skipped messages');
  while (s.nr < until) {
    const [ckr, mk] = kdfCk(s.ckr);
    s.skipped.set(skipKey(s.dhr, s.nr), mk);
    s.ckr = ckr;
    s.nr += 1;
  }
  while (s.skipped.size > MAX_SKIPPED_TOTAL) {
    const oldest = s.skipped.keys().next().value as string;
    wipe(s.skipped.get(oldest));
    s.skipped.delete(oldest);
  }
}

function dhRatchetStep(s: RatchetState, h: Header) {
  let ss: Uint8Array | null = null;
  if (h.kemCt) {
    if (!s.kems) throw new DecryptError('unexpected KEM ciphertext');
    ss = kemDecapsulate(h.kemCt, s.kems.secretKey);
  } else if (!s.allowClassicStep) {
    // Downgrade protection: after the first exchange every step MUST be hybrid.
    throw new DecryptError('missing post-quantum ratchet ciphertext');
  }
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.dhr = h.dh;
  s.kemr = h.kem;
  [s.rk, s.ckr] = kdfRk(s.rk, dh(s.dhs.secretKey, s.dhr), ss);
  // New sending chain: fresh X25519 key AND fresh ML-KEM encapsulation to the peer.
  wipe(s.dhs.secretKey, s.kems?.secretKey);
  s.dhs = dhKeyPair();
  s.kems = kemKeyPair();
  const enc = kemEncapsulate(s.kemr);
  s.sendCt = enc.ct;
  [s.rk, s.cks] = kdfRk(s.rk, dh(s.dhs.secretKey, s.dhr), enc.ss);
  s.allowClassicStep = false;
  s.steps += 1;
}

export function ratchetDecrypt(state: RatchetState, message: Uint8Array): { plaintext: Uint8Array; info: MessageInfo } {
  const r = new Reader(message);
  const hb = r.bytes(8192);
  const ct = r.bytes();
  r.done();
  const h = decodeHeader(hb);
  const ad = concat(state.ad, hb);

  // 1. A key we stashed earlier for an out-of-order message?
  const sk = skipKey(h.dh, h.n);
  const stashed = state.skipped.get(sk);
  if (stashed) {
    const { key, nonce } = messageKeys(stashed);
    const plaintext = open(key, nonce, ct, ad); // throws without touching state
    wipe(stashed);
    state.skipped.delete(sk);
    return { plaintext, info: { n: h.n, pn: h.pn, ratchetStep: state.steps, pqStep: h.kemCt !== null } };
  }

  const s = cloneState(state);
  if (!s.dhr || !equalBytes(h.dh, s.dhr)) {
    skipMessageKeys(s, h.pn);
    dhRatchetStep(s, h);
  }
  if (h.n < s.nr) throw new DecryptError('duplicate or replayed message');
  skipMessageKeys(s, h.n);
  if (!s.ckr) throw new DecryptError('no receiving chain');
  const [ckr, mk] = kdfCk(s.ckr);
  s.ckr = ckr;
  s.nr += 1;
  const { key, nonce } = messageKeys(mk);
  const plaintext = open(key, nonce, ct, ad);
  wipe(key, nonce, mk);
  commit(state, s);
  return { plaintext, info: { n: h.n, pn: h.pn, ratchetStep: s.steps, pqStep: h.kemCt !== null } };
}

// ---------- persistence ----------

export interface RatchetStateJSON {
  v: 1;
  rk: string;
  dhs: [string, string];
  dhr: string | null;
  kems: [string, string] | null;
  kemr: string | null;
  sendCt: string | null;
  cks: string | null;
  ckr: string | null;
  ns: number;
  nr: number;
  pn: number;
  skipped: [string, string][];
  ad: string;
  allowClassicStep: boolean;
  steps: number;
}

const ob = (b: Uint8Array | null) => (b ? toB64(b) : null);
const ib = (s: string | null) => (s ? fromB64(s) : null);

export function serializeState(s: RatchetState): RatchetStateJSON {
  return {
    v: 1,
    rk: toB64(s.rk),
    dhs: [toB64(s.dhs.publicKey), toB64(s.dhs.secretKey)],
    dhr: ob(s.dhr),
    kems: s.kems ? [toB64(s.kems.publicKey), toB64(s.kems.secretKey)] : null,
    kemr: ob(s.kemr),
    sendCt: ob(s.sendCt),
    cks: ob(s.cks),
    ckr: ob(s.ckr),
    ns: s.ns,
    nr: s.nr,
    pn: s.pn,
    skipped: [...s.skipped].map(([k, v]) => [k, toB64(v)]),
    ad: toB64(s.ad),
    allowClassicStep: s.allowClassicStep,
    steps: s.steps,
  };
}

export function deserializeState(j: RatchetStateJSON): RatchetState {
  if (j.v !== 1) throw new Error('unknown ratchet state version');
  return {
    rk: fromB64(j.rk),
    dhs: { publicKey: fromB64(j.dhs[0]), secretKey: fromB64(j.dhs[1]) },
    dhr: ib(j.dhr),
    kems: j.kems ? { publicKey: fromB64(j.kems[0]), secretKey: fromB64(j.kems[1]) } : null,
    kemr: ib(j.kemr),
    sendCt: ib(j.sendCt),
    cks: ib(j.cks),
    ckr: ib(j.ckr),
    ns: j.ns,
    nr: j.nr,
    pn: j.pn,
    skipped: new Map(j.skipped.map(([k, v]) => [k, fromB64(v)])),
    ad: fromB64(j.ad),
    allowClassicStep: j.allowClassicStep,
    steps: j.steps,
  };
}

