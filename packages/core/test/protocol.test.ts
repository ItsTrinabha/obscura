import { describe, expect, it } from 'vitest';
import {
  accountId,
  bundleFromJSON,
  bundleToJSON,
  decodePreKeyHeader,
  encodePreKeyHeader,
  generateIdentity,
  generateOneTimePreKeys,
  generatePqPreKey,
  generateSignedPreKey,
  IdentityKeyPair,
  KeyPair,
  PreKeyBundle,
  pqxdhInitiate,
  pqxdhRespond,
  publicIdentity,
  ratchetDecrypt,
  ratchetEncrypt,
  RatchetState,
  serializeState,
  deserializeState,
  utf8,
  fromUtf8,
  verifyIdentity,
  decodeHeader,
  Reader,
  MAX_SKIP,
  toB64,
  fromB64,
} from '../src/index.js';

function setupBob() {
  const id = generateIdentity();
  const spk = generateSignedPreKey(id, 1);
  const pq = generatePqPreKey(id, 2, false);
  const [opk] = generateOneTimePreKeys(3, 1);
  const bundle: PreKeyBundle = {
    identity: publicIdentity(id),
    signedPreKey: { id: spk.id, publicKey: spk.keyPair.publicKey, signature: spk.signature },
    pqPreKey: { id: pq.id, publicKey: pq.keyPair.publicKey, signature: pq.signature, lastResort: false },
    oneTimePreKey: { id: opk.id, publicKey: opk.keyPair.publicKey },
  };
  const lookup = {
    signedPreKey: (i: number): KeyPair | undefined => (i === spk.id ? spk.keyPair : undefined),
    oneTimePreKey: (i: number): KeyPair | undefined => (i === opk.id ? opk.keyPair : undefined),
    pqPreKey: (i: number): KeyPair | undefined => (i === pq.id ? pq.keyPair : undefined),
  };
  return { id, bundle, lookup };
}

function establish(): { alice: RatchetState; bob: RatchetState; aliceId: IdentityKeyPair; bobId: IdentityKeyPair } {
  const aliceId = generateIdentity();
  const b = setupBob();
  const { state: alice, header } = pqxdhInitiate(aliceId, b.bundle);
  const bob = pqxdhRespond(b.id, b.lookup, decodePreKeyHeader(encodePreKeyHeader(header)));
  return { alice, bob, aliceId, bobId: b.id };
}

const enc = (s: RatchetState, t: string) => ratchetEncrypt(s, utf8(t)).message;
const dec = (s: RatchetState, m: Uint8Array) => fromUtf8(ratchetDecrypt(s, m).plaintext);

describe('identity', () => {
  it('binds the X25519 key to the Ed25519 key', () => {
    const id = publicIdentity(generateIdentity());
    expect(verifyIdentity(id)).toBe(true);
    const other = publicIdentity(generateIdentity());
    expect(verifyIdentity({ ...id, dhPub: other.dhPub })).toBe(false);
  });
  it('derives a 32-char base32 account id from the signing key', () => {
    const id = generateIdentity();
    expect(accountId(id.sig.publicKey)).toMatch(/^[a-z2-7]{32}$/);
    expect(accountId(id.sig.publicKey)).toBe(accountId(id.sig.publicKey.slice()));
  });
});

describe('PQXDH', () => {
  it('both sides derive the same session and can talk', () => {
    const { alice, bob } = establish();
    expect(dec(bob, enc(alice, 'hello bob'))).toBe('hello bob');
    expect(dec(alice, enc(bob, 'hi alice'))).toBe('hi alice');
  });

  it('rejects a bundle whose signed prekey was swapped by the server', () => {
    const b = setupBob();
    const evil = generateSignedPreKey(generateIdentity(), 1);
    const forged = { ...b.bundle, signedPreKey: { ...b.bundle.signedPreKey, publicKey: evil.keyPair.publicKey } };
    expect(() => pqxdhInitiate(generateIdentity(), forged)).toThrow(/signed prekey/);
  });

  it('rejects a bundle whose post-quantum prekey was swapped', () => {
    const b = setupBob();
    const evil = generatePqPreKey(generateIdentity(), 2, false);
    const forged = { ...b.bundle, pqPreKey: { ...b.bundle.pqPreKey, publicKey: evil.keyPair.publicKey } };
    expect(() => pqxdhInitiate(generateIdentity(), forged)).toThrow(/post-quantum/);
  });

  it('fails closed if the ML-KEM ciphertext is tampered (session key depends on the PQ secret)', () => {
    const aliceId = generateIdentity();
    const b = setupBob();
    const { state: alice, header } = pqxdhInitiate(aliceId, b.bundle);
    header.kemCt = header.kemCt.slice();
    header.kemCt[10] ^= 1;
    const bob = pqxdhRespond(b.id, b.lookup, header);
    expect(() => dec(bob, enc(alice, 'x'))).toThrow();
  });

  it('works without a one-time prekey (server ran out)', () => {
    const aliceId = generateIdentity();
    const b = setupBob();
    const bundle = { ...b.bundle, oneTimePreKey: undefined };
    const { state: alice, header } = pqxdhInitiate(aliceId, bundle);
    expect(header.oneTimePreKeyId).toBeNull();
    const bob = pqxdhRespond(b.id, b.lookup, header);
    expect(dec(bob, enc(alice, 'no opk'))).toBe('no opk');
  });

  it('bundle JSON round-trips', () => {
    const b = setupBob();
    const j = bundleToJSON(b.bundle);
    const back = bundleFromJSON(JSON.parse(JSON.stringify(j)));
    expect(toB64(back.pqPreKey.publicKey)).toBe(toB64(b.bundle.pqPreKey.publicKey));
  });
});

describe('hybrid double ratchet', () => {
  it('handles a long ping-pong conversation with a PQ ratchet step on every turn', () => {
    const { alice, bob } = establish();
    for (let i = 0; i < 20; i++) {
      expect(dec(bob, enc(alice, `a${i}`))).toBe(`a${i}`);
      expect(dec(alice, enc(bob, `b${i}`))).toBe(`b${i}`);
    }
    expect(alice.steps).toBeGreaterThanOrEqual(20);
    expect(bob.steps).toBeGreaterThanOrEqual(20);
  });

  it('every header after the first exchange carries an ML-KEM ciphertext', () => {
    const { alice, bob } = establish();
    dec(bob, enc(alice, 'first'));
    const m = enc(bob, 'reply');
    const r = new Reader(m);
    const h = decodeHeader(r.bytes());
    expect(h.kemCt).not.toBeNull();
    expect(h.kemCt!.length).toBe(1088);
  });

  it('decrypts out-of-order and delayed messages', () => {
    const { alice, bob } = establish();
    const msgs = Array.from({ length: 10 }, (_, i) => enc(alice, `m${i}`));
    const order = [3, 0, 9, 1, 2, 8, 4, 7, 6, 5];
    for (const i of order) expect(dec(bob, msgs[i])).toBe(`m${i}`);
  });

  it('handles messages delayed across ratchet steps', () => {
    const { alice, bob } = establish();
    const early = enc(alice, 'early');
    dec(bob, enc(alice, 'second'));
    dec(alice, enc(bob, 'bob turn'));
    dec(bob, enc(alice, 'alice again'));
    expect(dec(bob, early)).toBe('early');
  });

  it('rejects replays (message keys are deleted after use)', () => {
    const { alice, bob } = establish();
    const m = enc(alice, 'once');
    expect(dec(bob, m)).toBe('once');
    expect(() => dec(bob, m)).toThrow();
  });

  it('a skipped message key can be used only once', () => {
    const { alice, bob } = establish();
    const m0 = enc(alice, 'zero');
    const m1 = enc(alice, 'one');
    dec(bob, m1);
    expect(dec(bob, m0)).toBe('zero');
    expect(() => dec(bob, m0)).toThrow();
  });

  it('rejects any bit flip in header or ciphertext, and the session survives', () => {
    const { alice, bob } = establish();
    const m = enc(alice, 'integrity');
    for (const pos of [5, 40, 1225, m.length - 20, m.length - 3]) {
      const bad = m.slice();
      bad[pos] ^= 0x01;
      expect(() => dec(bob, bad)).toThrow();
    }
    expect(dec(bob, m)).toBe('integrity');
  });

  it('refuses a downgrade: a later ratchet step without the ML-KEM ciphertext is rejected', () => {
    const { alice, bob } = establish();
    dec(bob, enc(alice, 'a'));
    dec(alice, enc(bob, 'b'));
    // Alice steps again; strip the KEM ciphertext from her header.
    const m = enc(alice, 'c');
    const r = new Reader(m);
    const hb = r.bytes();
    const ct = r.bytes();
    const h = decodeHeader(hb);
    expect(h.kemCt).not.toBeNull();
    const stripped = new Uint8Array([...hb.subarray(0, 1 + 32 + 1184), 0, ...hb.subarray(hb.length - 8)]);
    const w = new Uint8Array(4 + stripped.length + 4 + ct.length);
    const dv = new DataView(w.buffer);
    dv.setUint32(0, stripped.length);
    w.set(stripped, 4);
    dv.setUint32(4 + stripped.length, ct.length);
    w.set(ct, 8 + stripped.length);
    expect(() => dec(bob, w)).toThrow(/post-quantum/);
    expect(dec(bob, m)).toBe('c');
  });

  it('bounds skipped keys to stop memory exhaustion', () => {
    const { alice, bob } = establish();
    for (let i = 0; i <= MAX_SKIP + 1; i++) ratchetEncrypt(alice, utf8('x'));
    expect(() => dec(bob, enc(alice, 'far future'))).toThrow(/skipped/);
  });

  it('forward secrecy: a stolen current state cannot decrypt past traffic', () => {
    const { alice, bob } = establish();
    const past = enc(alice, 'secret from the past');
    dec(bob, past);
    dec(alice, enc(bob, 'ack'));
    dec(bob, enc(alice, 'later'));
    const stolen = deserializeState(serializeState(bob));
    expect(() => dec(stolen, past)).toThrow();
  });

  it('post-compromise security: after a round trip, a stolen state is useless', () => {
    const { alice, bob } = establish();
    dec(bob, enc(alice, 'hi'));
    dec(alice, enc(bob, 'hi'));
    const attacker = deserializeState(serializeState(bob)); // full compromise of Bob's state
    // Healing: one full round trip with fresh X25519 + ML-KEM secrets.
    const heal1 = enc(alice, 'heal 1');
    expect(dec(attacker, heal1)).toBe('heal 1'); // before healing, the compromise works
    dec(bob, heal1);
    dec(alice, enc(bob, 'heal 2'));
    const future = enc(alice, 'after healing');
    expect(dec(bob, future)).toBe('after healing');
    expect(() => dec(attacker, future)).toThrow();
  });

  it('state serialises and resumes', () => {
    const { alice, bob } = establish();
    dec(bob, enc(alice, '1'));
    const bob2 = deserializeState(JSON.parse(JSON.stringify(serializeState(bob))));
    dec(alice, enc(bob2, '2'));
    expect(dec(bob2, enc(alice, '3'))).toBe('3');
  });

  it('ciphertext reveals nothing obvious: same plaintext twice gives different bytes', () => {
    const { alice } = establish();
    const a = enc(alice, 'same');
    const b = enc(alice, 'same');
    expect(toB64(a)).not.toBe(toB64(b));
    expect(fromB64(toB64(a))).toEqual(a);
  });
});
