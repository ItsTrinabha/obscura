import { describe, expect, it } from 'vitest';
import {
  createVault,
  decryptAttachment,
  encryptAttachment,
  fingerprintDigits,
  fromB64,
  generateIdentity,
  MemoryKV,
  openEnvelope,
  padMessage,
  padme,
  parseAuthHeader,
  publicIdentity,
  safetyNumber,
  sealEnvelope,
  SecureStore,
  signRequest,
  toB64,
  unlockVault,
  unpadMessage,
  utf8,
  verifyRequest,
  accountId,
  KdfParams,
  randomBytes,
  sha256,
} from '../src/index.js';

const FAST_KDF: KdfParams = { alg: 'argon2id', memoryKiB: 1024, iterations: 1, parallelism: 1 };

describe('sealed sender', () => {
  it('hides the sender from the server and authenticates it to the recipient', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    const env = sealEnvelope(alice, publicIdentity(bob), utf8('payload'));
    // The sender's public keys appear nowhere in the envelope bytes.
    const hex = Buffer.from(env).toString('hex');
    expect(hex.includes(Buffer.from(alice.sig.publicKey).toString('hex'))).toBe(false);
    expect(hex.includes(Buffer.from(alice.dh.publicKey).toString('hex'))).toBe(false);
    const { sender, content } = openEnvelope(bob, env);
    expect(accountId(sender.sigPub)).toBe(accountId(alice.sig.publicKey));
    expect(new TextDecoder().decode(content)).toBe('payload');
  });

  it('cannot be opened by anyone but the recipient', () => {
    const env = sealEnvelope(generateIdentity(), publicIdentity(generateIdentity()), utf8('x'));
    expect(() => openEnvelope(generateIdentity(), env)).toThrow();
  });

  it('rejects tampering anywhere in the envelope', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    const env = sealEnvelope(alice, publicIdentity(bob), utf8('payload'));
    for (const pos of [1, 20, 40, 100, env.length - 1]) {
      const bad = env.slice();
      bad[pos] ^= 0x80;
      expect(() => openEnvelope(bob, bad)).toThrow();
    }
  });

  it('a third party cannot impersonate Alice to Bob (static-static layer)', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    const mallory = generateIdentity();
    // Mallory claims Alice's identity but only has her own DH secret.
    const forgedSender = { ...alice, dh: { publicKey: alice.dh.publicKey, secretKey: mallory.dh.secretKey } };
    const env = sealEnvelope(forgedSender, publicIdentity(bob), utf8('i am alice'));
    expect(() => openEnvelope(bob, env)).toThrow();
  });
});

describe('attachments', () => {
  it('round-trips files of many sizes including empty and multi-chunk', () => {
    for (const size of [0, 1, 1000, 65536, 65537, 300_000]) {
      const data = randomBytes(size);
      const { blob, pointer } = encryptAttachment(data, 64 * 1024);
      expect(blob.length).toBeGreaterThanOrEqual(size);
      expect(decryptAttachment(blob, pointer)).toEqual(data);
    }
  });

  it('pads sizes so similar files are indistinguishable', () => {
    const a = encryptAttachment(randomBytes(1_000_001)).blob.length;
    const b = encryptAttachment(randomBytes(1_010_000)).blob.length;
    expect(a).toBe(b);
  });

  it('detects tampering, truncation and chunk reordering', () => {
    const data = randomBytes(200_000);
    const { blob, pointer } = encryptAttachment(data, 64 * 1024);
    const flipped = blob.slice();
    flipped[100_000] ^= 1;
    expect(() => decryptAttachment(flipped, pointer)).toThrow();
    // Even with a matching digest (attacker controls the pointer?), chunk auth still holds:
    const truncated = blob.slice(0, blob.length - (64 * 1024 + 16));
    expect(() => decryptAttachment(truncated, { ...pointer, digest: sha256(truncated) })).toThrow();
    const c = 25 + 0; // header length
    const swapped = blob.slice();
    const chunk = 64 * 1024 + 16;
    swapped.set(blob.subarray(c + chunk, c + 2 * chunk), c);
    swapped.set(blob.subarray(c, c + chunk), c + chunk);
    expect(() => decryptAttachment(swapped, { ...pointer, digest: sha256(swapped) })).toThrow();
  });

  it('wrong key fails', () => {
    const { blob, pointer } = encryptAttachment(randomBytes(5000));
    expect(() => decryptAttachment(blob, { ...pointer, key: randomBytes(32) })).toThrow();
  });
});

describe('padding', () => {
  it('message padding hides length within 256-byte blocks', () => {
    expect(padMessage(utf8('ok')).length).toBe(256);
    expect(padMessage(new Uint8Array(200)).length).toBe(256);
    expect(padMessage(new Uint8Array(255)).length).toBe(256);
    expect(padMessage(new Uint8Array(256)).length).toBe(512);
    for (const n of [0, 1, 255, 256, 1000]) {
      const m = randomBytes(n);
      expect(unpadMessage(padMessage(m))).toEqual(m);
    }
  });
  it('padmé overhead stays under 12%', () => {
    for (const n of [100, 1234, 99_999, 5_000_000, 99_000_000]) {
      const p = padme(n);
      expect(p).toBeGreaterThanOrEqual(n);
      expect(p / n).toBeLessThan(1.12);
    }
  });
});

describe('vault (encryption at rest)', () => {
  it('unlocks with the right passphrase only', async () => {
    const { header, masterKey } = await createVault('correct horse battery staple', FAST_KDF);
    expect(await unlockVault('correct horse battery staple', header)).toEqual(masterKey);
    await expect(unlockVault('wrong passphrase', header)).rejects.toThrow(/wrong passphrase/);
  });

  it('defaults to Argon2id with 64 MiB / 3 passes', async () => {
    const { header } = await createVault('x'.repeat(12));
    expect(header.kdf).toEqual({ alg: 'argon2id', memoryKiB: 65536, iterations: 3, parallelism: 1 });
  });

  it('stores only ciphertext under hashed record names, bound to their slot', async () => {
    const kv = new MemoryKV();
    const store = new SecureStore(kv, randomBytes(32));
    await store.put('contacts', { alice: 'secret-name' });
    const keys = [...kv.map.keys()];
    expect(keys.every((k) => !k.includes('contacts'))).toBe(true);
    const raw = Buffer.from(kv.map.get(keys[0])!).toString();
    expect(raw.includes('secret-name')).toBe(false);
    expect(await store.get('contacts')).toEqual({ alice: 'secret-name' });
    // Moving a ciphertext into another slot is detected.
    await store.put('other', { x: 1 });
    const [k1, k2] = [...kv.map.keys()];
    kv.map.set(k2, kv.map.get(k1)!);
    await expect(store.get('other')).rejects.toThrow();
  });
});

describe('safety numbers', () => {
  it('are 60 digits and identical on both sides', () => {
    const a = publicIdentity(generateIdentity());
    const b = publicIdentity(generateIdentity());
    const ida = accountId(a.sigPub);
    const idb = accountId(b.sigPub);
    const s1 = safetyNumber(a, ida, b, idb);
    const s2 = safetyNumber(b, idb, a, ida);
    expect(s1).toMatch(/^\d{60}$/);
    expect(s1).toBe(s2);
  });
  it('change if either key changes', () => {
    const a = publicIdentity(generateIdentity());
    const b = publicIdentity(generateIdentity());
    const c = publicIdentity(generateIdentity());
    expect(fingerprintDigits(a, 'x')).not.toBe(fingerprintDigits(b, 'x'));
    expect(safetyNumber(a, 'a', b, 'b')).not.toBe(safetyNumber(a, 'a', c, 'b'));
  });
});

describe('request signing', () => {
  it('verifies a correctly signed request and rejects alterations', () => {
    const id = generateIdentity();
    const aid = accountId(id.sig.publicKey);
    const body = utf8('{"a":1}');
    const h = signRequest(aid, id.sig.secretKey, 'PUT', '/v1/keys', body);
    const p = parseAuthHeader(h)!;
    expect(verifyRequest(p, id.sig.publicKey, 'PUT', '/v1/keys', body)).toBe(true);
    expect(verifyRequest(p, id.sig.publicKey, 'PUT', '/v1/keys', utf8('{"a":2}'))).toBe(false);
    expect(verifyRequest(p, id.sig.publicKey, 'DELETE', '/v1/keys', body)).toBe(false);
    expect(verifyRequest(p, id.sig.publicKey, 'PUT', '/v1/keys', body, Date.now() + 10 * 60_000)).toBe(false);
    expect(verifyRequest(p, generateIdentity().sig.publicKey, 'PUT', '/v1/keys', body)).toBe(false);
  });
  it('base64url round-trips', () => {
    for (let n = 0; n < 40; n++) {
      const b = randomBytes(n);
      expect(fromB64(toB64(b))).toEqual(b);
    }
  });
});
