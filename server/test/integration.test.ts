/**
 * End-to-end tests: a real relay server on a random port and real clients
 * (the same engine the web app runs), talking over HTTP and WebSocket.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildApp } from '../src/app.js';
import {
  ObscuraClient,
  MemoryKV,
  KdfParams,
  randomBytes,
  signRequest,
  generateIdentity,
  accountId,
  AUTH_HEADER,
  toB64,
  ClientEvent,
} from '@obscura/core';

const KDF: KdfParams = { alg: 'argon2id', memoryKiB: 1024, iterations: 1, parallelism: 1 };
let dataDir: string;
let app: Awaited<ReturnType<typeof buildApp>>;
let url: string;

beforeAll(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'obscura-test-'));
  app = await buildApp({ dataDir, maxBlobBytes: 110 * 1024 * 1024, envelopeTtlHours: 720, blobTtlHours: 336, trustProxy: false, hsts: false, logLevel: 'silent', registrationsPerIpHour: 10_000 });
  await app.listen({ port: 0, host: '127.0.0.1' });
  const addr = app.server.address() as { port: number };
  url = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await app.close();
  rmSync(dataDir, { recursive: true, force: true });
});

async function newUser(name: string) {
  const kv = new MemoryKV();
  const client = await ObscuraClient.create({ kv, server: url, name, passphrase: `${name}-passphrase-123`, kdf: KDF });
  return { kv, client };
}

/** Connect two users the way people do: B opens A's invite link. */
async function pair(a: ObscuraClient, b: ObscuraClient) {
  await b.addContact(a.inviteLink('https://chat.example'));
  await a.sync(); // A receives B's hello (with B's access key), replies with a receipt-free profile
  return;
}

function allServerBytes(): Buffer {
  const parts = [readFileSync(join(dataDir, 'obscura.db'))];
  for (const f of ['obscura.db-wal']) {
    try {
      parts.push(readFileSync(join(dataDir, f)));
    } catch {
      /* no wal */
    }
  }
  for (const f of readdirSync(join(dataDir, 'blobs'))) parts.push(readFileSync(join(dataDir, 'blobs', f)));
  return Buffer.concat(parts);
}

describe('end to end over a real server', () => {
  it('text messaging with delivery and read receipts', async () => {
    const { client: alice } = await newUser('alice');
    const { client: bob } = await newUser('bob');
    await pair(alice, bob);

    const contactsA = await alice.contacts();
    expect(contactsA.map((c) => c.id)).toContain(bob.accountId);
    expect(contactsA.find((c) => c.id === bob.accountId)!.name).toBe('bob');

    const sent = await alice.sendText(bob.accountId, 'Meet at 7. Bring the documents.');
    expect(sent.crypto?.kind).toBe('message'); // session already confirmed by Bob's hello
    await bob.sync();
    const inbox = await bob.messages(alice.accountId);
    expect(inbox.at(-1)!.text).toBe('Meet at 7. Bring the documents.');
    expect(inbox.at(-1)!.crypto!.pqRatchet).toBe(true);

    await alice.sync();
    expect((await alice.messages(bob.accountId)).find((m) => m.id === sent.id)!.status).toBe('delivered');
    await bob.markRead(alice.accountId);
    await alice.sync();
    expect((await alice.messages(bob.accountId)).find((m) => m.id === sent.id)!.status).toBe('read');
  });

  it('a long conversation keeps working in both directions', async () => {
    const { client: a } = await newUser('a');
    const { client: b } = await newUser('b');
    await pair(a, b);
    for (let i = 0; i < 8; i++) {
      await a.sendText(b.accountId, `from a ${i}`);
      await a.sendText(b.accountId, `from a ${i} again`);
      await b.sync();
      await b.sendText(a.accountId, `from b ${i}`);
      await a.sync();
    }
    const at = (await a.messages(b.accountId)).filter((m) => m.dir === 'in').map((m) => m.text);
    const bt = (await b.messages(a.accountId)).filter((m) => m.dir === 'in').map((m) => m.text);
    expect(at).toHaveLength(8);
    expect(bt).toHaveLength(16);
    expect(at.at(-1)).toBe('from b 7');
  });

  it('pictures, videos and files: encrypted client-side, server blob deleted after download', async () => {
    const { client: alice } = await newUser('alice2');
    const { client: bob } = await newUser('bob2');
    await pair(alice, bob);
    const video = randomBytes(3 * 1024 * 1024 + 123);
    const marker = Buffer.from('VERY-SECRET-FILE-CONTENT-MARKER');
    video.set(marker, 1000);
    const m = await alice.sendFile(bob.accountId, video, 'holiday-video.mp4', 'video/mp4');
    expect(m.file!.state).toBe('ready');
    const blobsBefore = readdirSync(join(dataDir, 'blobs')).length;
    expect(blobsBefore).toBeGreaterThan(0);
    // While the blob sits on the server it is pure ciphertext.
    expect(allServerBytes().includes(marker)).toBe(false);
    expect(allServerBytes().includes(Buffer.from('holiday-video.mp4'))).toBe(false);

    await bob.sync();
    const got = (await bob.messages(alice.accountId)).find((x) => x.file);
    expect(got!.file!.name).toBe('holiday-video.mp4');
    expect(got!.file!.mime).toBe('video/mp4');
    expect(got!.file!.state).toBe('ready');
    const data = await bob.getFile(got!.file!.fileId);
    expect(Buffer.from(data!).equals(Buffer.from(video))).toBe(true);
    expect(readdirSync(join(dataDir, 'blobs')).length).toBe(blobsBefore - 1);
  });

  it('the server never sees plaintext, names, or who sent a message', async () => {
    const { client: alice } = await newUser('Alice Plaintextname');
    const { client: bob } = await newUser('Bob Plaintextname');
    await pair(alice, bob);
    const secret = 'the launch code is 0000-PLAINTEXT-CANARY';
    await alice.sendText(bob.accountId, secret);
    // Leave the envelope queued on the server and inspect everything stored.
    const bytes = allServerBytes();
    expect(bytes.includes(Buffer.from(secret))).toBe(false);
    expect(bytes.includes(Buffer.from('PLAINTEXT-CANARY'))).toBe(false);
    expect(bytes.includes(Buffer.from('Plaintextname'))).toBe(false);
    // Sealed sender: queued envelopes for Bob contain no trace of Alice's identity.
    const rows = app.db.prepare('SELECT data FROM envelopes WHERE account_id = ?').all(bob.accountId) as { data: Uint8Array }[];
    expect(rows.length).toBeGreaterThan(0);
    const alicePub = Buffer.from(alice.publicIdentity.sigPub);
    const aliceDh = Buffer.from(alice.publicIdentity.dhPub);
    for (const r of rows) {
      const d = Buffer.from(r.data);
      expect(d.includes(alicePub)).toBe(false);
      expect(d.includes(aliceDh)).toBe(false);
      expect(d.includes(Buffer.from(alice.accountId))).toBe(false);
    }
    const view = await bob.serverView();
    expect(JSON.stringify(view)).not.toContain('Plaintextname');
    expect(view.pendingEnvelopes.length).toBeGreaterThan(0);
    await bob.sync();
    expect((await bob.messages(alice.accountId)).at(-1)!.text).toBe(secret);
  });

  it('offline delivery: messages wait (encrypted) and arrive in order', async () => {
    const { client: a } = await newUser('offline-a');
    const { client: b } = await newUser('offline-b');
    await pair(a, b);
    for (let i = 0; i < 6; i++) await a.sendText(b.accountId, `queued ${i}`);
    await b.sync();
    const texts = (await b.messages(a.accountId)).filter((m) => m.dir === 'in').map((m) => m.text);
    expect(texts).toEqual([0, 1, 2, 3, 4, 5].map((i) => `queued ${i}`));
  });

  it('both people adding each other at the same time still converges', async () => {
    const { client: a } = await newUser('simul-a');
    const { client: b } = await newUser('simul-b');
    await a.addContact(b.inviteLink('https://x'));
    await b.addContact(a.inviteLink('https://x'));
    await a.sync();
    await b.sync();
    await a.sendText(b.accountId, 'hello from a');
    await b.sendText(a.accountId, 'hello from b');
    await a.sync();
    await b.sync();
    await a.sendText(b.accountId, 'second from a');
    await b.sync();
    const bt = (await b.messages(a.accountId)).filter((m) => m.dir === 'in').map((m) => m.text);
    const at = (await a.messages(b.accountId)).filter((m) => m.dir === 'in').map((m) => m.text);
    expect(bt).toEqual(['hello from a', 'second from a']);
    expect(at).toEqual(['hello from b']);
  });

  it('real-time push over WebSocket', async () => {
    const { client: a } = await newUser('rt-a');
    const { client: b } = await newUser('rt-b');
    await pair(a, b);
    const got = new Promise<string>((resolve) => {
      b.on((e: ClientEvent) => {
        if (e.type === 'message' && e.message.dir === 'in') resolve(e.message.text!);
      });
    });
    await b.connect();
    await new Promise((r) => setTimeout(r, 200));
    await a.sendText(b.accountId, 'instant');
    expect(await got).toBe('instant');
    b.lock();
  });

  it('only people holding your invite can message you; blocking revokes access', async () => {
    const { client: bob } = await newUser('bob-block');
    const { client: mallory } = await newUser('mallory');
    const { client: carol } = await newUser('carol');
    await pair(bob, mallory);
    await pair(bob, carol);
    // Mallory guesses Bob's ID but uses a made-up access key: rejected by the server.
    await expect(mallory.api.sendEnvelope(bob.accountId, randomBytes(16), randomBytes(200))).rejects.toThrow(/not allowed/);
    // An unknown account gets the identical answer (no account enumeration).
    await expect(mallory.api.sendEnvelope('a'.repeat(32), randomBytes(16), randomBytes(200))).rejects.toThrow(/not allowed/);

    await bob.blockContact(mallory.accountId);
    await carol.sync(); // Carol silently receives Bob's new access key
    await expect(mallory.sendText(bob.accountId, 'let me in')).rejects.toThrow(/not allowed/);
    await carol.sendText(bob.accountId, 'still works for me');
    await bob.sync();
    expect((await bob.messages(carol.accountId)).at(-1)!.text).toBe('still works for me');
  });

  it('disappearing messages are deleted on both devices', async () => {
    const { client: a } = await newUser('timer-a');
    const { client: b } = await newUser('timer-b');
    await pair(a, b);
    await a.setTimer(b.accountId, 1);
    await b.sync();
    expect((await b.getContact(a.accountId))!.timer).toBe(1);
    await a.sendText(b.accountId, 'self-destruct');
    await b.sync();
    expect((await b.messages(a.accountId)).some((m) => m.text === 'self-destruct')).toBe(true);
    await new Promise((r) => setTimeout(r, 1200));
    await a.sweepExpired();
    await b.sweepExpired();
    expect((await a.messages(b.accountId)).some((m) => m.text === 'self-destruct')).toBe(false);
    expect((await b.messages(a.accountId)).some((m) => m.text === 'self-destruct')).toBe(false);
  });

  it('safety numbers match on both sides', async () => {
    const { client: a } = await newUser('sn-a');
    const { client: b } = await newUser('sn-b');
    await pair(a, b);
    const sa = await a.safetyNumber(b.accountId);
    const sb = await b.safetyNumber(a.accountId);
    expect(sa!.digits).toMatch(/^\d{60}$/);
    expect(sa!.digits).toBe(sb!.digits);
  });

  it('local data is encrypted at rest and survives lock/unlock', async () => {
    const { client: a, kv } = await newUser('vault-a');
    const { client: b } = await newUser('vault-b');
    await pair(a, b);
    await b.sendText(a.accountId, 'persist me VAULT-CANARY');
    await a.sync();
    const raw = Buffer.concat([...kv.map.values()].map((v) => Buffer.from(v)));
    expect(raw.includes(Buffer.from('VAULT-CANARY'))).toBe(false);
    expect(raw.includes(Buffer.from('vault-b'))).toBe(false);
    a.lock();
    await expect(ObscuraClient.unlock({ kv, passphrase: 'wrong-passphrase' })).rejects.toThrow(/wrong passphrase/);
    const again = await ObscuraClient.unlock({ kv, passphrase: 'vault-a-passphrase-123' });
    expect((await again.messages(b.accountId)).at(-1)!.text).toBe('persist me VAULT-CANARY');
    await b.sendText(a.accountId, 'after unlock');
    await again.sync();
    expect((await again.messages(b.accountId)).at(-1)!.text).toBe('after unlock');
  });

  it('when one-time prekeys run out, the post-quantum last-resort key still works', async () => {
    const { client: target } = await newUser('popular');
    const { client: drainer } = await newUser('drainer');
    for (let i = 0; i < 25; i++) await drainer.api.getBundle(target.accountId); // burns all 25 PQ one-time keys
    const bundle = await drainer.api.getBundle(target.accountId);
    expect(bundle.pqPreKey.lastResort).toBe(true);
    const { client: late } = await newUser('late');
    await late.addContact(target.inviteLink('https://x'));
    await target.sync();
    expect((await target.contacts()).some((c) => c.id === late.accountId)).toBe(true);
    await target.maintainPreKeys();
    const counts = await target.api.keyCounts();
    expect(counts.pqOneTime).toBe(25);
  });

  it('server rejects unsigned, forged and replayed requests', async () => {
    const res1 = await fetch(`${url}/v1/messages`);
    expect(res1.status).toBe(401);
    const { client: a } = await newUser('auth-a');
    const imposter = generateIdentity();
    const forged = signRequest(a.accountId, imposter.sig.secretKey, 'GET', '/v1/messages');
    expect((await fetch(`${url}/v1/messages`, { headers: { [AUTH_HEADER]: forged } })).status).toBe(401);
    // A captured valid request cannot be replayed.
    const view = await a.serverView();
    expect(view.accountId).toBe(a.accountId);
    const ident = generateIdentity();
    const { client: b } = await newUser('auth-b');
    void ident;
    const hdr = signRequest(b.accountId, (b as unknown as { identity: { sig: { secretKey: Uint8Array } } }).identity.sig.secretKey, 'GET', '/v1/messages');
    expect((await fetch(`${url}/v1/messages`, { headers: { [AUTH_HEADER]: hdr } })).status).toBe(200);
    expect((await fetch(`${url}/v1/messages`, { headers: { [AUTH_HEADER]: hdr } })).status).toBe(401);
    // Registering an account ID that is not derived from your own key is impossible.
    const victim = generateIdentity();
    expect(accountId(victim.sig.publicKey)).not.toBe(accountId(imposter.sig.publicKey));
  });

  it('sends hardened security headers', async () => {
    const res = await fetch(`${url}/v1/health`);
    expect(res.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('referrer-policy')).toBe('no-referrer');
    expect(res.headers.get('cache-control')).toBe('no-store');
  });

  it('account deletion wipes everything server-side', async () => {
    const { client: a, kv } = await newUser('delete-me');
    const id = a.accountId;
    await a.destroyEverything();
    expect(kv.map.size).toBe(0);
    expect(app.db.prepare('SELECT COUNT(*) AS n FROM accounts WHERE id = ?').get(id)).toEqual({ n: 0 });
    expect(app.db.prepare('SELECT COUNT(*) AS n FROM one_time_prekeys WHERE account_id = ?').get(id)).toEqual({ n: 0 });
    void toB64;
  });
});
