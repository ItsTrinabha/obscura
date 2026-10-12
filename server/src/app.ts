/**
 * Obscura relay server.
 *
 * The server is deliberately dumb and deliberately blind: it stores public
 * prekeys, queues sealed envelopes it cannot open (and whose sender it cannot
 * see), and stores encrypted blobs it cannot decrypt. Compromising it yields
 * ciphertext and the minimum routing metadata, nothing else.
 */
import Fastify, { FastifyInstance, FastifyReply, FastifyRequest, LogController } from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyWebsocket from '@fastify/websocket';
import type { WebSocket } from 'ws';
import { createReadStream, existsSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  accountId as deriveAccountId,
  AUTH_HEADER,
  fromB64,
  parseAuthHeader,
  toB64,
  verify,
  verifyIdentity,
  verifyPqPreKey,
  verifyRequest,
  verifySignedPreKey,
  wsChallengeMessage,
  KEM_PUB_LEN,
  X25519_LEN,
} from '@obscura/core';
import { DB, dayNow, hourNow, openDb } from './db.js';

export interface ServerConfig {
  dataDir: string;
  webDir?: string;
  maxBlobBytes: number;
  envelopeTtlHours: number;
  blobTtlHours: number;
  trustProxy: boolean;
  hsts: boolean;
  logLevel?: string;
  registrationsPerIpHour?: number;
}

export const defaultConfig = (): ServerConfig => ({
  dataDir: process.env.DATA_DIR ?? './data',
  webDir: process.env.WEB_DIR ?? resolve(process.cwd(), 'web/dist'),
  maxBlobBytes: Number(process.env.MAX_BLOB_MB ?? 105) * 1024 * 1024,
  envelopeTtlHours: Number(process.env.ENVELOPE_TTL_DAYS ?? 30) * 24,
  blobTtlHours: Number(process.env.BLOB_TTL_DAYS ?? 14) * 24,
  trustProxy: process.env.TRUST_PROXY === '1',
  hsts: process.env.HSTS === '1',
  logLevel: process.env.LOG_LEVEL ?? 'info',
  registrationsPerIpHour: Number(process.env.REGISTRATIONS_PER_IP_HOUR ?? 20),
});

const ID_RE = /^[a-z2-7]{32}$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{22}$/;
const MAX_ENVELOPE = 256 * 1024;
const MAX_MAILBOX = 5000;
const MAX_OPK = 500;
const MAX_PQ_OPK = 100;

class HttpError extends Error {
  constructor(public status: number, msg: string) {
    super(msg);
  }
}

/** Fixed-window in-memory rate limiter (per IP or per account). */
class RateLimiter {
  private hits = new Map<string, { n: number; reset: number }>();
  check(key: string, limit: number, windowMs: number) {
    const now = Date.now();
    const h = this.hits.get(key);
    if (!h || h.reset < now) {
      this.hits.set(key, { n: 1, reset: now + windowMs });
      if (this.hits.size > 100_000) this.sweep(now);
      return;
    }
    if (++h.n > limit) throw new HttpError(429, 'rate limit exceeded');
  }
  sweep(now = Date.now()) {
    for (const [k, v] of this.hits) if (v.reset < now) this.hits.delete(k);
  }
}

const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest();
const randomId = () => randomBytes(16).toString('base64url');

function b64(field: unknown, len?: number, name = 'field'): Uint8Array {
  if (typeof field !== 'string') throw new HttpError(400, `${name} missing`);
  let v: Uint8Array;
  try {
    v = fromB64(field);
  } catch {
    throw new HttpError(400, `${name} is not base64url`);
  }
  if (len !== undefined && v.length !== len) throw new HttpError(400, `${name} has wrong length`);
  return v;
}

function u32(field: unknown, name = 'id'): number {
  if (!Number.isInteger(field) || (field as number) < 0 || (field as number) > 0xfffffffe) throw new HttpError(400, `${name} invalid`);
  return field as number;
}

declare module 'fastify' {
  interface FastifyRequest {
    rawBody?: Buffer;
  }
}

export async function buildApp(config: ServerConfig, existingDb?: DB): Promise<FastifyInstance & { db: DB }> {
  const db = existingDb ?? openDb(config.dataDir);
  const blobDir = join(config.dataDir, 'blobs');
  const app = Fastify({
    logger: config.logLevel === 'silent' ? false : { level: config.logLevel ?? 'info' },
    logController: new LogController({ disableRequestLogging: true }), // no per-request logs: no IPs, paths or timings
    trustProxy: config.trustProxy,
    bodyLimit: 2 * 1024 * 1024,
  }) as unknown as FastifyInstance & { db: DB };
  app.decorate('db', db);

  const limiter = new RateLimiter();
  const seenNonces = new Map<string, number>();
  const sockets = new Map<string, Set<WebSocket>>();
  const uploadQuota = new Map<string, { bytes: number; reset: number }>();

  // ---------------------------------------------------------------- body parsing
  app.removeAllContentTypeParsers();
  app.addContentTypeParser(['application/json', 'application/octet-stream'], { parseAs: 'buffer' }, (req, body, done) => {
    const buf = body as Buffer;
    req.rawBody = buf;
    if ((req.headers['content-type'] ?? '').startsWith('application/json')) {
      try {
        done(null, buf.length ? JSON.parse(buf.toString('utf8')) : {});
      } catch {
        done(new HttpError(400, 'invalid JSON'), undefined);
      }
    } else done(null, buf);
  });

  // ---------------------------------------------------------------- security headers
  app.addHook('onSend', async (req, reply, payload) => {
    reply.header(
      'content-security-policy',
      [
        "default-src 'none'",
        "script-src 'self' 'wasm-unsafe-eval'",
        "style-src 'self'",
        "img-src 'self' blob: data:",
        "media-src 'self' blob:",
        "connect-src 'self'",
        "font-src 'self'",
        "manifest-src 'self'",
        "worker-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
      ].join('; '),
    );
    reply.header('x-content-type-options', 'nosniff');
    reply.header('referrer-policy', 'no-referrer');
    reply.header('x-frame-options', 'DENY');
    reply.header('cross-origin-opener-policy', 'same-origin');
    reply.header('cross-origin-resource-policy', 'same-origin');
    reply.header('permissions-policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()');
    if (config.hsts) reply.header('strict-transport-security', 'max-age=63072000; includeSubDomains');
    if (req.url.startsWith('/v1/')) reply.header('cache-control', 'no-store');
    return payload;
  });

  app.setErrorHandler((err: Error & { statusCode?: number; status?: number }, _req, reply) => {
    const status = err instanceof HttpError ? err.status : err.statusCode ?? 500;
    if (status >= 500) app.log.error(err);
    reply.code(status).send({ error: status >= 500 ? 'internal error' : err.message });
  });

  // ---------------------------------------------------------------- auth
  const getAccount = db.prepare('SELECT id, sig_pub, dh_pub, dh_sig, access_hash, created_day FROM accounts WHERE id = ?');

  function checkNonce(nonce: string, ts: number) {
    const now = Date.now();
    if (seenNonces.has(nonce)) throw new HttpError(401, 'replayed request');
    seenNonces.set(nonce, ts + 5 * 60_000);
    if (seenNonces.size > 200_000) for (const [k, exp] of seenNonces) if (exp < now) seenNonces.delete(k);
  }

  function authenticate(req: FastifyRequest, sigPubOverride?: Uint8Array): string {
    const p = parseAuthHeader(req.headers[AUTH_HEADER] as string | undefined);
    if (!p) throw new HttpError(401, 'missing or malformed signature');
    let sigPub = sigPubOverride;
    if (!sigPub) {
      const row = getAccount.get(p.accountId) as { sig_pub: Uint8Array } | undefined;
      if (!row) throw new HttpError(401, 'unknown account');
      sigPub = new Uint8Array(row.sig_pub);
    }
    const path = req.url.split('?')[0];
    if (!verifyRequest(p, sigPub, req.method, path, req.rawBody ?? new Uint8Array(0))) throw new HttpError(401, 'bad signature');
    checkNonce(p.nonce, p.ts);
    limiter.check(`acct:${p.accountId}`, 600, 60_000);
    return p.accountId;
  }

  // ---------------------------------------------------------------- prekeys
  const upsertSpk = db.prepare('INSERT OR REPLACE INTO signed_prekeys (account_id, key_id, pub, sig) VALUES (?, ?, ?, ?)');
  const upsertPqLr = db.prepare('INSERT OR REPLACE INTO pq_last_resort (account_id, key_id, pub, sig) VALUES (?, ?, ?, ?)');
  const insertOpk = db.prepare('INSERT OR IGNORE INTO one_time_prekeys (account_id, key_id, pub) VALUES (?, ?, ?)');
  const insertPqOpk = db.prepare('INSERT OR IGNORE INTO pq_one_time_prekeys (account_id, key_id, pub, sig) VALUES (?, ?, ?, ?)');
  const countOpk = db.prepare('SELECT COUNT(*) AS n FROM one_time_prekeys WHERE account_id = ?');
  const countPqOpk = db.prepare('SELECT COUNT(*) AS n FROM pq_one_time_prekeys WHERE account_id = ?');

  interface PreKeyBody {
    signedPreKey?: { id: number; publicKey: string; signature: string };
    pqLastResort?: { id: number; publicKey: string; signature: string; lastResort: boolean };
    oneTimePreKeys?: { id: number; publicKey: string }[];
    pqOneTimePreKeys?: { id: number; publicKey: string; signature: string }[];
  }

  function storePreKeys(id: string, sigPub: Uint8Array, body: PreKeyBody) {
    if (body.signedPreKey) {
      const k = { id: u32(body.signedPreKey.id), publicKey: b64(body.signedPreKey.publicKey, X25519_LEN, 'signedPreKey'), signature: b64(body.signedPreKey.signature, 64) };
      if (!verifySignedPreKey(sigPub, k)) throw new HttpError(400, 'signed prekey signature invalid');
      upsertSpk.run(id, k.id, k.publicKey, k.signature);
    }
    if (body.pqLastResort) {
      const k = { id: u32(body.pqLastResort.id), publicKey: b64(body.pqLastResort.publicKey, KEM_PUB_LEN, 'pqLastResort'), signature: b64(body.pqLastResort.signature, 64), lastResort: true };
      if (!verifyPqPreKey(sigPub, k)) throw new HttpError(400, 'post-quantum last-resort prekey signature invalid');
      upsertPqLr.run(id, k.id, k.publicKey, k.signature);
    }
    const opks = body.oneTimePreKeys ?? [];
    const pqs = body.pqOneTimePreKeys ?? [];
    if (!Array.isArray(opks) || !Array.isArray(pqs)) throw new HttpError(400, 'prekey lists must be arrays');
    if ((countOpk.get(id) as { n: number }).n + opks.length > MAX_OPK) throw new HttpError(400, 'too many one-time prekeys');
    if ((countPqOpk.get(id) as { n: number }).n + pqs.length > MAX_PQ_OPK) throw new HttpError(400, 'too many post-quantum one-time prekeys');
    for (const k of opks) insertOpk.run(id, u32(k.id), b64(k.publicKey, X25519_LEN, 'oneTimePreKey'));
    for (const k of pqs) {
      const v = { id: u32(k.id), publicKey: b64(k.publicKey, KEM_PUB_LEN, 'pqOneTimePreKey'), signature: b64(k.signature, 64), lastResort: false };
      if (!verifyPqPreKey(sigPub, v)) throw new HttpError(400, 'post-quantum prekey signature invalid');
      insertPqOpk.run(id, v.id, v.publicKey, v.signature);
    }
  }

  // ---------------------------------------------------------------- routes: accounts
  app.get('/v1/health', async () => ({ ok: true, service: 'obscura', protocol: 'PQXDH(X25519+ML-KEM-768) + hybrid double ratchet' }));

  app.post('/v1/accounts', async (req, reply) => {
    limiter.check(`ip-register:${req.ip}`, config.registrationsPerIpHour ?? 20, 3600_000);
    const body = req.body as PreKeyBody & { identity?: { sigPub: string; dhPub: string; dhSig: string }; accessKeyHash?: string };
    if (!body?.identity) throw new HttpError(400, 'identity missing');
    const identity = {
      sigPub: b64(body.identity.sigPub, 32, 'sigPub'),
      dhPub: b64(body.identity.dhPub, 32, 'dhPub'),
      dhSig: b64(body.identity.dhSig, 64, 'dhSig'),
    };
    if (!verifyIdentity(identity)) throw new HttpError(400, 'identity signature invalid');
    const id = deriveAccountId(identity.sigPub);
    // Proof of possession: the registration itself must be signed by the identity key.
    const authed = authenticate(req, identity.sigPub);
    if (authed !== id) throw new HttpError(400, 'account id does not match identity key');
    const accessHash = b64(body.accessKeyHash, 32, 'accessKeyHash');
    if (!body.signedPreKey || !body.pqLastResort) throw new HttpError(400, 'signed prekey and post-quantum last-resort prekey are required');
    if (getAccount.get(id)) throw new HttpError(409, 'account exists');
    db.exec('BEGIN');
    try {
      db.prepare('INSERT INTO accounts (id, sig_pub, dh_pub, dh_sig, access_hash, created_day) VALUES (?, ?, ?, ?, ?, ?)').run(
        id,
        identity.sigPub,
        identity.dhPub,
        identity.dhSig,
        accessHash,
        dayNow(),
      );
      storePreKeys(id, identity.sigPub, body);
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
    reply.code(201);
    return { accountId: id };
  });

  app.get('/v1/accounts/me', async (req) => {
    const id = authenticate(req);
    const a = getAccount.get(id) as { id: string; sig_pub: Uint8Array; dh_pub: Uint8Array; dh_sig: Uint8Array; access_hash: Uint8Array; created_day: string };
    const spk = db.prepare('SELECT key_id FROM signed_prekeys WHERE account_id = ?').get(id) as { key_id: number } | undefined;
    const lr = db.prepare('SELECT key_id FROM pq_last_resort WHERE account_id = ?').get(id) as { key_id: number } | undefined;
    const env = db.prepare('SELECT id, length(data) AS bytes, received_hour FROM envelopes WHERE account_id = ? ORDER BY rowid').all(id) as {
      id: string;
      bytes: number;
      received_hour: number;
    }[];
    return {
      accountId: a.id,
      identity: { sigPub: toB64(new Uint8Array(a.sig_pub)), dhPub: toB64(new Uint8Array(a.dh_pub)), dhSig: toB64(new Uint8Array(a.dh_sig)) },
      accessKeyHash: toB64(new Uint8Array(a.access_hash)),
      createdDay: a.created_day,
      keys: {
        oneTime: (countOpk.get(id) as { n: number }).n,
        pqOneTime: (countPqOpk.get(id) as { n: number }).n,
        signedPreKeyId: spk?.key_id ?? null,
        pqLastResortId: lr?.key_id ?? null,
      },
      pendingEnvelopes: env.map((e) => ({ id: e.id, bytes: e.bytes, receivedHour: new Date(e.received_hour * 3600_000).toISOString() })),
      note: 'This is everything the server stores about you. No name, no phone number, no email, no contacts, no message contents, no sender identities, no IP addresses.',
    };
  });

  app.put('/v1/accounts/me/access-key', async (req) => {
    const id = authenticate(req);
    const h = b64((req.body as { accessKeyHash?: string })?.accessKeyHash, 32, 'accessKeyHash');
    db.prepare('UPDATE accounts SET access_hash = ? WHERE id = ?').run(h, id);
    return { ok: true };
  });

  app.delete('/v1/accounts/me', async (req) => {
    const id = authenticate(req);
    db.prepare('DELETE FROM accounts WHERE id = ?').run(id); // cascades to keys and queued envelopes
    for (const ws of sockets.get(id) ?? []) ws.close(4001, 'account deleted');
    sockets.delete(id);
    return { ok: true };
  });

  // ---------------------------------------------------------------- routes: keys
  app.put('/v1/keys', async (req) => {
    const id = authenticate(req);
    const a = getAccount.get(id) as { sig_pub: Uint8Array };
    db.exec('BEGIN');
    try {
      storePreKeys(id, new Uint8Array(a.sig_pub), (req.body ?? {}) as PreKeyBody);
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
    return { ok: true };
  });

  app.get('/v1/keys/me/count', async (req) => {
    const id = authenticate(req);
    const spk = db.prepare('SELECT key_id FROM signed_prekeys WHERE account_id = ?').get(id) as { key_id: number } | undefined;
    const lr = db.prepare('SELECT key_id FROM pq_last_resort WHERE account_id = ?').get(id) as { key_id: number } | undefined;
    return {
      oneTime: (countOpk.get(id) as { n: number }).n,
      pqOneTime: (countPqOpk.get(id) as { n: number }).n,
      signedPreKeyId: spk?.key_id ?? null,
      pqLastResortId: lr?.key_id ?? null,
    };
  });

  app.get('/v1/keys/:id', async (req) => {
    const requester = authenticate(req);
    limiter.check(`bundle:${requester}`, 60, 60_000);
    const target = (req.params as { id: string }).id;
    if (!ID_RE.test(target)) throw new HttpError(400, 'bad account id');
    const a = getAccount.get(target) as { sig_pub: Uint8Array; dh_pub: Uint8Array; dh_sig: Uint8Array } | undefined;
    if (!a) throw new HttpError(404, 'no such account');
    db.exec('BEGIN');
    try {
      const spk = db.prepare('SELECT key_id, pub, sig FROM signed_prekeys WHERE account_id = ?').get(target) as { key_id: number; pub: Uint8Array; sig: Uint8Array };
      // One-time keys are handed out exactly once, then deleted.
      const opk = db.prepare('SELECT key_id, pub FROM one_time_prekeys WHERE account_id = ? ORDER BY key_id LIMIT 1').get(target) as
        | { key_id: number; pub: Uint8Array }
        | undefined;
      if (opk) db.prepare('DELETE FROM one_time_prekeys WHERE account_id = ? AND key_id = ?').run(target, opk.key_id);
      let pq = db.prepare('SELECT key_id, pub, sig FROM pq_one_time_prekeys WHERE account_id = ? ORDER BY key_id LIMIT 1').get(target) as
        | { key_id: number; pub: Uint8Array; sig: Uint8Array }
        | undefined;
      let lastResort = false;
      if (pq) db.prepare('DELETE FROM pq_one_time_prekeys WHERE account_id = ? AND key_id = ?').run(target, pq.key_id);
      else {
        pq = db.prepare('SELECT key_id, pub, sig FROM pq_last_resort WHERE account_id = ?').get(target) as { key_id: number; pub: Uint8Array; sig: Uint8Array };
        lastResort = true;
      }
      db.exec('COMMIT');
      const t = (b: Uint8Array) => toB64(new Uint8Array(b));
      return {
        identity: { sigPub: t(a.sig_pub), dhPub: t(a.dh_pub), dhSig: t(a.dh_sig) },
        signedPreKey: { id: spk.key_id, publicKey: t(spk.pub), signature: t(spk.sig) },
        pqPreKey: { id: pq.key_id, publicKey: t(pq.pub), signature: t(pq.sig), lastResort },
        oneTimePreKey: opk ? { id: opk.key_id, publicKey: t(opk.pub) } : null,
      };
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  });

  // ---------------------------------------------------------------- routes: messages (sealed sender)
  const insertEnvelope = db.prepare('INSERT INTO envelopes (id, account_id, data, received_hour) VALUES (?, ?, ?, ?)');
  const countEnvelopes = db.prepare('SELECT COUNT(*) AS n FROM envelopes WHERE account_id = ?');

  app.put('/v1/messages/:id', { bodyLimit: MAX_ENVELOPE }, async (req, reply) => {
    limiter.check(`ip-send:${req.ip}`, 240, 60_000);
    const target = (req.params as { id: string }).id;
    const access = req.headers['x-obscura-access'];
    // Same answer for "no such account" and "wrong key": the endpoint cannot be used to enumerate accounts.
    const deny = new HttpError(401, 'not allowed');
    if (!ID_RE.test(target) || typeof access !== 'string' || !TOKEN_RE.test(access)) throw deny;
    const a = getAccount.get(target) as { access_hash: Uint8Array } | undefined;
    const provided = sha256(Buffer.from(access, 'base64url'));
    const expected = a ? Buffer.from(a.access_hash) : randomBytes(32);
    if (!timingSafeEqual(provided, expected) || !a) throw deny;
    const data = req.body as Buffer;
    if (!Buffer.isBuffer(data) || data.length < 64) throw new HttpError(400, 'envelope required');
    if ((countEnvelopes.get(target) as { n: number }).n >= MAX_MAILBOX) throw new HttpError(507, 'recipient mailbox full');
    const envId = randomId();
    insertEnvelope.run(envId, target, data, hourNow());
    const payload = JSON.stringify({ type: 'envelope', id: envId, data: data.toString('base64url') });
    for (const ws of sockets.get(target) ?? []) ws.send(payload);
    reply.code(202);
    return { ok: true };
  });

  app.get('/v1/messages', async (req) => {
    const id = authenticate(req);
    const rows = db.prepare('SELECT id, data FROM envelopes WHERE account_id = ? ORDER BY rowid LIMIT 500').all(id) as { id: string; data: Uint8Array }[];
    return rows.map((r) => ({ id: r.id, data: Buffer.from(r.data).toString('base64url') }));
  });

  app.delete('/v1/messages', async (req) => {
    const id = authenticate(req);
    const ids = (req.body as { ids?: unknown })?.ids;
    if (!Array.isArray(ids) || ids.length > 1000) throw new HttpError(400, 'ids required');
    const del = db.prepare('DELETE FROM envelopes WHERE id = ? AND account_id = ?');
    for (const e of ids) if (typeof e === 'string') del.run(e, id);
    return { ok: true };
  });

  // ---------------------------------------------------------------- routes: encrypted blobs
  app.post('/v1/blobs', { bodyLimit: config.maxBlobBytes }, async (req, reply) => {
    const id = authenticate(req);
    const data = req.body as Buffer;
    if (!Buffer.isBuffer(data) || data.length < 25) throw new HttpError(400, 'blob required');
    const now = Date.now();
    const q = uploadQuota.get(id);
    if (!q || q.reset < now) uploadQuota.set(id, { bytes: data.length, reset: now + 3600_000 });
    else if ((q.bytes += data.length) > 2 * 1024 * 1024 * 1024) throw new HttpError(429, 'upload quota exceeded');
    const blobId = randomId();
    const deleteToken = randomId();
    writeFileSync(join(blobDir, blobId), data, { mode: 0o600 });
    db.prepare('INSERT INTO blobs (id, delete_hash, size, created_hour) VALUES (?, ?, ?, ?)').run(blobId, sha256(Buffer.from(deleteToken)), data.length, hourNow());
    reply.code(201);
    return { id: blobId, deleteToken };
  });

  app.get('/v1/blobs/:id', async (req, reply) => {
    limiter.check(`ip-blob:${req.ip}`, 600, 60_000);
    const id = (req.params as { id: string }).id;
    if (!TOKEN_RE.test(id) || !db.prepare('SELECT 1 FROM blobs WHERE id = ?').get(id)) throw new HttpError(404, 'not found');
    const file = join(blobDir, id);
    if (!existsSync(file)) throw new HttpError(404, 'not found');
    reply.header('content-type', 'application/octet-stream');
    reply.header('content-length', statSync(file).size);
    return reply.send(createReadStream(file));
  });

  app.delete('/v1/blobs/:id', async (req) => {
    const id = (req.params as { id: string }).id;
    const token = req.headers['x-obscura-delete-token'];
    if (!TOKEN_RE.test(id) || typeof token !== 'string') throw new HttpError(400, 'bad request');
    const row = db.prepare('SELECT delete_hash FROM blobs WHERE id = ?').get(id) as { delete_hash: Uint8Array } | undefined;
    if (!row || !timingSafeEqual(Buffer.from(row.delete_hash), sha256(Buffer.from(token)))) throw new HttpError(404, 'not found');
    db.prepare('DELETE FROM blobs WHERE id = ?').run(id);
    rmSync(join(blobDir, id), { force: true });
    return { ok: true };
  });

  // ---------------------------------------------------------------- websocket push
  await app.register(fastifyWebsocket, { options: { maxPayload: 64 * 1024 } });
  app.get('/v1/ws', { websocket: true }, (socket: WebSocket, req: FastifyRequest) => {
    try {
      limiter.check(`ip-ws:${req.ip}`, 60, 60_000);
    } catch {
      socket.close(4029, 'rate limited');
      return;
    }
    const challenge = randomBytes(32);
    let account: string | null = null;
    const timeout = setTimeout(() => account || socket.close(4000, 'auth timeout'), 10_000);
    socket.send(JSON.stringify({ type: 'challenge', challenge: challenge.toString('base64url') }));
    socket.on('message', (raw: Buffer) => {
      let msg: { type?: string; accountId?: string; signature?: string };
      try {
        msg = JSON.parse(raw.toString('utf8'));
      } catch {
        return socket.close(4002, 'bad message');
      }
      if (msg.type === 'auth' && !account) {
        const row = typeof msg.accountId === 'string' && ID_RE.test(msg.accountId) ? (getAccount.get(msg.accountId) as { sig_pub: Uint8Array } | undefined) : undefined;
        let ok = false;
        try {
          ok = !!row && verify(new Uint8Array(row.sig_pub), wsChallengeMessage(challenge), fromB64(msg.signature ?? ''));
        } catch {
          ok = false;
        }
        if (!ok) return socket.close(4001, 'auth failed');
        account = msg.accountId!;
        clearTimeout(timeout);
        if (!sockets.has(account)) sockets.set(account, new Set());
        sockets.get(account)!.add(socket);
        socket.send(JSON.stringify({ type: 'ready' }));
        const rows = db.prepare('SELECT id, data FROM envelopes WHERE account_id = ? ORDER BY rowid LIMIT 500').all(account) as { id: string; data: Uint8Array }[];
        for (const r of rows) socket.send(JSON.stringify({ type: 'envelope', id: r.id, data: Buffer.from(r.data).toString('base64url') }));
      }
    });
    socket.on('close', () => {
      clearTimeout(timeout);
      if (account) {
        sockets.get(account)?.delete(socket);
        if (!sockets.get(account)?.size) sockets.delete(account);
      }
    });
  });

  // ---------------------------------------------------------------- web client
  if (config.webDir && existsSync(join(config.webDir, 'index.html'))) {
    await app.register(fastifyStatic, { root: resolve(config.webDir), prefix: '/', index: ['index.html'] });
  }
  app.setNotFoundHandler((req, reply) => {
    if (req.method === 'GET' && !req.url.startsWith('/v1/') && config.webDir && existsSync(join(config.webDir, 'index.html'))) {
      return reply.sendFile('index.html');
    }
    reply.code(404).send({ error: 'not found' });
  });

  // ---------------------------------------------------------------- retention
  const cleanup = () => {
    const now = hourNow();
    db.prepare('DELETE FROM envelopes WHERE received_hour < ?').run(now - config.envelopeTtlHours);
    const old = db.prepare('SELECT id FROM blobs WHERE created_hour < ?').all(now - config.blobTtlHours) as { id: string }[];
    for (const b of old) {
      rmSync(join(blobDir, b.id), { force: true });
      db.prepare('DELETE FROM blobs WHERE id = ?').run(b.id);
    }
    limiter.sweep();
  };
  cleanup();
  const timer = setInterval(cleanup, 3600_000);
  timer.unref();
  app.addHook('onClose', async () => {
    clearInterval(timer);
    if (!existingDb) db.close();
  });

  return app;
}

export type { FastifyReply };
