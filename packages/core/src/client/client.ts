/**
 * ObscuraClient: the complete messaging engine (accounts, contacts, sessions,
 * text, media, receipts, disappearing messages). It runs unchanged in the
 * browser (IndexedDB backend) and in Node (tests, bots), so the code that is
 * tested end to end is exactly the code users run.
 */
import { concat, equalBytes, fromB64, fromUtf8, Reader, toB64, utf8, wipe, Writer } from '../bytes.js';
import { decryptAttachment, encryptAttachment } from '../attachment.js';
import {
  accountId as deriveAccountId,
  bundleFromJSON,
  generateIdentity,
  generateOneTimePreKeys,
  generatePqPreKey,
  generateSignedPreKey,
  identityFromJSON,
  identityToJSON,
  IdentityKeyPair,
  PublicIdentity,
  PublicIdentityJSON,
  publicIdentity,
} from '../keys.js';
import { padMessage, unpadMessage } from '../padding.js';
import { decodePreKeyHeader, encodePreKeyHeader, pqxdhInitiate, pqxdhRespond } from '../pqxdh.js';
import { KeyPair, randomBytes, sha256 } from '../primitives.js';
import {
  deserializeState,
  MessageInfo,
  ratchetDecrypt,
  ratchetEncrypt,
  RatchetStateJSON,
  serializeState,
} from '../ratchet.js';
import { formatSafetyNumber, safetyNumber } from '../safety.js';
import { openEnvelope, sealEnvelope } from '../sealed.js';
import { createVault, KdfParams, KV, SecureStore, unlockVault, VaultHeader } from '../vault.js';
import { HttpApi, PreKeyUpload, QueuedEnvelope, ServerView } from './api.js';

// ---------------------------------------------------------------- types

export interface Contact {
  id: string;
  name: string;
  identity: PublicIdentityJSON | null;
  accessKey: string | null;
  verified: boolean;
  blocked: boolean;
  timer: number; // disappearing-message timer in seconds, 0 = off
  unread: number;
  addedAt: number;
  lastActivity: number;
}

export interface FileInfo {
  fileId: string;
  name: string;
  mime: string;
  size: number;
  state: 'ready' | 'downloading' | 'error';
}

export interface CryptoDetails {
  kind: 'prekey' | 'message';
  ratchetStep: number;
  counter: number;
  pqRatchet: boolean;
  envelopeBytes: number;
  envelopeHead: string; // base64 of the first bytes on the wire, for the inspector
}

export interface Message {
  id: string;
  dir: 'in' | 'out' | 'system';
  ts: number;
  text?: string;
  file?: FileInfo;
  status?: 'sending' | 'sent' | 'delivered' | 'read' | 'failed';
  expiresAt?: number | null;
  crypto?: CryptoDetails;
}

interface IdentityRecord {
  sigPub: string;
  sigSec: string;
  dhPub: string;
  dhSec: string;
  dhSig: string;
}

interface StoredSignedPreKey {
  id: number;
  pub: string;
  sec: string;
  sig: string;
  createdAt: number;
}

interface StoredPqPreKey extends StoredSignedPreKey {
  lastResort: boolean;
}

interface AccountRecord {
  v: 1;
  accountId: string;
  name: string;
  server: string;
  identity: IdentityRecord;
  accessKey: string;
  spks: StoredSignedPreKey[];
  pqLastResort: StoredPqPreKey[];
  nextKeyId: number;
  createdAt: number;
}

interface PreKeyStore {
  opk: Record<string, [string, string]>;
  pq: Record<string, StoredPqPreKey>;
}

interface SessionEntry {
  state: RatchetStateJSON;
  pending: string | null; // encoded PQXDH header, attached until the peer replies
  baseKey: string;
  createdAt: number;
}

type Payload =
  | { t: 'msg'; id: string; ts: number; text?: string; file?: FilePointerJSON; timer?: number; p?: ProfileJSON }
  | { t: 'receipt'; kind: 'delivered' | 'read'; ids: string[]; p?: ProfileJSON }
  | { t: 'profile'; p: ProfileJSON }
  | { t: 'timer'; timer: number; p?: ProfileJSON };

interface ProfileJSON {
  name: string;
  ak: string;
}

interface FilePointerJSON {
  blob: string;
  del: string;
  key: string;
  digest: string;
  size: number;
  name: string;
  mime: string;
}

export type ClientEvent =
  | { type: 'message'; contactId: string; message: Message }
  | { type: 'message-updated'; contactId: string; message: Message }
  | { type: 'messages-removed'; contactId: string; ids: string[] }
  | { type: 'contact'; contact: Contact }
  | { type: 'connection'; state: 'online' | 'offline' }
  | { type: 'error'; error: string };

const VAULT_KEY = 'vault';
const MAX_SESSIONS = 5;
const OPK_TARGET = 100;
const OPK_LOW = 25;
const PQ_OPK_TARGET = 25;
const PQ_OPK_LOW = 10;
const SPK_ROTATE_MS = 7 * 24 * 3600_000;
const PQ_LR_ROTATE_MS = 30 * 24 * 3600_000;
export const MAX_FILE_BYTES = 100 * 1024 * 1024;

const CONTENT_PREKEY = 0x01;
const CONTENT_MESSAGE = 0x02;

class Mutex {
  private tail: Promise<unknown> = Promise.resolve();
  run<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.tail.then(fn, fn);
    this.tail = next.catch(() => undefined);
    return next;
  }
}

const newId = () => toB64(randomBytes(16));

function identityFromRecord(r: IdentityRecord): IdentityKeyPair {
  return {
    sig: { publicKey: fromB64(r.sigPub), secretKey: fromB64(r.sigSec) },
    dh: { publicKey: fromB64(r.dhPub), secretKey: fromB64(r.dhSec) },
    dhSig: fromB64(r.dhSig),
  };
}

export interface InviteInfo {
  accountId: string;
  accessKey: Uint8Array;
  name?: string;
}

/** Invite links live in the URL fragment (#...), which browsers never send to any server. */
export function parseInvite(link: string): InviteInfo {
  const frag = link.includes('#') ? link.slice(link.indexOf('#') + 1) : link;
  const m = frag.match(/(?:^|\/)invite\/([a-z2-7]{32})\.([A-Za-z0-9_-]{22})(?:\.([A-Za-z0-9_-]*))?$/);
  if (!m) throw new Error('Not a valid Obscura invite link');
  const name = m[3] ? fromUtf8(fromB64(m[3])).slice(0, 64) : undefined;
  return { accountId: m[1], accessKey: fromB64(m[2]), name };
}

// ---------------------------------------------------------------- client

export class ObscuraClient {
  private listeners = new Set<(e: ClientEvent) => void>();
  private mutex = new Mutex();
  private stopRealtime: (() => void) | null = null;
  private sweepTimer: ReturnType<typeof setInterval> | null = null;
  private identity: IdentityKeyPair;
  readonly api: HttpApi;
  online = false;

  private constructor(private store: SecureStore, private kv: KV, private account: AccountRecord) {
    this.identity = identityFromRecord(account.identity);
    this.api = new HttpApi(account.server, { accountId: account.accountId, sigSecret: this.identity.sig.secretKey });
  }

  // ------------------------------------------------------------ lifecycle

  static async hasAccount(kv: KV): Promise<boolean> {
    return (await kv.get(VAULT_KEY)) !== undefined;
  }

  static async create(opts: { kv: KV; server: string; name: string; passphrase: string; kdf?: KdfParams }): Promise<ObscuraClient> {
    if (opts.passphrase.length < 8) throw new Error('Passphrase must be at least 8 characters');
    const { header, masterKey } = await createVault(opts.passphrase, opts.kdf);
    const store = new SecureStore(opts.kv, masterKey);
    wipe(masterKey);

    const identity = generateIdentity();
    const id = deriveAccountId(identity.sig.publicKey);
    const spk = generateSignedPreKey(identity, 1);
    const pqLr = generatePqPreKey(identity, 2, true);
    const accessKey = randomBytes(16);
    const account: AccountRecord = {
      v: 1,
      accountId: id,
      name: opts.name.trim().slice(0, 64) || 'Anonymous',
      server: opts.server,
      identity: {
        sigPub: toB64(identity.sig.publicKey),
        sigSec: toB64(identity.sig.secretKey),
        dhPub: toB64(identity.dh.publicKey),
        dhSec: toB64(identity.dh.secretKey),
        dhSig: toB64(identity.dhSig),
      },
      accessKey: toB64(accessKey),
      spks: [{ id: spk.id, pub: toB64(spk.keyPair.publicKey), sec: toB64(spk.keyPair.secretKey), sig: toB64(spk.signature), createdAt: spk.createdAt }],
      pqLastResort: [
        {
          id: pqLr.id,
          pub: toB64(pqLr.keyPair.publicKey),
          sec: toB64(pqLr.keyPair.secretKey),
          sig: toB64(pqLr.signature),
          createdAt: Date.now(),
          lastResort: true,
        },
      ],
      nextKeyId: 3,
      createdAt: Date.now(),
    };
    const client = new ObscuraClient(store, opts.kv, account);
    const upload = await client.generateKeyBatch(OPK_TARGET, PQ_OPK_TARGET);
    await client.api.register({
      identity: identityToJSON(publicIdentity(identity)),
      accessKeyHash: toB64(sha256(accessKey)),
      signedPreKey: { id: spk.id, publicKey: toB64(spk.keyPair.publicKey), signature: toB64(spk.signature) },
      pqLastResort: { id: pqLr.id, publicKey: toB64(pqLr.keyPair.publicKey), signature: toB64(pqLr.signature), lastResort: true },
      ...upload,
    });
    await store.put('account', client.account);
    await store.put('contacts', {});
    await opts.kv.put(VAULT_KEY, utf8(JSON.stringify(header)));
    return client;
  }

  static async unlock(opts: { kv: KV; passphrase: string }): Promise<ObscuraClient> {
    const raw = await opts.kv.get(VAULT_KEY);
    if (!raw) throw new Error('No account on this device');
    const header = JSON.parse(fromUtf8(raw)) as VaultHeader;
    const masterKey = await unlockVault(opts.passphrase, header);
    const store = new SecureStore(opts.kv, masterKey);
    wipe(masterKey);
    const account = await store.get<AccountRecord>('account');
    if (!account) throw new Error('Vault is empty or corrupted');
    return new ObscuraClient(store, opts.kv, account);
  }

  get accountId(): string {
    return this.account.accountId;
  }
  get name(): string {
    return this.account.name;
  }
  get server(): string {
    return this.account.server;
  }
  get publicIdentity(): PublicIdentity {
    return publicIdentity(this.identity);
  }

  on(fn: (e: ClientEvent) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }
  private emit(e: ClientEvent) {
    for (const fn of this.listeners) {
      try {
        fn(e);
      } catch {
        /* listener errors must not break the engine */
      }
    }
  }

  /** Go online: keep prekeys topped up, drain the mailbox, subscribe to pushes, start the disappearing-message sweeper. */
  async connect(opts: { realtime?: boolean } = {}): Promise<void> {
    await this.maintainPreKeys();
    await this.sync();
    if (opts.realtime !== false && !this.stopRealtime) {
      this.stopRealtime = this.api.connectRealtime({
        onEnvelope: (e) => void this.handleEnvelopes([e]),
        onState: (s) => {
          this.online = s === 'online';
          this.emit({ type: 'connection', state: s });
          if (s === 'online') void this.sync().catch(() => undefined);
        },
      });
    }
    if (!this.sweepTimer) this.sweepTimer = setInterval(() => void this.sweepExpired(), 2000);
    await this.sweepExpired();
  }

  /** Pull and process everything waiting on the server. */
  async sync(): Promise<number> {
    const envs = await this.api.fetchEnvelopes();
    await this.handleEnvelopes(envs);
    return envs.length;
  }

  /** Lock: stop networking and wipe key material from memory. */
  lock(): void {
    this.stopRealtime?.();
    this.stopRealtime = null;
    if (this.sweepTimer) clearInterval(this.sweepTimer);
    this.sweepTimer = null;
    wipe(this.identity.sig.secretKey, this.identity.dh.secretKey);
    this.store.close();
    this.listeners.clear();
  }

  /** Delete the account from the server and erase every local record. */
  async destroyEverything(): Promise<void> {
    try {
      await this.api.deleteAccount();
    } finally {
      this.lock();
      await this.kv.clear();
    }
  }

  // ------------------------------------------------------------ prekeys

  private async generateKeyBatch(opkCount: number, pqCount: number): Promise<PreKeyUpload> {
    const pre = (await this.store.get<PreKeyStore>('prekeys')) ?? { opk: {}, pq: {} };
    const opks = generateOneTimePreKeys(this.account.nextKeyId, opkCount);
    this.account.nextKeyId += opkCount;
    for (const k of opks) pre.opk[k.id] = [toB64(k.keyPair.publicKey), toB64(k.keyPair.secretKey)];
    const pqs = [];
    for (let i = 0; i < pqCount; i++) {
      const k = generatePqPreKey(this.identity, this.account.nextKeyId++, false);
      pre.pq[k.id] = {
        id: k.id,
        pub: toB64(k.keyPair.publicKey),
        sec: toB64(k.keyPair.secretKey),
        sig: toB64(k.signature),
        createdAt: Date.now(),
        lastResort: false,
      };
      pqs.push({ id: k.id, publicKey: toB64(k.keyPair.publicKey), signature: toB64(k.signature), lastResort: false });
    }
    await this.store.put('prekeys', pre);
    await this.store.put('account', this.account);
    return {
      oneTimePreKeys: opks.map((k) => ({ id: k.id, publicKey: toB64(k.keyPair.publicKey) })),
      pqOneTimePreKeys: pqs,
    };
  }

  /** Replenish one-time prekeys and rotate the signed / last-resort keys on schedule. */
  async maintainPreKeys(): Promise<void> {
    await this.mutex.run(async () => {
      const counts = await this.api.keyCounts();
      const upload: PreKeyUpload = {};
      const needOpk = counts.oneTime < OPK_LOW ? OPK_TARGET - counts.oneTime : 0;
      const needPq = counts.pqOneTime < PQ_OPK_LOW ? PQ_OPK_TARGET - counts.pqOneTime : 0;
      if (needOpk || needPq) Object.assign(upload, await this.generateKeyBatch(needOpk, needPq));
      const now = Date.now();
      if (now - this.account.spks[0].createdAt > SPK_ROTATE_MS) {
        const spk = generateSignedPreKey(this.identity, this.account.nextKeyId++);
        // Keep the previous two so in-flight prekey messages still decrypt.
        this.account.spks = [
          { id: spk.id, pub: toB64(spk.keyPair.publicKey), sec: toB64(spk.keyPair.secretKey), sig: toB64(spk.signature), createdAt: now },
          ...this.account.spks,
        ].slice(0, 3);
        upload.signedPreKey = { id: spk.id, publicKey: toB64(spk.keyPair.publicKey), signature: toB64(spk.signature) };
      }
      if (now - this.account.pqLastResort[0].createdAt > PQ_LR_ROTATE_MS) {
        const k = generatePqPreKey(this.identity, this.account.nextKeyId++, true);
        this.account.pqLastResort = [
          { id: k.id, pub: toB64(k.keyPair.publicKey), sec: toB64(k.keyPair.secretKey), sig: toB64(k.signature), createdAt: now, lastResort: true },
          ...this.account.pqLastResort,
        ].slice(0, 2);
        upload.pqLastResort = { id: k.id, publicKey: toB64(k.keyPair.publicKey), signature: toB64(k.signature), lastResort: true };
      }
      if (Object.keys(upload).length) {
        await this.store.put('account', this.account);
        await this.api.uploadPreKeys(upload);
      }
    });
  }

  // ------------------------------------------------------------ contacts

  inviteLink(origin: string, includeName = true): string {
    const base = `${origin.replace(/\/+$/, '')}/#/invite/${this.account.accountId}.${this.account.accessKey}`;
    return includeName ? `${base}.${toB64(utf8(this.account.name))}` : base;
  }

  async contacts(): Promise<Contact[]> {
    const map = (await this.store.get<Record<string, Contact>>('contacts')) ?? {};
    return Object.values(map).sort((a, b) => b.lastActivity - a.lastActivity);
  }

  async getContact(id: string): Promise<Contact | undefined> {
    const map = (await this.store.get<Record<string, Contact>>('contacts')) ?? {};
    return map[id];
  }

  private async saveContact(c: Contact): Promise<void> {
    const map = (await this.store.get<Record<string, Contact>>('contacts')) ?? {};
    map[c.id] = c;
    await this.store.put('contacts', map);
    this.emit({ type: 'contact', contact: c });
  }

  /** Add a contact from their invite link, establish a PQXDH session and say hello. */
  async addContact(invite: string, nickname?: string): Promise<Contact> {
    const info = parseInvite(invite);
    if (info.accountId === this.account.accountId) throw new Error("That's your own invite link");
    const contact = await this.mutex.run(async () => {
      const existing = await this.getContact(info.accountId);
      const c: Contact = existing ?? {
        id: info.accountId,
        name: nickname || info.name || 'New contact',
        identity: null,
        accessKey: null,
        verified: false,
        blocked: false,
        timer: 0,
        unread: 0,
        addedAt: Date.now(),
        lastActivity: Date.now(),
      };
      c.accessKey = toB64(info.accessKey);
      if (nickname) c.name = nickname;
      c.blocked = false;
      await this.saveContact(c);
      return c;
    });
    await this.sendPayload(contact.id, { t: 'profile', p: this.profile() });
    return (await this.getContact(contact.id))!;
  }

  async renameContact(id: string, name: string): Promise<void> {
    await this.mutex.run(async () => {
      const c = await this.getContact(id);
      if (!c) return;
      c.name = name.slice(0, 64);
      await this.saveContact(c);
    });
  }

  async safetyNumber(contactId: string): Promise<{ digits: string; groups: string[] } | null> {
    const c = await this.getContact(contactId);
    if (!c?.identity) return null;
    const digits = safetyNumber(this.publicIdentity, this.accountId, identityFromJSON(c.identity), c.id);
    return { digits, groups: formatSafetyNumber(digits) };
  }

  async setVerified(contactId: string, verified: boolean): Promise<void> {
    await this.mutex.run(async () => {
      const c = await this.getContact(contactId);
      if (!c) return;
      c.verified = verified;
      await this.saveContact(c);
    });
  }

  /**
   * Block = stop accepting their messages AND revoke their ability to reach us:
   * we rotate our access key and send the new one only to the contacts we keep.
   */
  async blockContact(contactId: string): Promise<void> {
    await this.mutex.run(async () => {
      const c = await this.getContact(contactId);
      if (!c) return;
      c.blocked = true;
      await this.saveContact(c);
    });
    await this.rotateAccessKey();
  }

  async rotateAccessKey(): Promise<void> {
    const ak = randomBytes(16);
    await this.api.setAccessKey(toB64(sha256(ak)));
    await this.mutex.run(async () => {
      this.account.accessKey = toB64(ak);
      await this.store.put('account', this.account);
    });
    for (const c of await this.contacts()) {
      if (!c.blocked && c.accessKey) await this.sendPayload(c.id, { t: 'profile', p: this.profile() }).catch(() => undefined);
    }
  }

  private profile(): ProfileJSON {
    return { name: this.account.name, ak: this.account.accessKey };
  }

  // ------------------------------------------------------------ messages

  async messages(contactId: string): Promise<Message[]> {
    return (await this.store.get<Message[]>(`msgs:${contactId}`)) ?? [];
  }

  private async appendMessage(contactId: string, m: Message): Promise<void> {
    const list = await this.messages(contactId);
    if (list.some((x) => x.id === m.id)) return;
    list.push(m);
    await this.store.put(`msgs:${contactId}`, list);
    this.emit({ type: 'message', contactId, message: m });
  }

  private async updateMessages(contactId: string, fn: (m: Message) => boolean): Promise<void> {
    const list = await this.messages(contactId);
    const changed: Message[] = [];
    for (const m of list) if (fn(m)) changed.push(m);
    if (!changed.length) return;
    await this.store.put(`msgs:${contactId}`, list);
    for (const m of changed) this.emit({ type: 'message-updated', contactId, message: m });
  }

  async sendText(contactId: string, text: string): Promise<Message> {
    if (!text.trim()) throw new Error('Empty message');
    if (text.length > 16_000) throw new Error('Message too long');
    return this.sendUserMessage(contactId, { text });
  }

  /** Encrypt a file locally, upload only ciphertext, then send the key inside an E2EE message. */
  async sendFile(contactId: string, data: Uint8Array, name: string, mime: string): Promise<Message> {
    if (data.length > MAX_FILE_BYTES) throw new Error('File is larger than 100 MB');
    const { blob, pointer } = encryptAttachment(data);
    const up = await this.api.uploadBlob(blob);
    const fileId = newId();
    await this.store.putBytes(`file:${fileId}`, data);
    const ptr: FilePointerJSON = {
      blob: up.id,
      del: up.deleteToken,
      key: toB64(pointer.key),
      digest: toB64(pointer.digest),
      size: pointer.size,
      name: name.slice(0, 200),
      mime: mime.slice(0, 100) || 'application/octet-stream',
    };
    wipe(pointer.key);
    return this.sendUserMessage(contactId, {
      file: ptr,
      local: { fileId, name: ptr.name, mime: ptr.mime, size: ptr.size, state: 'ready' },
    });
  }

  private async sendUserMessage(contactId: string, body: { text?: string; file?: FilePointerJSON; local?: FileInfo }): Promise<Message> {
    const c = await this.getContact(contactId);
    if (!c) throw new Error('Unknown contact');
    if (c.blocked) throw new Error('Contact is blocked');
    const now = Date.now();
    const msg: Message = {
      id: newId(),
      dir: 'out',
      ts: now,
      text: body.text,
      file: body.local,
      status: 'sending',
      expiresAt: c.timer ? now + c.timer * 1000 : null,
    };
    await this.mutex.run(() => this.appendMessage(contactId, msg));
    try {
      const details = await this.sendPayload(contactId, {
        t: 'msg',
        id: msg.id,
        ts: now,
        text: body.text,
        file: body.file,
        timer: c.timer || undefined,
      });
      await this.mutex.run(() =>
        this.updateMessages(contactId, (m) => {
          if (m.id !== msg.id) return false;
          if (m.status === 'sending') m.status = 'sent';
          m.crypto = details;
          return true;
        }),
      );
      msg.status = 'sent';
      msg.crypto = details;
    } catch (e) {
      await this.mutex.run(() => this.updateMessages(contactId, (m) => (m.id === msg.id ? ((m.status = 'failed'), true) : false)));
      throw e;
    }
    return msg;
  }

  async setTimer(contactId: string, seconds: number): Promise<void> {
    await this.mutex.run(async () => {
      const c = await this.getContact(contactId);
      if (!c) return;
      c.timer = seconds;
      await this.saveContact(c);
      await this.appendMessage(contactId, { id: newId(), dir: 'system', ts: Date.now(), text: timerText('You', seconds) });
    });
    await this.sendPayload(contactId, { t: 'timer', timer: seconds });
  }

  async markRead(contactId: string): Promise<void> {
    const ids: string[] = [];
    await this.mutex.run(async () => {
      await this.updateMessages(contactId, (m) => {
        if (m.dir === 'in' && m.status !== 'read') {
          m.status = 'read';
          ids.push(m.id);
          return true;
        }
        return false;
      });
      const c = await this.getContact(contactId);
      if (c && c.unread) {
        c.unread = 0;
        await this.saveContact(c);
      }
    });
    if (ids.length) await this.sendPayload(contactId, { t: 'receipt', kind: 'read', ids }).catch(() => undefined);
  }

  async deleteMessage(contactId: string, messageId: string): Promise<void> {
    await this.mutex.run(async () => {
      const list = await this.messages(contactId);
      const m = list.find((x) => x.id === messageId);
      if (m?.file) await this.store.del(`file:${m.file.fileId}`);
      await this.store.put(
        `msgs:${contactId}`,
        list.filter((x) => x.id !== messageId),
      );
      this.emit({ type: 'messages-removed', contactId, ids: [messageId] });
    });
  }

  async getFile(fileId: string): Promise<Uint8Array | undefined> {
    return this.store.getBytes(`file:${fileId}`);
  }

  async serverView(): Promise<ServerView> {
    return this.api.serverView();
  }

  // ------------------------------------------------------------ encryption

  private async loadSessions(contactId: string): Promise<SessionEntry[]> {
    return (await this.store.get<SessionEntry[]>(`sessions:${contactId}`)) ?? [];
  }

  private async sendPayload(contactId: string, payload: Payload): Promise<CryptoDetails> {
    // Encrypt under the lock (session state must advance atomically), send outside it.
    const { envelope, details, accessKey } = await this.mutex.run(async () => {
      const c = await this.getContact(contactId);
      if (!c) throw new Error('Unknown contact');
      if (!c.accessKey) throw new Error('This contact has not shared an invite with you yet');
      let sessions = await this.loadSessions(contactId);
      if (!sessions.length) {
        const bundle = bundleFromJSON(await this.api.getBundle(contactId));
        // The account ID *is* a hash of the identity key, so a malicious server cannot substitute keys.
        if (deriveAccountId(bundle.identity.sigPub) !== contactId) {
          throw new Error('Server returned keys that do not match this contact ID (possible interception). Refusing.');
        }
        if (c.identity && !sameIdentity(identityFromJSON(c.identity), bundle.identity)) {
          throw new Error('Identity key mismatch for this contact. Refusing.');
        }
        const { state, header } = pqxdhInitiate(this.identity, bundle);
        sessions = [
          { state: serializeState(state), pending: toB64(encodePreKeyHeader(header)), baseKey: toB64(header.ephemeral), createdAt: Date.now() },
        ];
        if (!c.identity) {
          c.identity = identityToJSON(bundle.identity);
          await this.saveContact(c);
        }
      }
      const entry = sessions[0];
      if (entry.pending && payload.t !== 'profile') (payload as { p?: ProfileJSON }).p = this.profile();
      const state = deserializeState(entry.state);
      const { message, info } = ratchetEncrypt(state, padMessage(utf8(JSON.stringify(payload))));
      entry.state = serializeState(state);
      await this.store.put(`sessions:${contactId}`, sessions);
      const content = entry.pending
        ? concat(Uint8Array.of(CONTENT_PREKEY), new Writer().bytes(fromB64(entry.pending)).bytes(message).finish())
        : concat(Uint8Array.of(CONTENT_MESSAGE), new Writer().bytes(message).finish());
      const envelope = sealEnvelope(this.identity, identityFromJSON(c.identity!), content);
      return {
        envelope,
        accessKey: fromB64(c.accessKey),
        details: cryptoDetails(entry.pending ? 'prekey' : 'message', info, envelope),
      };
    });
    await this.api.sendEnvelope(contactId, accessKey, envelope);
    return details;
  }

  private async decryptContent(sender: PublicIdentity, senderId: string, content: Uint8Array): Promise<{ plaintext: Uint8Array; details: CryptoDetails }> {
    const type = content[0];
    const r = new Reader(content.subarray(1));
    let sessions = await this.loadSessions(senderId);
    if (type === CONTENT_PREKEY) {
      const hb = r.bytes(8192);
      const msg = r.bytes();
      r.done();
      const header = decodePreKeyHeader(hb);
      if (!sameIdentity(header.identity, sender)) throw new Error('prekey identity does not match envelope sender');
      const baseKey = toB64(header.ephemeral);
      const idx = sessions.findIndex((s) => s.baseKey === baseKey);
      if (idx >= 0) {
        const state = deserializeState(sessions[idx].state);
        const { plaintext, info } = ratchetDecrypt(state, msg);
        const [entry] = sessions.splice(idx, 1);
        entry.state = serializeState(state);
        sessions.unshift(entry);
        await this.store.put(`sessions:${senderId}`, sessions);
        return { plaintext, details: cryptoDetails('prekey', info, content) };
      }
      const pre = (await this.store.get<PreKeyStore>('prekeys')) ?? { opk: {}, pq: {} };
      const kp = (pub: string, sec: string): KeyPair => ({ publicKey: fromB64(pub), secretKey: fromB64(sec) });
      const state = pqxdhRespond(this.identity, {
        signedPreKey: (id) => {
          const s = this.account.spks.find((k) => k.id === id);
          return s ? kp(s.pub, s.sec) : undefined;
        },
        oneTimePreKey: (id) => (pre.opk[id] ? kp(pre.opk[id][0], pre.opk[id][1]) : undefined),
        pqPreKey: (id) => {
          const k = pre.pq[id] ?? this.account.pqLastResort.find((x) => x.id === id);
          return k ? kp(k.pub, k.sec) : undefined;
        },
      }, header);
      const { plaintext, info } = ratchetDecrypt(state, msg);
      // Only now, after authentication succeeded, burn the one-time keys.
      if (header.oneTimePreKeyId !== null) delete pre.opk[header.oneTimePreKeyId];
      delete pre.pq[header.pqPreKeyId];
      await this.store.put('prekeys', pre);
      sessions.unshift({ state: serializeState(state), pending: null, baseKey, createdAt: Date.now() });
      sessions = sessions.slice(0, MAX_SESSIONS);
      await this.store.put(`sessions:${senderId}`, sessions);
      return { plaintext, details: cryptoDetails('prekey', info, content) };
    }
    if (type === CONTENT_MESSAGE) {
      const msg = r.bytes();
      r.done();
      for (let i = 0; i < sessions.length; i++) {
        const state = deserializeState(sessions[i].state);
        let res: { plaintext: Uint8Array; info: MessageInfo };
        try {
          res = ratchetDecrypt(state, msg);
        } catch {
          continue;
        }
        const [entry] = sessions.splice(i, 1);
        entry.state = serializeState(state);
        entry.pending = null; // the peer has our session: stop attaching the PQXDH header
        sessions.unshift(entry);
        await this.store.put(`sessions:${senderId}`, sessions);
        return { plaintext: res.plaintext, details: cryptoDetails('message', res.info, content) };
      }
      throw new Error('no session could decrypt this message');
    }
    throw new Error('unknown content type');
  }

  private async handleEnvelopes(envs: QueuedEnvelope[]): Promise<void> {
    const acks: string[] = [];
    const after: (() => Promise<unknown>)[] = [];
    for (const env of envs) {
      await this.mutex.run(async () => {
        try {
          await this.processEnvelope(env.data, after);
        } catch (e) {
          // Undecryptable (replayed, forged, or for a lost session): drop it. Never crash the engine.
          this.emit({ type: 'error', error: `Could not decrypt an incoming message: ${(e as Error).message}` });
        }
        acks.push(env.id);
      });
    }
    await this.api.ackEnvelopes(acks).catch(() => undefined);
    for (const job of after) await job().catch(() => undefined);
  }

  private async processEnvelope(data: Uint8Array, after: (() => Promise<unknown>)[]): Promise<void> {
    const { sender, content } = openEnvelope(this.identity, data);
    const senderId = deriveAccountId(sender.sigPub);
    let c = await this.getContact(senderId);
    if (c?.blocked) return;
    if (c?.identity && !sameIdentity(identityFromJSON(c.identity), sender)) throw new Error('sender identity changed');
    const { plaintext, details } = await this.decryptContent(sender, senderId, content);
    details.envelopeBytes = data.length;
    details.envelopeHead = toB64(data.subarray(0, 48));
    const payload = JSON.parse(fromUtf8(unpadMessage(plaintext))) as Payload;

    if (!c) {
      c = {
        id: senderId,
        name: 'New contact',
        identity: identityToJSON(sender),
        accessKey: null,
        verified: false,
        blocked: false,
        timer: 0,
        unread: 0,
        addedAt: Date.now(),
        lastActivity: Date.now(),
      };
    } else if (!c.identity) c.identity = identityToJSON(sender);
    if (payload.p) {
      if (c.name === 'New contact' || !c.name) c.name = String(payload.p.name).slice(0, 64);
      if (/^[A-Za-z0-9_-]{22}$/.test(payload.p.ak)) c.accessKey = payload.p.ak;
    }
    c.lastActivity = Date.now();

    if (payload.t === 'msg') {
      if (typeof payload.text === 'string') payload.text = payload.text.slice(0, 16_000);
      const now = Date.now();
      const m: Message = {
        id: String(payload.id),
        dir: 'in',
        ts: Number(payload.ts) || now,
        text: payload.text,
        status: 'delivered',
        expiresAt: payload.timer ? now + clampTimer(payload.timer) * 1000 : null,
        crypto: details,
      };
      if (payload.timer !== undefined) payload.timer = clampTimer(payload.timer);
      if (payload.timer !== undefined && payload.timer !== c.timer) c.timer = payload.timer;
      if (payload.file) {
        const f = payload.file;
        m.file = { fileId: newId(), name: String(f.name), mime: String(f.mime), size: Number(f.size), state: 'downloading' };
        const contactId = senderId;
        after.push(() => this.downloadFile(contactId, m.id, f, m.file!.fileId));
      }
      c.unread += 1;
      await this.saveContact(c);
      await this.appendMessage(senderId, m);
      const ids = [m.id];
      after.push(() => this.sendPayload(senderId, { t: 'receipt', kind: 'delivered', ids }));
    } else if (payload.t === 'receipt') {
      await this.saveContact(c);
      const rank = { sending: 0, failed: 0, sent: 1, delivered: 2, read: 3 } as const;
      const ids = new Set(payload.ids.map(String));
      await this.updateMessages(senderId, (m) => {
        if (m.dir !== 'out' || !ids.has(m.id) || !m.status) return false;
        if (rank[payload.kind] <= rank[m.status]) return false;
        m.status = payload.kind;
        return true;
      });
    } else if (payload.t === 'timer') {
      c.timer = clampTimer(payload.timer);
      await this.saveContact(c);
      await this.appendMessage(senderId, { id: newId(), dir: 'system', ts: Date.now(), text: timerText(c.name, c.timer) });
    } else if (payload.t === 'profile') {
      await this.saveContact(c);
    }
  }

  private async downloadFile(contactId: string, messageId: string, f: FilePointerJSON, fileId: string): Promise<void> {
    let state: FileInfo['state'] = 'ready';
    try {
      const blob = await this.api.downloadBlob(f.blob);
      const data = decryptAttachment(blob, { key: fromB64(f.key), digest: fromB64(f.digest), size: f.size });
      await this.store.putBytes(`file:${fileId}`, data);
      // Minimise retention: once the recipient has it, the ciphertext is deleted from the server.
      await this.api.deleteBlob(f.blob, f.del).catch(() => undefined);
    } catch {
      state = 'error';
    }
    await this.mutex.run(() =>
      this.updateMessages(contactId, (m) => (m.id === messageId && m.file ? ((m.file.state = state), true) : false)),
    );
  }

  /** Disappearing messages: delete expired messages and their media from local storage. */
  async sweepExpired(): Promise<void> {
    const now = Date.now();
    await this.mutex.run(async () => {
      for (const c of await this.contacts()) {
        const list = await this.messages(c.id);
        const expired = list.filter((m) => m.expiresAt && m.expiresAt <= now);
        if (!expired.length) continue;
        for (const m of expired) if (m.file) await this.store.del(`file:${m.file.fileId}`);
        await this.store.put(
          `msgs:${c.id}`,
          list.filter((m) => !(m.expiresAt && m.expiresAt <= now)),
        );
        this.emit({ type: 'messages-removed', contactId: c.id, ids: expired.map((m) => m.id) });
      }
    });
  }
}

function sameIdentity(a: PublicIdentity, b: PublicIdentity): boolean {
  return equalBytes(a.sigPub, b.sigPub) && equalBytes(a.dhPub, b.dhPub);
}

function cryptoDetails(kind: 'prekey' | 'message', info: MessageInfo, wire: Uint8Array): CryptoDetails {
  return {
    kind,
    ratchetStep: info.ratchetStep,
    counter: info.n,
    pqRatchet: info.pqStep,
    envelopeBytes: wire.length,
    envelopeHead: toB64(wire.subarray(0, 48)),
  };
}

/** Timer values arrive from the peer: never trust them blindly. */
function clampTimer(v: unknown): number {
  return Math.max(0, Math.min(Math.floor(Number(v)) || 0, 4 * 7 * 24 * 3600));
}

function timerText(who: string, seconds: number): string {
  if (!seconds) return `${who} turned off disappearing messages`;
  return `${who} set messages to disappear after ${formatDuration(seconds)}`;
}

export function formatDuration(s: number): string {
  if (s < 60) return `${s} seconds`;
  if (s < 3600) return `${Math.round(s / 60)} minutes`;
  if (s < 86400) return `${Math.round(s / 3600)} hours`;
  if (s < 604800) return `${Math.round(s / 86400)} days`;
  return `${Math.round(s / 604800)} weeks`;
}
