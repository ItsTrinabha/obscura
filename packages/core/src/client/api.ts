/**
 * HTTP + WebSocket transport to an Obscura relay server. The server is
 * untrusted: it only ever receives public keys, sealed envelopes and
 * encrypted blobs.
 */
import { fromB64, toB64, utf8 } from '../bytes.js';
import { AUTH_HEADER, signRequest, wsChallengeMessage } from '../auth.js';
import { PreKeyBundleJSON, PublicIdentityJSON } from '../keys.js';
import { sign } from '../primitives.js';

export interface SignedPreKeyJSON {
  id: number;
  publicKey: string;
  signature: string;
}
export interface PqPreKeyJSON extends SignedPreKeyJSON {
  lastResort: boolean;
}

export interface PreKeyUpload {
  signedPreKey?: SignedPreKeyJSON;
  pqLastResort?: PqPreKeyJSON;
  oneTimePreKeys?: { id: number; publicKey: string }[];
  pqOneTimePreKeys?: PqPreKeyJSON[];
}

export interface RegisterBody extends PreKeyUpload {
  identity: PublicIdentityJSON;
  accessKeyHash: string;
}

export interface KeyCounts {
  oneTime: number;
  pqOneTime: number;
  signedPreKeyId: number | null;
  pqLastResortId: number | null;
}

export interface QueuedEnvelope {
  id: string;
  data: Uint8Array;
}

export interface ServerView {
  accountId: string;
  identity: PublicIdentityJSON;
  accessKeyHash: string;
  createdDay: string;
  keys: KeyCounts;
  pendingEnvelopes: { id: string; bytes: number; receivedHour: string }[];
  note: string;
}

export class ApiError extends Error {
  constructor(public status: number, msg: string) {
    super(msg);
    this.name = 'ApiError';
  }
}

export interface Signer {
  accountId: string;
  sigSecret: Uint8Array;
}

export class HttpApi {
  constructor(public readonly baseUrl: string, private signer: Signer) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  private async req(method: string, path: string, opts: { body?: Uint8Array; json?: unknown; auth?: boolean; headers?: Record<string, string> } = {}) {
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    let body: Uint8Array | undefined = opts.body;
    if (opts.json !== undefined) {
      body = utf8(JSON.stringify(opts.json));
      headers['content-type'] = 'application/json';
    } else if (body) headers['content-type'] = 'application/octet-stream';
    if (opts.auth !== false) {
      headers[AUTH_HEADER] = signRequest(this.signer.accountId, this.signer.sigSecret, method, path, body ?? new Uint8Array(0));
    }
    const res = await fetch(this.baseUrl + path, { method, headers, body: body as BodyInit | undefined });
    if (!res.ok) {
      let msg = res.statusText;
      try {
        msg = ((await res.json()) as { error?: string }).error ?? msg;
      } catch {
        /* not json */
      }
      throw new ApiError(res.status, msg);
    }
    return res;
  }

  async register(body: RegisterBody): Promise<void> {
    await this.req('POST', '/v1/accounts', { json: body });
  }
  async deleteAccount(): Promise<void> {
    await this.req('DELETE', '/v1/accounts/me');
  }
  async serverView(): Promise<ServerView> {
    return (await this.req('GET', '/v1/accounts/me')).json() as Promise<ServerView>;
  }
  async setAccessKey(accessKeyHash: string): Promise<void> {
    await this.req('PUT', '/v1/accounts/me/access-key', { json: { accessKeyHash } });
  }
  async getBundle(accountId: string): Promise<PreKeyBundleJSON> {
    return (await this.req('GET', `/v1/keys/${accountId}`)).json() as Promise<PreKeyBundleJSON>;
  }
  async uploadPreKeys(body: PreKeyUpload): Promise<void> {
    await this.req('PUT', '/v1/keys', { json: body });
  }
  async keyCounts(): Promise<KeyCounts> {
    return (await this.req('GET', '/v1/keys/me/count')).json() as Promise<KeyCounts>;
  }
  /** Sealed sender: NOT signed. The server only checks the recipient's access key. */
  async sendEnvelope(recipientId: string, accessKey: Uint8Array, envelope: Uint8Array): Promise<void> {
    await this.req('PUT', `/v1/messages/${recipientId}`, {
      body: envelope,
      auth: false,
      headers: { 'x-obscura-access': toB64(accessKey) },
    });
  }
  async fetchEnvelopes(): Promise<QueuedEnvelope[]> {
    const list = (await (await this.req('GET', '/v1/messages')).json()) as { id: string; data: string }[];
    return list.map((e) => ({ id: e.id, data: fromB64(e.data) }));
  }
  async ackEnvelopes(ids: string[]): Promise<void> {
    if (ids.length) await this.req('DELETE', '/v1/messages', { json: { ids } });
  }
  async uploadBlob(blob: Uint8Array): Promise<{ id: string; deleteToken: string }> {
    return (await this.req('POST', '/v1/blobs', { body: blob })).json() as Promise<{ id: string; deleteToken: string }>;
  }
  async downloadBlob(id: string): Promise<Uint8Array> {
    const res = await this.req('GET', `/v1/blobs/${id}`, { auth: false });
    return new Uint8Array(await res.arrayBuffer());
  }
  async deleteBlob(id: string, deleteToken: string): Promise<void> {
    await this.req('DELETE', `/v1/blobs/${id}`, { auth: false, headers: { 'x-obscura-delete-token': deleteToken } });
  }

  /** Real-time push. Returns a close function. Reconnects with backoff until closed. */
  connectRealtime(handlers: { onEnvelope: (e: QueuedEnvelope) => void; onState?: (s: 'online' | 'offline') => void }): () => void {
    let closed = false;
    let ws: WebSocket | null = null;
    let delay = 500;
    const url = this.baseUrl.replace(/^http/, 'ws') + '/v1/ws';
    const open = () => {
      if (closed) return;
      ws = new WebSocket(url);
      ws.onmessage = (ev) => {
        const msg = JSON.parse(typeof ev.data === 'string' ? ev.data : new TextDecoder().decode(ev.data as ArrayBuffer));
        if (msg.type === 'challenge') {
          const sig = sign(this.signer.sigSecret, wsChallengeMessage(fromB64(msg.challenge)));
          ws!.send(JSON.stringify({ type: 'auth', accountId: this.signer.accountId, signature: toB64(sig) }));
        } else if (msg.type === 'ready') {
          delay = 500;
          handlers.onState?.('online');
        } else if (msg.type === 'envelope') {
          handlers.onEnvelope({ id: msg.id, data: fromB64(msg.data) });
        }
      };
      ws.onclose = () => {
        handlers.onState?.('offline');
        if (!closed) setTimeout(open, (delay = Math.min(delay * 2, 15_000)));
      };
      ws.onerror = () => {
        /* onclose handles reconnect */
      };
    };
    open();
    return () => {
      closed = true;
      ws?.close();
    };
  }
}
