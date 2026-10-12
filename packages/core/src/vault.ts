/**
 * Local encryption at rest. Everything the client stores (keys, sessions,
 * contacts, messages, decrypted media) is encrypted under a random 256-bit
 * master key. The master key is wrapped with a key derived from the user's
 * passphrase using Argon2id (RFC 9106), 64 MiB memory, 3 passes: slow and
 * memory-hard for anyone brute-forcing a stolen device or browser profile.
 *
 * Record names are HMAC'd too, so the storage layout does not even reveal
 * which contacts exist.
 */
import { argon2id } from 'hash-wasm';
import { concat, fromB64, toB64, toHex, utf8 } from './bytes.js';
import { DecryptError, hkdf, hmacSha256, openRandom, randomBytes, sealRandom } from './primitives.js';

export interface KdfParams {
  alg: 'argon2id';
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

export const DEFAULT_KDF: KdfParams = { alg: 'argon2id', memoryKiB: 64 * 1024, iterations: 3, parallelism: 1 };

export interface VaultHeader {
  v: 1;
  kdf: KdfParams;
  salt: string;
  wrapped: string;
}

async function deriveKek(passphrase: string, salt: Uint8Array, p: KdfParams): Promise<Uint8Array> {
  if (p.alg !== 'argon2id') throw new Error('unsupported KDF');
  return argon2id({
    password: utf8(passphrase.normalize('NFKC')),
    salt,
    parallelism: p.parallelism,
    iterations: p.iterations,
    memorySize: p.memoryKiB,
    hashLength: 32,
    outputType: 'binary',
  });
}

const wrapAD = (p: KdfParams) => utf8(`OBSCURA-VAULT-v1|${p.alg}|${p.memoryKiB}|${p.iterations}|${p.parallelism}`);

export async function createVault(passphrase: string, kdf: KdfParams = DEFAULT_KDF): Promise<{ header: VaultHeader; masterKey: Uint8Array }> {
  const salt = randomBytes(16);
  const masterKey = randomBytes(32);
  const kek = await deriveKek(passphrase, salt, kdf);
  const wrapped = sealRandom(kek, masterKey, wrapAD(kdf));
  kek.fill(0);
  return { header: { v: 1, kdf, salt: toB64(salt), wrapped: toB64(wrapped) }, masterKey };
}

export async function unlockVault(passphrase: string, header: VaultHeader): Promise<Uint8Array> {
  const kek = await deriveKek(passphrase, fromB64(header.salt), header.kdf);
  try {
    return openRandom(kek, fromB64(header.wrapped), wrapAD(header.kdf));
  } catch {
    throw new DecryptError('wrong passphrase');
  } finally {
    kek.fill(0);
  }
}

/** Minimal async key/value backend (IndexedDB in browsers, a Map in tests). */
export interface KV {
  get(key: string): Promise<Uint8Array | undefined>;
  put(key: string, value: Uint8Array): Promise<void>;
  del(key: string): Promise<void>;
  clear(): Promise<void>;
}

export class MemoryKV implements KV {
  readonly map = new Map<string, Uint8Array>();
  async get(k: string) {
    return this.map.get(k)?.slice();
  }
  async put(k: string, v: Uint8Array) {
    this.map.set(k, v.slice());
  }
  async del(k: string) {
    this.map.delete(k);
  }
  async clear() {
    this.map.clear();
  }
}

/** Encrypting wrapper: hashed record names, XChaCha20-Poly1305 values bound to their slot. */
export class SecureStore {
  private recordKey: Uint8Array;
  private nameKey: Uint8Array;
  constructor(private kv: KV, masterKey: Uint8Array) {
    this.recordKey = hkdf(masterKey, new Uint8Array(32), 'OBSCURA_STORE_RECORDS_v1', 32);
    this.nameKey = hkdf(masterKey, new Uint8Array(32), 'OBSCURA_STORE_NAMES_v1', 32);
  }
  private slot(name: string): string {
    return 'r:' + toHex(hmacSha256(this.nameKey, utf8(name)));
  }
  async getBytes(name: string): Promise<Uint8Array | undefined> {
    const slot = this.slot(name);
    const v = await this.kv.get(slot);
    if (!v) return undefined;
    return openRandom(this.recordKey, v, concat(utf8('OBSCURA-RECORD|'), utf8(slot)));
  }
  async putBytes(name: string, value: Uint8Array): Promise<void> {
    const slot = this.slot(name);
    await this.kv.put(slot, sealRandom(this.recordKey, value, concat(utf8('OBSCURA-RECORD|'), utf8(slot))));
  }
  async get<T>(name: string): Promise<T | undefined> {
    const b = await this.getBytes(name);
    return b ? (JSON.parse(new TextDecoder().decode(b)) as T) : undefined;
  }
  async put<T>(name: string, value: T): Promise<void> {
    await this.putBytes(name, utf8(JSON.stringify(value)));
  }
  async del(name: string): Promise<void> {
    await this.kv.del(this.slot(name));
  }
  close() {
    this.recordKey.fill(0);
    this.nameKey.fill(0);
  }
}
