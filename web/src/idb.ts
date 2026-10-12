import type { KV } from '@obscura/core';

/** IndexedDB key/value backend. Every value written here is already ciphertext (see SecureStore). */
export class IdbKV implements KV {
  private dbp: Promise<IDBDatabase>;
  constructor(name = 'obscura') {
    this.dbp = new Promise((resolve, reject) => {
      const req = indexedDB.open(name, 1);
      req.onupgradeneeded = () => req.result.createObjectStore('kv');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  private async tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    const db = await this.dbp;
    return new Promise((resolve, reject) => {
      const t = db.transaction('kv', mode);
      const req = fn(t.objectStore('kv'));
      t.oncomplete = () => resolve(req.result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  }
  async get(key: string): Promise<Uint8Array | undefined> {
    const v = await this.tx('readonly', (s) => s.get(key));
    return v ? new Uint8Array(v as ArrayBuffer) : undefined;
  }
  async put(key: string, value: Uint8Array): Promise<void> {
    await this.tx('readwrite', (s) => s.put(value.slice().buffer, key));
  }
  async del(key: string): Promise<void> {
    await this.tx('readwrite', (s) => s.delete(key));
  }
  async clear(): Promise<void> {
    await this.tx('readwrite', (s) => s.clear());
  }
}
