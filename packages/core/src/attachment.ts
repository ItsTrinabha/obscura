/**
 * Attachment encryption (pictures, videos, any file).
 *
 * Each file gets a fresh random 256-bit key. The (Padmé-padded) file is split
 * into 64 KiB chunks and sealed with XChaCha20-Poly1305 using the STREAM
 * construction (Hoang, Reyhanitabar, Rogaway, Vizár 2015): every chunk nonce
 * encodes its index and a "last chunk" flag, so chunks cannot be reordered,
 * dropped, duplicated or truncated without detection.
 *
 * The server stores only the opaque blob under a random ID. The key, the
 * SHA-256 digest of the blob, the real size, name and MIME type travel inside
 * the end-to-end encrypted message, never in the clear.
 */
import { concat, equalBytes, Reader, u32be, Writer } from './bytes.js';
import { DecryptError, open, randomBytes, seal, sha256, TAG_LEN } from './primitives.js';
import { padme } from './padding.js';

const MAGIC = new Uint8Array([0x4f, 0x42, 0x53, 0x41]); // "OBSA"
const VERSION = 1;
export const CHUNK_SIZE = 64 * 1024;
const HEADER_LEN = 4 + 1 + 4 + 16;

export interface AttachmentPointer {
  key: Uint8Array;
  digest: Uint8Array;
  size: number;
}

function chunkNonce(prefix: Uint8Array, index: number, last: boolean): Uint8Array {
  return concat(prefix, u32be(index), Uint8Array.of(last ? 1 : 0, 0, 0, 0));
}

export function encryptAttachment(data: Uint8Array, chunkSize = CHUNK_SIZE): { blob: Uint8Array; pointer: AttachmentPointer } {
  const key = randomBytes(32);
  const prefix = randomBytes(16);
  const header = new Writer().fixed(MAGIC, 4).u8(VERSION).u32(chunkSize).fixed(prefix, 16).finish();
  const paddedLen = Math.max(padme(data.length), 1);
  const padded = new Uint8Array(paddedLen);
  padded.set(data);
  const chunks = Math.max(1, Math.ceil(paddedLen / chunkSize));
  const out = new Uint8Array(HEADER_LEN + paddedLen + chunks * TAG_LEN);
  out.set(header);
  let off = HEADER_LEN;
  for (let i = 0; i < chunks; i++) {
    const pt = padded.subarray(i * chunkSize, Math.min((i + 1) * chunkSize, paddedLen));
    const ct = seal(key, chunkNonce(prefix, i, i === chunks - 1), pt, header);
    out.set(ct, off);
    off += ct.length;
  }
  return { blob: out, pointer: { key, digest: sha256(out), size: data.length } };
}

export function decryptAttachment(blob: Uint8Array, pointer: AttachmentPointer): Uint8Array {
  if (!equalBytes(sha256(blob), pointer.digest)) throw new DecryptError('attachment digest mismatch');
  const r = new Reader(blob.subarray(0, HEADER_LEN));
  const magic = r.fixed(4);
  if (!equalBytes(magic, MAGIC) || r.u8() !== VERSION) throw new DecryptError('not an Obscura attachment');
  const chunkSize = r.u32();
  if (chunkSize < 1024 || chunkSize > 16 * 1024 * 1024) throw new DecryptError('bad chunk size');
  const prefix = r.fixed(16);
  const header = blob.subarray(0, HEADER_LEN);
  const body = blob.subarray(HEADER_LEN);
  const full = chunkSize + TAG_LEN;
  const chunks = Math.max(1, Math.ceil(body.length / full));
  const out = new Uint8Array(body.length - chunks * TAG_LEN);
  let o = 0;
  for (let i = 0; i < chunks; i++) {
    const ct = body.subarray(i * full, Math.min((i + 1) * full, body.length));
    const pt = open(pointer.key, chunkNonce(prefix, i, i === chunks - 1), ct, header);
    out.set(pt, o);
    o += pt.length;
  }
  if (pointer.size > out.length) throw new DecryptError('attachment shorter than declared');
  return out.slice(0, pointer.size);
}
