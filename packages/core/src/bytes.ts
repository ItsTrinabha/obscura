/**
 * Byte helpers: encoding, concatenation and a tiny length-prefixed binary
 * writer/reader used for every wire format in Obscura. Binary encodings are
 * canonical, which matters because headers are fed into AEAD associated data.
 */

const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });

export const utf8 = (s: string): Uint8Array => te.encode(s);
export const fromUtf8 = (b: Uint8Array): string => td.decode(b);

export function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Constant-time comparison for secrets and MACs. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Best-effort zeroisation. JS cannot guarantee copies were not made, but we wipe what we own. */
export function wipe(...arrays: (Uint8Array | undefined | null)[]): void {
  for (const a of arrays) if (a) a.fill(0);
}

export function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}

export function toHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(h: string): Uint8Array {
  if (h.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(h)) throw new Error('invalid hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64_LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < B64.length; i++) B64_LOOKUP[B64.charCodeAt(i)] = i;

/** base64url without padding (RFC 4648 §5). */
export function toB64(b: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  const rem = b.length - i;
  if (rem === 1) {
    const n = b[i] << 16;
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
  } else if (rem === 2) {
    const n = (b[i] << 16) | (b[i + 1] << 8);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63];
  }
  return out;
}

export function fromB64(s: string): Uint8Array {
  if (s.length % 4 === 1) throw new Error('invalid base64url');
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let bits = 0;
  let acc = 0;
  let o = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? B64_LOOKUP[c] : -1;
    if (v < 0) throw new Error('invalid base64url');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  // Reject non-canonical encodings (dangling non-zero bits).
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) throw new Error('invalid base64url');
  return out.subarray(0, o);
}

const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
export function toB32(b: Uint8Array): string {
  let out = '';
  let bits = 0;
  let acc = 0;
  for (const x of b) {
    acc = (acc << 8) | x;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(acc >> bits) & 31];
    }
  }
  if (bits > 0) out += B32[(acc << (5 - bits)) & 31];
  return out;
}

/** Length-prefixed binary writer. Every variable-length field carries a u32 length. */
export class Writer {
  private parts: Uint8Array[] = [];
  u8(n: number): this {
    this.parts.push(Uint8Array.of(n & 0xff));
    return this;
  }
  u32(n: number): this {
    this.parts.push(u32be(n));
    return this;
  }
  fixed(b: Uint8Array, len: number): this {
    if (b.length !== len) throw new Error(`expected ${len} bytes, got ${b.length}`);
    this.parts.push(b);
    return this;
  }
  bytes(b: Uint8Array): this {
    this.parts.push(u32be(b.length), b);
    return this;
  }
  finish(): Uint8Array {
    return concat(...this.parts);
  }
}

export class Reader {
  private off = 0;
  private view: DataView;
  constructor(private buf: Uint8Array) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  private need(n: number) {
    if (this.off + n > this.buf.length) throw new Error('truncated input');
  }
  u8(): number {
    this.need(1);
    return this.buf[this.off++];
  }
  u32(): number {
    this.need(4);
    const v = this.view.getUint32(this.off, false);
    this.off += 4;
    return v;
  }
  fixed(len: number): Uint8Array {
    this.need(len);
    const v = this.buf.slice(this.off, this.off + len);
    this.off += len;
    return v;
  }
  bytes(max = 64 * 1024 * 1024): Uint8Array {
    const len = this.u32();
    if (len > max) throw new Error('field too large');
    return this.fixed(len);
  }
  rest(): Uint8Array {
    const v = this.buf.slice(this.off);
    this.off = this.buf.length;
    return v;
  }
  done(): void {
    if (this.off !== this.buf.length) throw new Error('trailing bytes');
  }
}
