/**
 * Length hiding.
 *
 *  - Messages: ISO/IEC 7816-4 padding (0x80 then zeros) to a multiple of 256
 *    bytes, so "ok" and a 200-character sentence produce identical ciphertext sizes.
 *  - Attachments: Padmé (Nikitin et al., PETS 2019) rounds sizes so that at most
 *    O(log log n) bits of the length leak, with < 12% overhead.
 */
export const MESSAGE_BLOCK = 256;

export function padMessage(b: Uint8Array, block = MESSAGE_BLOCK): Uint8Array {
  const len = Math.ceil((b.length + 1) / block) * block;
  const out = new Uint8Array(len);
  out.set(b);
  out[b.length] = 0x80;
  return out;
}

export function unpadMessage(b: Uint8Array): Uint8Array {
  for (let i = b.length - 1; i >= 0; i--) {
    if (b[i] === 0x80) return b.slice(0, i);
    if (b[i] !== 0) break;
  }
  throw new Error('invalid padding');
}

export function padme(len: number): number {
  if (len < 2) return len;
  const e = Math.floor(Math.log2(len));
  const s = Math.floor(Math.log2(e)) + 1;
  const lastBits = e - s;
  const unit = 2 ** lastBits;
  return Math.ceil(len / unit) * unit;
}
