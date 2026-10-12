/**
 * Sealed sender envelopes: the server learns WHO a message is for, never who
 * it is FROM. Modeled on Signal's sealed sender v1.
 *
 *   Layer 1: ephemeral X25519 to the recipient's identity key hides the sender's identity.
 *   Layer 2: static-static X25519 (sender identity x recipient identity), chained
 *            with layer 1, authenticates the sender to the recipient only.
 *
 * Envelope = version | ephemeral_pub | len|C1 | len|C2
 */
import { concat, Reader, Writer } from './bytes.js';
import { IdentityKeyPair, PublicIdentity, verifyIdentity } from './keys.js';
import {
  DecryptError,
  dh,
  dhKeyPair,
  hkdf,
  openRandom,
  sealRandom,
  ED25519_PUB_LEN,
  ED25519_SIG_LEN,
  X25519_LEN,
} from './primitives.js';
import { wipe } from './bytes.js';

const VERSION = 1;

export function sealEnvelope(sender: IdentityKeyPair, recipient: PublicIdentity, content: Uint8Array): Uint8Array {
  const eph = dhKeyPair();
  const base = concat(eph.publicKey, recipient.dhPub);
  const k1 = hkdf(dh(eph.secretKey, recipient.dhPub), base, 'OBSCURA_SEALED_SENDER_L1_v1', 64);
  const chainKey = k1.slice(0, 32);
  const c1 = sealRandom(k1.slice(32), concat(sender.sig.publicKey, sender.dh.publicKey, sender.dhSig), base);
  const k2 = hkdf(concat(chainKey, dh(sender.dh.secretKey, recipient.dhPub)), c1, 'OBSCURA_SEALED_SENDER_L2_v1', 32);
  const c2 = sealRandom(k2, content, concat(base, c1));
  wipe(eph.secretKey, k1, chainKey, k2);
  return new Writer().u8(VERSION).fixed(eph.publicKey, X25519_LEN).bytes(c1).bytes(c2).finish();
}

export function openEnvelope(recipient: IdentityKeyPair, envelope: Uint8Array): { sender: PublicIdentity; content: Uint8Array } {
  const r = new Reader(envelope);
  if (r.u8() !== VERSION) throw new DecryptError('unsupported envelope version');
  const ephPub = r.fixed(X25519_LEN);
  const c1 = r.bytes(1024);
  const c2 = r.bytes();
  r.done();
  const base = concat(ephPub, recipient.dh.publicKey);
  const k1 = hkdf(dh(recipient.dh.secretKey, ephPub), base, 'OBSCURA_SEALED_SENDER_L1_v1', 64);
  const chainKey = k1.slice(0, 32);
  const senderBytes = openRandom(k1.slice(32), c1, base);
  if (senderBytes.length !== ED25519_PUB_LEN + X25519_LEN + ED25519_SIG_LEN) throw new DecryptError('bad sender block');
  const sender: PublicIdentity = {
    sigPub: senderBytes.slice(0, 32),
    dhPub: senderBytes.slice(32, 64),
    dhSig: senderBytes.slice(64),
  };
  if (!verifyIdentity(sender)) throw new DecryptError('sender identity signature invalid');
  const k2 = hkdf(concat(chainKey, dh(recipient.dh.secretKey, sender.dhPub)), c1, 'OBSCURA_SEALED_SENDER_L2_v1', 32);
  const content = openRandom(k2, c2, concat(base, c1));
  wipe(k1, chainKey, k2);
  return { sender, content };
}
