# Obscura protocol specification (v1)

This document specifies every cryptographic construction in Obscura precisely
enough to re-implement or audit it. Code references point to
`packages/core/src`.

## 1. Primitives

| Purpose | Primitive | Library |
|---|---|---|
| Key agreement | X25519 (RFC 7748) | `@noble/curves` |
| Signatures | Ed25519, strict RFC 8032 verification (`zip215: false`) | `@noble/curves` |
| Post-quantum KEM | ML-KEM-768 (NIST FIPS 203) | `@noble/post-quantum` |
| AEAD | XChaCha20-Poly1305 | `@noble/ciphers` |
| KDF / MAC / hash | HKDF-SHA-256 (RFC 5869), HMAC-SHA-256, SHA-256, SHA-512 | `@noble/hashes` |
| Password hashing | Argon2id (RFC 9106), 64 MiB, t=3, p=1 | `hash-wasm` |
| Randomness | `crypto.getRandomValues` (WebCrypto CSPRNG) | platform |

No primitive is implemented in this repository. X25519 outputs that are all
zero (low-order peer points) are rejected.

## 2. Identity and account IDs (`keys.ts`)

Each account owns:

* `IK_sig`: Ed25519 key pair.
* `IK_dh`: X25519 key pair, bound to `IK_sig` by
  `dhSig = Sign(IK_sig, "OBSCURA-IDENTITY-DH-v1" || IK_dh.pub)`.

The **account ID** is `base32(SHA-256("OBSCURA-ACCOUNT-ID-v1" || IK_sig.pub)[0..20])`
(32 characters, 160 bits). Because the ID is a commitment to the identity key,
a client that obtained an ID out of band (invite link, QR code) rejects any key
bundle whose `IK_sig` does not hash to that ID. The server therefore cannot
substitute keys for a contact added by link.

## 3. Prekeys

| Key | Type | Signed | Lifetime |
|---|---|---|---|
| Signed prekey `SPK` | X25519 | `Sign(IK_sig, "OBSCURA-SIGNED-PREKEY-v1" \|\| u32(id) \|\| pub)` | rotated every 7 days, last 3 kept |
| One-time prekeys `OPK` | X25519 | no (as in Signal) | single use, 100 kept on server, refilled below 25 |
| PQ one-time prekeys `PQOPK` | ML-KEM-768 | `Sign(IK_sig, "OBSCURA-PQ-PREKEY-v1" \|\| 0x00 \|\| u32(id) \|\| pub)` | single use, 25 kept, refilled below 10 |
| PQ last-resort prekey `PQLR` | ML-KEM-768 | as above with flag `0x01` | rotated every 30 days, last 2 kept |

The server verifies every signature on upload and hands out one-time keys
exactly once (select-and-delete inside one SQLite transaction).

## 4. PQXDH session establishment (`pqxdh.ts`)

Follows Signal's PQXDH specification with `curve = X25519`, `hash = SHA-256`,
`pqkem = ML-KEM-768`.

Alice fetches Bob's bundle, verifies `dhSig`, the SPK signature and the PQPK
signature, and that `accountId(IK_sig_B) == the ID she was given`. Then:

```
EK_A ← X25519 keygen
DH1 = X25519(IK_dh_A, SPK_B)
DH2 = X25519(EK_A,    IK_dh_B)
DH3 = X25519(EK_A,    SPK_B)
DH4 = X25519(EK_A,    OPK_B)          (only if an OPK was provided)
(CT, SS) = ML-KEM-768.Encaps(PQPK_B)
SK = HKDF(salt = 0^32,
          ikm  = 0xFF^32 || DH1 || DH2 || DH3 [|| DH4] || SS,
          info = "OBSCURA_PQXDH_CURVE25519_SHA-256_ML-KEM-768_v1", L = 32)
AD = IK_sig_A || IK_dh_A || IK_sig_B || IK_dh_B
```

The prekey header sent with Alice's messages (until Bob replies) is:

```
u8 version=1 | IK_sig_A(32) | IK_dh_A(32) | dhSig_A(64) | EK_A(32)
| u32 spkId | u32 opkId (0xFFFFFFFF = none) | u32 pqpkId | CT(1088)
```

Bob recomputes `SK`, initialises his ratchet, and decrypts the first message.
**Only after that message authenticates** does he delete the OPK and PQOPK.
A tampered `CT`, `EK` or identity yields a different `SK` and the first AEAD
check fails.

## 5. Hybrid post-quantum Double Ratchet (`ratchet.ts`)

The Signal Double Ratchet with every DH ratchet step augmented by an ML-KEM-768
encapsulation:

```
KDF_RK(rk, dh, ss) = HKDF(salt = rk, ikm = dh || ss, info = I, L = 64) → (rk', ck)
    I = "OBSCURA_RATCHET_HYBRID_X25519_MLKEM768_v1"   when ss present
    I = "OBSCURA_RATCHET_CLASSIC_X25519_v1"           only for the initiator's first chain
KDF_CK(ck)        = (HMAC(ck, 0x02) → ck', HMAC(ck, 0x01) → mk)
Message keys      = HKDF(salt = 0^32, ikm = mk, info = "OBSCURA_MESSAGE_KEYS_v1", L = 56)
                    → key(32) || nonce(24)
```

Each party holds a ratchet X25519 pair `DHs` **and** a ratchet ML-KEM pair
`KEMs`. Headers carry both public keys and the KEM ciphertext that seeded the
sender's current chain:

```
u8 version=1 | DHs.pub(32) | KEMs.pub(1184) | u8 hasCt | [kemCt(1088)] | u32 PN | u32 N
```

On receiving a header with a new `DHs.pub`:

```
ss_r          = ML-KEM.Decaps(header.kemCt, KEMs.sk)          (required, see below)
rk, CKr       = KDF_RK(rk, X25519(DHs, DHr_new), ss_r)
DHs, KEMs     ← fresh key pairs
(ct, ss_s)    = ML-KEM.Encaps(header.kemPub)
rk, CKs       = KDF_RK(rk, X25519(DHs, DHr_new), ss_s)
sendCt        = ct          (repeated in every header of the new chain)
```

* Initialisation: Alice's first chain is derived classically from
  `X25519(DHs_A, SPK_B)` because `SK` already contains the PQXDH ML-KEM
  secret. Bob's state accepts exactly **one** classical step (that chain);
  every later step without a KEM ciphertext is rejected as a downgrade.
* Messages are encrypted with XChaCha20-Poly1305 under `key`/`nonce`, with
  associated data `AD || header`.
* Out-of-order delivery: up to 1000 skipped keys per gap and 2000 in total are
  stored (oldest evicted).
* Every state transition runs on a copy that is committed only if the AEAD tag
  verifies, so forged or corrupted messages cannot desynchronise a session.
* Used message keys and replaced ratchet secrets are zeroised (best effort in JS).

**Properties.** Per-message forward secrecy; post-compromise security after one
round trip; and because each healing step also depends on a fresh ML-KEM
secret, an adversary who records traffic and later gains a quantum computer
cannot recompute post-healing keys by breaking X25519 alone.

## 6. Sealed sender (`sealed.ts`)

```
e ← X25519 keygen;  base = e.pub || IK_dh_R
(chain, k1) = HKDF(salt = base, ikm = X25519(e, IK_dh_R), info = "OBSCURA_SEALED_SENDER_L1_v1", L = 64)
C1 = XChaCha20-Poly1305(k1, random nonce, IK_sig_S || IK_dh_S || dhSig_S, ad = base)
k2 = HKDF(salt = C1, ikm = chain || X25519(IK_dh_S, IK_dh_R), info = "OBSCURA_SEALED_SENDER_L2_v1", L = 32)
C2 = XChaCha20-Poly1305(k2, random nonce, content, ad = base || C1)
envelope = u8 1 | e.pub | len|C1 | len|C2
```

Layer 1 hides the sender; layer 2 authenticates the sender to the recipient
(only the holder of `IK_dh_S` can compute `k2`). `content` is
`0x01 | len|prekeyHeader | len|ratchetMessage` or `0x02 | len|ratchetMessage`.
The server receives only `recipientId`, the envelope, and the recipient's
access key.

## 7. Access control without identity (`server/src/app.ts`)

Each account has a random 128-bit **access key**; the server stores only
`SHA-256(accessKey)`. Delivering an envelope requires presenting the key
(header `x-obscura-access`), compared in constant time. Unknown recipients and
wrong keys get the identical `401`. The key travels in invite links (URL
fragment, never sent to servers) and inside E2EE profile messages. Blocking a
contact rotates the key and sends the new one only to remaining contacts.

## 8. Request authentication (`auth.ts`)

Authenticated endpoints carry
`x-obscura-auth: <accountId>.<unix-ms>.<nonce>.<sig>` with
`sig = Ed25519(IK_sig, "OBSCURA-AUTH-v1\n" METHOD "\n" PATH "\n" ts "\n" nonce "\n" hex(SHA-256(body)))`.
The server enforces ±120 s clock skew and a nonce replay cache. Registration is
signed with the key being registered (proof of possession). WebSocket login
signs a 32-byte server challenge (`"OBSCURA-WS-v1\n" || challenge`).

## 9. Attachments (`attachment.ts`)

```
key ← random 32 bytes;  prefix ← random 16 bytes
header = "OBSA" | u8 1 | u32 chunkSize(65536) | prefix
plaintext = file || zero padding up to Padmé(len(file))
chunk_i   = XChaCha20-Poly1305(key, prefix || u32(i) || u8(last) || 000, chunk, ad = header)
blob      = header || chunk_0 || ... || chunk_n
```

STREAM-style nonces prevent chunk reordering, duplication and truncation. The
message carries `{blobId, deleteToken, key, SHA-256(blob), size, name, mime}`
inside the ratchet; the recipient checks the digest, decrypts, then deletes
the blob from the server with the delete token. Unclaimed blobs expire after
14 days.

## 10. Length hiding (`padding.ts`)

Message plaintexts use ISO/IEC 7816-4 padding to a multiple of 256 bytes.
Attachments use Padmé (≤ 12% overhead, leaks O(log log n) bits of size).

## 11. Local storage (`vault.ts`)

```
masterKey ← random 32 bytes
KEK       = Argon2id(passphrase NFKC, salt(16), m = 64 MiB, t = 3, p = 1)
wrapped   = XChaCha20-Poly1305(KEK, masterKey, ad = "OBSCURA-VAULT-v1|params")
recordKey = HKDF(masterKey, "OBSCURA_STORE_RECORDS_v1");  nameKey = HKDF(masterKey, "OBSCURA_STORE_NAMES_v1")
slot(name)   = "r:" || hex(HMAC(nameKey, name))
record value = XChaCha20-Poly1305(recordKey, value, ad = "OBSCURA-RECORD|" || slot)
```

Record names are hashed (storage layout reveals nothing), and binding the slot
into the AD prevents swapping ciphertexts between records.

## 12. Safety numbers (`safety.ts`)

Per party: `h = SHA-512(0x0001 || IK_sig || IK_dh || accountId)`, then 5200
iterations of `h = SHA-512(h || IK_sig || IK_dh)`; the first 30 bytes become six
5-digit groups (each 40-bit chunk mod 100000). The two 30-digit strings are
sorted and concatenated into the 60-digit safety number shown on both devices.

## 13. Session conflicts

If both users initiate at the same time, each keeps up to five sessions per
contact. Incoming ratchet messages are tried against each (no state mutation on
failure); the session that decrypts is promoted, so both sides converge.
