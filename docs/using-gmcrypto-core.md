# Using `gmcrypto-core` Correctly — a Practical Guide

> 🌐 **Language / 语言:** **English** | [简体中文](using-gmcrypto-core.zh-CN.md)

> 📖 **Glossary:** Terminology is governed by [`glossary.md`](glossary.md) — used by both this guide and its Chinese counterpart.

A hands-on guide to using the published [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core)
crate (GM/T **SM2 / SM3 / SM4**) the *right* way, from a downstream consumer's
point of view. Every snippet here is drawn from the runnable, self-verifying
programs in [`examples/`](../examples/).

**Who this is for:** Rust developers integrating `gmcrypto-core` who want to call
the SDK correctly the first time and avoid the classic crypto footguns — reused
nonces, weak KDF settings, unauthenticated ciphertext, leaked key material.

**How each section is structured:**

- **What it is** — a line or two on the primitive.
- **Correct usage** — the key calls, with a runnable snippet.
- **Do / Don't** — the rules that actually matter in production.
- **Matching example** — the file under `examples/` and the command to run it.
- **Optional: ecosystem fit** — some sections end with a RustCrypto-trait H3.
  Skip it unless you need a generic bound (`D: Digest`, `Mac`, `BlockCipherEncrypt`, `Aead`).

> ⚠️ **Every key, IV, nonce, salt, and password in this demo (and in this guide)
> is a fixed _public fixture_.** They exist to make snippets reproducible. Never
> reuse them for real data — generate fresh, random secrets in production.

> 🛡️ **SDK stability (1.0+):** As of `gmcrypto-core 1.0.0` (2026-06-01) the SDK
> graduates to SemVer-stable. The **wire format** — the byte representation of
> SM2 signatures, SM2 ciphertexts, and SM4 mode outputs — is **frozen** and
> identical to the prior `0.16.0` line (upstream confirms via KAT + gmssl
> interop 11/11). Breaking *API-shape* changes go through major version bumps,
> enforced upstream by `cargo-semver-checks`; outputs serialized under 0.16.0
> remain readable and verifiable here.

## The golden rules

1. **Use a real CSPRNG.** Source randomness from the OS (`getrandom::SysRng`),
   never a fixed or low-entropy seed. → [§0](#0-getting-started-setup-rng-and-helpers)
2. **Never reuse a nonce / IV / counter under the same key.** This breaks CTR,
   GCM, and CBC in different but fatal ways.
   → [§6](#6-sm4-symmetric-encryption-cbc-and-ctr)–[§8](#8-sm4-xts-disk-and-sector-encryption)
3. **Prefer authenticated encryption.** Reach for SM4-GCM by default; CBC / CTR /
   XTS give confidentiality but **not** integrity.
   → [§7](#7-sm4-authenticated-encryption-gcm-and-ccm)
4. **Tune your KDF.** PBKDF2 iteration counts in the examples are deliberately low
   for speed; production needs far more (OWASP ≥ 600,000).
   → [§2](#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2)
5. **Protect private keys at rest.** Use encrypted PKCS#8 and keep the password
   out of source. → [§5](#5-sm2-key-management-and-serialization)
6. **Compare secrets in constant time.** Use the provided `verify(...)` helpers,
   not `==` on tags.
   → [§2](#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2)

## How to read this guide

Use this as a guided path, not a loose collection of notes. Start with setup,
then move from primitives → keys / signatures / encryption → symmetric modes →
final review → toolkit extras (§10–§12).

Two tracks: the numbered sections are **correct SDK usage**. Optional
RustCrypto-trait H3s at the end of §1, §2, §6, and §7 are **ecosystem fit** —
skip them unless you already write generic code against those traits.

| Stage | Read | What you get |
|---|---|---|
| Foundation | [§0](#0-getting-started-setup-rng-and-helpers) | Dependency setup, OS RNG, shared helpers |
| Hashing and keys | [§1](#1-sm3-hashing) → [§2](#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2) | SM3, HMAC-SM3, PBKDF2, constant-time verification |
| SM2 public-key crypto | [§3](#3-sm2-digital-signatures) → [§5](#5-sm2-key-management-and-serialization) | Signatures, encryption, key formats, encrypted PKCS#8 |
| SM4 symmetric crypto | [§6](#6-sm4-symmetric-encryption-cbc-and-ctr) → [§8](#8-sm4-xts-disk-and-sector-encryption) | CBC, CTR, GCM, CCM, XTS, and mode-specific hazards |
| Review | [§9](#9-doing-crypto-correctly-cross-cutting-review) | Cross-cutting rules for choosing and combining primitives safely |
| Toolkit | [§10](#10-x509-with-sm2-certificates) → [§12](#12-tlcp-toolkit) | X.509 leaf, SM2 key exchange, TLCP primitives |

## Table of contents

0. [Getting started: setup, RNG, and helpers](#0-getting-started-setup-rng-and-helpers)
1. [SM3 hashing](#1-sm3-hashing)
   - [RustCrypto `digest` traits (optional)](#rustcrypto-digest-traits)
2. [Message authentication and key derivation (HMAC-SM3, PBKDF2)](#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2)
   - [RustCrypto `digest::Mac` (optional)](#rustcrypto-digestmac-trait)
3. [SM2 digital signatures](#3-sm2-digital-signatures)
4. [SM2 public-key encryption](#4-sm2-public-key-encryption)
5. [SM2 key management and serialization](#5-sm2-key-management-and-serialization)
6. [SM4 symmetric encryption: CBC and CTR](#6-sm4-symmetric-encryption-cbc-and-ctr)
   - [RustCrypto `cipher` traits (optional)](#rustcrypto-cipher-traits)
7. [SM4 authenticated encryption: GCM and CCM](#7-sm4-authenticated-encryption-gcm-and-ccm)
   - [Length-committed streaming CCM (v1.12)](#length-committed-streaming-ccm-v112)
   - [RustCrypto `aead` traits (optional)](#rustcrypto-aead-traits-v111)
8. [SM4-XTS disk and sector encryption](#8-sm4-xts-disk-and-sector-encryption)
9. [Doing crypto correctly (cross-cutting review)](#9-doing-crypto-correctly-cross-cutting-review)
10. [X.509-with-SM2 certificates](#10-x509-with-sm2-certificates)
11. [SM2 key exchange](#11-sm2-key-exchange)
12. [TLCP toolkit](#12-tlcp-toolkit)

---

## 0. Getting started: setup, RNG, and helpers

The foundation every other section builds on: how to add the crate, get good
randomness, and the small shared helpers this demo uses.

### Add the dependency

This demo pins the published crate **exactly**, the way an outside user consumes
it — never a path / workspace / git dependency:

```toml
[dependencies]
gmcrypto-core = "=1.13.0"
getrandom = { version = "0.4.2", features = ["sys_rng"], default-features = false }
rand_core = "0.10.1"
```

> 📄 **Licence:** as of 1.11.0 `gmcrypto-core` is dual-licensed `MIT OR
> Apache-2.0` (it was `Apache-2.0` only through 1.9.0), and the published
> archive now carries both licence texts — earlier archives carried none.

Optional features turn on the gated capabilities (the default build stays lean).
The fence below is a capability map — comments and all — not a dump of this
demo's `Cargo.toml` (that file is alphabetical and has no comments):

```toml
[features]
sm4-aead         = ["gmcrypto-core/sm4-aead"]          # SM4-GCM / SM4-CCM  (guide §7)
aead-traits      = ["sm4-aead", "gmcrypto-core/aead-traits", "dep:aead"]  # RustCrypto aead 0.6 (guide §7)
digest-traits    = ["gmcrypto-core/digest-traits", "dep:digest"]  # RustCrypto digest 0.11 (guide §1, §2)
cipher-traits    = ["gmcrypto-core/cipher-traits", "dep:cipher"]  # RustCrypto cipher 0.5  (guide §6)
sm4-xts          = ["gmcrypto-core/sm4-xts"]           # SM4-XTS            (guide §8)
sm2-key-exchange = ["gmcrypto-core/sm2-key-exchange"]  # SM2 key exchange   (guide §11)
tlcp             = ["gmcrypto-core/tlcp"]              # TLCP toolkit       (guide §12)
x509             = ["gmcrypto-core/x509"]              # X.509-with-SM2     (guide §10)
```

### Get randomness right

SM2 signing and encryption need a cryptographically secure RNG, and the OS CSPRNG
is the right source. `getrandom::SysRng` implements the *fallible* `TryRngCore`
and is marked `CryptoRng`, so it satisfies the SDK's `TryCryptoRng` bound
directly — since 1.0 no `UnwrapErr` adapter is needed:

```rust
use getrandom::SysRng;

/// The OS CSPRNG, exposed for the SDK's `TryCryptoRng` bound (gmcrypto-core 1.0+).
pub fn os_rng() -> SysRng {
    SysRng
}
```

> - ✅ **Do** create your RNG from the OS on each run.
> - ⚠️ **Don't** hand the SDK a seeded or deterministic RNG (or any fixed value)
>   for real signatures / ciphertext — randomized SM2 depends on fresh entropy
>   every call.

### Load the sample key

The guide reuses one fixed GB/T 32918.2 sample private key. The recommended
constructor is `from_bytes_be` over a 32-byte big-endian scalar, and the matching
public key comes straight off the private key:

```rust
use gmcrypto_core::sm2::Sm2PrivateKey;

let bytes: [u8; 32] = /* decode "3945208F...4DF7C5B8" */;
let key = Sm2PrivateKey::from_bytes_be(&bytes).expect("valid scalar");
let public = key.public_key();
```

> ⚠️ This scalar is a **public** standards fixture. Generate your own private key
> for anything real.

**Matching code:** [`src/lib.rs`](../src/lib.rs) — `os_rng()`,
`sample_private_key()`, `sample_public_key()`, `encode_hex()` / `decode_hex()`.

---

## 1. SM3 hashing

**What it is:** SM3 is the GM/T 256-bit cryptographic hash (GB/T 32905-2016) —
the SM-family counterpart to SHA-256.

### What it's for

Integrity and fingerprinting: checksums, deduplication keys, content addressing,
and as the building block inside HMAC, PBKDF2, and SM2 signatures. A hash gives
you a tamper-evident fingerprint — **not** secrecy and **not** authentication.

### Correct usage

One-shot:

```rust
use gmcrypto_core::sm3;
let digest = sm3::hash(b"abc"); // [u8; 32]
```

Streaming, for data you don't have all at once:

```rust
use gmcrypto_core::sm3::Sm3;
let mut hasher = Sm3::new();
hasher.update(b"a");
hasher.update(b"bc");
let digest = hasher.finalize(); // identical to sm3::hash(b"abc")
```

### Do / Don't

> - ✅ **Do** stream large inputs with `update()` instead of concatenating them in memory.
> - ✅ **Do** use SM3 for integrity checks and as input to HMAC / signatures.
> - ⚠️ **Don't** hash a bare password with SM3 and store it — use PBKDF2-HMAC-SM3 ([§2](#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2)).
> - ⚠️ **Don't** treat a hash as authentication — anyone can recompute it. Use HMAC or a signature to prove origin.

**Matching example:** `cargo run --example sm3_hashing`

<a id="rustcrypto-digest-traits"></a>
### RustCrypto `digest` traits

> 📎 **Optional (ecosystem fit):** skip unless you need a `D: Digest` bound.

`Sm3` also implements the RustCrypto [`digest`](https://docs.rs/digest) 0.11
traits, so code already written against a `D: Digest` bound accepts SM3 next to
SHA-2 with no glue.

> 🧩 **Feature-gated, and `digest` is a companion crate:** `gmcrypto-core` does
> not re-export it, so you name it yourself.

```toml
[dependencies]
gmcrypto-core = { version = "=1.13.0", features = ["digest-traits"] }
digest = { version = "0.11.3", default-features = false, features = ["mac"] }
```

`mac` is not decorative: `digest::Mac` — all of HMAC-SM3's trait surface
([§2](#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2)) — sits
behind it, and it is **not** one of `digest`'s default features.

```rust
use digest::Digest;
use gmcrypto_core::sm3::Sm3;

// Name the trait. `Sm3` has inherent `update` / `finalize` too, and inherent
// methods win: `hasher.finalize()` returns [u8; 32], the trait one Output<Sm3>.
let digest = <Sm3 as Digest>::digest(b"abc");

let mut hasher = <Sm3 as Digest>::new();
Digest::update(&mut hasher, b"a");
Digest::update(&mut hasher, b"bc");
assert_eq!(<Sm3 as Digest>::finalize(hasher), digest);
```

> - ✅ **Do** reach for the traits when you need ecosystem fit — one `D: Digest` bound, many hash functions.
> - ⚠️ **Don't** write `hasher.finalize()` and assume you called the trait. The inherent method wins and the two return different types, so name the trait — here UFCS is a requirement, not a style choice.
> - ℹ️ `digest` 0.11 is pre-1.0, so a breaking `digest` release is **not** covered by `gmcrypto-core`'s SemVer. You bump it yourself.

**Matching example:** `cargo run --features digest-traits --example sm3_digest_traits`

---

## 2. Message authentication and key derivation (HMAC-SM3, PBKDF2)

**What it is:** Two keyed constructions built on SM3. HMAC-SM3 proves a message
came from someone holding the shared key; PBKDF2-HMAC-SM3 stretches a password
into key material.

### HMAC-SM3 — authenticate a message

```rust
use gmcrypto_core::hmac::{hmac_sm3, HmacSm3};

let tag = hmac_sm3(key, msg);        // one-shot -> [u8; 32]

let mut mac = HmacSm3::new(key);     // streaming
mac.update(b"authenticated ");
mac.update(b"message");
let tag = mac.finalize();
```

Verify with the built-in **constant-time** check — never `==`:

```rust
let mut mac = HmacSm3::new(key);
mac.update(msg);
assert!(mac.verify(&tag));            // constant-time comparison
```

> ⚠️ **Don't** compare tags with `tag == expected` — byte-by-byte `==` leaks
> timing and enables forgery. Use `verify()`.

### PBKDF2-HMAC-SM3 — derive a key from a password

```rust
use gmcrypto_core::kdf::pbkdf2_hmac_sm3;
let mut derived = [0u8; 32];
pbkdf2_hmac_sm3(password, salt, 600_000, &mut derived).expect("kdf");
```

Same password + same salt always derive the same key; a different salt diverges.

### Do / Don't

> - ✅ **Do** use a unique, random salt per password (≥ 16 bytes).
> - ✅ **Do** pick a high iteration count — OWASP suggests **≥ 600,000**. (The example uses 10,000 only so it runs fast.)
> - ⚠️ **Don't** reuse one salt across users or hardcode it.
> - ⚠️ **Don't** use a plain SM3 hash for password storage.

**Matching example:** `cargo run --example hmac_and_kdf`

<a id="rustcrypto-digestmac-trait"></a>
### RustCrypto `digest::Mac` trait

> 📎 **Optional (ecosystem fit):** skip unless you need a `digest::Mac` bound.

`HmacSm3` implements `digest::Mac` behind the same `digest-traits` flag and the
same companion-crate dependency as [§1](#1-sm3-hashing). Two things stop it from
being a silent drop-in, and both surface only in generic code.

```rust
use digest::{KeyInit, Mac};
use gmcrypto_core::hmac::HmacSm3;

// `KeySize` is 64 (the SM3 block size), but RFC 2104 keys are any length, so
// `new_from_slice` — not `KeyInit::new` — is the constructor to reach for.
let mac = <HmacSm3 as KeyInit>::new_from_slice(key)?;
let tag = Mac::finalize(Mac::chain_update(mac, msg)).into_bytes();

// verify_slice is the constant-time comparison. Never `==` the tag bytes.
let checked = <HmacSm3 as KeyInit>::new_from_slice(key)?;
Mac::verify_slice(Mac::chain_update(checked, msg), &tag)?;
```

> - ⚠️ **Don't** call `Reset::reset` on an `HmacSm3` — it **panics**, deliberately. The type keeps no copy of the key, so a reset has no defined meaning, and upstream chose a loud panic over a silently wrong no-op. Generic code bounded on `Mac + Reset` is the one place HMAC-SM3 is not interchangeable.
> - ⚠️ **Don't** construct through `KeyInit::new`: it takes a 64-byte `Key<HmacSm3>`, so an ordinary 20- or 32-byte key cannot be passed to it at all.
> - ✅ **Do** verify with `Mac::verify_slice` rather than comparing tag bytes yourself — it is the constant-time path (§9 rule 5).
> - ℹ️ `HmacSm3` implements no `FixedOutputReset`, so `Mac::finalize_reset` does not exist on it. `Sm3` has both; the two types are not symmetric here.

**Matching example:** `cargo run --features digest-traits --example sm3_digest_traits`

---

## 3. SM2 digital signatures

**What it is:** SM2 is the GM/T elliptic-curve cryptosystem (GB/T 32918).
Signatures give you **authenticity** and **non-repudiation**: a holder of the
private key signs; anyone with the public key verifies.

### The signer ID and Z

SM2 folds a signer-identity hash (`Z`) into the message hash. Use
`DEFAULT_SIGNER_ID` unless a protocol mandates a specific ID — and **both** signer
and verifier must use the same one.

```rust
use gmcrypto_core::sm2::{sign_with_id, verify_with_id, DEFAULT_SIGNER_ID};

let mut rng = os_rng();
let sig = sign_with_id(&key, DEFAULT_SIGNER_ID, msg, &mut rng).expect("sign");
let ok  = verify_with_id(&public, DEFAULT_SIGNER_ID, msg, &sig); // -> bool
```

SM2 signatures are **randomized**: signing the same message twice yields two
different (both valid) signatures. That is expected, not a bug.

### Do / Don't

> - ✅ **Do** verify with the *same* signer ID used to sign.
> - ✅ **Do** feed signing a fresh OS RNG ([§0](#0-getting-started-setup-rng-and-helpers)).
> - ⚠️ **Don't** assume signatures are deterministic or compare them for equality.
> - ⚠️ **Don't** confuse signing (authenticity) with encryption (secrecy) — they solve different problems.

**Matching example:** `cargo run --example sm2_sign_verify`

---

## 4. SM2 public-key encryption

**What it is:** SM2 can encrypt to a recipient's public key (GB/T 32918.4). Only
the holder of the matching private key can decrypt.

### Correct usage

```rust
use gmcrypto_core::sm2::{encrypt, decrypt};

let mut rng = os_rng();
let ciphertext = encrypt(&public, plaintext, &mut rng).expect("encrypt"); // DER bytes
let recovered  = decrypt(&key, &ciphertext).expect("decrypt");
```

Encryption is randomized — each call produces different ciphertext. Decryption
verifies the embedded **C3** hash, so a corrupted ciphertext is **rejected**
(returns `Err`) rather than silently mangled.

### When to use it

SM2 encryption is for **small** payloads — typically wrapping a symmetric key or
a short secret. For bulk data use the **hybrid** pattern: generate a random SM4
key, encrypt the data with SM4-GCM ([§7](#7-sm4-authenticated-encryption-gcm-and-ccm)),
then encrypt that SM4 key with SM2.

### Do / Don't

> - ✅ **Do** use SM2 to wrap a symmetric key, then SM4 for the payload.
> - ✅ **Do** treat a decrypt `Err` as "reject this message," not "retry."
> - ⚠️ **Don't** encrypt large blobs directly with SM2 — it's slow and not designed for it.

**Matching example:** `cargo run --example sm2_encrypt_decrypt`

---

## 5. SM2 key management and serialization

**What it is:** How to store, load, and exchange SM2 keys in the standard formats
— and how to protect a private key at rest.

### The formats

- **PKCS#8** — standard private-key container (DER).
- **SEC1** — EC private-key encoding.
- **SPKI** — standard public-key container (DER).
- **PEM** — base64 text wrapper around any of the above.
- **Encrypted PKCS#8** — a password-encrypted private key.

```rust
use gmcrypto_core::{pem, pkcs8, sec1, spki};

// Private key -> PKCS#8 DER -> PEM and back
let der = pkcs8::encode(&key);
let pem_str = pem::encode("PRIVATE KEY", &der);
let der2 = pem::decode(&pem_str, "PRIVATE KEY").expect("pem");
let key2 = pkcs8::decode(&der2).expect("pkcs8");

// Public key -> SPKI DER
let spki_der = spki::encode(&key.public_key());

// Private key at rest -> encrypted PKCS#8 (a wrong password is rejected)
let enc = pkcs8::encrypt(&key, password, salt, 600_000, &iv).expect("encrypt");
let key3 = pkcs8::decrypt(&enc, password).expect("decrypt");
```

### Do / Don't

> - ✅ **Do** store private keys as **encrypted** PKCS#8, with a random salt + IV and a high iteration count.
> - ✅ **Do** distribute public keys as SPKI / PEM for interoperability.
> - ⚠️ **Don't** commit private keys (encrypted or not) or their passwords to source control.
> - ⚠️ **Don't** reuse the encryption salt / IV across keys.

**Matching example:** `cargo run --example sm2_key_encoding`

---

## 6. SM4 symmetric encryption: CBC and CTR

**What it is:** SM4 is the GM/T 128-bit block cipher (GB/T 32907-2016) — the
SM-family counterpart to AES. CBC and CTR are classic modes that provide
**confidentiality only**.

### Correct usage

```rust
use gmcrypto_core::sm4::{mode_cbc, mode_ctr};

// CBC needs a 16-byte IV
let ct = mode_cbc::encrypt(&key, &iv, plaintext);
let pt = mode_cbc::decrypt(&key, &iv, &ct).expect("cbc");

// CTR needs a 16-byte initial counter block
let ct = mode_ctr::encrypt(&key, &counter, plaintext);
let pt = mode_ctr::decrypt(&key, &counter, &ct);
```

The raw single-block primitive (`Sm4Cipher::new(&key).encrypt_block(&mut block)`)
is also available, but you almost always want a mode, not bare blocks.

### The one rule that matters: never reuse the IV / counter under a key

> - ⚠️ **CTR:** reusing a `(key, counter)` pair leaks the XOR of the two plaintexts — catastrophic.
> - ⚠️ **CBC:** a predictable or reused IV enables chosen-plaintext attacks.
> - ✅ **Do** generate a fresh random IV / counter per message and store or send it alongside the ciphertext (it isn't secret).

### Bigger caveat: these are unauthenticated

CBC and CTR don't detect tampering — an attacker can flip bits and decryption
won't complain.

> ✅ **Do** prefer **SM4-GCM** ([§7](#7-sm4-authenticated-encryption-gcm-and-ccm)).
> If you must use CBC / CTR, add an HMAC-SM3 over the ciphertext (encrypt-then-MAC).

**Matching example:** `cargo run --example sm4_cbc_ctr`

<a id="rustcrypto-cipher-traits"></a>
### RustCrypto `cipher` traits

> 📎 **Optional (ecosystem fit):** skip unless you need a `BlockCipherEncrypt` bound.

`Sm4Cipher` implements the RustCrypto [`cipher`](https://docs.rs/cipher) 0.5
block-cipher traits, so a generic construction bounded on `BlockCipherEncrypt`
takes SM4 next to AES.

> 🧩 **Feature-gated, and `cipher` is a companion crate:** `gmcrypto-core` does
> not re-export it, so you name it yourself.

```toml
[dependencies]
gmcrypto-core = { version = "=1.13.0", features = ["cipher-traits"] }
cipher = { version = "0.5.2", default-features = false }
```

```rust
use cipher::array::Array;
use cipher::{BlockCipherEncrypt, KeyInit};
use gmcrypto_core::sm4::Sm4Cipher;

// Name the trait: the inherent `Sm4Cipher::new` takes &[u8; 16] and the
// inherent `encrypt_block` takes &mut [u8; 16], not the trait's Array type.
let cipher = <Sm4Cipher as KeyInit>::new_from_slice(&key)?;
let mut block = Array::from(plaintext_block);
<Sm4Cipher as BlockCipherEncrypt>::encrypt_block(&cipher, &mut block);
```

> - ⚠️ **Don't** encrypt real data through this surface. `encrypt_blocks` over more than one block **is ECB**: equal plaintext blocks give equal ciphertext blocks, which leaks structure. Use SM4-GCM ([§7](#7-sm4-authenticated-encryption-gcm-and-ccm)), or CBC / CTR with a MAC as above.
> - ✅ **Do** reach for the traits to hand SM4 to a generic construction that expects a block cipher — that is the whole purpose.
> - ℹ️ The backend declares `ParBlocksSize = U1`, so the trait's `encrypt_blocks` gets no SIMD fan-out even under upstream's `sm4-bitsliced-simd`. Batching lives on the inherent `Sm4Cipher::encrypt_blocks`.
> - ℹ️ `cipher` 0.5 is pre-1.0, so a breaking `cipher` release is **not** covered by `gmcrypto-core`'s SemVer. You bump it yourself.

**Matching example:** `cargo run --features cipher-traits --example sm4_cipher_traits`

---

## 7. SM4 authenticated encryption: GCM and CCM

**What it is:** SM4-GCM is **authenticated encryption with associated data
(AEAD)**: it encrypts *and* authenticates in one step, so tampering is detected on
decrypt. This should be your default for symmetric encryption.

> 🧩 **Feature-gated:** `gmcrypto-core = { version = "=1.13.0", features = ["sm4-aead"] }`.
> SM4-CCM lives in the same feature via `sm4::mode_ccm`.

### Correct usage

```rust
use gmcrypto_core::sm4::mode_gcm;

let nonce = /* 12 random bytes, unique per key */;
let (ciphertext, tag) = mode_gcm::encrypt(&key, &nonce, aad, plaintext);

// decrypt returns None if the ciphertext, tag, OR aad was altered
let pt = mode_gcm::decrypt(&key, &nonce, aad, &ciphertext, &tag).expect("auth ok");
```

`aad` (associated data) is authenticated but **not** encrypted — use it for
headers / metadata that must be bound to the ciphertext but can travel in the clear.

### Do / Don't

> - ⚠️ **Don't ever reuse a `(key, nonce)` pair.** Nonce reuse in GCM is catastrophic — it can leak the authentication key. Use a fresh 96-bit nonce per message.
> - ✅ **Do** treat a `None` from `decrypt` as "reject" — never fall back to using the bytes anyway.
> - ✅ **Do** put metadata you must trust (version, header, recipient) in `aad`.

**Matching example:** `cargo run --features sm4-aead --example sm4_aead`

**See also:** `cargo run --features sm4-aead --example sm4_ccm` for SM4-CCM, `cargo run --features sm4-aead --example sm4_streaming` for chunked SM4-GCM (Sm4GcmEncryptor / Sm4GcmDecryptor), and `cargo run --features sm4-aead --example sm4_ccm_streaming` for length-committed streaming SM4-CCM (Sm4CcmEncryptor / Sm4CcmDecryptor).

<a id="length-committed-streaming-ccm-v112"></a>
### Length-committed streaming CCM (v1.12)

Since 1.12 SM4-CCM can encrypt in chunks **if** the caller commits to the exact
plaintext length at construction — CCM encodes that length in the first CBC-MAC
block `B0`. Each `update` then emits that chunk's ciphertext immediately
(`O(chunk)` memory). `finalize` returns `None` when the stream was over-fed
(poisoned) or under-fed: a partial stream is never tag-authenticated. That is
deliberately stricter than `Sm4GcmEncryptor`, which still returns a tag after
poison.

`Sm4CcmDecryptor` matches the `Sm4GcmDecryptor` shape: input-incremental,
output-buffered, commit-on-verify. It is **not** output-streaming. Plaintext is
released only from `finalize_verify`.

A `(key, nonce)` pair plus a **different declared length** is still nonce reuse
(the length is part of `B0`). v1.13 additionally zeroizes the SM4 streaming
family on drop; there is no signature change.

```rust
use gmcrypto_core::sm4::Sm4CcmEncryptor;

// CCM encodes plaintext_len in B0: commit it at construction.
let mut enc = Sm4CcmEncryptor::new(&key, &nonce, aad, plaintext.len(), 16)
    .expect("valid nonce and tag length");
let mut ct = Vec::new();
for chunk in plaintext.chunks(16) {
    ct.extend_from_slice(&enc.update(chunk).expect("not over-fed"));
}
let tag = enc.finalize().expect("not under-fed");
```

**Matching example:** `cargo run --features sm4-aead --example sm4_ccm_streaming`

<a id="rustcrypto-aead-traits-v111"></a>
### RustCrypto `aead` traits (v1.11)

> 📎 **Optional (ecosystem fit):** skip unless you need an `Aead` / `AeadInOut` bound.

Since 1.11 the same two ciphers are also available as RustCrypto
[`aead`](https://docs.rs/aead) 0.6 types, so generic code already bounded on
`AeadInOut` (or the blanket `Aead`) accepts SM4-GCM and SM4-CCM next to AES-GCM
and ChaCha20Poly1305 with no glue.

> 🧩 **Feature-gated, and `aead` is a companion crate:** `gmcrypto-core` does
> not re-export it, so you name it yourself.

```toml
[dependencies]
gmcrypto-core = { version = "=1.13.0", features = ["aead-traits"] }
aead = { version = "0.6.1", default-features = false, features = ["alloc"] }
```

`alloc` is not decorative: the `Vec`-returning `aead::Aead` and `impl Buffer for
Vec<u8>` are both behind it, and it is **not** one of `aead`'s default features.

```rust
use aead::consts::{U4, U7};
use aead::{Aead, KeyInit, Payload};
use gmcrypto_core::sm4::{Sm4Ccm, Sm4Gcm};

let cipher = <Sm4Gcm as KeyInit>::new_from_slice(&key)?;

// one Vec holding ciphertext || tag — byte-identical to mode_gcm::encrypt
let wire = <Sm4Gcm as Aead>::encrypt(&cipher, &nonce.into(), Payload { msg: pt, aad })?;
let pt = <Sm4Gcm as Aead>::decrypt(&cipher, &nonce.into(), Payload { msg: &wire, aad })?;

// CCM's sizes are type parameters. Sm4Ccm defaults to a 16-byte tag and a
// 12-byte nonce; an illegal pair is a compile error, not a runtime None.
let short = <Sm4Ccm<U4, U7> as KeyInit>::new_from_slice(&key)?;
```

> - ✅ **Do** reach for the traits when you need ecosystem fit — one bound, many ciphers.
> - ⚠️ **Don't** reach for them on a hot path: each call re-runs the SM4 key schedule, and the `*_in_place` methods still allocate. `mode_gcm` / `mode_ccm` stay the fast path.
> - ⚠️ **Don't** expect detail from a failure: everything — bad tag, bad key length, oversized message — collapses to one opaque `aead::Error`. The inherent API's `None` is no more informative, but at least the two cases live in different functions.
> - ⚠️ `aead` 0.6 is pre-1.0, so a breaking `aead` release is **not** covered by `gmcrypto-core`'s SemVer. You bump it yourself.
> - ℹ️ `Sm4Gcm` is fixed at the canonical profile (12-byte nonce, 16-byte postfix tag). Truncated GCM tags and other nonce lengths stay on `mode_gcm`. SM4-XTS gets no `aead` type at all — it is confidentiality-only and must never be presented as an AEAD.

**Matching example:** `cargo run --features aead-traits --example sm4_aead_traits`

---

## 8. SM4-XTS disk and sector encryption

**What it is:** SM4-XTS is the mode for **data at rest** on block storage —
full-disk encryption, sectors, files — where the ciphertext can't grow. Each unit
is encrypted with a **tweak**, typically its sector number.

> 🧩 **Feature-gated:** `features = ["sm4-xts"]`.

### Correct usage

```rust
use gmcrypto_core::sm4::mode_xts;

// 32-byte key = TWO distinct 16-byte subkeys; identical halves are rejected (GB/T 17964)
let ct = mode_xts::encrypt(&key32, &tweak, sector).expect("xts");   // data unit >= 16 bytes
let pt = mode_xts::decrypt(&key32, &tweak, &ct).expect("xts");
```

### Do / Don't

> - ⚠️ **XTS is NOT authenticated.** Decrypting with the wrong tweak (or tampered ciphertext) returns *garbage*, not an error. It protects confidentiality on disk, not integrity.
> - ✅ **Do** use the storage position (sector index) as the tweak.
> - ✅ **Do** ensure the two key halves differ.
> - ⚠️ **Don't** use XTS for messages in transit — use SM4-GCM ([§7](#7-sm4-authenticated-encryption-gcm-and-ccm)) when you need tamper detection.

**Matching example:** `cargo run --features sm4-xts --example sm4_xts`

---

## 9. Doing crypto correctly (cross-cutting review)

The principles that span every primitive. If you remember nothing else from this
guide, remember these.

### 1. Randomness

Always source keys, nonces, IVs, and salts from the OS CSPRNG. In this SDK that's
`getrandom::SysRng`, used directly
([§0](#0-getting-started-setup-rng-and-helpers)). Never a constant, never a
low-entropy seed.

### 2. Uniqueness of nonces / IVs / counters

| Mode | Unique value needed | What reuse costs |
|---|---|---|
| SM4-CTR | initial counter | XOR of the two plaintexts leaks |
| SM4-CBC | IV | chosen-plaintext weaknesses |
| SM4-GCM | 96-bit nonce | **catastrophic** — can leak the auth key |
| SM4-XTS | tweak (per sector) | identical blocks leak across sectors |

Generate fresh per message; transmit / store the nonce or IV next to the
ciphertext — they aren't secret.

### 3. Authentication

Encryption ≠ integrity. CBC, CTR, and XTS are unauthenticated. Default to
**SM4-GCM**; otherwise encrypt-then-MAC with HMAC-SM3. Always treat a failed auth
(`Err` / `None` / `false`) as "reject," never "use the bytes anyway."

### 4. Key derivation and passwords

Never store raw-hashed passwords. Use PBKDF2-HMAC-SM3 with a unique random salt
and a high iteration count (OWASP ≥ 600,000). The demo's 10,000 is for speed only.

### 5. Constant-time comparison

Compare MACs / tags with the provided `verify()` (constant-time), not `==`.

### 6. Key management

Keep private keys in encrypted PKCS#8, with the password outside source control.
Share public keys as SPKI / PEM. Rotate keys; don't reuse one key across unrelated
purposes.

### 7. Pick the right tool

| Goal | Use |
|---|---|
| Fingerprint / integrity check | SM3 |
| Prove a message's origin (shared key) | HMAC-SM3 |
| Prove origin (publicly verifiable) | SM2 signature |
| Encrypt a small secret to someone | SM2 encryption |
| Encrypt bulk data (with integrity) | SM4-GCM |
| Encrypt data at rest on disk | SM4-XTS |
| Turn a password into a key | PBKDF2-HMAC-SM3 |
| Parse / signature-check an SM2 certificate | `x509` (not a trust decision) |
| Agree a shared secret (two parties) | SM2 key exchange (`sm2-key-exchange`); prefer confirmation — not SM2 encryption |
| TLCP session keys / records / cert pair | TLCP toolkit (`tlcp`; pair also needs `x509`) — not a protocol engine |

> ⚠️ **Remember:** every key, nonce, salt, and password in this demo is a public
> fixture. Production code must generate its own.

---

## 10. X.509-with-SM2 certificates

**What it is:** parse an X.509 v3 certificate in the GM/T 0015 (SM2-with-SM3)
profile and check its signature against a caller-supplied issuer key. This is
**not** a PKI validator: no chain, no clock, no hostname, no revocation.

> 🧩 **Feature-gated:** `features = ["x509"]`. Independent of `tlcp`.

A `Some` from `Certificate::from_der` means only "these bytes frame as a
well-formed cert in the accepted profile." A `true` from `verify_signature`
means only "this issuer key signed these `tbsCertificate` bytes." Neither is a
trust decision, and neither means "this is the peer."

### Correct usage

```rust
use gmcrypto_core::x509::Certificate;

let ca = Certificate::from_der(ca_der).expect("CA parses");
let leaf = Certificate::from_der(leaf_der).expect("leaf parses");

assert!(ca.is_self_issued());
assert!(ca.verify_signature(&ca.subject_public_key()));
assert!(leaf.verify_signature(&ca.subject_public_key()));
assert!(!leaf.verify_signature(&leaf.subject_public_key()));
```

Truncated input and trailing junk return `None` (never panic). A flipped byte in
the DER either fails to parse or fails to verify — it must not both parse and
verify. Wrong signer IDs fail (`verify_signature` uses the GM/T default ID
`"1234567812345678"`; use `verify_signature_with_id` when CA practice differs).

### Do / Don't

> - ⚠️ **Don't** treat `true` as "this is the peer." That is endpoint authentication, and you own it.
> - ⚠️ **Don't** treat parse as a trust decision. Pin trust anchors in a store you control.
> - ✅ **Do** compare issuer / subject `Name`s as raw DER (`issuer_raw` / `subject_raw`); the crate does not interpret DN strings.
> - ✅ **Do** keep your own clock if you need a validity window (`not_before` / `not_after` are exposed; the library has none).
> - ℹ️ TLCP's [sign, enc] certificate-pair check is [§12](#12-tlcp-toolkit) (`verify_pair`, needs `tlcp` **and** `x509`). This section does not call `verify_chain`.

**Matching example:** `cargo run --features x509 --example x509_sm2`

---

## 11. SM2 key exchange

**What it is:** the GM/T 0003.3 (≡ GB/T 32918.3) two-party key-exchange protocol.
Each side holds a static SM2 key, samples an ephemeral, and derives a shared
secret of caller-chosen length. The default flow includes key confirmation
(`S_A` / `S_B`); a no-confirmation pair of completers exists for protocols that
confirm the key themselves (TLCP ECDHE suites do this via Finished).

> 🧩 **Feature-gated:** `features = ["sm2-key-exchange"]`.

Every handshake step **consumes** its state value: an ephemeral cannot be reused,
and neither side can touch `K` before the peer's confirmation tag verifies
(confirmed flow). Generate fresh static keys for real use; the demo mixes a
fixture with an OS-sampled key only to show both constructors.

### Correct usage

Confirmed (prefer this unless the surrounding protocol supplies confirmation):

```rust
use gmcrypto_core::sm2::key_exchange::{Sm2KxInitiator, Sm2KxResponder};

let init = Sm2KxInitiator::new(&d_a, &p_b, id_a, id_b, 16).expect("kx");
let (r_a, init_waiting) = init.produce_ephemeral(&mut rng).expect("R_A");
let resp = Sm2KxResponder::new(&d_b, &p_a, id_a, id_b, 16).expect("kx");
let (r_b, s_b, resp_waiting) = resp.respond(&r_a, &mut rng).expect("R_B");
let (key_a, s_a) = init_waiting.confirm(&r_b, &s_b).expect("S_B");
let key_b = resp_waiting.finish(&s_a).expect("S_A");
assert_eq!(key_a.as_bytes(), key_b.as_bytes());
```

No-confirmation (TLCP ECDHE shape — the peer has proven nothing when these
return; a key mismatch surfaces later in the protocol):

```rust
let (r_b, key_b) = resp
    .respond_without_key_confirmation(&r_a, &mut rng)
    .expect("no-conf");
let key_a = init_waiting
    .derive_without_key_confirmation(&r_b)
    .expect("no-conf");
assert_eq!(key_a.as_bytes(), key_b.as_bytes());
```

### Do / Don't

> - ✅ **Do** prefer the confirmed flow. Reach for the no-confirmation completers only when the protocol itself confirms the key (TLCP Finished, [§12](#12-tlcp-toolkit)).
> - ✅ **Do** sample ephemerals from the OS CSPRNG and let consume-on-transition prevent reuse.
> - ⚠️ **Don't** wrap a secret for one recipient with key exchange — that is SM2 encryption ([§4](#4-sm2-public-key-encryption)).
> - ⚠️ **Don't** reuse an ephemeral across handshakes. Identity strings (`id_a`, `id_b`) must be identical on both sides.

**Matching example:** `cargo run --features sm2-key-exchange --example sm2_key_exchange`

---

## 12. TLCP toolkit

**What it is:** building blocks for GB/T 38636 TLCP — the TLS-1.2-style PRF
(key schedule), per-record protect/deprotect, and the [sign, enc] certificate-pair
check. **Not a protocol engine:** no handshake state machine, no 5-byte header
framing, no I/O. You own sequence numbers, transcript hashing, and "is this the
peer I dialed."

> 🧩 **Feature-gated:** `features = ["tlcp"]`. Certificate-pair verify also needs
> `x509`. SM4-GCM records additionally need `sm4-aead`.

### Correct usage

Key schedule (master secret, then a caller-carved key block, then Finished
`verify_data`):

```rust
use gmcrypto_core::tlcp::key_schedule::{
    derive_key_block, derive_master_secret, finished_verify_data, TlcpRole,
    FINISHED_VERIFY_DATA_LEN, MASTER_SECRET_LEN,
};

let mut master = [0u8; MASTER_SECRET_LEN];
derive_master_secret(&pre_master, &client_random, &server_random, &mut master);

let mut key_block = [0u8; 40]; // GCM suite: 2 * (16-byte key + 4-byte IV salt)
derive_key_block(&master, &client_random, &server_random, &mut key_block);

let mut client_finished = [0u8; FINISHED_VERIFY_DATA_LEN];
finished_verify_data(&master, TlcpRole::Client, &transcript_hash, &mut client_finished);
```

Record protection. `type` / `version` / `seq` are explicit because they are bound
into the MAC (CBC) / AAD (GCM). Never reuse a `(direction_key, seq)` pair.
`deprotect_cbc` is Lucky13-hardened: one constant-time `None`, and no plaintext
escapes on failure.

```rust
use gmcrypto_core::tlcp::record::{
    deprotect_cbc, protect_cbc, RecordKeysCbc, TLCP_RECORD_VERSION,
};

let record = protect_cbc(
    &client_keys,
    seq,
    content_type,
    TLCP_RECORD_VERSION,
    plaintext,
    &mut rng,
)
.expect("within 2^14");
let pt = deprotect_cbc(&client_keys, seq, content_type, TLCP_RECORD_VERSION, &record)
    .expect("authentic");
```

Certificate pair. Chains are **leaf-first**. `true` is structural link-to-anchor
+ role `keyUsage` + pair binding — **not** endpoint authentication. `at_time` is
caller-supplied (`X509Time`); the library has no clock.

```rust
use gmcrypto_core::tlcp::chain::verify_pair;

assert!(verify_pair(&[sign, int], &[enc, int], &[root], None));
assert!(!verify_pair(&[enc, int], &[sign, int], &[root], None)); // swapped roles
assert!(!verify_pair(&[sign, int], &[enc, int], &[], None));     // no anchor
```

### Do / Don't

> - ⚠️ **Don't** treat these APIs as "implement TLCP." They are primitives; the surrounding protocol is yours.
> - ⚠️ **Don't** treat `verify_pair == true` as hostname / endpoint authentication. Compare `subject_raw` yourself.
> - ✅ **Do** enable `sm4-aead` for the GCM record suite; CBC is available under bare `tlcp`.
> - ✅ **Do** advance `seq` per record. Reusing `(key, seq)` under GCM repeats the nonce and is catastrophic.
> - ✅ **Do** establish a fresh 48-byte pre-master secret per handshake (SM2 encryption or SM2-KX, [§11](#11-sm2-key-exchange)).

**Matching examples:** `cargo run --features tlcp --example tlcp_key_schedule`,
`cargo run --features tlcp --example tlcp_record`,
`cargo run --features tlcp,x509 --example tlcp_chain`
