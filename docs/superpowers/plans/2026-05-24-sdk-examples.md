# gmcrypto-core SDK Examples Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Cargo `examples/` directory that demonstrates every everyday feature of the published `gmcrypto-core` 0.12.0 crate, with narrated, self-verifying example programs.

**Architecture:** Extract shared helpers into `src/lib.rs` (bin + lib crate), then add one example per primitive family. Each example narrates with `println!` and asserts its own round-trips, so running it IS the test. Feature-gated examples (`sm4_aead`, `sm4_xts`) opt in via Cargo `[[example]]` `required-features`. CI runs every example.

**Tech Stack:** Rust 2021, edition-1.85 toolchain, `gmcrypto-core = "=0.12.0"`, `getrandom`/`rand_core` for the OS CSPRNG.

**Note on TDD for examples:** these are demonstration programs, not library code. The "test" for each example is *running it* — its internal `assert!`/`assert_eq!` calls panic (non-zero exit) on any regression. Task 1 (the lib extraction) is anchored by the existing `tests/cli.rs`, which must stay green.

**Branch:** `add-sdk-examples` (based on `upgrade-gmcrypto-core-0.12`). Rebase onto `main` after PR #1 merges.

---

## Task 1: Extract `src/lib.rs` with shared helpers

**Files:**
- Create: `src/lib.rs`
- Modify: `src/main.rs`
- Test: `tests/cli.rs` (existing — must stay green)

- [ ] **Step 1: Create `src/lib.rs`**

```rust
//! Shared helpers for the `gm-crypto-rs-demo` CLI and examples.
//!
//! The private key used throughout the demo is the fixed, **public**
//! GB/T 32918.2 sample key. Never use it for real data.

use gmcrypto_core::sm2::Sm2PrivateKey;
use getrandom::SysRng;
use rand_core::UnwrapErr;

/// Fixed, public GB/T 32918.2 sample private key scalar (big-endian hex).
pub const SAMPLE_PRIVATE_KEY_HEX: &str =
    "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";

/// Build the demo's sample SM2 private key from the fixed sample scalar.
pub fn sample_private_key() -> Sm2PrivateKey {
    let bytes: [u8; 32] = decode_hex(SAMPLE_PRIVATE_KEY_HEX)
        .expect("sample private key hex is valid")
        .try_into()
        .expect("sample private key is 32 bytes");
    Sm2PrivateKey::from_bytes_be(&bytes).expect("sample private key is valid")
}

/// The OS CSPRNG, adapted to the `rand_core` traits the SDK expects.
///
/// `getrandom::SysRng` is infallible on supported targets; `UnwrapErr`
/// adapts its `TryRngCore` impl to the infallible `RngCore` the SM2
/// signing/encryption APIs require.
pub fn os_rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

/// Lowercase-hex encode bytes.
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decode a hex string into bytes.
pub fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("hex input must have an even number of characters".to_owned());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", byte as char)),
    }
}
```

- [ ] **Step 2: Rewrite `src/main.rs` to use the lib**

```rust
use gm_crypto_rs_demo::{decode_hex, encode_hex, os_rng, sample_private_key};
use gmcrypto_core::sm2::{sign_with_id, verify_with_id, Sm2PublicKey, DEFAULT_SIGNER_ID};
use gmcrypto_core::sm3;
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            eprintln!();
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    match args.as_slice() {
        [command, message] if command == "hash" => {
            let digest = sm3::hash(message.as_bytes());
            println!("{}", encode_hex(&digest));
            Ok(ExitCode::SUCCESS)
        }
        [command, message] if command == "sign" => {
            let key = sample_private_key();
            let mut rng = os_rng();
            let signature = sign_with_id(&key, DEFAULT_SIGNER_ID, message.as_bytes(), &mut rng)
                .map_err(|_| "signing failed".to_owned())?;
            println!("{}", encode_hex(&signature));
            Ok(ExitCode::SUCCESS)
        }
        [command, message, signature_hex] if command == "verify" => {
            let signature = decode_hex(signature_hex)?;
            let key = sample_private_key();
            let public = Sm2PublicKey::from_point(key.public_key());
            if verify_with_id(&public, DEFAULT_SIGNER_ID, message.as_bytes(), &signature) {
                println!("valid");
                Ok(ExitCode::SUCCESS)
            } else {
                println!("invalid");
                Ok(ExitCode::from(1))
            }
        }
        [] => Err("missing command".to_owned()),
        [command, ..] => Err(format!("unknown or invalid command: {command}")),
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  gm-crypto-rs-demo hash <message>");
    eprintln!("  gm-crypto-rs-demo sign <message>");
    eprintln!("  gm-crypto-rs-demo verify <message> <der-signature-hex>");
}
```

- [ ] **Step 3: Verify build, lint, and existing tests pass**

Run: `cargo build && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: builds clean, no clippy warnings, `tests/cli.rs` → `2 passed`.

- [ ] **Step 4: Commit**

```bash
git add src/lib.rs src/main.rs
git commit -m "Extract shared helpers into src/lib.rs (bin + lib)"
```

---

## Task 2: `examples/sm3_hashing.rs`

**Files:**
- Create: `examples/sm3_hashing.rs`

- [ ] **Step 1: Write the example**

```rust
//! SM3 hashing — one-shot and streaming.
//! Run: cargo run --example sm3_hashing

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm3::{self, Sm3};

fn main() {
    println!("== SM3 (GB/T 32905-2016): 256-bit hash ==\n");

    // 1) One-shot hash of the standard "abc" test vector.
    let digest = sm3::hash(b"abc");
    println!("sm3(\"abc\") = {}", encode_hex(&digest));
    assert_eq!(
        encode_hex(&digest),
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        "SM3 must match the published GB/T 32905 vector",
    );
    println!("  matches the published GB/T 32905 vector");

    // 2) Streaming the same input in chunks yields the same digest.
    let mut hasher = Sm3::new();
    hasher.update(b"a");
    hasher.update(b"bc");
    let streamed = hasher.finalize();
    assert_eq!(streamed, digest, "streamed digest must equal one-shot");
    println!("  streaming update(\"a\") + update(\"bc\") == one-shot");

    println!("\nOK");
}
```

- [ ] **Step 2: Run it**

Run: `cargo run --example sm3_hashing`
Expected: prints the digest and two confirmations, ends with `OK`, exit 0.

- [ ] **Step 3: Commit**

```bash
git add examples/sm3_hashing.rs
git commit -m "Add SM3 hashing example"
```

---

## Task 3: `examples/hmac_and_kdf.rs`

**Files:**
- Create: `examples/hmac_and_kdf.rs`

- [ ] **Step 1: Write the example**

```rust
//! HMAC-SM3 and PBKDF2-HMAC-SM3.
//! Run: cargo run --example hmac_and_kdf

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::hmac::{hmac_sm3, HmacSm3};
use gmcrypto_core::kdf::pbkdf2_hmac_sm3;

fn main() {
    println!("== HMAC-SM3 and PBKDF2-HMAC-SM3 ==\n");

    let key = b"my mac key";
    let msg = b"authenticated message";

    // 1) One-shot HMAC.
    let tag = hmac_sm3(key, msg);
    println!("hmac_sm3 tag = {}", encode_hex(&tag));

    // 2) Streaming HMAC reproduces the same tag.
    let mut mac = HmacSm3::new(key);
    mac.update(b"authenticated ");
    mac.update(b"message");
    let streamed = mac.finalize();
    assert_eq!(streamed, tag, "streamed HMAC must equal one-shot");
    println!("  streaming HMAC == one-shot");

    // 3) verify() accepts the correct tag and rejects a tampered one.
    let mut ok = HmacSm3::new(key);
    ok.update(msg);
    assert!(ok.verify(&tag), "correct tag must verify");

    let mut wrong = tag;
    wrong[0] ^= 1;
    let mut bad = HmacSm3::new(key);
    bad.update(msg);
    assert!(!bad.verify(&wrong), "tampered tag must be rejected");
    println!("  verify() accepts the right tag, rejects a wrong one");

    // 4) PBKDF2-HMAC-SM3 derives a key from a password.
    let password = b"correct horse battery staple";
    let salt = b"demo-salt";
    let mut derived = [0u8; 32];
    pbkdf2_hmac_sm3(password, salt, 10_000, &mut derived).expect("pbkdf2");
    println!("pbkdf2(10000 iters) = {}", encode_hex(&derived));

    let mut again = [0u8; 32];
    pbkdf2_hmac_sm3(password, salt, 10_000, &mut again).expect("pbkdf2");
    assert_eq!(derived, again, "same inputs must derive the same key");

    let mut other = [0u8; 32];
    pbkdf2_hmac_sm3(password, b"other-salt", 10_000, &mut other).expect("pbkdf2");
    assert_ne!(derived, other, "a different salt must diverge");
    println!("  PBKDF2 is deterministic; a different salt diverges");

    println!("\nOK");
}
```

- [ ] **Step 2: Run it**

Run: `cargo run --example hmac_and_kdf`
Expected: prints tag + derived key, confirmations, ends with `OK`, exit 0.

- [ ] **Step 3: Commit**

```bash
git add examples/hmac_and_kdf.rs
git commit -m "Add HMAC-SM3 + PBKDF2 example"
```

---

## Task 4: `examples/sm2_sign_verify.rs`

**Files:**
- Create: `examples/sm2_sign_verify.rs`

- [ ] **Step 1: Write the example**

```rust
//! SM2 digital signatures — sign_with_id / verify_with_id.
//! Run: cargo run --example sm2_sign_verify

use gm_crypto_rs_demo::{encode_hex, os_rng, sample_private_key};
use gmcrypto_core::sm2::{
    compute_z, sign_with_id, verify_with_id, Sm2PublicKey, DEFAULT_SIGNER_ID,
};

fn main() {
    println!("== SM2 signatures (GB/T 32918.2) ==\n");

    let key = sample_private_key();
    let public = Sm2PublicKey::from_point(key.public_key());
    let message = b"hello";

    // The signer ID feeds the Z value that SM2 mixes into the hash.
    let z = compute_z(&public, DEFAULT_SIGNER_ID);
    println!("Z (from DEFAULT_SIGNER_ID) = {}", encode_hex(&z));

    // Sign twice: signatures differ (fresh random nonce k), both verify.
    let mut rng = os_rng();
    let sig1 = sign_with_id(&key, DEFAULT_SIGNER_ID, message, &mut rng).expect("sign");
    let sig2 = sign_with_id(&key, DEFAULT_SIGNER_ID, message, &mut rng).expect("sign");
    println!("sig1 = {}", encode_hex(&sig1));
    println!("sig2 = {}", encode_hex(&sig2));
    assert_ne!(sig1, sig2, "SM2 signatures are randomized");

    assert!(verify_with_id(&public, DEFAULT_SIGNER_ID, message, &sig1));
    assert!(verify_with_id(&public, DEFAULT_SIGNER_ID, message, &sig2));
    println!("  both independent signatures verify");

    // A tampered message must not verify against the signature.
    assert!(!verify_with_id(&public, DEFAULT_SIGNER_ID, b"h3llo", &sig1));
    println!("  tampered message rejected");

    println!("\nOK");
}
```

- [ ] **Step 2: Run it**

Run: `cargo run --example sm2_sign_verify`
Expected: prints Z + two distinct signatures, confirmations, ends with `OK`, exit 0.

- [ ] **Step 3: Commit**

```bash
git add examples/sm2_sign_verify.rs
git commit -m "Add SM2 sign/verify example"
```

---

## Task 5: `examples/sm2_encrypt_decrypt.rs`

**Files:**
- Create: `examples/sm2_encrypt_decrypt.rs`

- [ ] **Step 1: Write the example**

```rust
//! SM2 public-key encryption — encrypt / decrypt.
//! Run: cargo run --example sm2_encrypt_decrypt

use gm_crypto_rs_demo::{encode_hex, os_rng, sample_private_key};
use gmcrypto_core::sm2::{decrypt, encrypt, Sm2PublicKey};

fn main() {
    println!("== SM2 public-key encryption (GB/T 32918.4) ==\n");

    let key = sample_private_key();
    let public = Sm2PublicKey::from_point(key.public_key());
    let plaintext = b"secret message";

    // Encrypt twice: fresh nonce each time -> different ciphertext, both decrypt.
    let mut rng = os_rng();
    let ct1 = encrypt(&public, plaintext, &mut rng).expect("encrypt");
    let ct2 = encrypt(&public, plaintext, &mut rng).expect("encrypt");
    println!("ciphertext (DER) = {}", encode_hex(&ct1));
    assert_ne!(ct1, ct2, "fresh nonce -> different ciphertext each time");

    let recovered = decrypt(&key, &ct1).expect("decrypt");
    assert_eq!(&recovered[..], &plaintext[..], "decrypt must recover plaintext");
    let recovered2 = decrypt(&key, &ct2).expect("decrypt");
    assert_eq!(&recovered2[..], &plaintext[..], "decrypt must recover plaintext");
    println!("  both ciphertexts decrypt back to the plaintext");

    println!("\nOK");
}
```

- [ ] **Step 2: Run it**

Run: `cargo run --example sm2_encrypt_decrypt`
Expected: prints DER ciphertext, confirmation, ends with `OK`, exit 0.

- [ ] **Step 3: Commit**

```bash
git add examples/sm2_encrypt_decrypt.rs
git commit -m "Add SM2 encrypt/decrypt example"
```

---

## Task 6: `examples/sm2_key_encoding.rs`

**Files:**
- Create: `examples/sm2_key_encoding.rs`

- [ ] **Step 1: Write the example**

```rust
//! SM2 key serialization — PKCS#8, SEC1, SPKI, PEM, encrypted PKCS#8.
//! Run: cargo run --example sm2_key_encoding

use gm_crypto_rs_demo::sample_private_key;
use gmcrypto_core::sm2::Sm2PublicKey;
use gmcrypto_core::{pem, pkcs8, sec1, spki};

fn main() {
    println!("== SM2 key encoding ==\n");

    let key = sample_private_key();
    let expected_scalar = key.to_bytes_be();
    let public = Sm2PublicKey::from_point(key.public_key());

    // --- PKCS#8 (private key) -> DER -> PEM -> DER -> key ---
    let der = pkcs8::encode(&key);
    let pem_str = pem::encode("PRIVATE KEY", &der);
    println!("PKCS#8 PEM:\n{pem_str}");
    let der_back = pem::decode(&pem_str, "PRIVATE KEY").expect("pem decode");
    assert_eq!(der_back, der, "PEM round-trip");
    let key_back = pkcs8::decode(&der_back).expect("pkcs8 decode");
    assert_eq!(key_back.to_bytes_be(), expected_scalar, "PKCS#8 round-trip");
    println!("PKCS#8 -> PEM -> PKCS#8 round-trips");

    // --- SEC1 (EC private key, with embedded public key) ---
    let sec1_der = sec1::encode(&expected_scalar, Some(&public.to_sec1_uncompressed()));
    let ec = sec1::decode(&sec1_der).expect("sec1 decode");
    assert_eq!(ec.scalar_be, expected_scalar, "SEC1 round-trip");
    println!("SEC1 EC private key round-trips");

    // --- SPKI (public key) ---
    let point = key.public_key();
    let spki_der = spki::encode(&point);
    let point_back = spki::decode(&spki_der).expect("spki decode");
    let pub_back = Sm2PublicKey::from_point(point_back);
    assert_eq!(
        pub_back.to_sec1_uncompressed(),
        public.to_sec1_uncompressed(),
        "SPKI round-trip",
    );
    println!("SPKI public key round-trips");

    // --- Encrypted PKCS#8 (password-protected, PBES2/SM4-CBC) ---
    let password = b"demo-password";
    let salt = b"demo-salt-1234567";
    let iv = [0x11u8; 16];
    let enc = pkcs8::encrypt(&key, password, salt, 10_000, &iv).expect("encrypt pkcs8");
    let dec = pkcs8::decrypt(&enc, password).expect("decrypt pkcs8");
    assert_eq!(dec.to_bytes_be(), expected_scalar, "encrypted PKCS#8 round-trip");
    assert!(
        pkcs8::decrypt(&enc, b"wrong-password").is_err(),
        "wrong password must be rejected",
    );
    println!("Encrypted PKCS#8 round-trips; wrong password rejected");

    println!("\nOK");
}
```

- [ ] **Step 2: Run it**

Run: `cargo run --example sm2_key_encoding`
Expected: prints a PEM block + four round-trip confirmations, ends with `OK`, exit 0.

- [ ] **Step 3: Commit**

```bash
git add examples/sm2_key_encoding.rs
git commit -m "Add SM2 key-encoding example (PKCS#8/SEC1/SPKI/PEM)"
```

---

## Task 7: `examples/sm4_cbc_ctr.rs`

**Files:**
- Create: `examples/sm4_cbc_ctr.rs`

- [ ] **Step 1: Write the example**

```rust
//! SM4 block cipher — CBC and CTR modes, plus the raw block primitive.
//! Run: cargo run --example sm4_cbc_ctr

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm4::{mode_cbc, mode_ctr, Sm4Cipher};

fn main() {
    println!("== SM4 (GB/T 32907): 128-bit block cipher ==\n");

    // Fixed, non-secret demo key + IV (16 bytes each).
    let key = [0x01u8; 16];
    let iv = [0x02u8; 16];
    let plaintext = b"SM4 mode demonstration payload";

    // --- CBC (the SDK applies PKCS#7 padding internally) ---
    let ct = mode_cbc::encrypt(&key, &iv, plaintext);
    let pt = mode_cbc::decrypt(&key, &iv, &ct).expect("cbc decrypt");
    assert_eq!(&pt[..], &plaintext[..], "CBC round-trip");
    println!("CBC ciphertext = {}", encode_hex(&ct));
    println!("CBC round-trips");

    // --- CTR (stream cipher; the IV is the initial 16-byte counter) ---
    let ct = mode_ctr::encrypt(&key, &iv, plaintext);
    let pt = mode_ctr::decrypt(&key, &iv, &ct);
    assert_eq!(&pt[..], &plaintext[..], "CTR round-trip");
    println!("CTR round-trips");

    // --- Raw single-block primitive ---
    let cipher = Sm4Cipher::new(&key);
    let mut block = [0u8; 16];
    cipher.encrypt_block(&mut block);
    let enc = block;
    cipher.decrypt_block(&mut block);
    assert_eq!(block, [0u8; 16], "block decrypt must invert encrypt");
    println!("raw block: encrypt then decrypt returns the original (ct = {})", encode_hex(&enc));

    println!("\nOK");
}
```

- [ ] **Step 2: Run it**

Run: `cargo run --example sm4_cbc_ctr`
Expected: prints CBC ciphertext + confirmations, ends with `OK`, exit 0.

- [ ] **Step 3: Commit**

```bash
git add examples/sm4_cbc_ctr.rs
git commit -m "Add SM4 CBC/CTR + raw block example"
```

---

## Task 8: SM4-GCM AEAD example (feature-gated)

**Files:**
- Modify: `Cargo.toml`
- Create: `examples/sm4_aead.rs`

- [ ] **Step 1: Add the feature + example entry to `Cargo.toml`**

Append after the `[dependencies]` block:

```toml
[features]
sm4-aead = ["gmcrypto-core/sm4-aead"]
sm4-xts = ["gmcrypto-core/sm4-xts"]

[[example]]
name = "sm4_aead"
required-features = ["sm4-aead"]

[[example]]
name = "sm4_xts"
required-features = ["sm4-xts"]
```

(Both `[[example]]` entries are added now so Cargo.toml is touched once; the `sm4_xts.rs` file is created in Task 9.)

- [ ] **Step 2: Write `examples/sm4_aead.rs`**

```rust
//! SM4-GCM authenticated encryption (AEAD). Requires the `sm4-aead` feature.
//! Run: cargo run --features sm4-aead --example sm4_aead

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm4::mode_gcm;

fn main() {
    println!("== SM4-GCM authenticated encryption ==\n");

    let key = [0x01u8; 16];
    let nonce = [0x02u8; 12]; // 96-bit nonce (the standard size)
    let aad = b"header-authenticated-not-encrypted";
    let plaintext = b"authenticated and encrypted";

    let (ciphertext, tag) = mode_gcm::encrypt(&key, &nonce, aad, plaintext);
    println!("ciphertext = {}", encode_hex(&ciphertext));
    println!("tag        = {}", encode_hex(&tag));

    // Correct key/nonce/aad/tag -> recovers plaintext.
    let recovered = mode_gcm::decrypt(&key, &nonce, aad, &ciphertext, &tag).expect("auth ok");
    assert_eq!(&recovered[..], &plaintext[..], "GCM round-trip");
    println!("  decrypt with correct inputs succeeds");

    // Any tampering fails authentication (returns None).
    let mut bad_ct = ciphertext.clone();
    bad_ct[0] ^= 1;
    assert!(
        mode_gcm::decrypt(&key, &nonce, aad, &bad_ct, &tag).is_none(),
        "tampered ciphertext must be rejected",
    );

    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    assert!(
        mode_gcm::decrypt(&key, &nonce, aad, &ciphertext, &bad_tag).is_none(),
        "tampered tag must be rejected",
    );

    assert!(
        mode_gcm::decrypt(&key, &nonce, b"different-aad", &ciphertext, &tag).is_none(),
        "changed AAD must be rejected",
    );
    println!("  tampered ciphertext / tag / AAD are all rejected");

    // SM4-CCM is also available under the same feature via
    // gmcrypto_core::sm4::mode_ccm.
    println!("\nOK");
}
```

- [ ] **Step 3: Run it**

Run: `cargo run --features sm4-aead --example sm4_aead`
Expected: prints ciphertext + tag, confirmations, ends with `OK`, exit 0.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml examples/sm4_aead.rs
git commit -m "Add SM4-GCM AEAD example (sm4-aead feature)"
```

---

## Task 9: SM4-XTS example (feature-gated)

**Files:**
- Create: `examples/sm4_xts.rs`

(The `sm4-xts` feature and `[[example]]` entry were added in Task 8.)

- [ ] **Step 1: Write `examples/sm4_xts.rs`**

```rust
//! SM4-XTS sector/disk encryption. Requires the `sm4-xts` feature.
//! Run: cargo run --features sm4-xts --example sm4_xts

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm4::mode_xts;

fn main() {
    println!("== SM4-XTS (sector encryption) ==\n");

    // XTS uses a 32-byte key (two 16-byte subkeys) and a 16-byte tweak
    // (typically the sector number). The data unit must be >= 16 bytes.
    let key = [0x01u8; 32];
    let tweak = [0x02u8; 16];
    let sector = b"a disk sector worth of bytes to encrypt!";

    let ct = mode_xts::encrypt(&key, &tweak, sector).expect("xts encrypt");
    let pt = mode_xts::decrypt(&key, &tweak, &ct).expect("xts decrypt");
    assert_eq!(&pt[..], &sector[..], "XTS round-trip");
    println!("ciphertext = {}", encode_hex(&ct));
    println!("XTS round-trips");

    println!("\nOK");
}
```

- [ ] **Step 2: Run it**

Run: `cargo run --features sm4-xts --example sm4_xts`
Expected: prints ciphertext + confirmation, ends with `OK`, exit 0.

- [ ] **Step 3: Commit**

```bash
git add examples/sm4_xts.rs
git commit -m "Add SM4-XTS example (sm4-xts feature)"
```

---

## Task 10: Run all examples in CI

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Replace `.github/workflows/ci.yml` with the version below**

```yaml
name: CI

on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.85
      - run: cargo test
      - name: Run default-feature examples
        run: |
          for ex in sm3_hashing hmac_and_kdf sm2_sign_verify sm2_encrypt_decrypt sm2_key_encoding sm4_cbc_ctr; do
            echo "=== $ex ==="
            cargo run --quiet --example "$ex"
          done
      - name: Run feature-gated examples
        run: |
          cargo run --quiet --features sm4-aead --example sm4_aead
          cargo run --quiet --features sm4-xts --example sm4_xts
```

- [ ] **Step 2: Verify locally by mirroring the CI steps**

Run:
```bash
for ex in sm3_hashing hmac_and_kdf sm2_sign_verify sm2_encrypt_decrypt sm2_key_encoding sm4_cbc_ctr; do cargo run --quiet --example "$ex" >/dev/null || { echo "FAIL $ex"; break; }; done && \
cargo run --quiet --features sm4-aead --example sm4_aead >/dev/null && \
cargo run --quiet --features sm4-xts --example sm4_xts >/dev/null && echo "ALL EXAMPLES OK"
```
Expected: `ALL EXAMPLES OK`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "Run all examples in CI"
```

---

## Task 11: Document examples in the README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Insert an Examples section before the `## Test` section**

Add this block immediately above the existing `## Test` heading in `README.md`:

```markdown
## Examples

Runnable, self-verifying examples covering the full `gmcrypto-core` surface live
in [`examples/`](examples/). Each narrates what it does and asserts its own
round-trips, so it doubles as a smoke test.

| Example | Demonstrates | Run |
|---|---|---|
| `sm3_hashing` | SM3 one-shot + streaming hasher | `cargo run --example sm3_hashing` |
| `hmac_and_kdf` | HMAC-SM3 (one-shot/streaming/verify) + PBKDF2-HMAC-SM3 | `cargo run --example hmac_and_kdf` |
| `sm2_sign_verify` | SM2 sign/verify, signer-ID `Z`, tamper rejection | `cargo run --example sm2_sign_verify` |
| `sm2_encrypt_decrypt` | SM2 public-key encryption | `cargo run --example sm2_encrypt_decrypt` |
| `sm2_key_encoding` | PKCS#8 / SEC1 / SPKI / PEM + encrypted PKCS#8 | `cargo run --example sm2_key_encoding` |
| `sm4_cbc_ctr` | SM4 CBC + CTR + raw block | `cargo run --example sm4_cbc_ctr` |
| `sm4_aead` | SM4-GCM authenticated encryption | `cargo run --features sm4-aead --example sm4_aead` |
| `sm4_xts` | SM4-XTS sector encryption | `cargo run --features sm4-xts --example sm4_xts` |

The `sm4_aead` and `sm4_xts` examples are gated behind the `sm4-aead` / `sm4-xts`
features respectively.
```

- [ ] **Step 2: Sanity-check the rendered file**

Run: `sed -n '/## Examples/,/## Test/p' README.md`
Expected: the new section prints, immediately followed by the `## Test` heading.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "Document SDK examples in README"
```

---

## Task 12: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Full clean check**

Run:
```bash
cargo build --all-targets --features "sm4-aead sm4-xts" && \
cargo clippy --all-targets --features "sm4-aead sm4-xts" -- -D warnings && \
cargo test
```
Expected: builds clean, no clippy warnings, `tests/cli.rs` → `2 passed`.

- [ ] **Step 2: Run every example end-to-end**

Run:
```bash
for ex in sm3_hashing hmac_and_kdf sm2_sign_verify sm2_encrypt_decrypt sm2_key_encoding sm4_cbc_ctr; do cargo run --quiet --example "$ex"; done
cargo run --quiet --features sm4-aead --example sm4_aead
cargo run --quiet --features sm4-xts --example sm4_xts
```
Expected: every example prints its walkthrough and ends with `OK`.

- [ ] **Step 3: Confirm the tree is clean and the branch is ready**

Run: `git status --short`
Expected: empty (all work committed).

---

## Self-Review

**Spec coverage:**
- SM3 one-shot + streaming → Task 2 ✓
- HMAC-SM3 (one-shot/streaming/verify) + PBKDF2 → Task 3 ✓
- SM2 sign/verify + compute_z + tamper → Task 4 ✓
- SM2 encrypt/decrypt → Task 5 ✓
- Key encoding PKCS#8/SEC1/SPKI/PEM + encrypted PKCS#8 → Task 6 ✓
- SM4 CBC/CTR + raw block → Task 7 ✓
- SM4-GCM AEAD (feature) → Task 8 ✓
- SM4-XTS (feature) → Task 9 ✓
- `src/lib.rs` shared helpers → Task 1 ✓
- Cargo feature wiring → Task 8 ✓
- CI runs all examples → Task 10 ✓
- README table → Task 11 ✓

**Type consistency:** `from_point(ProjectivePoint)` (owned), `public_key() -> ProjectivePoint` (owned), `to_sec1_uncompressed() -> [u8; 65]`, `to_bytes_be() -> [u8; 32]`, `pkcs8::encrypt(&key, pw, salt, u32, &[u8; 16])`, `mode_gcm::encrypt(...) -> (Vec<u8>, [u8; 16])`, `mode_gcm::decrypt(..., &[u8; 16]) -> Option`, `mode_xts::{encrypt,decrypt}(&[u8; 32], &[u8; 16], &[u8]) -> Option`, `pbkdf2_hmac_sm3(.., &mut [u8]) -> Option<()>`, `HmacSm3::verify(self, &[u8; 32]) -> bool` — all consistent with the 0.12.0 source.

**Placeholder scan:** none — every step contains complete code or an exact command.
