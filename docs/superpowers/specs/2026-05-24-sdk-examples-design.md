# Design: Comprehensive `gmcrypto-core` SDK usage examples

Date: 2026-05-24
Status: Approved (design)
Repo: `gm-crypto-rs-demo` (downstream smoke-test demo for the published `gmcrypto-core` crate)
Depends on: the `=0.12.0` upgrade (PR #1, branch `upgrade-gmcrypto-core-0.12`)

## Goal

Show downstream users how to use **every everyday feature** of the published
`gmcrypto-core` 0.12.0 crate, with runnable, self-verifying examples. Each
example must double as (a) readable documentation that narrates what it does and
why, and (b) a smoke test that asserts its own round-trip so the examples cannot
silently rot.

Non-goal: re-teaching cryptography theory, or exercising low-level/internal
surfaces (see Out of Scope).

## Approach

Add a Cargo **`examples/` directory** — one standalone `.rs` file per primitive
family, run via `cargo run --example <name>`. Rationale:

- Idiomatic Rust: `examples/` is exactly where downstream users look for usage.
- Each file is focused, independently understandable, and independently runnable.
- `cargo build --examples` (and our CI) compiles them; running them asserts behavior.
- Keeps the quickstart CLI (`src/main.rs`) small and unchanged in spirit.

Rejected alternatives: expanding the single CLI with ~16 subcommands (conflates
concerns; awkward binary I/O for keys/IVs/AEAD tags); a markdown-only cookbook
(not compiled or verified, drifts from the real API).

## Shared code: extract `src/lib.rs`

Convert the crate from bin-only to **bin + lib**. Move the existing helpers out
of `src/main.rs` into `src/lib.rs` so both the CLI and all examples reuse them:

- `pub fn encode_hex(bytes: &[u8]) -> String`
- `pub fn decode_hex(input: &str) -> Result<Vec<u8>, String>`
- `pub const SAMPLE_PRIVATE_KEY_HEX: &str`
- `pub fn sample_private_key() -> Sm2PrivateKey` (built via `from_bytes_be`)

`src/main.rs` keeps its CLI logic but imports these from the lib
(`use gm_crypto_rs_demo::{...}`). No behavior change to the CLI; `tests/cli.rs`
stays green.

## Example inventory

All round-trips use `assert!`/`assert_eq!`; a failure panics → non-zero exit, so
CI catches regressions. Each `main()` prints a short narrated walkthrough.

### Default features (no extra dependencies)

1. **`sm3_hashing.rs`**
   - `sm3::hash(b"abc")` equals the GB/T 32905 vector
     `66c7f0f4…b8f4ba8e0`.
   - Stream the same input through `sm3::Sm3::new()` + `update()` + `finalize()`;
     assert it equals the one-shot digest.

2. **`hmac_and_kdf.rs`**
   - `hmac::hmac_sm3(key, msg)` one-shot; reproduce via `HmacSm3::new(key)` +
     `update` + `finalize`; assert equal. Show `HmacSm3::verify` accepts the right
     tag and rejects a wrong one.
   - `kdf::pbkdf2_hmac_sm3(password, salt, iterations, out_len)` derives a key;
     show determinism (same inputs → same key) and that a different salt diverges.

3. **`sm2_sign_verify.rs`** (library-level mirror of the CLI)
   - Build key + public key; `sm2::compute_z(&pub, DEFAULT_SIGNER_ID)` to show the
     Z value that SM2 mixes in.
   - `sign_with_id(...)` then `verify_with_id(...) == true`; show a tampered
     message verifies `false`. Note signatures are randomized (sign twice → differ,
     both verify).

4. **`sm2_encrypt_decrypt.rs`**
   - `sm2::encrypt(&pub, plaintext, &mut rng)` → DER ciphertext (print hex);
     `sm2::decrypt(&priv, &ciphertext)?` returns the plaintext; assert equal.
   - Show encrypting twice yields different ciphertext (fresh nonce), both decrypt.

5. **`sm2_key_encoding.rs`**
   - `pkcs8::encode(&key)` → DER; `pem::encode("PRIVATE KEY", der)` → PEM string;
     `pem::decode` + `pkcs8::decode` round-trips back to an equal key
     (compare `to_bytes_be`).
   - `spki::encode(&pub_point)` for the public key; `spki::decode` round-trips.
   - `sec1::encode/decode` for the EC private key form.
   - Password-encrypted PKCS#8: `pkcs8::encrypt(&key, password, iterations)` then
     `pkcs8::decrypt(der, password)` round-trips; wrong password fails.

6. **`sm4_cbc_ctr.rs`**
   - `sm4::mode_cbc::encrypt(key, iv, pt)` / `decrypt(...)` round-trip.
   - `sm4::mode_ctr::encrypt/decrypt` round-trip.
   - Raw `Sm4Cipher::new(key)` + `encrypt_block`/`decrypt_block` on one block.
   - Use fixed demo key/IV constants (clearly labeled non-secret).

### Feature-gated (declared via `[[example]]` `required-features`)

7. **`sm4_aead.rs`** — requires `sm4-aead`
   - `sm4::mode_gcm::encrypt(key, nonce, aad, pt)` / `decrypt(...)`; assert
     plaintext round-trips and that flipping a ciphertext/tag/AAD byte makes
     `decrypt` fail (authentication). Brief note pointing at `mode_ccm`.

8. **`sm4_xts.rs`** — requires `sm4-xts`
   - `sm4::mode_xts::encrypt/decrypt` over a sector-sized buffer with a tweak;
     assert round-trip.

## Cargo wiring

```toml
[features]
sm4-aead = ["gmcrypto-core/sm4-aead"]
sm4-xts  = ["gmcrypto-core/sm4-xts"]

[[example]]
name = "sm4_aead"
required-features = ["sm4-aead"]

[[example]]
name = "sm4_xts"
required-features = ["sm4-xts"]
```

The default build/feature set stays lean (no `gmcrypto-simd`); the gated examples
opt in explicitly.

## CI

Extend `.github/workflows/ci.yml` (already on Rust 1.85) to run the examples so
they stay healthy, e.g. after `cargo test`:

- Run each default example: `cargo run --example sm3_hashing` … `sm4_cbc_ctr`.
- Run gated examples with features: `cargo run --features sm4-aead --example sm4_aead`,
  `cargo run --features sm4-xts --example sm4_xts`.

(Implementation may use a small shell loop; exact form decided in the plan.)

## README

Add an **Examples** section with a table: example name → what it demonstrates →
run command (including `--features` for gated ones).

## Testing / verification strategy

- Examples self-verify via assertions (the primary signal).
- `tests/cli.rs` remains unchanged and green (CLI behavior preserved).
- CI builds and runs all examples; green CI is the completion gate.
- Manual: `cargo run --example <name>` for each prints a clean narrated walkthrough.

## Out of scope (available on request)

Low-level `mul_g`/`mul_var` scalar multiplication, `sign_raw_with_id`, the
RustCrypto `cipher-traits`/`digest-traits` interop, and the `sm4-bitsliced`
backend toggle — advanced/internal rather than everyday usage.

## Risks / notes

- Exact argument shapes for `pkcs8::encrypt`, `mode_gcm::encrypt`,
  `mode_ccm::encrypt`, and `mode_xts::encrypt` will be confirmed against the
  0.12.0 source during implementation (signatures already located; nonce/AAD/tweak
  parameter details to be pinned per function).
- The private key remains the fixed, public GB/T sample key — never for real data.
- Built on branch `add-sdk-examples` (off `upgrade-gmcrypto-core-0.12`); rebase
  onto `main` after PR #1 merges.
