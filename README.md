# gm-crypto-rs-demo

> 🌐 [English](README.md) · [简体中文](README.zh-CN.md) · [📚 Guide](docs/using-gmcrypto-core.md) · [📚 中文指南](docs/using-gmcrypto-core.zh-CN.md)

Runnable cookbook for the published [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core)
crate (GM/T **SM2 / SM3 / SM4**). Clone it, run the tour, copy a snippet.

It pins the crates.io release exactly — never a path or workspace checkout —
so it also smoke-tests what an outside user actually gets:

```toml
gmcrypto-core = "=1.13.0"
```

All sample keys, IVs, passwords, signer IDs, and outputs in this repository
are public demo material. Do not use them for real data.

## Start here

Install Git and Rust 1.85 or newer (including Cargo). The shell examples use
Bash/Zsh syntax. Clone the repository and run the tour:

```bash
git clone https://github.com/frankxue831/gm-crypto-rs-demo.git
cd gm-crypto-rs-demo
cargo run -- tour
```

Run the remaining commands from this directory. The first run downloads and
compiles the dependencies.

## Try the CLI

CLI subcommands below are `cargo run -- <subcommand>`.

SM2 commands use the bundled sample key pair. SM4 commands use the bundled
key and IV. These commands do not accept your own keys; the examples show
how to call the SDK with explicit key arguments.

Hash a message with SM3:

```bash
cargo run -- hash abc
```

Sign and verify with a custom SM2 signer ID:

```bash
sig=$(cargo run --quiet -- sign hello --id alice@example)
cargo run -- verify hello "$sig" --id alice@example
```

Encrypt and decrypt with SM2:

```bash
ct=$(cargo run --quiet -- encrypt "secret message")
cargo run -- decrypt "$ct"
```

Encrypt and decrypt with SM4-CBC:

```bash
sm4=$(cargo run --quiet -- sm4-encrypt "bulk data")
cargo run -- sm4-decrypt "$sm4"
```

Compute HMAC-SM3:

```bash
cargo run -- hmac 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b "Hi There"
```

Derive key material with PBKDF2-HMAC-SM3:

```bash
cargo run -- pbkdf2 password 73616c74 10000 32
```

## Capability map

What this demo exposes, grouped by how you reach it. Gated rows need `--features`
(see [Cookbook examples](#cookbook-examples)). The cross-cutting checklist is [guide §9](docs/using-gmcrypto-core.md#9-doing-crypto-correctly-cross-cutting-review), not a separate example.

### Default capabilities

No feature flag. The CLI covers the operations noted below; the examples
demonstrate the fuller SDK APIs.

| Use case | CLI | Example | Guide |
| --- | --- | --- | --- |
| SM3 hashing (GB/T 32905) | `hash <msg>` | [`sm3_hashing`](examples/sm3_hashing.rs) | [§1](docs/using-gmcrypto-core.md#1-sm3-hashing) |
| HMAC-SM3 message authentication | `hmac <key-hex> <msg>` | [`hmac_and_kdf`](examples/hmac_and_kdf.rs) | [§2](docs/using-gmcrypto-core.md#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2) |
| PBKDF2-HMAC-SM3 password stretching | `pbkdf2 <pw> <salt-hex> <iter> <len>` | [`hmac_and_kdf`](examples/hmac_and_kdf.rs) | [§2](docs/using-gmcrypto-core.md#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2) |
| SM2 digital signatures (GB/T 32918.2) | `sign` / `verify` | [`sm2_sign_verify`](examples/sm2_sign_verify.rs) | [§3](docs/using-gmcrypto-core.md#3-sm2-digital-signatures) |
| SM2 public-key encryption (GB/T 32918.4) | `encrypt` / `decrypt` | [`sm2_encrypt_decrypt`](examples/sm2_encrypt_decrypt.rs) | [§4](docs/using-gmcrypto-core.md#4-sm2-public-key-encryption) |
| SM2 key encoding (PKCS#8 / SEC1 / SPKI / PEM) | `key-info` (SEC1/SPKI public key, including PEM; PKCS#8 in example only) | [`sm2_key_encoding`](examples/sm2_key_encoding.rs) | [§5](docs/using-gmcrypto-core.md#5-sm2-key-management-and-serialization) |
| SM4-CBC / CTR symmetric encryption | `sm4-encrypt` / `sm4-decrypt` (CBC only; CTR in example only) | [`sm4_cbc_ctr`](examples/sm4_cbc_ctr.rs) | [§6](docs/using-gmcrypto-core.md#6-sm4-symmetric-encryption-cbc-and-ctr) |

### Feature-gated modes

| Use case | Example | Feature | Guide |
| --- | --- | --- | --- |
| SM4-GCM authenticated encryption (AEAD) | [`sm4_aead`](examples/sm4_aead.rs) | `sm4-aead` | [§7](docs/using-gmcrypto-core.md#7-sm4-authenticated-encryption-gcm-and-ccm) |
| SM4-CCM authenticated encryption (constrained AEAD) | [`sm4_ccm`](examples/sm4_ccm.rs) | `sm4-aead` | [§7](docs/using-gmcrypto-core.md#7-sm4-authenticated-encryption-gcm-and-ccm) |
| SM4-GCM streaming (chunked AEAD) | [`sm4_streaming`](examples/sm4_streaming.rs) | `sm4-aead` | [§7](docs/using-gmcrypto-core.md#7-sm4-authenticated-encryption-gcm-and-ccm) |
| SM4-CCM streaming (length-committed AEAD) | [`sm4_ccm_streaming`](examples/sm4_ccm_streaming.rs) | `sm4-aead` | [§7](docs/using-gmcrypto-core.md#7-sm4-authenticated-encryption-gcm-and-ccm) |
| SM2 key exchange (GB/T 32918.3, confirmed + no-confirmation) | [`sm2_key_exchange`](examples/sm2_key_exchange.rs) | `sm2-key-exchange` | [§11](docs/using-gmcrypto-core.md#11-sm2-key-exchange) |
| TLCP key schedule (GB/T 38636 PRF) | [`tlcp_key_schedule`](examples/tlcp_key_schedule.rs) | `tlcp` | [§12](docs/using-gmcrypto-core.md#12-tlcp-toolkit) |
| TLCP record protection (GB/T 38636 §6.3) | [`tlcp_record`](examples/tlcp_record.rs) | `tlcp` | [§12](docs/using-gmcrypto-core.md#12-tlcp-toolkit) |
| TLCP certificate pair (GB/T 38636 §4) | [`tlcp_chain`](examples/tlcp_chain.rs) | `tlcp`, `x509` | [§12](docs/using-gmcrypto-core.md#12-tlcp-toolkit) |
| X.509-with-SM2 leaf parse / signature check | [`x509_sm2`](examples/x509_sm2.rs) | `x509` | [§10](docs/using-gmcrypto-core.md#10-x509-with-sm2-certificates) |
| SM4-XTS sector / disk encryption | [`sm4_xts`](examples/sm4_xts.rs) | `sm4-xts` | [§8](docs/using-gmcrypto-core.md#8-sm4-xts-disk-and-sector-encryption) |

### Ecosystem traits

Skip this group unless you already write generic RustCrypto code (`D: Digest`,
`BlockCipherEncrypt`, `Aead`). The inherent APIs above are the default.

| Use case | Example | Feature | Guide |
| --- | --- | --- | --- |
| SM3 / HMAC-SM3 via `digest` 0.11 (`Sm3` / `HmacSm3`) | [`sm3_digest_traits`](examples/sm3_digest_traits.rs) | `digest-traits` | [§1](docs/using-gmcrypto-core.md#1-sm3-hashing), [§2](docs/using-gmcrypto-core.md#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2) |
| SM4 block primitive via `cipher` 0.5 (`Sm4Cipher`) | [`sm4_cipher_traits`](examples/sm4_cipher_traits.rs) | `cipher-traits` | [§6](docs/using-gmcrypto-core.md#6-sm4-symmetric-encryption-cbc-and-ctr) |
| SM4-GCM / CCM via `aead` 0.6 (`Sm4Gcm` / `Sm4Ccm`) | [`sm4_aead_traits`](examples/sm4_aead_traits.rs) | `aead-traits` | [§7](docs/using-gmcrypto-core.md#7-sm4-authenticated-encryption-gcm-and-ccm) |

## Cookbook examples

Each file under [`examples/`](examples/) is a small standalone program that
narrates what it does and asserts its own round-trips. CI runs all of them.

### Default examples

| Example | Demonstrates | Run |
|---|---|---|
| [`sm3_hashing`](examples/sm3_hashing.rs) | SM3 one-shot + streaming hasher | `cargo run --example sm3_hashing` |
| [`hmac_and_kdf`](examples/hmac_and_kdf.rs) | HMAC-SM3 (one-shot/streaming/verify) + PBKDF2-HMAC-SM3 | `cargo run --example hmac_and_kdf` |
| [`sm2_sign_verify`](examples/sm2_sign_verify.rs) | SM2 sign/verify, signer-ID `Z`, tamper rejection | `cargo run --example sm2_sign_verify` |
| [`sm2_encrypt_decrypt`](examples/sm2_encrypt_decrypt.rs) | SM2 public-key encryption | `cargo run --example sm2_encrypt_decrypt` |
| [`sm2_key_encoding`](examples/sm2_key_encoding.rs) | PKCS#8 / SEC1 / SPKI / PEM + encrypted PKCS#8 | `cargo run --example sm2_key_encoding` |
| [`sm4_cbc_ctr`](examples/sm4_cbc_ctr.rs) | SM4 CBC + CTR + raw block | `cargo run --example sm4_cbc_ctr` |

### Feature-gated examples

| Example | Demonstrates | Run |
|---|---|---|
| [`sm4_aead`](examples/sm4_aead.rs) | SM4-GCM authenticated encryption | `cargo run --features sm4-aead --example sm4_aead` |
| [`sm4_ccm`](examples/sm4_ccm.rs) | SM4-CCM in two nonce/tag shapes (12+16, 13+8) | `cargo run --features sm4-aead --example sm4_ccm` |
| [`sm4_streaming`](examples/sm4_streaming.rs) | SM4-GCM streaming (chunked encrypt/decrypt) | `cargo run --features sm4-aead --example sm4_streaming` |
| [`sm4_ccm_streaming`](examples/sm4_ccm_streaming.rs) | SM4-CCM streaming (length-committed encrypt / buffered decrypt) | `cargo run --features sm4-aead --example sm4_ccm_streaming` |
| [`sm2_key_exchange`](examples/sm2_key_exchange.rs) | SM2 key exchange — confirmed + no-confirmation (TLCP) variants | `cargo run --features sm2-key-exchange --example sm2_key_exchange` |
| [`tlcp_key_schedule`](examples/tlcp_key_schedule.rs) | TLCP PRF: master secret, key block, Finished `verify_data` | `cargo run --features tlcp --example tlcp_key_schedule` |
| [`tlcp_record`](examples/tlcp_record.rs) | TLCP record protect/deprotect: SM4-CBC (+ GCM) round-trip & rejection | `cargo run --features tlcp --example tlcp_record` |
| [`tlcp_chain`](examples/tlcp_chain.rs) | TLCP [sign, enc] certificate-pair verify (leaf-first chains) | `cargo run --features tlcp,x509 --example tlcp_chain` |
| [`x509_sm2`](examples/x509_sm2.rs) | X.509-with-SM2 leaf parse + signature verify (parse is not trust) | `cargo run --features x509 --example x509_sm2` |
| [`sm4_xts`](examples/sm4_xts.rs) | SM4-XTS sector encryption | `cargo run --features sm4-xts --example sm4_xts` |

### Ecosystem-trait examples

| Example | Demonstrates | Run |
|---|---|---|
| [`sm3_digest_traits`](examples/sm3_digest_traits.rs) | SM3 / HMAC-SM3 behind RustCrypto `digest` 0.11 — byte-identical to `sm3::hash`/`hmac_sm3` | `cargo run --features digest-traits --example sm3_digest_traits` |
| [`sm4_cipher_traits`](examples/sm4_cipher_traits.rs) | `Sm4Cipher` behind RustCrypto `cipher` 0.5 — byte-identical, and why multi-block is ECB | `cargo run --features cipher-traits --example sm4_cipher_traits` |
| [`sm4_aead_traits`](examples/sm4_aead_traits.rs) | SM4-GCM/CCM behind RustCrypto `aead` 0.6 — byte-identical to `mode_gcm`/`mode_ccm` | `cargo run --features aead-traits --example sm4_aead_traits` |

## Guide

Do/don't walkthrough of each primitive — RNG, nonce uniqueness, authenticated vs
unauthenticated modes, PBKDF2 iterations, key storage, and a
[pick-the-right-tool sheet (§9)](docs/using-gmcrypto-core.md#9-doing-crypto-correctly-cross-cutting-review):
[`docs/using-gmcrypto-core.md`](docs/using-gmcrypto-core.md).

Two tracks in that guide: **SDK usage** is each section body; **RustCrypto trait
fits** are optional H3s at the end of §1, §2, §6, and §7. The closing
[toolkit sections (§10–§12)](docs/using-gmcrypto-core.md#10-x509-with-sm2-certificates)
cover X.509-with-SM2, SM2 key exchange, and the TLCP primitives.

## Test

Run the default tests and then the tests with every optional feature enabled:

```bash
cargo test
cargo test --all-features
```

Compile all examples:

```bash
cargo test --examples --all-features
```

This checks that the examples build, but does not execute the assertions in
their `main` functions. Use the `cargo run --example …` commands in the
[cookbook tables](#cookbook-examples) to run them; CI runs every listed example.
