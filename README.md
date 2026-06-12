# gm-crypto-rs-demo

> 🌐 [English](README.md) · [简体中文](README.zh-CN.md) · [📚 Guide](docs/using-gmcrypto-core.md) · [📚 中文指南](docs/using-gmcrypto-core.zh-CN.md)

Downstream SDK tour for the published [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core)
crate.

This repository intentionally depends on the crates.io release:

```toml
gmcrypto-core = "=1.4.0"
```

It does not use a path dependency or workspace dependency from a local
`gm-crypto-rs` checkout. That makes it useful as a smoke test for what an
outside user gets from the published crate.

All sample keys, IVs, passwords, signer IDs, and outputs in this repository
are public demo material. Do not use them for real data.

## Quick Tour

Run the full walkthrough:

```bash
cargo run -- tour
```

## Capability map

Every capability this demo exposes from `gmcrypto-core`, mapped to the CLI subcommand, the cookbook example, and the matching guide section.

| Use case | CLI | Example | Guide § |
| --- | --- | --- | --- |
| SM3 hashing (GB/T 32905) | `cargo run -- hash <msg>` | `examples/sm3_hashing.rs` | `§1` |
| HMAC-SM3 message authentication | `cargo run -- hmac <key-hex> <msg>` | `examples/hmac_and_kdf.rs` | `§2` |
| PBKDF2-HMAC-SM3 password stretching | `cargo run -- pbkdf2 <pw> <salt-hex> <iter> <len>` | `examples/hmac_and_kdf.rs` | `§2` |
| SM2 digital signatures (GB/T 32918.2) | `cargo run -- sign` / `verify` | `examples/sm2_sign_verify.rs` | `§3` |
| SM2 public-key encryption (GB/T 32918.4) | `cargo run -- encrypt` / `decrypt` | `examples/sm2_encrypt_decrypt.rs` | `§4` |
| SM2 key encoding (PKCS#8 / SEC1 / SPKI / PEM) | `cargo run -- key-info` | `examples/sm2_key_encoding.rs` | `§5` |
| SM4-CBC / CTR symmetric encryption | `cargo run -- sm4-encrypt` / `sm4-decrypt` | `examples/sm4_cbc_ctr.rs` | `§6` |
| SM4-GCM authenticated encryption (AEAD) | — | `examples/sm4_aead.rs` (feature `sm4-aead`) | `§7` |
| SM4-XTS sector / disk encryption | — | `examples/sm4_xts.rs` (feature `sm4-xts`) | `§8` |
| Cross-cutting correctness checklist | — | — | `§9` |
| End-to-end walkthrough of every primitive | `cargo run -- tour` | — | `§0`–`§9` |

## Commands

| Area | Command | Shows |
| --- | --- | --- |
| SM3 | `hash <message>` | Single-shot SM3 digest |
| SM2 | `sign <message> [--id <signer-id>]` | SM2 signature with default or custom signer ID |
| SM2 | `verify <message> <der-signature-hex> [--id <signer-id>]` | SM2 signature verification |
| SM2 | `key-info` | SEC1, SPKI DER, and SPKI PEM public key export |
| SM2 | `encrypt <message>` | SM2 public-key encryption to DER ciphertext hex |
| SM2 | `decrypt <der-ciphertext-hex>` | SM2 private-key decryption |
| SM4 | `sm4-encrypt <message>` | SM4-CBC encryption with fixed demo key and IV |
| SM4 | `sm4-decrypt <ciphertext-hex>` | SM4-CBC decryption with the same demo key and IV |
| MAC | `hmac <key-hex> <message>` | HMAC-SM3 |
| KDF | `pbkdf2 <password> <salt-hex> <iterations> <out-len>` | PBKDF2-HMAC-SM3 |

## Examples

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

## Cookbook Examples

Each example under [`examples/`](examples/) is a small standalone program that
narrates what it does and asserts its own round-trips, so it doubles as a smoke
test (CI runs all of them):

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

## Guide

For a deeper, do/don't walkthrough of how to use each primitive correctly — RNG
handling, nonce/IV uniqueness, authenticated vs. unauthenticated modes, PBKDF2
iteration counts, key storage, and a "pick the right tool" cheat sheet — see
[`docs/using-gmcrypto-core.md`](docs/using-gmcrypto-core.md).

## Test

```bash
cargo test
```
