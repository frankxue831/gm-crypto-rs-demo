# gm-crypto-rs-demo

> 🌐 [English](README.md) · [简体中文](README.zh-CN.md) · [📚 Guide](docs/using-gmcrypto-core.md) · [📚 中文指南](docs/using-gmcrypto-core.zh-CN.md)

Runnable cookbook for the published [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core)
crate (GM/T **SM2 / SM3 / SM4**). Clone it, run the tour, copy a snippet.

It pins the crates.io release exactly — never a path or workspace checkout —
so it also smoke-tests what an outside user actually gets:

```toml
gmcrypto-core = "=1.11.2"
```

All sample keys, IVs, passwords, signer IDs, and outputs in this repository
are public demo material. Do not use them for real data.

## Start here

```bash
cargo run -- tour
```

## Try the CLI

CLI subcommands below are `cargo run -- <subcommand>`.

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
(see Cookbook). The cross-cutting checklist is [guide §9](docs/using-gmcrypto-core.md#9-doing-crypto-correctly-cross-cutting-review), not a separate example.

### Default capabilities

No feature flag. These are the inherent SDK APIs, and they have CLI commands.

| Use case | CLI | Example | Guide |
| --- | --- | --- | --- |
| SM3 hashing (GB/T 32905) | `hash <msg>` | `sm3_hashing` | `§1` |
| HMAC-SM3 message authentication | `hmac <key-hex> <msg>` | `hmac_and_kdf` | `§2` |
| PBKDF2-HMAC-SM3 password stretching | `pbkdf2 <pw> <salt-hex> <iter> <len>` | `hmac_and_kdf` | `§2` |
| SM2 digital signatures (GB/T 32918.2) | `sign` / `verify` | `sm2_sign_verify` | `§3` |
| SM2 public-key encryption (GB/T 32918.4) | `encrypt` / `decrypt` | `sm2_encrypt_decrypt` | `§4` |
| SM2 key encoding (PKCS#8 / SEC1 / SPKI / PEM) | `key-info` | `sm2_key_encoding` | `§5` |
| SM4-CBC / CTR symmetric encryption | `sm4-encrypt` / `sm4-decrypt` | `sm4_cbc_ctr` | `§6` |

### Feature-gated modes

| Use case | Example | Feature | Guide |
| --- | --- | --- | --- |
| SM4-GCM authenticated encryption (AEAD) | `sm4_aead` | `sm4-aead` | `§7` |
| SM4-CCM authenticated encryption (constrained AEAD) | `sm4_ccm` | `sm4-aead` | `§7` |
| SM4-GCM streaming (chunked AEAD) | `sm4_streaming` | `sm4-aead` | `§7` |
| SM2 key exchange (GB/T 32918.3, confirmed + no-confirmation) | `sm2_key_exchange` | `sm2-key-exchange` | — |
| TLCP key schedule (GB/T 38636 PRF) | `tlcp_key_schedule` | `tlcp` | — |
| TLCP record protection (GB/T 38636 §6.3) | `tlcp_record` | `tlcp` | — |
| SM4-XTS sector / disk encryption | `sm4_xts` | `sm4-xts` | `§8` |

### Ecosystem traits

Skip this group unless you already write generic RustCrypto code (`D: Digest`,
`BlockCipherEncrypt`, `Aead`). The inherent APIs above are the default.

| Use case | Example | Feature | Guide |
| --- | --- | --- | --- |
| SM3 / HMAC-SM3 via `digest` 0.11 (`Sm3` / `HmacSm3`) | `sm3_digest_traits` | `digest-traits` | `§1`, `§2` |
| SM4 block primitive via `cipher` 0.5 (`Sm4Cipher`) | `sm4_cipher_traits` | `cipher-traits` | `§6` |
| SM4-GCM / CCM via `aead` 0.6 (`Sm4Gcm` / `Sm4Ccm`) | `sm4_aead_traits` | `aead-traits` | `§7` |

## Cookbook examples

Each file under [`examples/`](examples/) is a small standalone program that
narrates what it does and asserts its own round-trips. CI runs all of them.

### Default examples

| Example | Demonstrates | Run |
|---|---|---|
| `sm3_hashing` | SM3 one-shot + streaming hasher | `cargo run --example sm3_hashing` |
| `hmac_and_kdf` | HMAC-SM3 (one-shot/streaming/verify) + PBKDF2-HMAC-SM3 | `cargo run --example hmac_and_kdf` |
| `sm2_sign_verify` | SM2 sign/verify, signer-ID `Z`, tamper rejection | `cargo run --example sm2_sign_verify` |
| `sm2_encrypt_decrypt` | SM2 public-key encryption | `cargo run --example sm2_encrypt_decrypt` |
| `sm2_key_encoding` | PKCS#8 / SEC1 / SPKI / PEM + encrypted PKCS#8 | `cargo run --example sm2_key_encoding` |
| `sm4_cbc_ctr` | SM4 CBC + CTR + raw block | `cargo run --example sm4_cbc_ctr` |

### Feature-gated examples

| Example | Demonstrates | Run |
|---|---|---|
| `sm4_aead` | SM4-GCM authenticated encryption | `cargo run --features sm4-aead --example sm4_aead` |
| `sm4_ccm` | SM4-CCM in two nonce/tag shapes (12+16, 13+8) | `cargo run --features sm4-aead --example sm4_ccm` |
| `sm4_streaming` | SM4-GCM streaming (chunked encrypt/decrypt) | `cargo run --features sm4-aead --example sm4_streaming` |
| `sm2_key_exchange` | SM2 key exchange — confirmed + no-confirmation (TLCP) variants | `cargo run --features sm2-key-exchange --example sm2_key_exchange` |
| `tlcp_key_schedule` | TLCP PRF: master secret, key block, Finished `verify_data` | `cargo run --features tlcp --example tlcp_key_schedule` |
| `tlcp_record` | TLCP record protect/deprotect: SM4-CBC (+ GCM) round-trip & rejection | `cargo run --features tlcp --example tlcp_record` |
| `sm4_xts` | SM4-XTS sector encryption | `cargo run --features sm4-xts --example sm4_xts` |

### Ecosystem-trait examples

| Example | Demonstrates | Run |
|---|---|---|
| `sm3_digest_traits` | SM3 / HMAC-SM3 behind RustCrypto `digest` 0.11 — byte-identical to `sm3::hash`/`hmac_sm3` | `cargo run --features digest-traits --example sm3_digest_traits` |
| `sm4_cipher_traits` | `Sm4Cipher` behind RustCrypto `cipher` 0.5 — byte-identical, and why multi-block is ECB | `cargo run --features cipher-traits --example sm4_cipher_traits` |
| `sm4_aead_traits` | SM4-GCM/CCM behind RustCrypto `aead` 0.6 — byte-identical to `mode_gcm`/`mode_ccm` | `cargo run --features aead-traits --example sm4_aead_traits` |

## Guide

Do/don't walkthrough of each primitive — RNG, nonce uniqueness, authenticated vs
unauthenticated modes, PBKDF2 iterations, key storage, and a
[pick-the-right-tool sheet (§9)](docs/using-gmcrypto-core.md#9-doing-crypto-correctly-cross-cutting-review):
[`docs/using-gmcrypto-core.md`](docs/using-gmcrypto-core.md).

Two tracks in that guide: **SDK usage** is each section body; **RustCrypto trait
fits** are optional H3s at the end of §1, §2, §6, and §7.

## Test

```bash
cargo test
```
