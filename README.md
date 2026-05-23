# gm-crypto-rs-demo

Downstream SDK tour for the published [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core)
crate.

This repository intentionally depends on the crates.io release:

```toml
gmcrypto-core = "=0.12.0"
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

Each example is a small standalone Rust program:

```bash
cargo run --example sm3_hash
cargo run --example sm2_sign_verify
cargo run --example sm2_encrypt_decrypt
cargo run --example sm4_cbc
cargo run --example hmac_sm3
cargo run --example pbkdf2_hmac_sm3
```

## Test

```bash
cargo test
```
