# gm-crypto-rs-demo

Small downstream demo for the published [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core)
crate.

This repository intentionally depends on the crates.io release:

```toml
gmcrypto-core = "=0.12.0"
```

It does not use a path dependency or workspace dependency from the local
`gm-crypto-rs` checkout. That makes it useful as a smoke test for what an
outside user gets from the published crate.

## Commands

Hash a message with SM3:

```bash
cargo run -- hash abc
```

Sign a message with the GB/T 32918.2 sample private key:

```bash
cargo run -- sign hello
```

Verify a DER signature hex string produced by `sign`:

```bash
sig=$(cargo run --quiet -- sign hello)
cargo run -- verify hello "$sig"
```

The demo key is fixed and public. Do not use it for real data.

## Examples

Runnable, self-verifying examples covering the everyday `gmcrypto-core` surface live
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

## Test

```bash
cargo test
```

`cargo test` covers the CLI. The examples above are runnable smoke tests too —
CI runs all eight (six default plus the two feature-gated) on every push.
