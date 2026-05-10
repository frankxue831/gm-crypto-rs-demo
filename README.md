# gm-crypto-rs-demo

Small downstream demo for the published [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core)
crate.

This repository intentionally depends on the crates.io release:

```toml
gmcrypto-core = "=0.1.0"
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

## Test

```bash
cargo test
```
