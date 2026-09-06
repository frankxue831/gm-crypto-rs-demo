# Public certificate fixtures

Copied from [`gmcrypto-core` 1.13.0 `tests/data/`](https://github.com/frankxue831/gm-crypto-rs/tree/v1.13.0/crates/gmcrypto-core/tests/data)
(`x509_*.der`, `x509_chain_*.der`; MIT OR Apache-2.0). Generated with GmSSL 3.1.1 under the
GM/T 0015 profile; regen recipe is upstream `tests/data/x509_regen.md`.

These files are **public demo fixtures**. They are not production CAs, not
trust anchors, and not secret. Do not ship them in a real PKI.

| File | Used by |
|---|---|
| `x509_ca.der`, `x509_leaf.der` | `examples/x509_sm2.rs` |
| `x509_chain_{root,int,sign,enc}.der` | `examples/tlcp_chain.rs` |
