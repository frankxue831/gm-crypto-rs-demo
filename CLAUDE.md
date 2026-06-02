# CLAUDE.md

Downstream **smoke-test demo** for the published `gmcrypto-core` crate (GM/T
SM2/SM3/SM4). Depends on the crates.io release exactly as an outside user would.

The full cross-agent contract (architectural principles, done criteria) lives in
[AGENTS.md](AGENTS.md). This file is the Claude Code summary; where they differ
on tooling, this file wins.

## Commands (from repo root)
```bash
cargo fmt --check
cargo clippy --all-targets --features "sm4-aead sm4-xts" -- -D warnings
cargo test                                            # tests/cli.rs (CLI smoke tests)
cargo run --example sm3_hashing                       # + hmac_and_kdf, sm2_sign_verify,
                                                      #   sm2_encrypt_decrypt, sm2_key_encoding, sm4_cbc_ctr
cargo run --features sm4-aead --example sm4_aead      # gated: SM4-GCM
cargo run --features sm4-xts  --example sm4_xts       # gated: SM4-XTS
cargo run -- tour                                     # CLI walkthrough of all primitives
```

## Layout
- `src/lib.rs` — shared helpers (`encode_hex`/`decode_hex`/`sample_private_key`/
  `sample_public_key`/`os_rng`) used by both the CLI and the examples.
- `src/main.rs` — the CLI (`hash`/`sign`/`verify`/`encrypt`/`decrypt`/`sm4-*`/
  `hmac`/`pbkdf2`/`key-info`/`tour`).
- `examples/` — 8 self-verifying cookbook examples; CI builds and runs them all.

## Gotchas
- **Keep the pin exact:** `gmcrypto-core = "=1.0.0"` — never a path/workspace/git
  dep (it would defeat the published-crate smoke test).
- **Gated examples** `sm4_aead`/`sm4_xts` need `--features sm4-aead`/`sm4-xts`; the
  default build stays lean (no `gmcrypto-simd`). Lint with those features to cover them.
- **All sample keys/IVs/passwords are public fixtures** — never production-safe.
- **No randomness in exact-output assertions** — assert round-trips/validity, not
  exact signatures/ciphertexts.
- **CI** runs clippy + `cargo test` + all 8 examples.

## Claude Code specifics
- Skills/superpowers come from your installed Claude plugins. The Codex-specific
  notes in AGENTS.md (`~/.codex/superpowers`, "restart Codex",
  `superpowers-codex bootstrap`) do not apply here.

## Bilingual docs (`.zh-CN.md` pairs)

- `docs/using-gmcrypto-core.md` ↔ `docs/using-gmcrypto-core.zh-CN.md` — keep code blocks byte-identical (CI enforces via `scripts/check-doc-sync.sh`).
- `README.md` ↔ `README.zh-CN.md` — also drift-checked by `scripts/check-doc-sync.sh`.
- Terminology lives in `docs/glossary.md` — single source of truth, no inline glosses.
- Substantive prose changes must ship both languages in the same PR, or add a `> ⚠️ 本节落后于英文版` banner until they catch up.
- Full policy: see `AGENTS.md` "Bilingual Documentation" section and `docs/superpowers/specs/2026-05-31-bilingual-docs-design.md`.
