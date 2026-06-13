# CLAUDE.md

Downstream **smoke-test demo** for the published `gmcrypto-core` crate (GM/T
SM2/SM3/SM4). Depends on the crates.io release exactly as an outside user would.

The full cross-agent contract (architectural principles, done criteria) lives in
[AGENTS.md](AGENTS.md). This file is the Claude Code summary; where they differ
on tooling, this file wins.

## Commands (from repo root)
```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test                                            # tests/cli.rs (16 CLI smoke tests, default features)
cargo test --all-features                             # same tests under feature-gated build (separate CI step)
cargo run --example sm3_hashing                       # + hmac_and_kdf, sm2_sign_verify,
                                                      #   sm2_encrypt_decrypt, sm2_key_encoding, sm4_cbc_ctr
cargo run --features sm4-aead --example sm4_aead      # gated: SM4-GCM (single-shot)
cargo run --features sm4-aead --example sm4_ccm       # gated: SM4-CCM (12+16 / 13+8 nonce-tag shapes)
cargo run --features sm4-aead --example sm4_streaming # gated: SM4-GCM streaming (Sm4GcmEncryptor / Decryptor)
cargo run --features sm2-key-exchange --example sm2_key_exchange  # gated: SM2 KX (GM/T 0003.3, key confirmation)
cargo run --features sm4-xts  --example sm4_xts       # gated: SM4-XTS
cargo run -- tour                                     # CLI walkthrough of all primitives
```

## Layout
- `src/lib.rs` — shared helpers (`encode_hex`/`decode_hex`/`sample_private_key`/
  `sample_public_key`/`os_rng`) + canonical demo fixtures as `pub const`:
  `DEMO_SM4_KEY/IV` (CBC), `DEMO_HMAC_KEY/MSG` (RFC 4231 inputs),
  `DEMO_PBKDF2_{PASSWORD,SALT,ITER,LEN}` (RFC 6070 inputs). CLI + examples both import these.
- `src/main.rs` — the CLI (`hash`/`sign`/`verify`/`encrypt`/`decrypt`/`sm4-*`/
  `hmac`/`pbkdf2`/`key-info`/`tour`).
- `examples/` — 11 self-verifying cookbook examples; CI builds and runs them all.
  Default-feature: `sm3_hashing`, `hmac_and_kdf`, `sm2_sign_verify`, `sm2_encrypt_decrypt`,
  `sm2_key_encoding`, `sm4_cbc_ctr`. Gated: `sm4_aead`, `sm4_ccm`, `sm4_streaming` (`sm4-aead`);
  `sm2_key_exchange` (`sm2-key-exchange`); `sm4_xts` (`sm4-xts`).

## Gotchas
- **Keep the pin exact:** `gmcrypto-core = "=1.4.0"` — never a path/workspace/git
  dep (it would defeat the published-crate smoke test).
- **Gated examples** need their feature flag (`sm4-aead` for `sm4_aead`/`sm4_ccm`/`sm4_streaming`,
  `sm2-key-exchange` for `sm2_key_exchange`, `sm4-xts` for `sm4_xts`); the default
  build stays lean (no `gmcrypto-simd`). Lint with `--all-features` to cover them.
- **All sample keys/IVs/passwords are public fixtures** — never production-safe.
- **No randomness in exact-output assertions** — assert round-trips/validity, not
  exact signatures/ciphertexts.
- **Fixture safety stencil:** every fixture site (in `src/lib.rs` consts and in example
  `let`-bindings) carries a 3-line canonical block:
  `// DEMO ONLY: <what> / // Production: <alternative> / // Reusing this risks: <failure mode>`.
  New fixtures should follow this shape; `grep -E 'DEMO ONLY:|Production:|Reusing this' src/ examples/`
  should always cover every fixed key/IV/nonce/salt.
- **§9 safety anchors:** every `examples/*.rs` `//!` header carries one line like
  `//! Safety: §9 rule N. <Label>` pointing at `docs/using-gmcrypto-core.md` §9
  ("Doing crypto correctly"). The guide uses bare H3 numbering (`### 1. Randomness` …
  `### 7. Pick the right tool`) under H2 `## 9.` — NOT compound `§9.1` notation.
  If §9 sub-rules are reordered, run `grep -n "Safety: §9" examples/` and resync.
- **Tour feature-gated sections** use `#[cfg(feature = "...")]` blocks with `#[cfg(not(...))]`
  skip-line fallbacks; `tests/cli.rs::tour_prints_non_flaky_section_results` wraps the
  relevant assertions in `if cfg!(feature = "...") { … } else { … }` so the same test passes
  under both default and feature-gated (`--all-features`) builds.
- **CI** runs `cargo fmt --check`, clippy with `--all-features`, `cargo test` (default),
  `cargo test --all-features`, all 11 examples (gated ones each under their minimal
  feature), both `check-doc-sync.sh` invocations, `check-example-sync.sh` (every
  `examples/*.rs` must appear in ci.yml + both README tables), and `gitleaks detect`.

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
