# Bilingual (English + Simplified Chinese) docs — design

**Status:** Approved 2026-05-31. Co-reviewed by Codex and Grok before approval.

## Why

`gm-crypto-rs-demo` is a downstream smoke-test for `gmcrypto-core`, a Rust
implementation of China's GM/T crypto standards (SM2/SM3/SM4 + HMAC/PBKDF2/AEAD).
A large share of readers are mainland-China developers who read Chinese more
comfortably than English. Today every prose surface is English-only.

End state: every prose doc in this repo has an English and a Simplified Chinese
version, kept in sync. Example code stays English (Rust ecosystem convention;
keeps the snippets globally readable).

## Goal (Phase 1)

Land the bilingual *infrastructure* and the *highest-value* Chinese surface — the
SDK usage guide — in one PR. Subsequent phases reuse the same infrastructure for
the README and (optionally) the Notion lecture series.

## Non-goals

- A translation pipeline (po4a, gettext, .po files). Manual side-by-side is
  cheaper and gives better prose at this scale.
- A third language. The layout chosen supports it cleanly if needed later, but
  it is not in scope now.
- Localizing example source code (`examples/*.rs`) — comments, docstrings, and
  expected program output stay English.

## File layout

Mirror-by-suffix. Every translated file lives next to its English sibling with a
`.zh-CN.md` suffix:

```
gm-crypto-rs-demo/
├── README.md                              # existing
├── README.zh-CN.md                        # Phase 2
├── docs/
│   ├── using-gmcrypto-core.md             # existing
│   ├── using-gmcrypto-core.zh-CN.md       # NEW (Phase 1)
│   └── glossary.md                        # NEW (Phase 1) — shared bilingual terminology
├── examples/*.rs                          # unchanged, English-only
└── scripts/
    └── check-doc-sync.sh                  # NEW (Phase 1) — drift guard, runs in CI
```

Rejected alternatives:
- `docs/zh-CN/` mirror directory — `README` must live at repo root, forcing the
  suffix pattern *somewhere*. Using it everywhere keeps one convention.
- Bilingual inline (English + Chinese in the same file) — doubles file length,
  neither audience gets a clean read.

## Language switcher

Every translated file gets a one-line switcher directly under the H1, pointing
to its sibling. Bold marks the current language.

English file:
```markdown
# Using gmcrypto-core Correctly

> 🌐 **Language / 语言:** **English** | [简体中文](using-gmcrypto-core.zh-CN.md)
```

Chinese file:
```markdown
# 正确使用 gmcrypto-core

> 🌐 **Language / 语言:** [English](using-gmcrypto-core.md) | **简体中文**
```

`README.md` gets a more prominent banner directly under the title:
```markdown
# gm-crypto-rs-demo

> 🌐 [English](README.md) · [简体中文](README.zh-CN.md) · [📚 Guide](docs/using-gmcrypto-core.md) · [📚 中文指南](docs/using-gmcrypto-core.zh-CN.md)
```

In Phase 1 the `README.zh-CN.md` link is a stub (`# gm-crypto-rs-demo` + one
sentence pointing readers at the Chinese guide and noting the full README
translation is forthcoming). Phase 2 replaces the stub with a real translation.

## Headings & anchors

`.zh-CN.md` heading text is **Chinese only** — natural reading for the target
audience. To keep cross-file anchor parity for deep links and tooling, every
H2/H3 in the Chinese guide carries a manual stable anchor immediately above it,
matching the English file's auto-generated slug:

```markdown
<a id="getting-started"></a>

## §0 起步
```

Rationale: GitHub's auto-anchor for `§0 起步 / Getting Started` would be
`#§0-起步--getting-started` — long, punctuation-sensitive, and divergent from
the English file's `#getting-started`. Bilingual heading text was rejected as
"the worst single idea in the plan" by both reviewers.

The English file does **not** need to backfill manual anchors — its
auto-generated slugs already match the manual anchors used in the Chinese file.

## Terminology — shared glossary

`docs/glossary.md` is a single bilingual terminology table. Both guides link to
it; first-use inline glosses ("AEAD（认证加密）") are **not** used — they drift
across 19 KB of prose. Initial entries (extend as needed):

| English | 中文 | Notes |
|---|---|---|
| signature | 签名 | |
| sign / verify | 签名 / 验证 | |
| encrypt / decrypt | 加密 / 解密 | |
| key agreement | 密钥协商 | |
| key derivation | 密钥派生 | |
| nonce | nonce | keep English; gloss as 一次性数 only in glossary |
| IV (initialization vector) | IV（初始化向量） | acronym stays English |
| AEAD | AEAD | gloss as 认证加密 only in glossary |
| authentication tag | 认证标签 | |
| ciphertext / plaintext | 密文 / 明文 | |
| MAC / HMAC | MAC / HMAC | |
| salt | 盐值 | |
| iteration count | 迭代次数 | |
| public key / private key | 公钥 / 私钥 | |
| signer ID | 签名者 ID | for SM2 Z-value |
| encoding (DER/PEM/PKCS#8/SEC1/SPKI) | 编码 | format names stay English in backticks |

Rule: API names, crate names, commands, filenames, feature flags, error
messages, and format names (DER, PEM, PKCS#8, SEC1, SPKI) stay in **backticks
and untranslated** in both languages.

## Code blocks

Runnable code blocks (Rust, shell, TOML) are **byte-identical** between the
English and Chinese files. This is enforced by `scripts/check-doc-sync.sh` (see
below).

Explicitly:
- Rust code inside ` ```rust ` fences stays identical, including comments
  (because the source `examples/*.rs` they mirror are English).
- Shell commands inside ` ```bash `/` ```sh ` fences stay identical.
- TOML inside ` ```toml ` fences stays identical.
- Expected program **output** snippets are not localized — the demo programs
  themselves emit English.

## Drift guard — `scripts/check-doc-sync.sh`

Wired into CI. Runs on every push touching `docs/**`. Fails if:

1. **Fenced code block count differs** between `using-gmcrypto-core.md` and
   `using-gmcrypto-core.zh-CN.md` (any language tag: `rust`, `bash`, `sh`,
   `toml`, untagged).
2. **Any same-index fenced block has different content** (after trimming
   trailing whitespace on each line — protects against rustfmt-style drift).
3. **H2/H3 heading count differs** between the two files.

Implementation: ~30–40 lines of bash + `awk`/`diff`. No external dependencies.

Not enforced (out of scope for Phase 1): H4+ counts, prose paragraph parity,
anchor presence in the Chinese file. These are owned by reviewer discipline,
not the script.

## Shipping policy

Steady-state rule (added to `AGENTS.md` and `CLAUDE.md` in Phase 1):

> Substantive changes to `docs/using-gmcrypto-core.md` must ship a matching
> `.zh-CN.md` edit in the same PR.
>
> If a fix is genuinely urgent and the Chinese translation cannot be done in
> the same PR, the affected section of the Chinese file must carry a top
> banner until the translation catches up:
>
> ```markdown
> > ⚠️ 本节落后于英文版，请以英文版为准。Last synced: <commit-sha-short>
> ```
>
> The drift-guard script does **not** enforce this — reviewer discipline does.
> The banner is a visible signal so readers know the English is canonical for
> that section.

Tie-breaker when translation conventions conflict: **correctness/safety > idiomatic Chinese > 1:1 structural mirror.** The SDK author has final say on
crypto-safety wording.

Phase 1 itself is exempt — this is the translation effort that *establishes*
the policy, so it can't retroactively be governed by it.

## Translation conventions (Phase 1, frozen for future phases)

- **Tone:** idiomatic developer-doc Chinese, not literal English-shaped
  sentences. Read like docs originally written in Chinese.
- **Terms-of-art:** governed by `docs/glossary.md`. No inline glosses.
- **Backtick-wrapped tokens** (API names, commands, filenames, format names,
  feature flags, error messages) stay untranslated.
- **Code blocks** byte-identical (enforced).
- **Headings** Chinese-only in the Chinese file, with manual `<a id>` anchors
  for cross-file parity.
- **Cross-references** to in-repo files (`../examples/sm3_hashing.rs`,
  `../src/lib.rs`) stay verbatim — Chinese guide → English code is expected.
- **Markers** (✅/❌, 💡, 🧭) preserved.

## Phasing

| Phase | Surface | PR scope |
|---|---|---|
| **1 (this design)** | Guide + glossary + drift script + lang switcher in English files + README banner + stub `README.zh-CN.md` + shipping policy in `AGENTS.md`/`CLAUDE.md` | One PR |
| **2** | Full `README.zh-CN.md` translation | One PR |
| **3 (optional)** | Notion lecture series Chinese mirror | Outside the repo |

## Done criteria (Phase 1)

- `docs/using-gmcrypto-core.zh-CN.md` complete, covers all §0–§9 sections.
- `docs/glossary.md` exists and is linked from both English and Chinese guides.
- `scripts/check-doc-sync.sh` exists, is executable, passes against the
  freshly-translated pair, and is invoked from CI.
- `README.md` carries the language banner; `README.zh-CN.md` stub exists.
- English `docs/using-gmcrypto-core.md` carries the language switcher header.
- Shipping policy added to `AGENTS.md` and `CLAUDE.md`.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`
  all green (no code changes expected, but defensive run).
- `gitleaks detect --source . --redact --verbose` exits 0 (we are touching docs).
- `git diff --check` exits 0.
- CI green on the branch.

## Risk and rollback

- **If translation quality is wrong**: it's docs, not code. Edit-and-fix in a
  follow-up PR. The drift script ensures code samples can't be wrong.
- **If the drift script is too strict**: tune the trim rules or relax to a
  warning. The script lives in `scripts/`, not in the build — easy to amend.
- **If the bilingual switcher pattern doesn't render well on some surface**
  (e.g. a markdown renderer that mangles emojis): swap the 🌐 emoji for plain
  text. Cosmetic only.
