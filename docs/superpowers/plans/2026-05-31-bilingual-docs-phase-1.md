# Bilingual Docs — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the bilingual infrastructure (drift guard, glossary, language switchers, shipping policy, CI) plus the highest-value Chinese surface (`docs/using-gmcrypto-core.zh-CN.md`) in one PR.

**Architecture:** Mirror-by-suffix file layout (`<name>.zh-CN.md`). Drift between English and Chinese guides is enforced mechanically by `scripts/check-doc-sync.sh` (byte-identical code blocks + heading-count parity) running in CI. Shared terminology lives in `docs/glossary.md`. Headings in `.zh-CN.md` are Chinese-only with manual `<a id>` anchors mirroring the English file's auto-slugs.

**Tech Stack:** Bash (drift script), Markdown (all docs), GitHub Actions (CI), Rust (unchanged — we are not touching source code).

**Spec:** [`docs/superpowers/specs/2026-05-31-bilingual-docs-design.md`](../specs/2026-05-31-bilingual-docs-design.md)

**Branch:** `docs-chinese-guide` (already created off `main` at `e65e56a`; spec already committed at `31e5e74`).

---

## Task 1: Build the drift-guard script

**Files:**
- Create: `scripts/check-doc-sync.sh`
- Test fixtures (temporary, deleted after verification): `/tmp/sync-test-a.md`, `/tmp/sync-test-b.md`

**Why first:** The script must exist before the translation lands so we can run it against the translation as proof. We do *not* wire it into CI yet (Task 11) because it will fail on the still-untranslated state in intermediate commits.

- [ ] **Step 1: Create the script**

Create `scripts/check-doc-sync.sh` with executable bit set. The script accepts two file arguments (English first, Chinese second) and fails (exit 1) if any of:

1. Number of fenced code blocks differs
2. Any same-index code block has different content (trailing whitespace stripped per line)
3. Number of H2 (`##`) or H3 (`###`) headings differs

```bash
#!/usr/bin/env bash
# scripts/check-doc-sync.sh
# Verifies that an English doc and its .zh-CN.md sibling stay in structural
# sync: identical fenced code blocks (in count and content) and equal H2/H3
# heading counts. See docs/superpowers/specs/2026-05-31-bilingual-docs-design.md.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <english.md> <chinese.zh-CN.md>" >&2
    exit 2
fi

EN="$1"
ZH="$2"

for f in "$EN" "$ZH"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: file not found: $f" >&2
        exit 2
    fi
done

# Extract every fenced code block (between ``` lines), one block per file,
# strip trailing whitespace per line so rustfmt drift inside one file doesn't
# false-positive against the other (both must be reformatted in lockstep,
# but we don't care about EOL whitespace).
extract_blocks() {
    awk '
        /^```/ {
            in_block = !in_block
            if (in_block) {
                block_idx++
                next
            } else {
                print "---END-BLOCK---"
                next
            }
        }
        in_block { print "B" block_idx ": " $0 }
    ' "$1" | sed 's/[[:space:]]*$//'
}

EN_BLOCKS=$(extract_blocks "$EN")
ZH_BLOCKS=$(extract_blocks "$ZH")

EN_COUNT=$(printf '%s\n' "$EN_BLOCKS" | grep -c '^---END-BLOCK---$' || true)
ZH_COUNT=$(printf '%s\n' "$ZH_BLOCKS" | grep -c '^---END-BLOCK---$' || true)

if [ "$EN_COUNT" != "$ZH_COUNT" ]; then
    echo "FAIL: fenced code block count differs" >&2
    echo "  $EN: $EN_COUNT blocks" >&2
    echo "  $ZH: $ZH_COUNT blocks" >&2
    exit 1
fi

if [ "$EN_BLOCKS" != "$ZH_BLOCKS" ]; then
    echo "FAIL: fenced code block contents differ between $EN and $ZH" >&2
    diff <(printf '%s\n' "$EN_BLOCKS") <(printf '%s\n' "$ZH_BLOCKS") | head -40 >&2
    exit 1
fi

# Heading counts (H2 + H3)
count_h2_h3() {
    grep -cE '^#{2,3} ' "$1" || true
}
EN_H=$(count_h2_h3 "$EN")
ZH_H=$(count_h2_h3 "$ZH")

if [ "$EN_H" != "$ZH_H" ]; then
    echo "FAIL: H2+H3 heading count differs" >&2
    echo "  $EN: $EN_H headings" >&2
    echo "  $ZH: $ZH_H headings" >&2
    exit 1
fi

echo "OK: $EN and $ZH are in sync ($EN_COUNT code blocks, $EN_H H2/H3 headings)"
```

- [ ] **Step 2: Mark executable**

Run: `chmod +x scripts/check-doc-sync.sh`

- [ ] **Step 3: Verify happy path with a synthetic fixture**

Create two trivial matched files and run the script. Expected: prints `OK:`, exits 0.

```bash
cat > /tmp/sync-test-a.md <<'EOF'
# Title
## H2 one
```rust
let x = 1;
```
## H2 two
```bash
echo hi
```
EOF
cp /tmp/sync-test-a.md /tmp/sync-test-b.md
./scripts/check-doc-sync.sh /tmp/sync-test-a.md /tmp/sync-test-b.md
```
Expected stdout: `OK: /tmp/sync-test-a.md and /tmp/sync-test-b.md are in sync (2 code blocks, 2 H2/H3 headings)`
Expected exit: 0

- [ ] **Step 4: Verify failure on code-block divergence**

```bash
sed -i.bak 's/let x = 1;/let x = 2;/' /tmp/sync-test-b.md
./scripts/check-doc-sync.sh /tmp/sync-test-a.md /tmp/sync-test-b.md
echo "exit=$?"
```
Expected: `FAIL: fenced code block contents differ ...`, exit 1.

- [ ] **Step 5: Verify failure on heading-count drift**

```bash
cp /tmp/sync-test-a.md /tmp/sync-test-b.md
echo "## H2 three" >> /tmp/sync-test-a.md
./scripts/check-doc-sync.sh /tmp/sync-test-a.md /tmp/sync-test-b.md
echo "exit=$?"
```
Expected: `FAIL: H2+H3 heading count differs ...`, exit 1.

- [ ] **Step 6: Clean up fixtures**

```bash
rm -f /tmp/sync-test-a.md /tmp/sync-test-a.md.bak /tmp/sync-test-b.md /tmp/sync-test-b.md.bak
```

- [ ] **Step 7: Commit**

```bash
git add scripts/check-doc-sync.sh
git commit -m "Add drift-guard script for bilingual docs

Verifies that an English doc and its .zh-CN.md sibling stay structurally
synced: identical fenced code blocks (count + content, trailing-whitespace
tolerant) and equal H2/H3 heading counts. Wired into CI in a later commit
once the Chinese guide lands.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Create the shared glossary

**Files:**
- Create: `docs/glossary.md`

- [ ] **Step 1: Write the glossary**

Create `docs/glossary.md`:

```markdown
# Glossary / 术语表

> 🌐 **Language / 语言:** This page is intentionally bilingual — it is the single source of truth for terminology used in both [the English guide](using-gmcrypto-core.md) and [中文指南](using-gmcrypto-core.zh-CN.md).

Rule: when an English term appears in this table, use the corresponding Chinese term in `.zh-CN.md`. Do not coin alternative translations. If a term is missing, add it here first, then use it in prose.

API names, crate names, commands, filenames, feature flags, error messages, and format names (`DER`, `PEM`, `PKCS#8`, `SEC1`, `SPKI`) stay in backticks and are **not** translated in either language.

| English | 中文 | Notes / 备注 |
|---|---|---|
| signature | 签名 | |
| sign / verify | 签名 / 验证 | |
| encrypt / decrypt | 加密 / 解密 | |
| ciphertext / plaintext | 密文 / 明文 | |
| key | 密钥 | |
| public key / private key | 公钥 / 私钥 | |
| key agreement | 密钥协商 | |
| key derivation | 密钥派生 | |
| key encapsulation | 密钥封装 | |
| MAC | MAC | acronym kept English |
| HMAC | HMAC | acronym kept English |
| AEAD | AEAD | gloss: 认证加密 (authenticated encryption) |
| authentication tag | 认证标签 | also "tag" alone → 标签 |
| nonce | nonce | acronym kept English; gloss: 一次性数 |
| IV | IV | acronym kept English; gloss: 初始化向量 (initialization vector) |
| counter | 计数器 | for CTR mode |
| salt | 盐值 | |
| iteration count | 迭代次数 | |
| signer ID | 签名者 ID | SM2 Z-value input; ID kept English |
| Z value | Z 值 | SM2 user-identity hash |
| hash / digest | 哈希 / 摘要 | "hash" for the operation, "digest" for the output |
| randomness / RNG | 随机性 / RNG | RNG acronym kept English |
| sector / data unit | 扇区 / 数据单元 | for XTS |
| tweak | tweak | XTS-specific; keep English |
| feature flag | 特性开关 / feature | "feature" alone also acceptable |
| crate | crate | Rust ecosystem term; keep English |
| round-trip | 往返 | as in "encrypt-then-decrypt round-trip" |
| constant-time comparison | 恒定时间比较 | |
| side channel | 侧信道 | |
| sample / fixture | 示例 / 测试用例 | "demo fixture" → 演示用样例 |
| production-safe | 生产安全 | "not production-safe" → 非生产安全 |
```

- [ ] **Step 2: Verify renders correctly**

Run: `head -20 docs/glossary.md` to eyeball formatting.

- [ ] **Step 3: Commit**

```bash
git add docs/glossary.md
git commit -m "Add shared bilingual terminology glossary

Single source of truth for translation between the English and Chinese
guides. Both guides link here; no inline first-use glosses.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Translate front matter + §0 (Getting started)

**Files:**
- Create: `docs/using-gmcrypto-core.zh-CN.md` (this task creates the file; subsequent translation tasks append)
- Read for source: `docs/using-gmcrypto-core.md` lines 1–137

**Source structure being translated (English source line numbers):**
- L1: Title + intro paragraph
- L23: `## The golden rules` (4 rules)
- L42: `## How to read this guide` (paragraph + path table)
- L56: `## Table of contents` (10 anchored links)
- L71: `## 0. Getting started: setup, RNG, and helpers`
- L76: `### Add the dependency` (with `toml` and `bash` fences)
- L96: `### Get randomness right` (with `rust` fence)
- L117: `### Load the sample key` (with `rust` fence)

- [ ] **Step 1: Read the English source for this group**

Run: `sed -n '1,137p' docs/using-gmcrypto-core.md` to load the exact text into your context.

- [ ] **Step 2: Create the Chinese file with front matter**

Create `docs/using-gmcrypto-core.zh-CN.md` starting with:

```markdown
# 正确使用 `gmcrypto-core` —— 一份实战指南

> 🌐 **Language / 语言:** [English](using-gmcrypto-core.md) | **简体中文**

> 📖 **术语表:** 本文档中的术语翻译以 [`glossary.md`](glossary.md) 为准。
```

Then translate the English title's intro paragraph (L3-L21 of the source) into idiomatic Chinese. Preserve the four golden rules under `## 黄金法则` with `<a id="the-golden-rules"></a>` immediately above the heading. Preserve `## 如何阅读本指南` (anchor: `how-to-read-this-guide`) and `## 目录` (anchor: `table-of-contents`). The ToC links should point to the *Chinese* file's anchors (same slugs since we mirror the English auto-slugs via `<a id>`).

- [ ] **Step 3: Translate §0**

Append the §0 section. Heading: `## §0 起步：环境、RNG 与辅助函数` with `<a id="0-getting-started-setup-rng-and-helpers"></a>` directly above. The three H3s inside §0 each need their own `<a id>`:
- `<a id="add-the-dependency"></a>` above `### 添加依赖`
- `<a id="get-randomness-right"></a>` above `### 正确使用随机性 (RNG)`
- `<a id="load-the-sample-key"></a>` above `### 加载示例密钥`

**Critical:** the `toml`, `bash`, and `rust` fenced code blocks inside §0 must be **byte-identical** to the English source. Only the surrounding Chinese prose changes.

- [ ] **Step 4: Verify with the drift script**

Run: `./scripts/check-doc-sync.sh docs/using-gmcrypto-core.md docs/using-gmcrypto-core.zh-CN.md`

Expected: it will **FAIL** at this point because the English file has many more sections than what we've translated so far. That is expected. Note the exact failure message — it should be "H2+H3 heading count differs" (English has many more) or "fenced code block count differs". If it complains about *block content* mismatch, that's a real bug — fix it by re-checking byte equality with the source.

- [ ] **Step 5: Commit**

```bash
git add docs/using-gmcrypto-core.zh-CN.md
git commit -m "Translate guide front matter + §0 (getting started) to Chinese

Partial translation; drift-guard will fail until all sections land.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Translate §1 (SM3) + §2 (HMAC / PBKDF2)

**Files:**
- Modify (append): `docs/using-gmcrypto-core.zh-CN.md`
- Read for source: `docs/using-gmcrypto-core.md` lines 138–229

**Source structure:**
- L138: `## 1. SM3 hashing` → `## §1 SM3 哈希`
- L143: `### What it's for` → `### 用途`
- L149: `### Correct usage` → `### 正确用法` (contains a `rust` fence)
- L168: `### Do / Don't` → `### Do / Don't` (heading kept English-style; markers ✅/❌ preserved)
- L179: `## 2. Message authentication and key derivation (HMAC-SM3, PBKDF2)` → `## §2 消息认证与密钥派生（HMAC-SM3, PBKDF2）`
- L185: `### HMAC-SM3 — authenticate a message` (with `rust` fence)
- L209: `### PBKDF2-HMAC-SM3 — derive a key from a password` (with `rust` fence)
- L219: `### Do / Don't`

- [ ] **Step 1: Read the English source**

Run: `sed -n '138,229p' docs/using-gmcrypto-core.md`

- [ ] **Step 2: Append the §1 and §2 translations**

For every H2 and H3 in this range, add a matching `<a id>` anchor immediately above it whose slug matches the English file's auto-slug. (For "What it's for" the slug is `whats-it-for` — verify with the existing English file's anchor or use GitHub's heading-anchor rules: lowercase, spaces → hyphens, punctuation stripped.)

Code blocks: byte-identical. Use the glossary for `signature`/`verify`/`HMAC`/`MAC`/`PBKDF2`/`salt`/`iteration count`/`key derivation`/`derive`.

- [ ] **Step 3: Drift script (still expected to fail — but failure mode should be heading/block COUNT, never content)**

Run: `./scripts/check-doc-sync.sh docs/using-gmcrypto-core.md docs/using-gmcrypto-core.zh-CN.md`

Expected failure mode: count mismatch. If content mismatch on any block, that's a translation bug — fix.

- [ ] **Step 4: Commit**

```bash
git add docs/using-gmcrypto-core.zh-CN.md
git commit -m "Translate guide §1 (SM3) + §2 (HMAC/PBKDF2) to Chinese

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Translate §3 (SM2 signatures) + §4 (SM2 encryption) + §5 (SM2 key management)

**Files:**
- Modify (append): `docs/using-gmcrypto-core.zh-CN.md`
- Read for source: `docs/using-gmcrypto-core.md` lines 230–340

**Source structure:**
- L230: `## 3. SM2 digital signatures` → `## §3 SM2 数字签名`
- L236: `### The signer ID and Z` → `### 签名者 ID 与 Z 值` (rust fence inside)
- L253: `### Do / Don't`
- L264: `## 4. SM2 public-key encryption` → `## §4 SM2 公钥加密`
- L269: `### Correct usage` (rust fence)
- L283: `### When to use it` → `### 何时使用`
- L290: `### Do / Don't`
- L300: `## 5. SM2 key management and serialization` → `## §5 SM2 密钥管理与序列化`
- L305: `### The formats` → `### 编码格式` (table inside — preserve column alignment)
- L330: `### Do / Don't`

- [ ] **Step 1: Read the English source**

Run: `sed -n '230,340p' docs/using-gmcrypto-core.md`

- [ ] **Step 2: Append §3, §4, §5 translations**

Same pattern: `<a id>` per heading, byte-identical code blocks, glossary terms.

For the format table in §5 (`### The formats`): the Markdown table header row stays English (`Format | Use case | Where in this repo`), the data rows' first column (format names like `PKCS#8`, `SEC1`) stays English in backticks, but the descriptive cells get translated.

- [ ] **Step 3: Drift script**

Run: `./scripts/check-doc-sync.sh docs/using-gmcrypto-core.md docs/using-gmcrypto-core.zh-CN.md`

Expected: count mismatch, no content mismatch.

- [ ] **Step 4: Commit**

```bash
git add docs/using-gmcrypto-core.zh-CN.md
git commit -m "Translate guide §3-§5 (SM2 signatures, encryption, keys) to Chinese

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Translate §6 (SM4 CBC/CTR) + §7 (SM4 AEAD) + §8 (SM4-XTS)

**Files:**
- Modify (append): `docs/using-gmcrypto-core.zh-CN.md`
- Read for source: `docs/using-gmcrypto-core.md` lines 341–444

**Source structure:**
- L341: `## 6. SM4 symmetric encryption: CBC and CTR` → `## §6 SM4 对称加密：CBC 与 CTR`
- L347: `### Correct usage` (rust fence)
- L364: `### The one rule that matters: never reuse the IV / counter under a key`
- L370: `### Bigger caveat: these are unauthenticated`
- L382: `## 7. SM4 authenticated encryption: GCM and CCM` → `## §7 SM4 认证加密：GCM 与 CCM`
- L391: `### Correct usage` (rust fence with `--features sm4-aead` shell + cargo)
- L406: `### Do / Don't`
- L416: `## 8. SM4-XTS disk and sector encryption` → `## §8 SM4-XTS 磁盘/扇区加密`
- L424: `### Correct usage` (rust fence)
- L434: `### Do / Don't`

- [ ] **Step 1: Read the English source**

Run: `sed -n '341,444p' docs/using-gmcrypto-core.md`

- [ ] **Step 2: Append §6, §7, §8 translations**

Key glossary terms in this group: `AEAD`, `nonce`, `IV`, `counter`, `tweak`, `sector`, `authentication tag`, `unauthenticated`.

- [ ] **Step 3: Drift script (counts now close to matching — only §9 remaining)**

Run: `./scripts/check-doc-sync.sh docs/using-gmcrypto-core.md docs/using-gmcrypto-core.zh-CN.md`

- [ ] **Step 4: Commit**

```bash
git add docs/using-gmcrypto-core.zh-CN.md
git commit -m "Translate guide §6-§8 (SM4 CBC/CTR/GCM/CCM/XTS) to Chinese

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Translate §9 (cross-cutting review)

**Files:**
- Modify (append): `docs/using-gmcrypto-core.zh-CN.md`
- Read for source: `docs/using-gmcrypto-core.md` lines 445–503

**Source structure:**
- L445: `## 9. Doing crypto correctly (cross-cutting review)` → `## §9 正确做加密（横向回顾）`
- 7 H3 subsections (Randomness, Uniqueness, Authentication, KDF/passwords, Constant-time, Key management, Pick the right tool)
- Likely contains a small comparison table for "Pick the right tool"

- [ ] **Step 1: Read the English source**

Run: `sed -n '445,503p' docs/using-gmcrypto-core.md`

- [ ] **Step 2: Append §9 translation**

Glossary terms: `constant-time comparison`, `side channel`, `key management`.

For the §9.7 "Pick the right tool" table (if present): header row English-only style as in Task 5, data cells translated except API/feature flag names in backticks.

- [ ] **Step 3: Drift script — should now PASS**

Run: `./scripts/check-doc-sync.sh docs/using-gmcrypto-core.md docs/using-gmcrypto-core.zh-CN.md`

Expected: `OK: ... in sync (N code blocks, M H2/H3 headings)`, exit 0.

If it fails:
- **count mismatch:** an `<a id>` was forgotten or an extra/missing H3 was introduced. Diff the headings: `diff <(grep -E '^#{2,3} ' docs/using-gmcrypto-core.md) <(grep -E '^#{2,3} ' docs/using-gmcrypto-core.zh-CN.md)`
- **content mismatch:** a code block was edited during translation. The output prints the diff — fix by copy-pasting from the English source.

- [ ] **Step 4: Commit**

```bash
git add docs/using-gmcrypto-core.zh-CN.md
git commit -m "Translate guide §9 (cross-cutting review) to Chinese

Drift-guard now passes — Chinese guide structurally mirrors the English.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Add language switcher + glossary link to English guide

**Files:**
- Modify: `docs/using-gmcrypto-core.md` (lines 1–5, insert switcher under H1)

- [ ] **Step 1: Read the current top of the English guide**

Run: `sed -n '1,6p' docs/using-gmcrypto-core.md`

- [ ] **Step 2: Insert switcher + glossary pointer under the H1**

Use Edit to add directly after line 1 (the H1) and before whatever currently follows:

```markdown
# Using `gmcrypto-core` Correctly — a Practical Guide

> 🌐 **Language / 语言:** **English** | [简体中文](using-gmcrypto-core.zh-CN.md)

> 📖 **Glossary:** Terminology is governed by [`glossary.md`](glossary.md) — used by both this guide and its Chinese counterpart.

```

(Preserve exactly one blank line between the new lines and the existing first paragraph.)

- [ ] **Step 3: Verify drift script still passes**

The English file just gained two block-quote lines and one blank line — *not* code blocks and *not* headings — so the script should still pass.

Run: `./scripts/check-doc-sync.sh docs/using-gmcrypto-core.md docs/using-gmcrypto-core.zh-CN.md`
Expected: `OK: ...`, exit 0.

- [ ] **Step 4: Commit**

```bash
git add docs/using-gmcrypto-core.md
git commit -m "Add language switcher + glossary pointer to English guide

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: README banner + stub `README.zh-CN.md`

**Files:**
- Modify: `README.md` (insert banner under H1)
- Create: `README.zh-CN.md`

- [ ] **Step 1: Read the current top of README**

Run: `sed -n '1,6p' README.md`

- [ ] **Step 2: Add banner under H1 in English README**

Use Edit to insert directly after the H1 (`# gm-crypto-rs-demo`):

```markdown
# gm-crypto-rs-demo

> 🌐 [English](README.md) · [简体中文](README.zh-CN.md) · [📚 Guide](docs/using-gmcrypto-core.md) · [📚 中文指南](docs/using-gmcrypto-core.zh-CN.md)

```

(Blank line preserved before the existing first paragraph.)

- [ ] **Step 3: Create the stub Chinese README**

Create `README.zh-CN.md`:

```markdown
# gm-crypto-rs-demo

> 🌐 [English](README.md) · [简体中文](README.zh-CN.md) · [📚 Guide](docs/using-gmcrypto-core.md) · [📚 中文指南](docs/using-gmcrypto-core.zh-CN.md)

本仓库是已发布 crate [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core)（中国 GM/T 国密标准：SM2/SM3/SM4 等）的下游演示项目，专门用于验证 crates.io 发布版本对外部用户的实际可用性。

完整的中文使用指南：**[`docs/using-gmcrypto-core.zh-CN.md`](docs/using-gmcrypto-core.zh-CN.md)** —— 涵盖每个原语的正确用法、常见错误、可运行示例与命令对照。

> ℹ️ **Note / 说明:** 完整的 README 中文翻译将随 Phase 2 PR 一起合入。当前请参考英文版 [`README.md`](README.md) 获取命令列表、示例和测试说明。

所有示例中的密钥、IV、密码、签名者 ID 与密文均为公开演示用素材，**非生产安全**。
```

- [ ] **Step 4: Commit**

```bash
git add README.md README.zh-CN.md
git commit -m "Add language banner to README + stub Chinese README

Stub points readers at the full Chinese guide; full README translation
lands in Phase 2.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Shipping policy in AGENTS.md + CLAUDE.md

**Files:**
- Modify: `AGENTS.md` (append a new section)
- Modify: `CLAUDE.md` (append a new section)

- [ ] **Step 1: Append the policy section to `AGENTS.md`**

Use Edit to add a new section at the end of `AGENTS.md` (after the "If a required command cannot be run..." paragraph on line 112-ish):

```markdown

## Bilingual Documentation

This repo ships bilingual prose docs (English + Simplified Chinese). The
file layout is mirror-by-suffix: `<name>.zh-CN.md` lives next to its
English sibling. Examples (`examples/*.rs`) stay English.

**Shipping policy:**

- Substantive changes to `docs/using-gmcrypto-core.md` must ship a matching
  `docs/using-gmcrypto-core.zh-CN.md` edit in the same PR.
- If an urgent fix cannot be paired with a Chinese translation, the affected
  section of `docs/using-gmcrypto-core.zh-CN.md` must carry a top banner
  until the translation catches up:

  ```markdown
  > ⚠️ 本节落后于英文版，请以英文版为准。Last synced: <commit-sha-short>
  ```

- Code blocks (Rust/shell/TOML) inside the two guide files must be
  byte-identical. This is enforced by `scripts/check-doc-sync.sh` in CI.
- Terminology is governed by `docs/glossary.md` — add new terms there first,
  then use them in prose. No inline first-use glosses.
- Tie-breaker when translation conventions conflict: **correctness/safety > idiomatic Chinese > 1:1 structural mirror.**

See `docs/superpowers/specs/2026-05-31-bilingual-docs-design.md` for full
rationale.
```

- [ ] **Step 2: Append a brief mirror section to `CLAUDE.md`**

Use Edit to add at the end of `CLAUDE.md`:

```markdown

## Bilingual docs (`.zh-CN.md` pairs)

- `docs/using-gmcrypto-core.md` ↔ `docs/using-gmcrypto-core.zh-CN.md` — keep code blocks byte-identical (CI enforces via `scripts/check-doc-sync.sh`).
- `README.md` ↔ `README.zh-CN.md` (stub in Phase 1; full translation Phase 2).
- Terminology lives in `docs/glossary.md` — single source of truth, no inline glosses.
- Substantive prose changes must ship both languages in the same PR, or add a `> ⚠️ 本节落后于英文版` banner until they catch up.
- Full policy: see `AGENTS.md` "Bilingual Documentation" section and `docs/superpowers/specs/2026-05-31-bilingual-docs-design.md`.
```

- [ ] **Step 3: Commit**

```bash
git add AGENTS.md CLAUDE.md
git commit -m "Document bilingual-docs shipping policy in AGENTS.md + CLAUDE.md

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Wire drift script into CI

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Read the current CI**

Run: `cat .github/workflows/ci.yml`

- [ ] **Step 2: Add a drift-guard step at the end of the existing `test` job**

Use Edit to append after the `Run feature-gated examples` step:

```yaml
      - name: Check bilingual docs are in sync
        run: ./scripts/check-doc-sync.sh docs/using-gmcrypto-core.md docs/using-gmcrypto-core.zh-CN.md
```

(Preserve YAML indentation — 6 spaces for the `- name:` because it's nested under `steps:` which is under the `test:` job. Match the existing steps' indentation exactly.)

- [ ] **Step 3: Run the script locally one more time before commit**

Run: `./scripts/check-doc-sync.sh docs/using-gmcrypto-core.md docs/using-gmcrypto-core.zh-CN.md`
Expected: `OK: ...`, exit 0.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "Run bilingual-docs drift guard in CI

Fails the build if the English and Chinese guides drift on code blocks or
heading structure.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: Final validation gate + open PR

**Files:** None modified — verification only.

- [ ] **Step 1: Format check**

Run: `cargo fmt --check`
Expected: exit 0 (we touched no Rust).

- [ ] **Step 2: Clippy**

Run: `cargo clippy --all-targets --features "sm4-aead sm4-xts" -- -D warnings`
Expected: exit 0.

- [ ] **Step 3: Tests**

Run: `cargo test`
Expected: exit 0.

- [ ] **Step 4: Drift guard (final)**

Run: `./scripts/check-doc-sync.sh docs/using-gmcrypto-core.md docs/using-gmcrypto-core.zh-CN.md`
Expected: `OK: ...`, exit 0.

- [ ] **Step 5: Gitleaks**

Run: `gitleaks detect --source . --redact --verbose`
Expected: exit 0. If a public demo fixture trips it, add a narrow `.gitleaks.toml` allowlist entry — do not weaken global rules.

- [ ] **Step 6: Working tree check**

Run: `git diff --check && git status --short`
Expected: `git diff --check` exits 0, `git status --short` shows nothing (all committed).

- [ ] **Step 7: Push the branch**

Run: `git push -u origin docs-chinese-guide`

- [ ] **Step 8: Open the PR via `gh`**

Run:
```bash
gh pr create --title "Add bilingual docs (Phase 1): Chinese guide + drift guard" --body "$(cat <<'EOF'
## Summary

Phase 1 of bilingual-docs effort. Lands the **infrastructure** plus the **highest-value Chinese surface** (`docs/using-gmcrypto-core.zh-CN.md`) in one PR.

- New `docs/using-gmcrypto-core.zh-CN.md` — full Chinese translation of the SDK usage guide
- New `docs/glossary.md` — shared bilingual terminology table (single source of truth)
- New `scripts/check-doc-sync.sh` — drift guard: asserts code blocks byte-identical and H2/H3 counts match between the two guides
- CI: wired the drift guard into `.github/workflows/ci.yml`
- `README.md` + Chinese guide get language-switcher banners; stub `README.zh-CN.md` points readers at the Chinese guide
- `AGENTS.md` + `CLAUDE.md` document the shipping policy

**Design + co-review:** [`docs/superpowers/specs/2026-05-31-bilingual-docs-design.md`](docs/superpowers/specs/2026-05-31-bilingual-docs-design.md) (co-reviewed by Codex and Grok before approval).

**Phase 2** (separate PR): full `README.zh-CN.md` translation.

## Test plan

- [x] \`cargo fmt --check\`
- [x] \`cargo clippy --all-targets --features "sm4-aead sm4-xts" -- -D warnings\`
- [x] \`cargo test\`
- [x] \`./scripts/check-doc-sync.sh docs/using-gmcrypto-core.md docs/using-gmcrypto-core.zh-CN.md\`
- [x] \`gitleaks detect --source . --redact --verbose\`
- [x] \`git diff --check\`
- [ ] CI green on this branch

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Return the PR URL when done.

---

## Self-Review

**Spec coverage check:**
- ✅ File layout (mirror-by-suffix) → Tasks 3-7 (create `.zh-CN.md`), 9 (stub README)
- ✅ Language switcher → Tasks 8 (English guide), 9 (README), 3 (Chinese guide header)
- ✅ Headings + manual `<a id>` anchors → Tasks 3-7 each call this out
- ✅ Glossary → Task 2; linked from both guides in Tasks 3 and 8
- ✅ Code blocks byte-identical → enforced by Task 1 script, run in Tasks 3-8
- ✅ Drift guard script → Task 1
- ✅ Drift guard in CI → Task 11
- ✅ Shipping policy → Task 10 (AGENTS.md + CLAUDE.md)
- ✅ Done criteria (fmt/clippy/test/gitleaks/git diff --check) → Task 12

**No placeholders:** scanned — all steps have concrete commands, code, and expected output.

**Type / name consistency:** script name `check-doc-sync.sh` used consistently across Tasks 1, 7, 11, 12. Glossary path `docs/glossary.md` consistent.

**Scope:** Phase 1 only. Phase 2 (`README.zh-CN.md` full translation) and Phase 3 (Notion mirror) explicitly deferred per spec.
