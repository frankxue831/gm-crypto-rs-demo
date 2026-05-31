#!/usr/bin/env bash
# scripts/check-doc-sync.sh
# Verifies that an English doc and its .zh-CN.md sibling stay in structural
# sync: identical fenced code blocks (in count and content) and equal H2/H3
# heading counts. See docs/superpowers/specs/2026-05-31-bilingual-docs-design.md.
#
# Supported markdown subset:
#   - Backtick fences only (```), at column 0.
#   - Nested fences via longer opening (e.g. ````markdown wrapping a ```rust
#     block) work correctly: a fence closes only when it matches the opener's
#     length. Tilde fences (~~~) are rejected with a clear error rather than
#     silently mis-parsed.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <english.md> <chinese.zh-CN.md>" >&2
    exit 2
fi

EN="$1"
ZH="$2"

# Same-file argument is almost always a wiring mistake (e.g. wrong YAML var).
# Every check below is reflexive against identical input and would falsely
# report OK, so fail loudly instead.
if [ "$EN" = "$ZH" ]; then
    echo "ERROR: both arguments resolve to the same file: $EN" >&2
    exit 2
fi

for f in "$EN" "$ZH"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: file not found: $f" >&2
        exit 2
    fi
    # Tilde fences are valid GFM but rare in this repo and would silently
    # bypass the block extractor. Fail fast with an actionable message instead.
    if grep -qE '^~{3,}' "$f"; then
        echo "ERROR: tilde fences (~~~) are not supported by this script; please use backticks in $f" >&2
        exit 2
    fi
done

# Extract every fenced code block, one block per file. Tracks the *length* of
# the opening fence so a closing fence is only recognised when it matches
# (CommonMark requires the closer to use the same character and be at least as
# long as the opener; we accept "exactly as long" for simplicity since longer
# closers are vanishingly rare in practice).
#
# Trailing whitespace is stripped from every output line so rustfmt-style drift
# inside one file doesn't false-positive against the other. Block boundaries
# are marked with ---END-BLOCK--- and block contents are prefixed with
# "B<idx>: " so a content diff identifies *which* block diverged.
extract_blocks() {
    awk '
        /^`{3,}/ {
            # Extract the fence string (length matters for nested fences).
            match($0, /^`+/)
            fence_len = RLENGTH
            if (!in_block) {
                in_block = 1
                open_fence_len = fence_len
                block_idx++
                next
            }
            # Inside a block: only a fence of matching length closes it.
            # Anything else (e.g. inner ```rust inside ````markdown) is content.
            if (fence_len == open_fence_len) {
                in_block = 0
                open_fence_len = 0
                print "---END-BLOCK---"
                next
            }
            print "B" block_idx ": " $0
            next
        }
        in_block { print "B" block_idx ": " $0 }
    ' "$1" | sed 's/[[:space:]]*$//'
}

EN_BLOCKS=$(extract_blocks "$EN")
ZH_BLOCKS=$(extract_blocks "$ZH")

# `grep -c` exits 1 when zero matches. `|| true` is REQUIRED here because
# `set -euo pipefail` + command substitution would otherwise abort the
# script when either file legitimately contains zero fenced blocks.
# Do not "clean this up" — the `|| true` is load-bearing.
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

# Heading counts (H2 + H3). The trailing space in `^#{2,3} ` correctly
# excludes H4+ (`#### foo` has `##` at start but the 3rd/4th char is `#`,
# not space). `|| true` is REQUIRED here too — see note above.
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
