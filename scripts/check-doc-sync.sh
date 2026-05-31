#!/usr/bin/env bash
# scripts/check-doc-sync.sh
# Verifies that an English doc and its .zh-CN.md sibling stay structural
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
