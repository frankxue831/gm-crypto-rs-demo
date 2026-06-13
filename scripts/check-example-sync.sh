#!/usr/bin/env bash
# scripts/check-example-sync.sh
# Verifies that every cookbook example under examples/*.rs is wired into the
# files that hand-list the example inventory:
#   1. .github/workflows/ci.yml      (run line)
#   2. README.md                     (cookbook / capability table row)
#   3. README.zh-CN.md               (the bilingual mirror of the same row)
#   4. CLAUDE.md                     (Commands + Layout example lists)
#
# The repo's convention for tolerated duplication is "duplicate + machine
# drift-check" (see scripts/check-doc-sync.sh for the bilingual doc pairs).
# This script closes the recurring failure where a new example lands with CI
# wiring but a hand-maintained list is forgotten (happened for sm4_ccm /
# sm4_streaming in the README tables between PR #10 and PR #14, and for
# CLAUDE.md's stale test count).
#
# Matching is heuristic by design: a name "appears" in ci.yml if it occurs as
# a whole word anywhere (covers both `--example <name>` flags and the for-loop
# list), and in a markdown file if it occurs wrapped in backticks. The guide
# pair is deliberately NOT checked: it may legitimately lag behind (an example
# can ship before its guide section). The reverse direction needs no check
# here: a name in ci.yml or Cargo.toml without a matching file already fails
# `cargo run` / `cargo build` in CI.
set -euo pipefail

if [ "$#" -ne 0 ]; then
    echo "usage: $0   (no arguments; run from the repo root)" >&2
    exit 2
fi

CI_YML=".github/workflows/ci.yml"
MD_LISTS=("README.md" "README.zh-CN.md" "CLAUDE.md")

for f in "$CI_YML" "${MD_LISTS[@]}"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: file not found: $f (run from the repo root)" >&2
        exit 2
    fi
done

EXAMPLES=(examples/*.rs)
# An unmatched glob stays literal ('examples/*.rs'), so a single missing-file
# test detects the empty case without needing nullglob or compgen.
if [ ! -f "${EXAMPLES[0]}" ]; then
    echo "ERROR: no examples/*.rs found (run from the repo root)" >&2
    exit 2
fi

FAILED=0
for path in "${EXAMPLES[@]}"; do
    name=$(basename "$path" .rs)

    if ! grep -qw -- "$name" "$CI_YML"; then
        echo "FAIL: example '$name' ($path) is not run in $CI_YML" >&2
        FAILED=1
    fi
    for doc in "${MD_LISTS[@]}"; do
        if ! grep -q -- "\`$name\`" "$doc"; then
            echo "FAIL: example '$name' ($path) is not listed (backticked) in $doc" >&2
            FAILED=1
        fi
    done
done

if [ "$FAILED" -ne 0 ]; then
    echo "FAIL: example inventory has drifted; add the missing rows/run lines above" >&2
    exit 1
fi

echo "OK: all ${#EXAMPLES[@]} examples are wired into $CI_YML, ${MD_LISTS[*]}"
