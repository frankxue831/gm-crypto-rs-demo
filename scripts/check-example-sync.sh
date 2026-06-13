#!/usr/bin/env bash
# scripts/check-example-sync.sh
# Verifies that every cookbook example under examples/*.rs is wired into the
# three places that hand-list the example inventory:
#   1. .github/workflows/ci.yml      (a cargo run line, or the default-feature
#                                     `for ex in ...` list)
#   2. README.md                     (cookbook / capability table row)
#   3. README.zh-CN.md               (the bilingual mirror of the same row)
#
# The repo's convention for tolerated duplication is "duplicate + machine
# drift-check" (see scripts/check-doc-sync.sh for the bilingual doc pairs).
# This script closes the recurring failure where a new example lands with CI
# wiring but the README tables are forgotten (happened for sm4_ccm /
# sm4_streaming between PR #10 and PR #14).
#
# Matching is heuristic by design: a name "appears" in ci.yml if it occurs as
# a whole word anywhere (covers both `--example <name>` flags and the for-loop
# list), and in a README if it occurs wrapped in backticks (table rows render
# example names as `code`). The reverse direction needs no check here: a name
# in ci.yml or Cargo.toml without a matching file already fails `cargo run` /
# `cargo build` in CI.
set -euo pipefail

if [ "$#" -ne 0 ]; then
    echo "usage: $0   (no arguments; run from the repo root)" >&2
    exit 2
fi

CI_YML=".github/workflows/ci.yml"
README_EN="README.md"
README_ZH="README.zh-CN.md"

for f in "$CI_YML" "$README_EN" "$README_ZH"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: file not found: $f (run from the repo root)" >&2
        exit 2
    fi
done

if ! compgen -G "examples/*.rs" > /dev/null; then
    echo "ERROR: no examples/*.rs found (run from the repo root)" >&2
    exit 2
fi

FAILED=0
COUNT=0
for path in examples/*.rs; do
    name=$(basename "$path" .rs)
    COUNT=$((COUNT + 1))

    if ! grep -qw -- "$name" "$CI_YML"; then
        echo "FAIL: example '$name' ($path) is not run in $CI_YML" >&2
        FAILED=1
    fi
    for readme in "$README_EN" "$README_ZH"; do
        if ! grep -q -- "\`$name\`" "$readme"; then
            echo "FAIL: example '$name' ($path) has no \`$name\` table row in $readme" >&2
            FAILED=1
        fi
    done
done

if [ "$FAILED" -ne 0 ]; then
    echo "FAIL: example inventory has drifted; add the missing rows/run lines above" >&2
    exit 1
fi

echo "OK: all $COUNT examples are wired into $CI_YML, $README_EN, and $README_ZH"
