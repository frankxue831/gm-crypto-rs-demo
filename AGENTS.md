# AGENTS.md instructions for gm-crypto-rs-demo

This file defines the project-local operating contract for coding agents working
in this repository.

## Superpowers System

<EXTREMELY_IMPORTANT>
You have superpowers. Skills are discovered from `~/.agents/skills/superpowers` (a symlink to `~/.codex/superpowers/skills`).

If you need to update superpowers skills, run:

```bash
cd ~/.codex/superpowers && git pull
```

If skill discovery paths are changed, restart Codex to reload skills.

Do not run the deprecated `superpowers-codex bootstrap` command.
</EXTREMELY_IMPORTANT>

## Tech Stack

- Language: Rust 2021.
- Minimum supported Rust version: `1.85`, as declared in `Cargo.toml`.
- Package manager and build tool: Cargo.
- Primary dependency: published `gmcrypto-core = "=0.12.0"` from crates.io.
- RNG dependencies: `getrandom` with `sys_rng`, plus `rand_core`.
- Test surface: Rust unit/integration tests and CLI smoke tests under `tests/`.
- CI baseline: GitHub Actions (Rust toolchain `1.85`) runs `cargo clippy -D warnings`,
  `cargo test`, and every example — the default set plus the `sm4-aead` / `sm4-xts`
  gated ones.

## Architectural Principles

- Preserve downstream isolation: this repository must exercise the published
  crates.io package exactly as an external user would consume it.
- Do not replace `gmcrypto-core = "=0.12.0"` with a path dependency, workspace
  dependency, git dependency, or unpublished local checkout.
- Keep demo code small and direct. Prefer explicit SDK calls over helper
  frameworks, hidden setup, or abstraction layers that obscure the API surface.
- Keep command behavior stable and copy-pasteable. Existing CLI outputs should
  not change unless the task explicitly requires a breaking demo change.
- Treat all sample keys, IVs, passwords, signer IDs, and ciphertexts as public
  demo fixtures only. Do not present them as production-safe material.
- Keep randomness out of exact-output tests. For randomized crypto operations,
  assert round-trip behavior, validity labels, or stable section markers rather
  than exact signatures or ciphertexts.
- Keep repository hygiene strict. Do not commit local worktrees, IDE folders,
  generated build output, local machine paths, credentials, or tool scratch
  directories.
- Respect user changes in the working tree. Do not revert or overwrite changes
  you did not make unless explicitly asked.

## Terminal Commands

Run these commands from the repository root.

### Formatting

```bash
cargo fmt --check
```

### Linting

```bash
cargo clippy --all-targets -- -D warnings
```

### Tests

```bash
cargo test
```

### Example Build Coverage

```bash
cargo test --examples
```

### Secret Scan

Run when changing docs, examples, CI, keys, tokens, or cryptographic fixtures:

```bash
gitleaks detect --source . --redact --verbose
```

If `gitleaks` reports a public demo fixture, prefer a narrow `.gitleaks.toml`
allowlist entry for that exact fixture over weakening scan rules globally.

## Done Criteria

Before delivering a task, all applicable checks must exit with code `0`.

- `cargo fmt --check` exits `0`.
- `cargo clippy --all-targets -- -D warnings` exits `0` for Rust code changes.
- `cargo test` exits `0`.
- `cargo test --examples` exits `0` when examples exist or are changed.
- `gitleaks detect --source . --redact --verbose` exits `0` when the task
  touches docs, examples, CI, keys, tokens, or cryptographic fixtures.
- `git diff --check` exits `0` before staging or committing.
- The working tree contains only intentional changes for the task.
- Public-facing text does not expose local usernames, absolute local paths,
  private repository locations, credentials, tokens, or machine-specific state.
- New behavior is documented in `README.md` or a focused project doc when it
  changes the CLI, examples, or developer workflow.

If a required command cannot be run, report the exact command, why it could not
run, and what risk remains.
