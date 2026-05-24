# gmcrypto-core SDK Tour Demo Design

## Goal

Expand `gm-crypto-rs-demo` from a narrow smoke-test CLI into a broader SDK tour for the published `gmcrypto-core = "=0.12.0"` crate.

The demo should help an outside Rust user quickly see what the SDK can do, run representative operations from the terminal, and read small source examples that map directly to SDK APIs.

## Current State

The repository is intentionally small and depends on the crates.io release of `gmcrypto-core`, not a local path dependency. The current CLI demonstrates:

- SM3 single-shot hashing via `hash <message>`
- SM2 signing with a fixed public sample private key via `sign <message>`
- SM2 verification via `verify <message> <der-signature-hex>`

This makes the repository useful as a downstream smoke test, but it does not show enough of the SDK surface.

## Recommended Direction

Use a combined demo structure:

- Command Gallery: terminal commands for individual SDK features
- Cookbook Examples: small `examples/*.rs` files that developers can read and run
- End-to-End Tour: a `tour` command that prints a concise walkthrough using sample inputs

This keeps the project practical from both directions: evaluators can run one command, while SDK users can inspect focused source files.

## Command Gallery

Keep the CLI as the first runnable entry point. Commands should be small, copy-pasteable, and integration-tested.

Initial commands:

- `hash <message>`: existing SM3 single-shot digest
- `sign <message> [--id <signer-id>]`: SM2 sign with default or custom signer ID
- `verify <message> <der-signature-hex> [--id <signer-id>]`: SM2 verify with matching signer ID
- `key-info`: print the sample public key as SEC1 uncompressed hex, SPKI DER hex, and SPKI PEM
- `encrypt <message>`: SM2 public-key encryption, printing DER ciphertext hex
- `decrypt <ciphertext-hex>`: SM2 private-key decryption from DER ciphertext hex
- `sm4-encrypt <message>`: SM4-CBC encryption with fixed demo key and IV
- `sm4-decrypt <ciphertext-hex>`: SM4-CBC decryption with the same fixed demo key and IV
- `hmac <key-hex> <message>`: HMAC-SM3 single-shot MAC
- `pbkdf2 <password> <salt-hex> <iterations> <out-len>`: PBKDF2-HMAC-SM3 derived key bytes
- `tour`: run a readable end-to-end walkthrough

The public API of `gmcrypto-core = 0.12.0` has been checked locally. These commands can use:

- `gmcrypto_core::sm2::encrypt`
- `gmcrypto_core::sm2::decrypt`
- `gmcrypto_core::sm4::mode_cbc::{encrypt, decrypt}`
- `gmcrypto_core::hmac::hmac_sm3`
- `gmcrypto_core::kdf::pbkdf2_hmac_sm3`
- `gmcrypto_core::{spki, pem}`

Optional `--id` parsing should stay deliberately small: only accept the trailing form `--id <signer-id>` after the required command arguments. Missing values, duplicated flags, or flags in other positions should produce the existing usage error path.

## Cookbook Examples

Add focused examples under `examples/` once matching public Rust APIs are confirmed:

- `examples/sm3_hash.rs`
- `examples/sm2_sign_verify.rs`
- `examples/sm2_encrypt_decrypt.rs`
- `examples/sm4_cbc.rs`
- `examples/hmac_sm3.rs`
- `examples/pbkdf2_hmac_sm3.rs`

Each example should be short, self-contained, and built around static demo material. Avoid framework code, configuration files, or abstractions that obscure the SDK calls.

## Tour Command

The `tour` command should print a concise sequence of operations:

1. Hash a sample message.
2. Load or derive the fixed demo SM2 key pair.
3. Sign and verify a message with the default signer ID.
4. Demonstrate a failed verification after tampering.
5. Export public key information.
6. Encrypt/decrypt with SM2.
7. Encrypt/decrypt with SM4-CBC.
8. Run HMAC-SM3 and PBKDF2-HMAC-SM3 steps.

The output should be readable and stable enough for tests where randomness is not involved. For randomized operations such as SM2 signatures or encryption, the command may print the random signature or ciphertext with clear labels, but tests must assert section labels and success/failure verdicts rather than exact randomized bytes.

## Safety and Messaging

All sample keys, IVs, passwords, and signer IDs are public demo material. The README and CLI output should clearly say they are not production secrets.

Use these fixed demo values for SM4-CBC:

- Key hex: `0123456789abcdeffedcba9876543210`
- IV hex: `000102030405060708090a0b0c0d0e0f`

Avoid presenting the combined workflow as a production protocol. It is an SDK tour, not cryptographic protocol guidance.

## Implementation Constraints

- Continue depending on `gmcrypto-core = "=0.12.0"` from crates.io.
- Do not add a path dependency to a local `gm-crypto-rs` checkout.
- Keep new dependencies minimal. Prefer the standard library and existing dependencies.
- Prefer direct SDK API examples over wrapper abstractions.
- Preserve existing command behavior where possible.
- Keep CLI parsing simple unless the number of options grows enough to justify a parser dependency.

## Testing

Update integration tests in `tests/cli.rs` to cover:

- Existing hash output remains the known SM3 digest for `abc`.
- Signing verifies successfully and rejects tampered messages.
- Custom signer ID succeeds only when signing and verifying use the same ID.
- Custom signer ID verification fails when verifying with a different ID.
- `key-info` prints stable labels for SEC1 uncompressed hex, SPKI DER hex, and SPKI PEM.
- SM2 encryption commands round-trip without asserting exact ciphertext.
- SM4 commands round-trip with the fixed demo key and IV.
- HMAC-SM3 prints a stable tag for a fixed key and message.
- PBKDF2-HMAC-SM3 prints stable derived bytes for fixed inputs.
- `tour` exits successfully and includes section labels for the demonstrated features.

Add example build coverage through `cargo test --examples` if the local toolchain supports it.

## Documentation

Update `README.md` with:

- A short description that this is a broader SDK tour.
- A command table grouped by SM3, SM2, SM4, and optional KDF/MAC features.
- Copy-paste command snippets.
- Example file list.
- A warning that all demo material is public and unsuitable for real data.

## Implementation Check

The exact public API of `gmcrypto-core = 0.12.0` was inspected before implementation planning. All commands in this design map to APIs exposed by that published Rust crate, so the implementation should not add alternate crypto dependencies or switch to a path dependency.
