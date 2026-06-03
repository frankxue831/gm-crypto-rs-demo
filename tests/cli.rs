use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_gm-crypto-rs-demo");

fn run(args: &[&str]) -> std::process::Output {
    Command::new(BIN).args(args).output().expect("run demo")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf8 stdout")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf8 stderr")
}

#[test]
fn hash_prints_known_sm3_digest() {
    let output = run(&["hash", "abc"]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0\n"
    );
}

#[test]
fn sign_and_verify_accept_custom_signer_id() {
    let signed = run(&["sign", "hello", "--id", "alice@example"]);
    assert!(signed.status.success(), "stderr: {}", stderr(&signed));
    let sig_hex = stdout(&signed);
    let sig_hex = sig_hex.trim();

    let verified = run(&["verify", "hello", sig_hex, "--id", "alice@example"]);
    assert!(verified.status.success(), "stderr: {}", stderr(&verified));
    assert_eq!(stdout(&verified), "valid\n");

    let wrong_id = run(&["verify", "hello", sig_hex, "--id", "bob@example"]);
    assert!(!wrong_id.status.success());
    assert_eq!(stdout(&wrong_id), "invalid\n");
}

#[test]
fn key_info_prints_labeled_public_key_formats() {
    let output = run(&["key-info"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);

    assert!(out.contains("sample public key"));
    assert!(out.contains("sec1-uncompressed-hex: 04"));
    assert!(out.contains("spki-der-hex: 30"));
    assert!(out.contains("spki-pem:"));
    assert!(out.contains("-----BEGIN PUBLIC KEY-----"));
}

#[test]
fn sm2_encrypt_decrypt_round_trips_message() {
    let encrypted = run(&["encrypt", "secret message"]);
    assert!(encrypted.status.success(), "stderr: {}", stderr(&encrypted));
    let ciphertext_hex = stdout(&encrypted);
    let ciphertext_hex = ciphertext_hex.trim();
    assert!(!ciphertext_hex.is_empty());

    let decrypted = run(&["decrypt", ciphertext_hex]);
    assert!(decrypted.status.success(), "stderr: {}", stderr(&decrypted));
    assert_eq!(stdout(&decrypted), "secret message\n");
}

#[test]
fn sm4_encrypt_decrypt_round_trips_message() {
    let encrypted = run(&["sm4-encrypt", "bulk data"]);
    assert!(encrypted.status.success(), "stderr: {}", stderr(&encrypted));
    let ciphertext_hex = stdout(&encrypted);
    let ciphertext_hex = ciphertext_hex.trim();
    assert!(!ciphertext_hex.is_empty());

    let decrypted = run(&["sm4-decrypt", ciphertext_hex]);
    assert!(decrypted.status.success(), "stderr: {}", stderr(&decrypted));
    assert_eq!(stdout(&decrypted), "bulk data\n");
}

#[test]
fn hmac_and_pbkdf2_print_known_outputs() {
    let hmac = run(&[
        "hmac",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "Hi There",
    ]);
    assert!(hmac.status.success(), "stderr: {}", stderr(&hmac));
    assert_eq!(
        stdout(&hmac),
        "51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70\n"
    );

    let pbkdf2 = run(&["pbkdf2", "password", "73616c74", "10000", "32"]);
    assert!(pbkdf2.status.success(), "stderr: {}", stderr(&pbkdf2));
    assert_eq!(
        stdout(&pbkdf2),
        "738c8c432372d98a73350bc252209e4cf2acdde7cc816730b9812bdfd55c1265\n"
    );
}

#[test]
fn tour_prints_non_flaky_section_results() {
    let output = run(&["tour"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);

    // Section headers, in the new canonical order. `contains` only -- the test
    // does not enforce ordering, but every label must appear verbatim.
    for label in [
        "== SM3 hash ==",
        "== HMAC-SM3 ==",
        "== PBKDF2-HMAC-SM3 ==",
        "== SM2 key info ==",
        "== SM2 sign/verify ==",
        "== SM2 encrypt/decrypt ==",
        "== SM4-CBC ==",
        "== What else? ==",
    ] {
        assert!(out.contains(label), "missing label {label}: {out}");
    }

    // Deterministic byte values (HMAC and PBKDF2 outputs are SM3-keyed and
    // pinned in `hmac_and_pbkdf2_print_known_outputs` -- same inputs here).
    assert!(out.contains("tag: 51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70"));
    assert!(out
        .contains("derived-key: 738c8c432372d98a73350bc252209e4cf2acdde7cc816730b9812bdfd55c1265"));

    // SM2 sign/verify scaffolding (deterministic structure; we do NOT pin sig
    // bytes -- SM2 signing is randomized, which the tour now demonstrates).
    assert!(out.contains("signer-z (default id): "));
    assert!(out.contains("signature-1-der-hex: "));
    assert!(out.contains("signature-2-der-hex: "));
    assert!(out.contains("verify default id: valid"));
    assert!(out.contains("verify tampered message: invalid"));
    assert!(out.contains("sm2 decrypted: hello sdk"));
    assert!(out.contains("sm4 decrypted: hello sdk"));

    // SM4-GCM / SM4-XTS sections render different content depending on the
    // feature flags this test crate was compiled with.
    if cfg!(feature = "sm4-aead") {
        assert!(out.contains("== SM4-GCM ==\n"));
        assert!(out.contains("sm4-gcm decrypted: hello sdk"));
    } else {
        assert!(out.contains("== SM4-GCM ==  (skipped -- rebuild with --features sm4-aead)"));
    }
    if cfg!(feature = "sm4-xts") {
        assert!(out.contains("== SM4-XTS ==\n"));
        // XTS data unit must be >= 16 bytes, so the tour uses a longer plaintext
        // than the SM4-CBC section ("hello sdk" is only 9 bytes).
        assert!(out.contains("sm4-xts decrypted: a disk sector worth of bytes to encrypt!"));
    } else {
        assert!(out.contains("== SM4-XTS ==  (skipped -- rebuild with --features sm4-xts)"));
    }

    // Epilogue pointers.
    assert!(out.contains("PKCS#8 / encrypted PKCS#8:  cargo run --example sm2_key_encoding"));
    assert!(out
        .contains("SM4-GCM (AEAD):             cargo run --features sm4-aead --example sm4_aead"));
    assert!(
        out.contains("SM4-XTS:                    cargo run --features sm4-xts  --example sm4_xts")
    );
    assert!(out.contains("Production safety:          docs/using-gmcrypto-core.md \u{a7}9"));
}

#[test]
fn sign_output_verifies_and_rejects_tampering() {
    let signed = run(&["sign", "hello"]);
    assert!(
        signed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let sig_hex = String::from_utf8(signed.stdout).expect("utf8 signature");
    let sig_hex = sig_hex.trim();
    assert!(!sig_hex.is_empty());

    let verified = run(&["verify", "hello", sig_hex]);
    assert!(
        verified.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert_eq!(
        String::from_utf8(verified.stdout).expect("utf8 stdout"),
        "valid\n"
    );

    let tampered = run(&["verify", "tampered", sig_hex]);
    assert!(!tampered.status.success());
    assert_eq!(
        String::from_utf8(tampered.stdout).expect("utf8 stdout"),
        "invalid\n"
    );
}

#[test]
fn empty_argv_prints_missing_command_and_usage() {
    let output = run(&[]);
    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(err.contains("missing command"), "stderr: {err}");
    assert!(err.contains("Usage:"), "stderr: {err}");
}

#[test]
fn bogus_subcommand_prints_unknown_command_error() {
    let output = run(&["bogus"]);
    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(
        err.contains("unknown or invalid command: bogus"),
        "stderr: {err}"
    );
}

#[test]
fn verify_with_bad_hex_signature_fails() {
    // `zz` is even-length but not valid hex, so decode_hex hits the
    // "invalid hex character" branch deterministically.
    let output = run(&["verify", "hello", "zz"]);
    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(err.contains("invalid hex character: z"), "stderr: {err}");
}

#[test]
fn pbkdf2_with_non_numeric_iter_fails() {
    // Salt-hex and out-len are valid; only the iter argument is non-numeric,
    // so the parse-error branch fires first.
    let output = run(&["pbkdf2", "password", "73616c74", "abc", "32"]);
    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(
        err.contains("iterations must be a positive 32-bit integer"),
        "stderr: {err}"
    );
}

#[test]
fn sm4_decrypt_rejects_tampered_ciphertext() {
    let encrypted = run(&["sm4-encrypt", "bulk data"]);
    assert!(encrypted.status.success(), "stderr: {}", stderr(&encrypted));
    let ct_hex = stdout(&encrypted);
    let ct_hex = ct_hex.trim();
    assert!(ct_hex.len() >= 2 && ct_hex.len() % 2 == 0);

    // Flip the low nibble of the final ciphertext byte. The last block is
    // the PKCS#7 padding block, so this deterministically corrupts the pad
    // without changing the hex length or introducing non-hex characters.
    let mut tampered: Vec<u8> = ct_hex.as_bytes().to_vec();
    let last = tampered.len() - 1;
    let nibble = u8::from_str_radix(
        std::str::from_utf8(&tampered[last..]).expect("utf8 nibble"),
        16,
    )
    .expect("hex nibble");
    let flipped = nibble ^ 0x1;
    let flipped_hex = format!("{flipped:x}");
    tampered[last] = flipped_hex.as_bytes()[0];
    let tampered_hex = String::from_utf8(tampered).expect("utf8 tampered");
    assert_ne!(tampered_hex, ct_hex);

    let decrypted = run(&["sm4-decrypt", &tampered_hex]);
    assert!(!decrypted.status.success());
    let err = stderr(&decrypted);
    assert!(err.contains("SM4-CBC decryption failed"), "stderr: {err}");
}
