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

    for label in [
        "== SM3 hash ==",
        "== SM2 sign/verify ==",
        "== SM2 key info ==",
        "== SM2 encrypt/decrypt ==",
        "== SM4-CBC ==",
        "== HMAC-SM3 ==",
        "== PBKDF2-HMAC-SM3 ==",
    ] {
        assert!(out.contains(label), "missing label {label}: {out}");
    }
    assert!(out.contains("verify default id: valid"));
    assert!(out.contains("verify tampered message: invalid"));
    assert!(out.contains("sm2 decrypted: hello sdk"));
    assert!(out.contains("sm4 decrypted: hello sdk"));
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
