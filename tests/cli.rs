use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_gm-crypto-rs-demo");

fn run(args: &[&str]) -> std::process::Output {
    Command::new(BIN).args(args).output().expect("run demo")
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
