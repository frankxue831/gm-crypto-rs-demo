use gmcrypto_core::kdf::pbkdf2_hmac_sm3;

fn main() {
    let mut output = [0u8; 32];
    pbkdf2_hmac_sm3(b"password", b"salt", 10_000, &mut output).expect("derive");
    println!("{}", hex(&output));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
