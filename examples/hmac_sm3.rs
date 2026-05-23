use gmcrypto_core::hmac::hmac_sm3;

fn main() {
    let tag = hmac_sm3(&[0x0b; 20], b"Hi There");
    println!("{}", hex(&tag));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
