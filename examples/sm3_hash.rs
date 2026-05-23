use gmcrypto_core::sm3;

fn main() {
    let digest = sm3::hash(b"abc");
    println!("{}", hex(&digest));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
