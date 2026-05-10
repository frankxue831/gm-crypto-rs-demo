use crypto_bigint::U256;
use gmcrypto_core::sm2::{
    sign_with_id, verify_with_id, Sm2PrivateKey, Sm2PublicKey, DEFAULT_SIGNER_ID,
};
use gmcrypto_core::sm3;
use rand_core::OsRng;
use std::env;
use std::process::ExitCode;

const SAMPLE_PRIVATE_KEY_HEX: &str =
    "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            eprintln!();
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    match args.as_slice() {
        [command, message] if command == "hash" => {
            let digest = sm3::hash(message.as_bytes());
            println!("{}", encode_hex(&digest));
            Ok(ExitCode::SUCCESS)
        }
        [command, message] if command == "sign" => {
            let key = sample_private_key();
            let signature = sign_with_id(&key, DEFAULT_SIGNER_ID, message.as_bytes(), &mut OsRng)
                .map_err(|_| "signing failed".to_owned())?;
            println!("{}", encode_hex(&signature));
            Ok(ExitCode::SUCCESS)
        }
        [command, message, signature_hex] if command == "verify" => {
            let signature = decode_hex(signature_hex)?;
            let key = sample_private_key();
            let public = Sm2PublicKey::from_point(key.public_key());
            if verify_with_id(&public, DEFAULT_SIGNER_ID, message.as_bytes(), &signature) {
                println!("valid");
                Ok(ExitCode::SUCCESS)
            } else {
                println!("invalid");
                Ok(ExitCode::from(1))
            }
        }
        [] => Err("missing command".to_owned()),
        [command, ..] => Err(format!("unknown or invalid command: {command}")),
    }
}

fn sample_private_key() -> Sm2PrivateKey {
    let d = U256::from_be_hex(SAMPLE_PRIVATE_KEY_HEX);
    Sm2PrivateKey::new(d).expect("sample private key is valid")
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("hex input must have an even number of characters".to_owned());
    }

    let mut out = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", byte as char)),
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  gm-crypto-rs-demo hash <message>");
    eprintln!("  gm-crypto-rs-demo sign <message>");
    eprintln!("  gm-crypto-rs-demo verify <message> <der-signature-hex>");
}
