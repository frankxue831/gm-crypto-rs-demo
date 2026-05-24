use gm_crypto_rs_demo::{decode_hex, encode_hex, os_rng, sample_private_key};
use gmcrypto_core::sm2::{sign_with_id, verify_with_id, Sm2PublicKey, DEFAULT_SIGNER_ID};
use gmcrypto_core::sm3;
use std::env;
use std::process::ExitCode;

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
            let mut rng = os_rng();
            let signature = sign_with_id(&key, DEFAULT_SIGNER_ID, message.as_bytes(), &mut rng)
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

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  gm-crypto-rs-demo hash <message>");
    eprintln!("  gm-crypto-rs-demo sign <message>");
    eprintln!("  gm-crypto-rs-demo verify <message> <der-signature-hex>");
}
