use getrandom::SysRng;
use gmcrypto_core::hmac::hmac_sm3;
use gmcrypto_core::kdf::pbkdf2_hmac_sm3;
use gmcrypto_core::pem;
use gmcrypto_core::sm2::{
    decrypt as sm2_decrypt, encrypt as sm2_encrypt, sign_with_id, verify_with_id, Sm2PrivateKey,
    Sm2PublicKey, DEFAULT_SIGNER_ID,
};
use gmcrypto_core::sm3;
use gmcrypto_core::sm4::mode_cbc;
use gmcrypto_core::spki;
use rand_core::UnwrapErr;
use std::env;
use std::process::ExitCode;

const SAMPLE_PRIVATE_KEY_HEX: &str =
    "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
const DEMO_SM4_KEY: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];
const DEMO_SM4_IV: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

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
        [command, message] if command == "hash" => print_hash(message),
        [command, message] if command == "sign" => print_signature(message, DEFAULT_SIGNER_ID),
        [command, message, flag, signer_id] if command == "sign" && flag == "--id" => {
            print_signature(message, signer_id.as_bytes())
        }
        [command, message, signature_hex] if command == "verify" => {
            print_verification(message, signature_hex, DEFAULT_SIGNER_ID)
        }
        [command, message, signature_hex, flag, signer_id]
            if command == "verify" && flag == "--id" =>
        {
            print_verification(message, signature_hex, signer_id.as_bytes())
        }
        [command] if command == "key-info" => print_key_info(),
        [command, message] if command == "encrypt" => print_sm2_ciphertext(message),
        [command, ciphertext_hex] if command == "decrypt" => print_sm2_plaintext(ciphertext_hex),
        [command, message] if command == "sm4-encrypt" => print_sm4_ciphertext(message),
        [command, ciphertext_hex] if command == "sm4-decrypt" => {
            print_sm4_plaintext(ciphertext_hex)
        }
        [command, key_hex, message] if command == "hmac" => print_hmac(key_hex, message),
        [command, password, salt_hex, iterations, out_len] if command == "pbkdf2" => {
            print_pbkdf2(password, salt_hex, iterations, out_len)
        }
        [command] if command == "tour" => print_tour(),
        [] => Err("missing command".to_owned()),
        [command, ..] => Err(format!("unknown or invalid command: {command}")),
    }
}

fn print_hash(message: &str) -> Result<ExitCode, String> {
    let digest = sm3::hash(message.as_bytes());
    println!("{}", encode_hex(&digest));
    Ok(ExitCode::SUCCESS)
}

fn print_signature(message: &str, signer_id: &[u8]) -> Result<ExitCode, String> {
    let key = sample_private_key();
    let mut rng = UnwrapErr(SysRng);
    let signature = sign_with_id(&key, signer_id, message.as_bytes(), &mut rng)
        .map_err(|_| "signing failed".to_owned())?;
    println!("{}", encode_hex(&signature));
    Ok(ExitCode::SUCCESS)
}

fn print_verification(
    message: &str,
    signature_hex: &str,
    signer_id: &[u8],
) -> Result<ExitCode, String> {
    let signature = decode_hex(signature_hex)?;
    let public = sample_public_key();
    if verify_with_id(&public, signer_id, message.as_bytes(), &signature) {
        println!("valid");
        Ok(ExitCode::SUCCESS)
    } else {
        println!("invalid");
        Ok(ExitCode::from(1))
    }
}

fn print_key_info() -> Result<ExitCode, String> {
    let public = sample_public_key();
    let sec1 = public.to_sec1_uncompressed();
    let spki_der = spki::encode_uncompressed(&sec1);
    let spki_pem = pem::encode("PUBLIC KEY", &spki_der);

    println!("sample public key");
    println!("sec1-uncompressed-hex: {}", encode_hex(&sec1));
    println!("spki-der-hex: {}", encode_hex(&spki_der));
    println!("spki-pem:");
    print!("{spki_pem}");
    Ok(ExitCode::SUCCESS)
}

fn print_sm2_ciphertext(message: &str) -> Result<ExitCode, String> {
    let public = sample_public_key();
    let mut rng = UnwrapErr(SysRng);
    let ciphertext = sm2_encrypt(&public, message.as_bytes(), &mut rng)
        .map_err(|_| "SM2 encryption failed".to_owned())?;
    println!("{}", encode_hex(&ciphertext));
    Ok(ExitCode::SUCCESS)
}

fn print_sm2_plaintext(ciphertext_hex: &str) -> Result<ExitCode, String> {
    let ciphertext = decode_hex(ciphertext_hex)?;
    let plaintext = sm2_decrypt(&sample_private_key(), &ciphertext)
        .map_err(|_| "SM2 decryption failed".to_owned())?;
    println!("{}", String::from_utf8_lossy(&plaintext));
    Ok(ExitCode::SUCCESS)
}

fn print_sm4_ciphertext(message: &str) -> Result<ExitCode, String> {
    let ciphertext = mode_cbc::encrypt(&DEMO_SM4_KEY, &DEMO_SM4_IV, message.as_bytes());
    println!("{}", encode_hex(&ciphertext));
    Ok(ExitCode::SUCCESS)
}

fn print_sm4_plaintext(ciphertext_hex: &str) -> Result<ExitCode, String> {
    let ciphertext = decode_hex(ciphertext_hex)?;
    let plaintext = mode_cbc::decrypt(&DEMO_SM4_KEY, &DEMO_SM4_IV, &ciphertext)
        .ok_or_else(|| "SM4-CBC decryption failed".to_owned())?;
    println!("{}", String::from_utf8_lossy(&plaintext));
    Ok(ExitCode::SUCCESS)
}

fn print_hmac(key_hex: &str, message: &str) -> Result<ExitCode, String> {
    let key = decode_hex(key_hex)?;
    let tag = hmac_sm3(&key, message.as_bytes());
    println!("{}", encode_hex(&tag));
    Ok(ExitCode::SUCCESS)
}

fn print_pbkdf2(
    password: &str,
    salt_hex: &str,
    iterations: &str,
    out_len: &str,
) -> Result<ExitCode, String> {
    let salt = decode_hex(salt_hex)?;
    let iterations = iterations
        .parse::<u32>()
        .map_err(|_| "iterations must be a positive 32-bit integer".to_owned())?;
    let out_len = out_len
        .parse::<usize>()
        .map_err(|_| "out-len must be a positive integer".to_owned())?;
    let mut output = vec![0u8; out_len];
    pbkdf2_hmac_sm3(password.as_bytes(), &salt, iterations, &mut output)
        .ok_or_else(|| "PBKDF2-HMAC-SM3 derivation failed".to_owned())?;
    println!("{}", encode_hex(&output));
    Ok(ExitCode::SUCCESS)
}

fn print_tour() -> Result<ExitCode, String> {
    let message = "hello sdk";

    println!("== SM3 hash ==");
    println!("message: {message}");
    println!("digest: {}", encode_hex(&sm3::hash(message.as_bytes())));
    println!();

    println!("== SM2 sign/verify ==");
    let key = sample_private_key();
    let public = sample_public_key();
    let mut rng = UnwrapErr(SysRng);
    let signature = sign_with_id(&key, DEFAULT_SIGNER_ID, message.as_bytes(), &mut rng)
        .map_err(|_| "signing failed".to_owned())?;
    println!("signature-der-hex: {}", encode_hex(&signature));
    println!(
        "verify default id: {}",
        if verify_with_id(&public, DEFAULT_SIGNER_ID, message.as_bytes(), &signature) {
            "valid"
        } else {
            "invalid"
        }
    );
    println!(
        "verify tampered message: {}",
        if verify_with_id(&public, DEFAULT_SIGNER_ID, b"tampered", &signature) {
            "valid"
        } else {
            "invalid"
        }
    );
    println!();

    println!("== SM2 key info ==");
    let sec1 = public.to_sec1_uncompressed();
    let spki_der = spki::encode_uncompressed(&sec1);
    println!("sec1-uncompressed-hex: {}", encode_hex(&sec1));
    println!("spki-der-hex: {}", encode_hex(&spki_der));
    println!();

    println!("== SM2 encrypt/decrypt ==");
    let ciphertext = sm2_encrypt(&public, message.as_bytes(), &mut rng)
        .map_err(|_| "SM2 encryption failed".to_owned())?;
    let plaintext =
        sm2_decrypt(&key, &ciphertext).map_err(|_| "SM2 decryption failed".to_owned())?;
    println!("ciphertext-der-hex: {}", encode_hex(&ciphertext));
    println!("sm2 decrypted: {}", String::from_utf8_lossy(&plaintext));
    println!();

    println!("== SM4-CBC ==");
    let sm4_ciphertext = mode_cbc::encrypt(&DEMO_SM4_KEY, &DEMO_SM4_IV, message.as_bytes());
    let sm4_plaintext = mode_cbc::decrypt(&DEMO_SM4_KEY, &DEMO_SM4_IV, &sm4_ciphertext)
        .ok_or_else(|| "SM4-CBC decryption failed".to_owned())?;
    println!("ciphertext-hex: {}", encode_hex(&sm4_ciphertext));
    println!("sm4 decrypted: {}", String::from_utf8_lossy(&sm4_plaintext));
    println!();

    println!("== HMAC-SM3 ==");
    let hmac = hmac_sm3(&[0x0b; 20], b"Hi There");
    println!("tag: {}", encode_hex(&hmac));
    println!();

    println!("== PBKDF2-HMAC-SM3 ==");
    let mut derived = [0u8; 32];
    pbkdf2_hmac_sm3(b"password", b"salt", 10_000, &mut derived)
        .ok_or_else(|| "PBKDF2-HMAC-SM3 derivation failed".to_owned())?;
    println!("derived-key: {}", encode_hex(&derived));

    Ok(ExitCode::SUCCESS)
}

fn sample_private_key() -> Sm2PrivateKey {
    let bytes: [u8; 32] = decode_hex(SAMPLE_PRIVATE_KEY_HEX)
        .expect("sample private key hex is valid")
        .try_into()
        .expect("sample private key is 32 bytes");
    Sm2PrivateKey::from_bytes_be(&bytes).expect("sample private key is valid")
}

fn sample_public_key() -> Sm2PublicKey {
    Sm2PublicKey::from_point(sample_private_key().public_key())
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
    eprintln!("  gm-crypto-rs-demo sign <message> [--id <signer-id>]");
    eprintln!("  gm-crypto-rs-demo verify <message> <der-signature-hex> [--id <signer-id>]");
    eprintln!("  gm-crypto-rs-demo key-info");
    eprintln!("  gm-crypto-rs-demo encrypt <message>");
    eprintln!("  gm-crypto-rs-demo decrypt <der-ciphertext-hex>");
    eprintln!("  gm-crypto-rs-demo sm4-encrypt <message>");
    eprintln!("  gm-crypto-rs-demo sm4-decrypt <ciphertext-hex>");
    eprintln!("  gm-crypto-rs-demo hmac <key-hex> <message>");
    eprintln!("  gm-crypto-rs-demo pbkdf2 <password> <salt-hex> <iterations> <out-len>");
    eprintln!("  gm-crypto-rs-demo tour");
}
