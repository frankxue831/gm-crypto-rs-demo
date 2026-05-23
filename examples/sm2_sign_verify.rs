use getrandom::SysRng;
use gmcrypto_core::sm2::{sign_with_id, verify_with_id, Sm2PrivateKey, Sm2PublicKey};
use rand_core::UnwrapErr;

const SAMPLE_PRIVATE_KEY_HEX: &str =
    "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";

fn main() {
    let key = sample_private_key();
    let public = Sm2PublicKey::from_point(key.public_key());
    let mut rng = UnwrapErr(SysRng);
    let signer_id = b"demo-user";
    let message = b"hello sdk";

    let signature = sign_with_id(&key, signer_id, message, &mut rng).expect("sign");
    let valid = verify_with_id(&public, signer_id, message, &signature);

    println!("valid: {valid}");
}

fn sample_private_key() -> Sm2PrivateKey {
    let bytes: [u8; 32] = decode_hex(SAMPLE_PRIVATE_KEY_HEX)
        .expect("sample private key hex is valid")
        .try_into()
        .expect("sample private key is 32 bytes");
    Sm2PrivateKey::from_bytes_be(&bytes).expect("sample private key is valid")
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
