//! Shared helpers for the `gm-crypto-rs-demo` CLI and examples.
//!
//! All sample keys, IVs, and outputs in this crate are fixed, **public**
//! demo material — the private key is the GB/T 32918.2 sample key. Never
//! use them for real data.

use getrandom::SysRng;
use gmcrypto_core::sm2::{Sm2PrivateKey, Sm2PublicKey};
use rand_core::UnwrapErr;

/// Fixed, public GB/T 32918.2 sample private key scalar (big-endian hex).
pub const SAMPLE_PRIVATE_KEY_HEX: &str =
    "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";

/// Build the demo's sample SM2 private key from the fixed sample scalar.
pub fn sample_private_key() -> Sm2PrivateKey {
    let bytes: [u8; 32] = decode_hex(SAMPLE_PRIVATE_KEY_HEX)
        .expect("sample private key hex is valid")
        .try_into()
        .expect("decoded sample key must be exactly 32 bytes");
    Sm2PrivateKey::from_bytes_be(&bytes).expect("sample private key is valid")
}

/// The sample SM2 public key derived from [`sample_private_key`].
pub fn sample_public_key() -> Sm2PublicKey {
    Sm2PublicKey::from_point(sample_private_key().public_key())
}

/// The OS CSPRNG, adapted to the `rand_core` traits the SDK expects.
///
/// `getrandom::SysRng` is infallible on supported targets; `UnwrapErr`
/// adapts its `TryRngCore` impl to the infallible `RngCore` the SM2
/// signing/encryption APIs require.
pub fn os_rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

/// Lowercase-hex encode bytes.
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decode a hex string into bytes.
pub fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
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
