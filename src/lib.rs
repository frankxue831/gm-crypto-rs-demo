//! Shared helpers for the `gm-crypto-rs-demo` CLI and examples.
//!
//! All sample keys, IVs, and outputs in this crate are fixed, **public**
//! demo material — the private key is the GB/T 32918.2 sample key. Never
//! use them for real data.

use getrandom::SysRng;
use gmcrypto_core::sm2::{Sm2PrivateKey, Sm2PublicKey};

/// Fixed, public GB/T 32918.2 sample private key scalar (big-endian hex).
///
// DEMO ONLY: GB/T 32918.2 Appendix-A sample scalar — known to every reader of the spec.
// Production: generate via `Sm2PrivateKey::generate(&mut os_rng())` and persist out-of-band (PEM/PKCS#8 in a vault).
// Reusing this key risks: anyone can forge signatures and decrypt every ciphertext produced with it.
pub const SAMPLE_PRIVATE_KEY_HEX: &str =
    "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";

/// Fixed, public SM4-128 demo key — chosen so the CLI `tour` and the
/// `sm4_cbc_ctr` example produce reproducible, byte-identical ciphertexts
/// in CI and in docs.
///
// DEMO ONLY: public, fixed 128-bit SM4 key for reproducible demo output.
// Production: derive per-session keys via a KDF or unwrap a KEK-wrapped DEK; never hard-code.
// Reusing this risks: anyone with the source can decrypt every ciphertext produced with it.
pub const DEMO_SM4_KEY: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

/// Fixed, public SM4 demo IV paired with [`DEMO_SM4_KEY`] for CBC-mode
/// demonstrations. Held constant so example/tour output stays reproducible.
///
// DEMO ONLY: public, fixed 128-bit CBC IV for reproducible demo output.
// Production: generate a fresh random IV per message via `os_rng()` and prepend it to the ciphertext.
// Reusing this (key, IV) pair risks: CBC prefix-equality leak — identical plaintext prefixes produce identical ciphertext prefixes, revealing equality of messages.
pub const DEMO_SM4_IV: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

/// Fixed, public HMAC-SM3 demo key — 20 bytes of 0x0b, borrowed from
/// RFC 4231 test case 1. Held constant so the CLI `tour` and the
/// `hmac_and_kdf` example produce reproducible, byte-identical tags.
///
// DEMO ONLY: input vector borrowed from RFC 4231 test case 1; HMAC-SM3 output is SM3-specific (not in the RFC).
// Production: generate a random 32-byte (256-bit) key via `os_rng()` and store it in a secret manager.
// Reusing this key risks: any reader of the source can forge MACs that this verifier will accept.
pub const DEMO_HMAC_KEY: [u8; 20] = [0x0b; 20];

/// Fixed, public HMAC-SM3 demo message — `"Hi There"`, borrowed from
/// RFC 4231 test case 1.
///
// DEMO ONLY: input vector borrowed from RFC 4231 test case 1; HMAC-SM3 output is SM3-specific (not in the RFC).
// Production: the message is whatever you are authenticating — not a fixture.
// Reusing this constant in real code risks: nothing on its own, but it is here purely to make demo output reproducible.
pub const DEMO_HMAC_MSG: &[u8] = b"Hi There";

/// Fixed, public PBKDF2-HMAC-SM3 demo password — borrowed from
/// RFC 6070 input shape (the SM3-keyed output is not in the RFC).
///
// DEMO ONLY: input vector borrowed from RFC 6070; PBKDF2-HMAC-SM3 output is SM3-specific (not in the RFC).
// Production: take the password from user input — never hard-code.
// Reusing this (password, salt) pair risks: rainbow-table / offline dictionary attacks become trivial once the derived key leaks.
pub const DEMO_PBKDF2_PASSWORD: &[u8] = b"password";

/// Fixed, public PBKDF2-HMAC-SM3 demo salt — ASCII `"salt"`, borrowed
/// from RFC 6070 input shape.
///
// DEMO ONLY: input vector borrowed from RFC 6070; PBKDF2-HMAC-SM3 output is SM3-specific (not in the RFC).
// Production: generate a fresh per-user random salt (>= 16 bytes) via `os_rng()` and store it alongside the hash.
// Reusing this salt risks: defeats the whole point of salting — identical passwords across users derive identical keys.
pub const DEMO_PBKDF2_SALT: &[u8] = b"salt";

/// Fixed PBKDF2-HMAC-SM3 iteration count for the tour and `hmac_and_kdf`
/// example. Held low so the demo runs fast in CI.
///
// NOTE: 10_000 iterations keeps this demo fast. For real password
// hashing use a far higher count (OWASP suggests >= 600_000).
pub const DEMO_PBKDF2_ITER: u32 = 10_000;

/// Fixed PBKDF2-HMAC-SM3 derived-key length (bytes) for the tour and
/// `hmac_and_kdf` example.
pub const DEMO_PBKDF2_LEN: usize = 32;

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
    sample_private_key().public_key()
}

/// The OS CSPRNG, exposed for the SDK's `TryCryptoRng` bound (gmcrypto-core 1.0+).
///
/// `getrandom::SysRng` implements `TryRngCore` and is marked `CryptoRng`, so
/// it satisfies `TryCryptoRng` directly — no adapter needed since 1.0.
pub fn os_rng() -> SysRng {
    SysRng
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
