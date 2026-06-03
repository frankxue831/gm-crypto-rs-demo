//! SM4-XTS sector/disk encryption. Requires the `sm4-xts` feature.
//! Run: cargo run --features sm4-xts --example sm4_xts
//! Safety: §9 rule 1. Randomness, §9 rule 2. Uniqueness of nonces / IVs / counters, §9 rule 3. Authentication, §9 rule 7. Pick the right tool.

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm4::mode_xts;

fn main() {
    println!("== SM4-XTS (sector encryption) ==\n");

    // DEMO ONLY: public, fixed 256-bit SM4-XTS key (two distinct 16-byte subkeys per XTS) for reproducible demo output.
    // Production: derive both subkeys from a master KEK; persist out-of-band and rotate per volume.
    // Reusing this risks: any reader of the source can decrypt every sector ever encrypted under it.
    let key: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f,
    ];
    // DEMO ONLY: fixed 16-byte XTS tweak for reproducible demo output.
    // Production: use the sector/block index (typically little-endian u128) as the tweak — never a fixed value.
    // Reusing this (key, tweak) pair across sectors risks: plaintext-equality leak — two sectors with the same plaintext produce identical ciphertext, revealing the duplication.
    let tweak = [0x02u8; 16];
    let sector = b"a disk sector worth of bytes to encrypt!";

    let ct = mode_xts::encrypt(&key, &tweak, sector).expect("xts encrypt");
    println!("ciphertext = {}", encode_hex(&ct));
    let pt = mode_xts::decrypt(&key, &tweak, &ct).expect("xts decrypt");
    assert_eq!(&pt[..], &sector[..], "XTS round-trip");
    println!("XTS round-trips");

    // Unlike SM4-GCM, XTS provides confidentiality but NO authentication:
    // decrypting with the wrong tweak still "succeeds" — it just returns
    // garbage rather than failing. Use an AEAD mode when you need integrity.
    let mut wrong_tweak = tweak;
    wrong_tweak[0] ^= 1;
    let garbled = mode_xts::decrypt(&key, &wrong_tweak, &ct).expect("xts decrypt");
    assert_ne!(
        &garbled[..],
        &sector[..],
        "wrong tweak yields garbage, not an error"
    );
    println!("wrong tweak decrypts to garbage (XTS is unauthenticated)");

    // Identical key halves are rejected per GB/T 17964.
    assert!(mode_xts::encrypt(&[0x42u8; 32], &tweak, sector).is_none());
    println!("identical key halves are rejected (GB/T 17964)");

    println!("\nOK");
}
