//! SM4-GCM authenticated encryption (AEAD). Requires the `sm4-aead` feature.
//! Run: cargo run --features sm4-aead --example sm4_aead
//! Safety: §9 rule 1. Randomness, §9 rule 2. Uniqueness of nonces / IVs / counters, §9 rule 3. Authentication.

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm4::mode_gcm;

fn main() {
    println!("== SM4-GCM authenticated encryption ==\n");

    // DEMO ONLY: public, fixed 128-bit SM4-GCM key for reproducible demo output.
    // Production: derive per-session keys via a KDF or unwrap a KEK-wrapped DEK; never hard-code.
    // Reusing this risks: anyone with the source can decrypt every ciphertext produced with it.
    let key = [0x01u8; 16];
    // DEMO ONLY: fixed 96-bit GCM nonce (the standard size) for reproducible demo output.
    // Production: generate a fresh random nonce per message via `os_rng()` (or a strictly-monotonic counter).
    // Reusing this (key, nonce) pair risks: catastrophic — recovers the GHASH authentication key, enabling forgery of any ciphertext.
    let nonce = [0x02u8; 12];
    let aad = b"header-authenticated-not-encrypted";
    let plaintext = b"authenticated and encrypted";

    // In 1.0, single-shot mode_gcm::encrypt returns Option<…> — it rejects
    // plaintext above the GCM length ceiling (2^36 − 32 bytes). Our fixed
    // 27-byte demo input is nowhere near the ceiling, so .expect() is fine.
    let (ciphertext, tag) = mode_gcm::encrypt(&key, &nonce, aad, plaintext)
        .expect("plaintext under GCM length ceiling");
    println!("ciphertext = {}", encode_hex(&ciphertext));
    println!("tag        = {}", encode_hex(&tag));

    let recovered = mode_gcm::decrypt(&key, &nonce, aad, &ciphertext, &tag).expect("auth ok");
    assert_eq!(&recovered[..], &plaintext[..], "GCM round-trip");
    println!("  decrypt with correct inputs succeeds");

    let mut bad_ct = ciphertext.clone(); // clone so we can flip a byte for the tamper test
    bad_ct[0] ^= 1;
    assert!(
        mode_gcm::decrypt(&key, &nonce, aad, &bad_ct, &tag).is_none(),
        "tampered ciphertext must be rejected",
    );

    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    assert!(
        mode_gcm::decrypt(&key, &nonce, aad, &ciphertext, &bad_tag).is_none(),
        "tampered tag must be rejected",
    );

    assert!(
        mode_gcm::decrypt(&key, &nonce, b"different-aad", &ciphertext, &tag).is_none(),
        "changed AAD must be rejected",
    );
    println!("  tampered ciphertext / tag / AAD are all rejected");

    // SM4-CCM is demonstrated in examples/sm4_ccm.rs (same sm4-aead feature).
    // Streaming SM4-GCM is demonstrated in examples/sm4_streaming.rs.
    println!("\nOK");
}
