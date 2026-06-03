//! SM4-GCM streaming AEAD (chunked encrypt / decrypt). Requires the `sm4-aead` feature.
//! Run: cargo run --features sm4-aead --example sm4_streaming
//! Safety: §9 rule 1. Randomness, §9 rule 2. Uniqueness of nonces / IVs / counters, §9 rule 3. Authentication.

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm4::{mode_gcm, Sm4GcmDecryptor, Sm4GcmEncryptor};

fn main() {
    println!("== SM4-GCM streaming AEAD ==\n");

    // DEMO ONLY: public, fixed 128-bit SM4-GCM key for reproducible demo output.
    // Production: derive per-session keys via a KDF or unwrap a KEK-wrapped DEK; never hard-code.
    // Reusing this risks: anyone with the source can decrypt every ciphertext produced with it.
    let key = [0x11u8; 16];
    // DEMO ONLY: fixed 96-bit GCM nonce for reproducible demo output.
    // Production: generate a fresh random nonce per message via `os_rng()` (or a strictly-monotonic counter).
    // Reusing this (key, nonce) pair risks: catastrophic -- recovers the GHASH authentication key and enables forgery.
    let nonce = [0x22u8; 12];
    let aad = b"header-authenticated-not-encrypted";

    // Build a plaintext that does not align to the 16-byte SM4 block boundary,
    // so the chunked path exercises partial-block buffering.
    let plaintext: Vec<u8> = (0u8..50).collect();
    let chunks: [&[u8]; 3] = [&plaintext[..7], &plaintext[7..32], &plaintext[32..]];

    // ---- Streaming encrypt: feed chunks, collect emitted ciphertext, finalize the tag. ----
    let mut enc = Sm4GcmEncryptor::new(&key, &nonce, aad);
    let mut streamed_ct: Vec<u8> = Vec::with_capacity(plaintext.len());
    for chunk in &chunks {
        let out = enc.update(chunk).expect("under GCM length ceiling");
        streamed_ct.extend_from_slice(&out);
    }
    let tag = enc.finalize();
    println!("streamed ct = {}", encode_hex(&streamed_ct));
    println!("tag         = {}", encode_hex(&tag));

    // Compare against single-shot mode_gcm::encrypt on the full plaintext.
    let (oneshot_ct, oneshot_tag) =
        mode_gcm::encrypt(&key, &nonce, aad, &plaintext).expect("under GCM length ceiling");
    assert_eq!(
        streamed_ct, oneshot_ct,
        "streamed ciphertext matches single-shot"
    );
    assert_eq!(tag, oneshot_tag, "streamed tag matches single-shot");
    println!("  chunked encrypt output equals single-shot output");

    // ---- Streaming decrypt: input-incremental, output-buffered, commit-on-verify. ----
    // The decryptor releases plaintext ONLY after finalize_verify checks the tag.
    let mut dec = Sm4GcmDecryptor::new(&key, &nonce, aad);
    let mid = streamed_ct.len() / 2;
    dec.update(&streamed_ct[..mid]);
    dec.update(&streamed_ct[mid..]);
    let recovered = dec.finalize_verify(&tag).expect("auth ok");
    assert_eq!(recovered, plaintext, "streaming GCM round-trip");
    println!("  chunked decrypt verifies tag and returns the original plaintext");

    // Tamper check: a flipped tag byte must cause finalize_verify to return None.
    let mut dec_bad = Sm4GcmDecryptor::new(&key, &nonce, aad);
    dec_bad.update(&streamed_ct);
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    assert!(
        dec_bad.finalize_verify(&bad_tag).is_none(),
        "tampered tag must be rejected by the streaming decryptor",
    );
    println!("  tampered tag is rejected on finalize_verify");

    println!("\nOK");
}
