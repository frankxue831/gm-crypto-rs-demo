//! Length-committed streaming SM4-CCM (v1.12). Requires the `sm4-aead` feature.
//! Run: cargo run --features sm4-aead --example sm4_ccm_streaming
//! Safety: §9 rule 1. Randomness, §9 rule 2. Uniqueness of nonces / IVs / counters, §9 rule 3. Authentication.
//!
//! v1.13: `Sm4CcmEncryptor` / `Sm4CcmDecryptor` (and the rest of the SM4 streaming
//! family) zeroize key material on drop. No signature change.

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm4::{mode_ccm, Sm4CcmDecryptor, Sm4CcmEncryptor};

fn main() {
    println!("== SM4-CCM length-committed streaming AEAD ==\n");

    // DEMO ONLY: public, fixed 128-bit SM4-CCM key for reproducible demo output.
    // Production: derive per-session keys via a KDF or unwrap a KEK-wrapped DEK; never hard-code.
    // Reusing this risks: anyone with the source can decrypt every ciphertext produced with it.
    let key = [0x42u8; 16];
    // DEMO ONLY: fixed 96-bit CCM nonce for reproducible demo output.
    // Production: generate a fresh random nonce per message via `os_rng()` (or a strictly-monotonic counter).
    // Reusing this (key, nonce) pair risks: catastrophic for CCM -- it breaks confidentiality and authenticity.
    // A different declared plaintext_len on the same pair is still nonce reuse (CCM encodes the length in B0).
    let nonce = [0x01u8; 12];
    let aad = b"header-authenticated-not-encrypted";
    let tag_len = 16;

    // Build a plaintext that does not align to the 16-byte SM4 block boundary,
    // so the chunked path exercises partial-block buffering.
    let plaintext: Vec<u8> = (0u8..50).collect();
    let chunks: [&[u8]; 3] = [&plaintext[..7], &plaintext[7..32], &plaintext[32..]];

    // ---- Length-committed encrypt: declare plaintext.len() at construction. ----
    // CCM encodes that length in B0; in exchange every update emits ciphertext
    // immediately (O(chunk) memory). Over-feed poisons; under-feed yields no tag.
    let mut enc = Sm4CcmEncryptor::new(&key, &nonce, aad, plaintext.len(), tag_len)
        .expect("valid CCM nonce and tag length");
    let mut streamed_ct: Vec<u8> = Vec::with_capacity(plaintext.len());
    for chunk in &chunks {
        let out = enc.update(chunk).expect("not over the committed length");
        streamed_ct.extend_from_slice(&out);
    }
    let tag = enc.finalize().expect("fed exactly the committed length");
    println!("streamed ct = {}", encode_hex(&streamed_ct));
    println!("tag         = {}", encode_hex(&tag));

    // Compare against single-shot mode_ccm::encrypt (one buffer: ciphertext || tag).
    let oneshot =
        mode_ccm::encrypt(&key, &nonce, aad, &plaintext, tag_len).expect("valid CCM parameters");
    assert_eq!(oneshot.len(), plaintext.len() + tag_len);
    let (oneshot_ct, oneshot_tag) = oneshot.split_at(plaintext.len());
    assert_eq!(
        streamed_ct, oneshot_ct,
        "streamed ciphertext matches single-shot"
    );
    assert_eq!(tag, oneshot_tag, "streamed tag matches single-shot");
    println!("  chunked encrypt output equals single-shot output");

    // ---- Decryptor: input-incremental, output-buffered, commit-on-verify. ----
    // Unlike the encryptor this is not output-streaming: plaintext is released
    // only after finalize_verify checks the tag.
    let mut dec = Sm4CcmDecryptor::new(&key, &nonce, aad).expect("valid nonce");
    let mid = streamed_ct.len() / 2;
    dec.update(&streamed_ct[..mid]);
    dec.update(&streamed_ct[mid..]);
    let recovered = dec.finalize_verify(&tag).expect("auth ok");
    assert_eq!(recovered, plaintext, "streaming CCM round-trip");
    println!("  chunked decrypt verifies tag and returns the original plaintext");

    let mut dec_bad = Sm4CcmDecryptor::new(&key, &nonce, aad).expect("valid nonce");
    dec_bad.update(&streamed_ct);
    let mut bad_tag = tag.clone();
    bad_tag[0] ^= 1;
    assert!(
        dec_bad.finalize_verify(&bad_tag).is_none(),
        "tampered tag must be rejected by the streaming decryptor",
    );
    println!("  tampered tag is rejected on finalize_verify");

    // ---- CCM-only contract: over-feed poisons; under-feed never tags. ----
    // Stricter than Sm4GcmEncryptor, which still returns a tag after poison.
    // DEMO ONLY: extra nonce so these encryptors do not reuse the happy-path pair.
    // Production: every encryptor still needs a fresh nonce, including failed attempts.
    // Reusing this (key, nonce) pair risks: the same catastrophic CCM nonce-reuse as above.
    let over_nonce = [0x03u8; 12];
    let mut over =
        Sm4CcmEncryptor::new(&key, &over_nonce, aad, 10, tag_len).expect("valid CCM params");
    assert!(
        over.update(&[0u8; 11]).is_none(),
        "over-feeding update must poison and emit nothing",
    );
    assert!(
        over.finalize().is_none(),
        "poisoned finalize must not emit a tag",
    );
    println!("  over-feeding poisons the encryptor; finalize returns None");

    // DEMO ONLY: extra nonce so the under-fed encryptor does not reuse a prior pair.
    // Production: generate a fresh random nonce per encryptor via `os_rng()`.
    // Reusing this (key, nonce) pair risks: the same catastrophic CCM nonce-reuse as above.
    let under_nonce = [0x04u8; 12];
    let mut under = Sm4CcmEncryptor::new(&key, &under_nonce, aad, plaintext.len(), tag_len)
        .expect("valid CCM params");
    let _ = under
        .update(&plaintext[..10])
        .expect("still under the committed length");
    assert!(
        under.finalize().is_none(),
        "under-fed finalize must not emit a tag",
    );
    println!("  under-feeding finalize returns None (no tag for a partial stream)");

    println!("\nOK");
}
