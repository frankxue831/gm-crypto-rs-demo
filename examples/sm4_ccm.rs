//! SM4-CCM authenticated encryption (AEAD). Requires the `sm4-aead` feature.
//! Run: cargo run --features sm4-aead --example sm4_ccm
//! Safety: §9 rule 1. Randomness, §9 rule 2. Uniqueness of nonces / IVs / counters, §9 rule 3. Authentication.

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm4::mode_ccm;

fn main() {
    println!("== SM4-CCM authenticated encryption ==\n");

    // DEMO ONLY: public, fixed 128-bit SM4-CCM key for reproducible demo output.
    // Production: derive per-session keys via a KDF or unwrap a KEK-wrapped DEK; never hard-code.
    // Reusing this risks: anyone with the source can decrypt every ciphertext produced with it.
    let key = [0x42u8; 16];

    // ---- Case 1: 12-byte nonce, 16-byte tag (recommended defaults) ----
    println!("-- Case 1: 12-byte nonce, 16-byte tag --");

    // DEMO ONLY: fixed 96-bit CCM nonce for reproducible demo output.
    // Production: generate a fresh random nonce per message via `os_rng()` (or a strictly-monotonic counter).
    // Reusing this (key, nonce) pair risks: catastrophic for CCM as well as GCM -- it breaks confidentiality and authenticity.
    let nonce12 = [0x01u8; 12];
    let aad = b"header-authenticated-not-encrypted";
    let plaintext = b"authenticated and encrypted via SM4-CCM";
    let tag_len_full = 16;

    // mode_ccm::encrypt returns Option<Vec<u8>>; the output is ciphertext||tag in one buffer.
    let ct_with_tag = mode_ccm::encrypt(&key, &nonce12, aad, plaintext, tag_len_full)
        .expect("valid CCM parameters");
    assert_eq!(ct_with_tag.len(), plaintext.len() + tag_len_full);
    println!("ct||tag = {}", encode_hex(&ct_with_tag));

    let recovered =
        mode_ccm::decrypt(&key, &nonce12, aad, &ct_with_tag, tag_len_full).expect("auth ok");
    assert_eq!(&recovered[..], &plaintext[..], "CCM round-trip");
    println!("  decrypt with correct inputs succeeds");

    // Tamper the tag (last `tag_len_full` bytes of ct_with_tag).
    let mut bad_tag_buf = ct_with_tag.clone();
    let tag_off = bad_tag_buf.len() - tag_len_full;
    bad_tag_buf[tag_off] ^= 1;
    assert!(
        mode_ccm::decrypt(&key, &nonce12, aad, &bad_tag_buf, tag_len_full).is_none(),
        "tampered tag must be rejected",
    );

    // Tamper the ciphertext (first byte).
    let mut bad_ct_buf = ct_with_tag.clone();
    bad_ct_buf[0] ^= 1;
    assert!(
        mode_ccm::decrypt(&key, &nonce12, aad, &bad_ct_buf, tag_len_full).is_none(),
        "tampered ciphertext must be rejected",
    );

    // Wrong AAD.
    assert!(
        mode_ccm::decrypt(&key, &nonce12, b"different-aad", &ct_with_tag, tag_len_full).is_none(),
        "changed AAD must be rejected",
    );
    println!("  tampered ct / tag / AAD are all rejected");

    // ---- Case 2: 13-byte nonce, 8-byte truncated tag (Zigbee / 802.15.4 shape) ----
    println!("\n-- Case 2: 13-byte nonce, 8-byte tag --");

    // DEMO ONLY: fixed 13-byte CCM nonce for reproducible demo output (13 bytes is common in 802.15.4 / Zigbee).
    // Production: generate a fresh random nonce per message via `os_rng()` (or a strictly-monotonic counter that fits 13 bytes).
    // Reusing this (key, nonce) pair risks: catastrophic for CCM as well as GCM — it breaks confidentiality and authenticity.
    let nonce13 = [0x07u8; 13];
    let tag_len_short = 8;

    let ct_with_tag2 =
        mode_ccm::encrypt(&key, &nonce13, aad, plaintext, tag_len_short).expect("valid CCM params");
    assert_eq!(ct_with_tag2.len(), plaintext.len() + tag_len_short);
    println!("ct||tag = {}", encode_hex(&ct_with_tag2));

    let recovered2 =
        mode_ccm::decrypt(&key, &nonce13, aad, &ct_with_tag2, tag_len_short).expect("auth ok");
    assert_eq!(
        &recovered2[..],
        &plaintext[..],
        "CCM round-trip (short tag)"
    );
    println!("  decrypt with correct inputs succeeds");

    // Wrong nonce (flip first byte) must be rejected.
    let mut bad_nonce = nonce13;
    bad_nonce[0] ^= 1;
    assert!(
        mode_ccm::decrypt(&key, &bad_nonce, aad, &ct_with_tag2, tag_len_short).is_none(),
        "tampered nonce must be rejected",
    );
    println!("  tampered nonce is rejected");

    println!("\nOK");
}
