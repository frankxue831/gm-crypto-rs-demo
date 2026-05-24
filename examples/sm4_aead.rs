//! SM4-GCM authenticated encryption (AEAD). Requires the `sm4-aead` feature.
//! Run: cargo run --features sm4-aead --example sm4_aead

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm4::mode_gcm;

fn main() {
    println!("== SM4-GCM authenticated encryption ==\n");

    let key = [0x01u8; 16];
    let nonce = [0x02u8; 12]; // 96-bit nonce (the standard size); never reuse per key
    let aad = b"header-authenticated-not-encrypted";
    let plaintext = b"authenticated and encrypted";

    let (ciphertext, tag) = mode_gcm::encrypt(&key, &nonce, aad, plaintext);
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

    // SM4-CCM is also available under the same feature via
    // gmcrypto_core::sm4::mode_ccm.
    println!("\nOK");
}
