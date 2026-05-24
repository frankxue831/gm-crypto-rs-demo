//! SM2 public-key encryption — encrypt / decrypt.
//! Run: cargo run --example sm2_encrypt_decrypt

use gm_crypto_rs_demo::{encode_hex, os_rng, sample_private_key};
use gmcrypto_core::sm2::{decrypt, encrypt, Sm2PublicKey};

fn main() {
    println!("== SM2 public-key encryption (GB/T 32918.4) ==\n");

    let key = sample_private_key();
    let public = Sm2PublicKey::from_point(key.public_key());
    let plaintext = b"secret message";

    let mut rng = os_rng();
    let ct1 = encrypt(&public, plaintext, &mut rng).expect("encrypt");
    let ct2 = encrypt(&public, plaintext, &mut rng).expect("encrypt");
    println!("ciphertext (DER) = {}", encode_hex(&ct1));
    assert_ne!(ct1, ct2, "fresh nonce -> different ciphertext each time");

    let recovered = decrypt(&key, &ct1).expect("decrypt");
    assert_eq!(&recovered[..], &plaintext[..], "decrypt must recover plaintext");
    let recovered2 = decrypt(&key, &ct2).expect("decrypt");
    assert_eq!(&recovered2[..], &plaintext[..], "decrypt must recover plaintext");
    println!("  both ciphertexts decrypt back to the plaintext");

    // SM2 decryption verifies the embedded C3 hash, so corrupted input is
    // rejected rather than silently mangled.
    assert!(
        decrypt(&key, b"not a valid ciphertext").is_err(),
        "corrupt ciphertext must be rejected",
    );
    println!("  corrupted ciphertext is rejected");

    println!("\nOK");
}
