//! SM4 block cipher — CBC and CTR modes, plus the raw block primitive.
//! Run: cargo run --example sm4_cbc_ctr
//! Safety: §9 rule 1. Randomness, §9 rule 2. Uniqueness of nonces / IVs / counters, §9 rule 3. Authentication.

use gm_crypto_rs_demo::{encode_hex, DEMO_SM4_IV, DEMO_SM4_KEY};
use gmcrypto_core::sm4::{mode_cbc, mode_ctr, Sm4Cipher};

fn main() {
    println!("== SM4 (GB/T 32907-2016): 128-bit block cipher ==\n");

    // DEMO ONLY: reuses the crate-wide `DEMO_SM4_KEY` / `DEMO_SM4_IV` so this
    // example's CBC ciphertext matches what `cargo run -- tour` prints.
    // Production: fresh random key (out-of-band) + per-message random IV from `os_rng()`.
    // Reusing this (key, IV) pair risks: CBC prefix-equality leak across messages.
    let key = DEMO_SM4_KEY;
    let iv = DEMO_SM4_IV;
    let plaintext = b"SM4 mode demonstration payload";

    let ct = mode_cbc::encrypt(&key, &iv, plaintext);
    let pt = mode_cbc::decrypt(&key, &iv, &ct).expect("cbc decrypt");
    assert_eq!(&pt[..], &plaintext[..], "CBC round-trip");
    println!("CBC ciphertext = {}", encode_hex(&ct));
    println!("CBC round-trips");

    // DEMO ONLY: fixed 16-byte initial counter block (distinct role from the CBC IV) for reproducible output.
    // Production: generate a fresh random nonce/counter per message via `os_rng()` and never reuse the (key, counter) pair.
    // Reusing this (key, counter) pair risks: two-time-pad — XORing the two ciphertexts reveals the XOR of the plaintexts.
    let counter = [0x03u8; 16];
    let ct = mode_ctr::encrypt(&key, &counter, plaintext);
    let pt = mode_ctr::decrypt(&key, &counter, &ct);
    assert_eq!(&pt[..], &plaintext[..], "CTR round-trip");
    println!("CTR round-trips");

    let cipher = Sm4Cipher::new(&key);
    let mut block = [0u8; 16];
    cipher.encrypt_block(&mut block);
    let enc = block;
    cipher.decrypt_block(&mut block);
    assert_eq!(block, [0u8; 16], "block decrypt must invert encrypt");
    println!(
        "raw block: encrypt then decrypt returns the original (ct = {})",
        encode_hex(&enc)
    );

    println!("\nOK");
}
