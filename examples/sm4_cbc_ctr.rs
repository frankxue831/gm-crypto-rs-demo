//! SM4 block cipher — CBC and CTR modes, plus the raw block primitive.
//! Run: cargo run --example sm4_cbc_ctr

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm4::{mode_cbc, mode_ctr, Sm4Cipher};

fn main() {
    println!("== SM4 (GB/T 32907-2016): 128-bit block cipher ==\n");

    let key = [0x01u8; 16];
    let iv = [0x02u8; 16];
    let plaintext = b"SM4 mode demonstration payload";

    let ct = mode_cbc::encrypt(&key, &iv, plaintext);
    let pt = mode_cbc::decrypt(&key, &iv, &ct).expect("cbc decrypt");
    assert_eq!(&pt[..], &plaintext[..], "CBC round-trip");
    println!("CBC ciphertext = {}", encode_hex(&ct));
    println!("CBC round-trips");

    // CTR uses a 16-byte initial counter block (distinct role from the CBC IV).
    // The (key, counter) pair MUST be unique per message: reusing it leaks the
    // XOR of the two plaintexts.
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
