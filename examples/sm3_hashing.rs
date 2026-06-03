//! SM3 hashing — one-shot and streaming.
//! Run: cargo run --example sm3_hashing
//! Safety: §9 rule 1. Randomness, §9 rule 7. Pick the right tool.

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm3::{self, Sm3};

fn main() {
    println!("== SM3 (GB/T 32905-2016): 256-bit hash ==\n");

    let digest = sm3::hash(b"abc");
    println!("sm3(\"abc\") = {}", encode_hex(&digest));
    assert_eq!(
        encode_hex(&digest),
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        "SM3 must match the published GB/T 32905 vector",
    );
    println!("  matches the published GB/T 32905 vector");

    let mut hasher = Sm3::new();
    hasher.update(b"a");
    hasher.update(b"bc");
    let streamed = hasher.finalize();
    assert_eq!(streamed, digest, "streamed digest must equal one-shot");
    println!("  streaming update(\"a\") + update(\"bc\") == one-shot");

    println!("\nOK");
}
