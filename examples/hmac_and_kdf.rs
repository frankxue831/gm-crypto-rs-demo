//! HMAC-SM3 and PBKDF2-HMAC-SM3.
//! Run: cargo run --example hmac_and_kdf

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::hmac::{hmac_sm3, HmacSm3};
use gmcrypto_core::kdf::pbkdf2_hmac_sm3;

fn main() {
    println!("== HMAC-SM3 and PBKDF2-HMAC-SM3 ==\n");

    let key = b"my mac key";
    let msg = b"authenticated message";

    let tag = hmac_sm3(key, msg);
    println!("hmac_sm3 tag = {}", encode_hex(&tag));

    let mut mac = HmacSm3::new(key);
    mac.update(b"authenticated ");
    mac.update(b"message");
    let streamed = mac.finalize();
    assert_eq!(streamed, tag, "streamed HMAC must equal one-shot");
    println!("  streaming HMAC == one-shot");

    let mut ok = HmacSm3::new(key);
    ok.update(msg);
    assert!(ok.verify(&tag), "correct tag must verify");

    let mut wrong = tag;
    wrong[0] ^= 1;
    let mut bad = HmacSm3::new(key);
    bad.update(msg);
    assert!(!bad.verify(&wrong), "tampered tag must be rejected");
    println!("  verify() accepts the right tag, rejects a wrong one");

    // NOTE: 10_000 iterations keeps this example fast. For real password
    // hashing use a far higher count (OWASP suggests >= 600_000).
    let password = b"correct horse battery staple";
    let salt = b"demo-salt";
    let mut derived = [0u8; 32];
    pbkdf2_hmac_sm3(password, salt, 10_000, &mut derived).expect("pbkdf2");
    println!("pbkdf2(10000 iters) = {}", encode_hex(&derived));

    let mut again = [0u8; 32];
    pbkdf2_hmac_sm3(password, salt, 10_000, &mut again).expect("pbkdf2");
    assert_eq!(derived, again, "same inputs must derive the same key");

    let mut other = [0u8; 32];
    pbkdf2_hmac_sm3(password, b"other-salt", 10_000, &mut other).expect("pbkdf2");
    assert_ne!(derived, other, "a different salt must diverge");
    println!("  PBKDF2 is deterministic; a different salt diverges");

    println!("\nOK");
}
