//! HMAC-SM3 and PBKDF2-HMAC-SM3.
//! Run: cargo run --example hmac_and_kdf
//! Safety: §9 rule 4. Key derivation and passwords, §9 rule 5. Constant-time comparison.

use gm_crypto_rs_demo::{
    encode_hex, DEMO_HMAC_KEY, DEMO_HMAC_MSG, DEMO_PBKDF2_ITER, DEMO_PBKDF2_LEN,
    DEMO_PBKDF2_PASSWORD, DEMO_PBKDF2_SALT,
};
use gmcrypto_core::hmac::{hmac_sm3, HmacSm3};
use gmcrypto_core::kdf::pbkdf2_hmac_sm3;

fn main() {
    println!("== HMAC-SM3 and PBKDF2-HMAC-SM3 ==\n");

    // Fixture stencils (DEMO ONLY / Production / Reusing-this-risks) live on
    // the pub consts in src/lib.rs -- single source of truth.
    let key = &DEMO_HMAC_KEY;
    let msg = DEMO_HMAC_MSG;

    let tag = hmac_sm3(key, msg);
    println!("hmac_sm3 tag = {}", encode_hex(&tag));

    let mut mac = HmacSm3::new(key);
    mac.update(msg);
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

    let password = DEMO_PBKDF2_PASSWORD;
    let salt = DEMO_PBKDF2_SALT;
    let mut derived = vec![0u8; DEMO_PBKDF2_LEN];
    pbkdf2_hmac_sm3(password, salt, DEMO_PBKDF2_ITER, &mut derived).expect("pbkdf2");
    println!(
        "pbkdf2({} iters) = {}",
        DEMO_PBKDF2_ITER,
        encode_hex(&derived)
    );

    let mut again = vec![0u8; DEMO_PBKDF2_LEN];
    pbkdf2_hmac_sm3(password, salt, DEMO_PBKDF2_ITER, &mut again).expect("pbkdf2");
    assert_eq!(derived, again, "same inputs must derive the same key");

    let mut other = vec![0u8; DEMO_PBKDF2_LEN];
    // DEMO ONLY: inline `b"other-salt"` exists purely to show that two different salts produce two different derived keys -- same caveats as the `salt` binding above apply.
    pbkdf2_hmac_sm3(password, b"other-salt", DEMO_PBKDF2_ITER, &mut other).expect("pbkdf2");
    assert_ne!(derived, other, "a different salt must diverge");
    println!("  PBKDF2 is deterministic; a different salt diverges");

    println!("\nOK");
}
