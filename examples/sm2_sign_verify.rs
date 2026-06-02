//! SM2 digital signatures — sign_with_id / verify_with_id.
//! Run: cargo run --example sm2_sign_verify

use gm_crypto_rs_demo::{encode_hex, os_rng, sample_private_key};
use gmcrypto_core::sm2::{compute_z, sign_with_id, verify_with_id, DEFAULT_SIGNER_ID};

fn main() {
    println!("== SM2 signatures (GB/T 32918.2) ==\n");

    let key = sample_private_key();
    let public = key.public_key();
    let message = b"hello";

    // Z is the identity hash SM2 folds into the message hash. Shown here for
    // inspection only — sign_with_id / verify_with_id compute it internally.
    let z = compute_z(&public, DEFAULT_SIGNER_ID);
    println!("Z (from DEFAULT_SIGNER_ID) = {}", encode_hex(&z));

    let mut rng = os_rng();
    let sig1 = sign_with_id(&key, DEFAULT_SIGNER_ID, message, &mut rng).expect("sign");
    let sig2 = sign_with_id(&key, DEFAULT_SIGNER_ID, message, &mut rng).expect("sign");
    println!("sig1 = {}", encode_hex(&sig1));
    println!("sig2 = {}", encode_hex(&sig2));
    assert_ne!(sig1, sig2, "SM2 signatures are randomized");

    assert!(verify_with_id(&public, DEFAULT_SIGNER_ID, message, &sig1));
    assert!(verify_with_id(&public, DEFAULT_SIGNER_ID, message, &sig2));
    println!("  both independent signatures verify");

    assert!(!verify_with_id(&public, DEFAULT_SIGNER_ID, b"h3llo", &sig1));
    println!("  tampered message rejected");

    println!("\nOK");
}
