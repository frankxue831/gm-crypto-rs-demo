//! SM2 key serialization — PKCS#8, SEC1, SPKI, PEM, encrypted PKCS#8.
//! Run: cargo run --example sm2_key_encoding

use gm_crypto_rs_demo::sample_private_key;
use gmcrypto_core::sm2::Sm2PublicKey;
use gmcrypto_core::{pem, pkcs8, sec1, spki};

fn main() {
    println!("== SM2 key encoding ==\n");

    let key = sample_private_key();
    let expected_scalar = key.to_bytes_be();
    let public = Sm2PublicKey::from_point(key.public_key());

    let der = pkcs8::encode(&key);
    let pem_str = pem::encode("PRIVATE KEY", &der);
    println!("PKCS#8 PEM:\n{pem_str}");
    let der_back = pem::decode(&pem_str, "PRIVATE KEY").expect("pem decode");
    assert_eq!(der_back, der, "PEM round-trip");
    let key_back = pkcs8::decode(&der_back).expect("pkcs8 decode");
    assert_eq!(key_back.to_bytes_be(), expected_scalar, "PKCS#8 round-trip");
    println!("PKCS#8 -> PEM -> PKCS#8 round-trips");

    let sec1_der = sec1::encode(&expected_scalar, Some(&public.to_sec1_uncompressed()));
    let ec = sec1::decode(&sec1_der).expect("sec1 decode");
    assert_eq!(ec.scalar_be, expected_scalar, "SEC1 round-trip");
    println!("SEC1 EC private key round-trips");

    let point = key.public_key();
    let spki_der = spki::encode(&point);
    let point_back = spki::decode(&spki_der).expect("spki decode");
    let pub_back = Sm2PublicKey::from_point(point_back);
    assert_eq!(
        pub_back.to_sec1_uncompressed(),
        public.to_sec1_uncompressed(),
        "SPKI round-trip",
    );
    println!("SPKI public key round-trips");

    let password = b"demo-password";
    let salt = b"demo-salt-1234567";
    let iv = [0x11u8; 16];
    let enc = pkcs8::encrypt(&key, password, salt, 10_000, &iv).expect("encrypt pkcs8");
    let dec = pkcs8::decrypt(&enc, password).expect("decrypt pkcs8");
    assert_eq!(dec.to_bytes_be(), expected_scalar, "encrypted PKCS#8 round-trip");
    assert!(
        pkcs8::decrypt(&enc, b"wrong-password").is_err(),
        "wrong password must be rejected",
    );
    println!("Encrypted PKCS#8 round-trips; wrong password rejected");

    println!("\nOK");
}
