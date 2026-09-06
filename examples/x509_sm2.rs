//! X.509-with-SM2 leaf parse + signature verify (GM/T 0015). Requires `x509`.
//! Run: cargo run --features x509 --example x509_sm2
//! Safety: §9 rule 6. Key management, §9 rule 7. Pick the right tool.
//!
//! Parsing and `verify_signature` make **no trust decisions**: no chain, no
//! clock, no hostname, no revocation. `true` means only "this issuer key
//! signed these tbsCertificate bytes".

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::x509::Certificate;

fn main() {
    println!("== X.509-with-SM2 (GM/T 0015 leaf parse + verify) ==\n");

    // DEMO ONLY: public gmssl-generated GM/T 0015 CA certificate (gmcrypto-core 1.13.0 tests/data).
    // Production: obtain CA certificates from your PKI or a real trust store; never hard-code a trust anchor.
    // Reusing this risks: anyone with the source can treat this identity as a CA in a demo; the key is not secret.
    const CA_DER: &[u8] = include_bytes!("data/x509_ca.der");
    // DEMO ONLY: public gmssl-generated leaf issued by that CA (same upstream tests/data).
    // Production: present the peer's certificate from the handshake or a directory; do not embed production leaves.
    // Reusing this risks: the leaf identity is a published fixture, not a server you dialed.
    const LEAF_DER: &[u8] = include_bytes!("data/x509_leaf.der");

    let ca = Certificate::from_der(CA_DER).expect("CA fixture parses");
    let leaf = Certificate::from_der(LEAF_DER).expect("leaf fixture parses");

    assert!(ca.is_self_issued(), "CA fixture is self-issued");
    assert!(!leaf.is_self_issued(), "leaf is issued by the CA");
    assert_eq!(leaf.issuer_raw(), ca.subject_raw());
    println!("CA serial   = {}", encode_hex(ca.serial_raw()));
    println!("leaf serial = {}", encode_hex(leaf.serial_raw()));

    let ca_key = ca.subject_public_key();
    assert!(
        ca.verify_signature(&ca_key),
        "self-signed CA verifies with its own subject key"
    );
    assert!(
        leaf.verify_signature(&ca_key),
        "leaf verifies against the CA subject key"
    );
    assert!(
        !leaf.verify_signature(&leaf.subject_public_key()),
        "leaf must not verify against its own key"
    );
    assert!(
        !leaf.verify_signature_with_id(&ca_key, b"WRONG-ID"),
        "wrong signer ID must fail (fixtures use the GM/T default ID)"
    );
    println!("  CA self-signature and leaf-under-CA both verify");
    println!("  wrong issuer key / wrong signer ID are rejected");

    // Truncation and trailing junk must not parse (single None, never panic).
    assert!(Certificate::from_der(&LEAF_DER[..LEAF_DER.len() / 2]).is_none());
    let mut padded = LEAF_DER.to_vec();
    padded.push(0x00);
    assert!(Certificate::from_der(&padded).is_none());
    println!("  truncated / trailing-byte inputs fail to parse");

    // Flip one byte in the middle: either parse fails or the signature fails.
    // Never "parses AND verifies" after tampering the covered bytes.
    let mut tampered = LEAF_DER.to_vec();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 1;
    match Certificate::from_der(&tampered) {
        None => println!("  tampered DER fails to parse"),
        Some(cert) => {
            assert!(
                !cert.verify_signature(&ca_key),
                "tampered tbs must not verify"
            );
            println!("  tampered DER parses but the signature is rejected");
        }
    }

    println!("\nOK");
}
