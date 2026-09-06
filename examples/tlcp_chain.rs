//! TLCP [sign, enc] certificate-pair verification (GB/T 38636 §4).
//! Requires `tlcp` and `x509`.
//! Run: cargo run --features tlcp,x509 --example tlcp_chain
//! Safety: §9 rule 6. Key management, §9 rule 7. Pick the right tool.
//!
//! `verify_pair` returning `true` means each chain links to a caller-trusted
//! anchor, each leaf matches its TLCP role, and the pair shares one identity.
//! It is **not** endpoint authentication (hostname / "the peer I dialed").
//! The library has no clock: pass `at_time` yourself if you want a window.

use gmcrypto_core::tlcp::chain::verify_pair;
use gmcrypto_core::x509::Certificate;

fn parse(der: &[u8]) -> Certificate {
    Certificate::from_der(der).expect("chain fixture parses")
}

fn main() {
    println!("== TLCP certificate pair (GB/T 38636 §4) ==\n");

    // DEMO ONLY: public gmssl-generated TLCP pair (gmcrypto-core 1.13.0 tests/data).
    // Production: take the peer's sign+enc chains from the handshake; pin anchors in a trust store you control.
    // Reusing this risks: treating a published demo CA as a trust anchor for a real peer.
    const ROOT: &[u8] = include_bytes!("data/x509_chain_root.der");
    const INT: &[u8] = include_bytes!("data/x509_chain_int.der");
    const SIGN: &[u8] = include_bytes!("data/x509_chain_sign.der");
    const ENC: &[u8] = include_bytes!("data/x509_chain_enc.der");

    // Chains are leaf-first. Both legs share the same intermediate (byte-equal
    // tbs from index 1), which is what pins the issuer *key*, not just its Name.
    assert!(
        verify_pair(
            &[parse(SIGN), parse(INT)],
            &[parse(ENC), parse(INT)],
            &[parse(ROOT)],
            None,
        ),
        "real TLCP sign+enc pair must verify"
    );
    println!("  sign+enc pair verifies against the demo root");

    // Enc cert in the sign slot lacks digitalSignature → role reject.
    assert!(
        !verify_pair(
            &[parse(ENC), parse(INT)],
            &[parse(SIGN), parse(INT)],
            &[parse(ROOT)],
            None,
        ),
        "swapped pair roles must be rejected"
    );
    println!("  swapped sign/enc roles are rejected");

    assert!(
        !verify_pair(
            &[parse(SIGN), parse(INT)],
            &[parse(ENC), parse(INT)],
            &[],
            None,
        ),
        "missing anchor must be rejected"
    );
    println!("  missing trust anchor is rejected");

    println!("\nOK");
}
