//! SM2 key exchange (GM/T 0003.3 ≡ GB/T 32918.3) with key confirmation.
//! Requires the `sm2-key-exchange` feature.
//! Run: cargo run --features sm2-key-exchange --example sm2_key_exchange
//! Safety: §9 rule 1. Randomness, §9 rule 6. Key management.

use gm_crypto_rs_demo::{encode_hex, os_rng, sample_private_key};
use gmcrypto_core::sm2::key_exchange::{
    Sm2KxConfirm, Sm2KxEphemeralPoint, Sm2KxInitiator, Sm2KxResponder,
};
use gmcrypto_core::sm2::Sm2PrivateKey;
use rand_core::TryRng;

// DEMO ONLY: fixed identity strings so the demo narration is reproducible.
// Production: use each party's real, agreed identity (certificate DN, account ID) — both sides must pass identical bytes.
// Reusing this risks: nothing secret leaks, but mismatched IDs between the parties make the Z-values differ and the handshake fail closed.
const ID_A: &[u8] = b"alice@example";
const ID_B: &[u8] = b"bob@example";

/// Length of the agreed key in bytes — 16 here, i.e. a fresh SM4-sized key.
const KLEN: usize = 16;

/// Generate a fresh SM2 private key from the OS CSPRNG.
///
/// The SDK has no keygen helper by design: you draw 32 random bytes and
/// let `from_bytes_be` reject out-of-range candidates (zero or >= n,
/// roughly 1 in 2^32), so this loop almost never repeats. Production
/// code should also zeroize the candidate buffer after use.
fn generate_private_key() -> Sm2PrivateKey {
    let mut rng = os_rng();
    loop {
        let mut candidate = [0u8; 32];
        rng.try_fill_bytes(&mut candidate)
            .expect("OS RNG must be available");
        // from_bytes_be returns a constant-time CtOption; convert to a
        // plain Option so we can branch on it.
        if let Some(key) = Option::from(Sm2PrivateKey::from_bytes_be(&candidate)) {
            return key;
        }
    }
}

fn main() {
    println!("== SM2 key exchange (GM/T 0003.3) ==\n");
    let mut rng = os_rng();

    // Party A's static key is the fixed GB/T 32918.2 sample key (public
    // demo fixture, stencilled in src/lib.rs); party B's is generated
    // fresh each run — the demo shows both ways to obtain a key.
    let d_a = sample_private_key();
    let p_a = d_a.public_key();
    let d_b = generate_private_key();
    let p_b = d_b.public_key();

    // ---- Happy path: full handshake with key confirmation ----
    // Every step consumes its state value, so an ephemeral can never be
    // reused and neither side can touch K before the peer's tag verifies.
    let init = Sm2KxInitiator::new(&d_a, &p_b, ID_A, ID_B, KLEN).expect("valid KX parameters");
    let (r_a, init_waiting) = init.produce_ephemeral(&mut rng).expect("sample r_A");
    println!("A -> B  R_A = {}", encode_hex(&r_a.to_bytes()));

    let resp = Sm2KxResponder::new(&d_b, &p_a, ID_A, ID_B, KLEN).expect("valid KX parameters");
    let (r_b, s_b, resp_waiting) = resp.respond(&r_a, &mut rng).expect("respond to R_A");
    println!("B -> A  R_B = {}", encode_hex(&r_b.to_bytes()));
    println!("B -> A  S_B = {}", encode_hex(&s_b.to_bytes()));

    // A verifies S_B (constant-time) before its key is released, then
    // emits S_A for the reverse confirmation.
    let (key_a, s_a) = init_waiting.confirm(&r_b, &s_b).expect("S_B verifies");
    println!("A -> B  S_A = {}", encode_hex(&s_a.to_bytes()));

    // B holds K until S_A checks out (commit-on-confirm), then releases it.
    let key_b = resp_waiting.finish(&s_a).expect("S_A verifies");

    assert_eq!(
        key_a.as_bytes(),
        key_b.as_bytes(),
        "both sides must derive the same key"
    );
    assert_eq!(key_a.as_bytes().len(), KLEN);
    println!("agreed key  = {}", encode_hex(key_a.as_bytes()));
    println!("both sides agree on a {KLEN}-byte key (zeroized on drop)\n");

    // ---- Tampered S_B: initiator rejects, key never released ----
    let init = Sm2KxInitiator::new(&d_a, &p_b, ID_A, ID_B, KLEN).expect("valid KX parameters");
    let (r_a, init_waiting) = init.produce_ephemeral(&mut rng).expect("sample r_A");
    let resp = Sm2KxResponder::new(&d_b, &p_a, ID_A, ID_B, KLEN).expect("valid KX parameters");
    let (r_b, s_b, _resp_waiting) = resp.respond(&r_a, &mut rng).expect("respond to R_A");
    let mut bad_s_b = s_b.to_bytes();
    bad_s_b[0] ^= 1;
    assert!(
        init_waiting
            .confirm(&r_b, &Sm2KxConfirm::from_bytes(&bad_s_b))
            .is_err(),
        "tampered S_B must be rejected",
    );
    println!("tampered S_B is rejected (initiator never releases K)");

    // ---- Tampered S_A: responder rejects, key never released ----
    let init = Sm2KxInitiator::new(&d_a, &p_b, ID_A, ID_B, KLEN).expect("valid KX parameters");
    let (r_a, init_waiting) = init.produce_ephemeral(&mut rng).expect("sample r_A");
    let resp = Sm2KxResponder::new(&d_b, &p_a, ID_A, ID_B, KLEN).expect("valid KX parameters");
    let (r_b, s_b, resp_waiting) = resp.respond(&r_a, &mut rng).expect("respond to R_A");
    let (_key_a, s_a) = init_waiting.confirm(&r_b, &s_b).expect("S_B verifies");
    let mut bad_s_a = s_a.to_bytes();
    bad_s_a[31] ^= 1;
    assert!(
        resp_waiting
            .finish(&Sm2KxConfirm::from_bytes(&bad_s_a))
            .is_err(),
        "tampered S_A must be rejected",
    );
    println!("tampered S_A is rejected (responder never releases K)");

    // ---- Garbage peer point: rejected before any key math ----
    // [0x04; 65] has a valid SEC1 tag but is not on the curve, so the
    // responder's invalid-curve defense collapses it to Error::Failed —
    // the same indistinguishable error every KX failure maps to.
    let resp = Sm2KxResponder::new(&d_b, &p_a, ID_A, ID_B, KLEN).expect("valid KX parameters");
    let garbage = Sm2KxEphemeralPoint::from_bytes(&[0x04u8; 65]);
    assert!(
        resp.respond(&garbage, &mut rng).is_err(),
        "off-curve peer point must be rejected",
    );
    println!("off-curve peer point is rejected (invalid-curve defense)");

    println!("\nOK");
}
