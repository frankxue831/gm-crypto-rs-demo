//! SM3 and HMAC-SM3 behind the RustCrypto `digest` 0.11 traits — the interop
//! surface behind the `digest-traits` feature.
//! Run: cargo run --features digest-traits --example sm3_digest_traits
//! Safety: §9 rule 5. Constant-time comparison, §9 rule 7. Pick the right tool.
//!
//! The traits add no cryptography, so this example's job is to *prove* that and
//! then map the sharp edges — it does not re-teach SM3 or HMAC (see
//! `sm3_hashing` and `hmac_and_kdf` for the inherent API). `digest` is a
//! companion crate you declare yourself; gmcrypto-core does not re-export it.

use digest::common::KeySizeUser;
use digest::typenum::Unsigned;
use digest::{Digest, KeyInit, Mac, Reset};
use gm_crypto_rs_demo::{encode_hex, DEMO_HMAC_KEY, DEMO_HMAC_MSG};
use gmcrypto_core::hmac::{hmac_sm3, HmacSm3};
use gmcrypto_core::sm3::{hash, Sm3};

/// Generic over any RustCrypto digest — this function has never heard of SM3.
/// Written against `Digest` alone, it takes Sha256 or Blake2 unchanged, and it
/// is the whole point of the feature: `Sm3` is now one of the types it accepts.
fn fingerprint<D: Digest>(chunks: &[&[u8]]) -> Vec<u8> {
    let mut hasher = D::new();
    for chunk in chunks {
        Digest::update(&mut hasher, chunk);
    }
    <D as Digest>::finalize(hasher).to_vec()
}

fn main() {
    println!("== SM3 / HMAC-SM3 via the RustCrypto `digest` traits ==\n");

    // ---- 1. UFCS is not a style choice here — the names genuinely collide ----
    // `Sm3` and `HmacSm3` carry inherent `update` / `finalize` methods, and
    // inherent methods win over trait methods in a `hasher.finalize()` call. So
    // the plain form silently picks the inherent one, and the two differ in
    // return type: `[u8; 32]` inherent vs `Output<Sm3>` through the trait.
    // (This is the collision `sm4_aead_traits` does *not* have — `Sm4Gcm` and
    // `Sm4Ccm` carry no inherent methods at all, so there both forms compile to
    // the same call. Here, naming the trait is the only way to be sure.)
    let mut collide = Sm3::new();
    collide.update(b"abc"); // ambiguous to a reader; resolves to the inherent method
    let inherent_out: [u8; 32] = collide.finalize(); // inherent: a plain array
    let trait_out = <Sm3 as Digest>::digest(b"abc"); // trait: Output<Sm3>
    assert_eq!(
        inherent_out.as_slice(),
        trait_out.as_slice(),
        "same bytes, two different Rust types",
    );
    println!("UFCS: `<Sm3 as Digest>::finalize` returns Output<Sm3>, the inherent one [u8; 32]");
    println!("  same 32 bytes either way: {}", encode_hex(&inherent_out));

    // ---- 2. Byte-identical to the inherent path, one-shot and streaming ----
    // Nothing is pinned to a constant: the expected bytes are recomputed
    // through the inherent API on every run, so this catches drift in *either*
    // path. (`sm3_hashing` is where the published GB/T 32905 vector is checked.)
    let message: &[u8] = b"the trait surface must not change a single byte";
    assert_eq!(
        <Sm3 as Digest>::digest(message).as_slice(),
        hash(message).as_slice(),
        "Digest::digest == sm3::hash",
    );

    let mut streamed = <Sm3 as Digest>::new();
    for chunk in [&message[..1], &message[1..17], &message[17..]] {
        Digest::update(&mut streamed, chunk);
    }
    assert_eq!(
        <Sm3 as Digest>::finalize(streamed).as_slice(),
        hash(message).as_slice(),
        "the trait must not see the chunking",
    );
    println!("hash: trait one-shot and trait streaming both == sm3::hash");

    // `Sm3` implements `FixedOutputReset`, so `Digest::finalize_reset` reuses
    // the allocation instead of dropping the hasher. Note below that `HmacSm3`
    // deliberately does *not* — the two types are not symmetric here.
    let mut reusable = <Sm3 as Digest>::new();
    Digest::update(&mut reusable, b"first");
    let first = Digest::finalize_reset(&mut reusable);
    Digest::update(&mut reusable, b"second");
    let second = Digest::finalize_reset(&mut reusable);
    assert_eq!(first.as_slice(), hash(b"first").as_slice());
    assert_eq!(second.as_slice(), hash(b"second").as_slice());
    println!("  finalize_reset gives a fresh hasher without reallocating");

    // ---- 3. The payoff: generic code that has never heard of SM3 ----
    let via_generic = fingerprint::<Sm3>(&[b"ecosystem", b"-", b"fit"]);
    assert_eq!(
        via_generic,
        hash(b"ecosystem-fit").as_slice(),
        "a `D: Digest` function drives SM3 with no glue",
    );
    println!("generic `fn fingerprint<D: Digest>` drives Sm3 unmodified");

    // ---- 4. HMAC-SM3 as digest::Mac ----
    // DEMO ONLY: input vector borrowed from RFC 4231 test case 1; HMAC-SM3 output is SM3-specific (not in the RFC).
    // Production: generate a random 32-byte (256-bit) key via `os_rng()` and store it in a secret manager.
    // Reusing this key risks: any reader of the source can forge MACs that this verifier will accept.
    let key = DEMO_HMAC_KEY;
    let expected = hmac_sm3(&key, DEMO_HMAC_MSG);

    let mac = <HmacSm3 as KeyInit>::new_from_slice(&key).expect("variable-length key accepted");
    let tag = Mac::finalize(Mac::chain_update(mac, DEMO_HMAC_MSG)).into_bytes();
    assert_eq!(tag.as_slice(), expected.as_slice(), "Mac path == hmac_sm3");
    println!(
        "\nmac: trait tag == hmac_sm3 tag ({})",
        encode_hex(&expected)
    );

    // `Mac::verify_slice` is the constant-time comparison (§9 rule 5) — reach
    // for it rather than `==` on the tag bytes, exactly as with the inherent
    // `HmacSm3::verify`.
    let fresh = || <HmacSm3 as KeyInit>::new_from_slice(&key).expect("variable-length key");
    Mac::verify_slice(Mac::chain_update(fresh(), DEMO_HMAC_MSG), &expected)
        .expect("the genuine tag verifies");
    let mut forged = expected;
    forged[0] ^= 1;
    Mac::verify_slice(Mac::chain_update(fresh(), DEMO_HMAC_MSG), &forged)
        .expect_err("a flipped tag byte must be rejected");
    println!("  verify_slice accepts the real tag, rejects a flipped byte (constant-time)");

    // ---- 5. Two sharp edges the trait surface introduces ----
    // (a) `KeySize` says 64 bytes, but RFC 2104 keys are variable-length. The
    // crate resolves that by advertising the SM3 block size as the canonical
    // fixed-length entry point while overriding `new_from_slice` to accept any
    // length. Consequence: generic code that constructs via `KeyInit::new`
    // (which takes `&Key<Self>`, a *64-byte* array) cannot pass this 20-byte
    // key at all — `new_from_slice` is the one to reach for.
    assert_eq!(
        <HmacSm3 as KeySizeUser>::KeySize::USIZE,
        64,
        "KeySize is the SM3 block size, not the length your key has to be",
    );
    for len in [0usize, 1, 20, 64, 131] {
        let variable = vec![0xaau8; len];
        let via_trait = <HmacSm3 as KeyInit>::new_from_slice(&variable).expect("any length");
        assert_eq!(
            Mac::finalize(Mac::chain_update(via_trait, DEMO_HMAC_MSG))
                .into_bytes()
                .as_slice(),
            hmac_sm3(&variable, DEMO_HMAC_MSG).as_slice(),
            "new_from_slice accepts a {len}-byte key and agrees with hmac_sm3",
        );
    }
    println!("edge: KeySize is 64, yet new_from_slice takes 0/1/20/64/131-byte keys");

    // (b) `Reset::reset` on `HmacSm3` panics — by design, and loudly. `HmacSm3`
    // does not retain the key after construction, so a post-finalize reset has
    // no well-defined meaning; upstream chose a panic over a silently wrong
    // no-op. `digest::Mac` documents `Reset` as rarely useful on MACs, but
    // generic code written against `Mac + Reset` will still reach for it. This
    // is the one place where swapping HMAC-SM3 into such code is not a drop-in.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {})); // keep the demo's output readable
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut resettable = fresh();
        Reset::reset(&mut resettable);
    }));
    std::panic::set_hook(hook);
    assert!(
        outcome.is_err(),
        "HmacSm3::reset must panic rather than silently do the wrong thing",
    );
    println!("edge: HmacSm3 panics on Reset::reset (no key retained) — proven, not asserted");
    println!("      and it implements no FixedOutputReset, so Mac::finalize_reset is absent");

    // ---- 6. Which surface to reach for ----
    println!("\nuse the traits for ecosystem fit: `D: Digest` / `M: Mac` code takes");
    println!("  SM3 and HMAC-SM3 next to SHA-2 and HMAC-SHA-2, no glue");
    println!("keep sm3::hash / hmac::hmac_sm3 for the direct path — plain arrays,");
    println!("  no Output<D> wrapper, and no UFCS needed to say what you meant");
    println!("PBKDF2 has no trait here: drive kdf::pbkdf2_hmac_sm3 directly");

    println!("\nOK");
}
