//! SM4-GCM / SM4-CCM behind the RustCrypto `aead` 0.6 traits — the interop
//! surface added in gmcrypto-core 1.11. Requires the `aead-traits` feature.
//! Run: cargo run --features aead-traits --example sm4_aead_traits
//! Safety: §9 rule 1. Randomness, §9 rule 2. Uniqueness of nonces / IVs / counters, §9 rule 3. Authentication.
//!
//! `Sm4Gcm` / `Sm4Ccm` are thin wrappers that add no cryptography, so this
//! example's job is to *prove* that and then price the trade — it does not
//! re-teach GCM or CCM (see `sm4_aead` / `sm4_ccm` for the inherent API and
//! `sm4_streaming` for chunked input). `aead` is a companion crate you declare
//! yourself; gmcrypto-core does not re-export it.

use aead::array::typenum::Unsigned;
use aead::consts::{U13, U16, U4, U7};
use aead::inout::InOutBuf;
use aead::{Aead, AeadCore, AeadInOut, KeyInit, Payload, TagPosition};
use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm4::{mode_ccm, mode_gcm, Sm4Ccm, Sm4Gcm};

fn main() {
    println!("== SM4 AEAD via the RustCrypto `aead` traits ==\n");

    // DEMO ONLY: public, fixed 128-bit SM4-GCM key for reproducible demo output.
    // Production: derive per-session keys via a KDF or unwrap a KEK-wrapped DEK; never hard-code.
    // Reusing this risks: anyone with the source can decrypt every ciphertext produced with it.
    let gcm_key = [0x01u8; 16];
    // DEMO ONLY: fixed 96-bit nonce — the size `Sm4Gcm` fixes at the type level.
    // Production: generate a fresh random nonce per message via `os_rng()` (or a strictly-monotonic counter).
    // Reusing this (key, nonce) pair risks: catastrophic — recovers the GHASH authentication key, enabling forgery of any ciphertext.
    let nonce = [0x02u8; 12];
    let aad: &[u8] = b"header-authenticated-not-encrypted";
    let plaintext: &[u8] = b"authenticated and encrypted";

    // UFCS (`<T as Trait>::m(..)`) throughout. `Sm4Gcm` and `Sm4Ccm` carry no
    // inherent methods, so plain `cipher.encrypt(..)` compiles too — naming the
    // trait is how you tell at a glance which surface a call came from, and it
    // is what upstream's own trait tests do. For the associated sizes in
    // section 1 it is the only form there is.
    let gcm = <Sm4Gcm as KeyInit>::new_from_slice(&gcm_key).expect("16-byte SM4 key");

    // ---- 1. The type carries the profile: 96-bit nonce, 128-bit postfix tag ----
    // On the inherent API these are runtime arguments you have to get right.
    // Here they are associated types — facts about `Sm4Gcm` the compiler knows.
    assert_eq!(
        <Sm4Gcm as AeadCore>::NonceSize::USIZE,
        12,
        "Sm4Gcm fixes a 96-bit nonce",
    );
    assert_eq!(
        <Sm4Gcm as AeadCore>::TagSize::USIZE,
        16,
        "Sm4Gcm fixes a 128-bit tag",
    );
    assert!(
        matches!(<Sm4Gcm as AeadCore>::TAG_POSITION, TagPosition::Postfix),
        "the tag is appended, so one Vec carries ciphertext || tag",
    );
    println!("profile: 12-byte nonce, 16-byte tag, tag appended (all fixed by the type)");

    // ---- 2. Byte-identical to mode_gcm — the wrapper adds no cryptography ----
    // This is the assertion that matters. Nothing is pinned to a constant: the
    // expected bytes are recomputed through the inherent API on every run, so
    // this catches a drift in *either* path.
    let (inherent_ct, inherent_tag) = mode_gcm::encrypt(&gcm_key, &nonce, aad, plaintext)
        .expect("plaintext under GCM length ceiling");
    let wire = <Sm4Gcm as Aead>::encrypt(
        &gcm,
        &nonce.into(),
        Payload {
            msg: plaintext,
            aad,
        },
    )
    .expect("plaintext under GCM length ceiling");

    let mut joined = inherent_ct.clone();
    joined.extend_from_slice(&inherent_tag);
    assert_eq!(
        wire, joined,
        "the trait's Vec is mode_gcm's ciphertext || tag",
    );
    println!("wire = {}", encode_hex(&wire));
    println!("  trait output == mode_gcm ciphertext || tag, byte for byte");

    // Going trait -> inherent means splitting at len - TagSize. That split is
    // the only bookkeeping the trait hides from you.
    let (ct, tag) = wire.split_at(wire.len() - <Sm4Gcm as AeadCore>::TagSize::USIZE);
    let tag: [u8; 16] = tag.try_into().expect("16-byte tag");
    let via_inherent = mode_gcm::decrypt(&gcm_key, &nonce, aad, ct, &tag).expect("auth ok");
    assert_eq!(
        via_inherent, plaintext,
        "mode_gcm decrypts what Sm4Gcm produced",
    );

    let via_trait = <Sm4Gcm as Aead>::decrypt(&gcm, &nonce.into(), Payload { msg: &joined, aad })
        .expect("auth ok");
    assert_eq!(
        via_trait, plaintext,
        "Sm4Gcm decrypts what mode_gcm produced",
    );
    println!("  each side decrypts the other's output");

    // ---- 3. The in-place and detached shapes produce the same bytes ----
    // "in place" describes the *buffer*, not the allocation: these wrappers
    // still allocate internally, which upstream states plainly.
    let mut buf = plaintext.to_vec();
    <Sm4Gcm as AeadInOut>::encrypt_in_place(&gcm, &nonce.into(), aad, &mut buf).expect("encrypt");
    assert_eq!(
        buf, wire,
        "encrypt_in_place appends the tag to the same wire"
    );
    <Sm4Gcm as AeadInOut>::decrypt_in_place(&gcm, &nonce.into(), aad, &mut buf).expect("auth ok");
    assert_eq!(
        buf, plaintext,
        "decrypt_in_place truncates back to the plaintext",
    );

    // The detached shape IS the inherent API's shape: ciphertext in the buffer,
    // tag returned separately, no concatenation anywhere.
    let mut detached = plaintext.to_vec();
    let detached_tag = <Sm4Gcm as AeadInOut>::encrypt_inout_detached(
        &gcm,
        &nonce.into(),
        aad,
        InOutBuf::from(&mut detached[..]),
    )
    .expect("encrypt");
    assert_eq!(
        detached, inherent_ct,
        "detached ciphertext == mode_gcm ciphertext",
    );
    assert_eq!(
        detached_tag.as_slice(),
        &inherent_tag[..],
        "detached tag == mode_gcm tag",
    );
    println!("  in-place and detached shapes agree with both of the above");

    // ---- 4. SM4-CCM: the (tag, nonce) sizes move from run time to compile time ----
    // DEMO ONLY: public, fixed 128-bit SM4-CCM key for reproducible demo output.
    // Production: derive per-session keys via a KDF or unwrap a KEK-wrapped DEK; never hard-code.
    // Reusing this risks: anyone with the source can decrypt every ciphertext produced with it.
    let ccm_key = [0x42u8; 16];

    // The inherent API takes tag_len as a runtime usize and answers an invalid
    // one with None — you find out at run time, on the unhappy path.
    assert!(
        mode_ccm::encrypt(&ccm_key, &nonce, aad, plaintext, 5).is_none(),
        "5 is not one of CCM's 4/6/8/10/12/14/16 tag lengths — a runtime None",
    );

    // `Sm4Ccm<M, N>` puts the same rule in sealed marker traits, so the invalid
    // case never reaches run time. This does not compile, and that is the point:
    //
    //     let _ = <Sm4Ccm<aead::consts::U5, U7> as KeyInit>::new_from_slice(&ccm_key);
    //     error[E0277]: the trait bound `UInt<UInt<UInt<UTerm, B1>, B0>, B1>: CcmTagSize` is not satisfied
    //
    // A *valid* exotic profile still has to agree with the inherent call.
    // DEMO ONLY: fixed 7-byte CCM nonce for reproducible demo output (7 is CCM's minimum).
    // Production: generate a fresh random nonce per message via `os_rng()`; at 7 bytes the collision margin is thin, so prefer a counter.
    // Reusing this (key, nonce) pair risks: catastrophic for CCM as well as GCM — it breaks both confidentiality and authenticity.
    let nonce7 = [0x03u8; 7];
    let ccm47 = <Sm4Ccm<U4, U7> as KeyInit>::new_from_slice(&ccm_key).expect("16-byte SM4 key");
    let ccm_wire = <Sm4Ccm<U4, U7> as Aead>::encrypt(
        &ccm47,
        &nonce7.into(),
        Payload {
            msg: plaintext,
            aad,
        },
    )
    .expect("under the CCM length ceiling");
    assert_eq!(
        ccm_wire,
        mode_ccm::encrypt(&ccm_key, &nonce7, aad, plaintext, 4).expect("valid CCM parameters"),
        "Sm4Ccm<U4, U7> == mode_ccm at tag_len 4 with a 7-byte nonce",
    );
    assert_eq!(
        ccm_wire.len(),
        plaintext.len() + 4,
        "a 4-byte tag costs 4 bytes of overhead",
    );
    let back = <Sm4Ccm<U4, U7> as Aead>::decrypt(
        &ccm47,
        &nonce7.into(),
        Payload {
            msg: &ccm_wire,
            aad,
        },
    )
    .expect("auth ok");
    assert_eq!(back, plaintext, "Sm4Ccm<U4, U7> round-trips");
    println!("CCM: invalid sizes are a compile error; valid ones match mode_ccm exactly");

    // ---- 5. The price: one opaque aead::Error for every kind of failure ----
    // The inherent API's None is just as silent, but the trait collapses two
    // different *kinds* of failure into one value: an attack (a flipped byte)
    // and a caller bug (a message past CCM's length ceiling) are
    // indistinguishable. Log the context yourself; the error carries none.
    let mut tampered = wire.clone();
    *tampered.last_mut().expect("non-empty record") ^= 1;
    let from_attack: aead::Error = <Sm4Gcm as Aead>::decrypt(
        &gcm,
        &nonce.into(),
        Payload {
            msg: &tampered,
            aad,
        },
    )
    .expect_err("a flipped tag byte must be rejected");

    // With a 13-byte nonce CCM spends only 15 - 13 = 2 bytes on the length
    // field, capping the message at 2^16 - 1. One byte more is a parameter
    // error, not an attack.
    // DEMO ONLY: fixed 13-byte CCM nonce for reproducible demo output (13 is CCM's maximum, common in 802.15.4 / Zigbee).
    // Production: generate a fresh random nonce per message via `os_rng()` (or a strictly-monotonic counter that fits in 13 bytes).
    // Reusing this (key, nonce) pair risks: catastrophic for CCM as well as GCM — it breaks both confidentiality and authenticity.
    let nonce13 = [0x04u8; 13];
    let ccm1613 = <Sm4Ccm<U16, U13> as KeyInit>::new_from_slice(&ccm_key).expect("16-byte SM4 key");
    let too_long = vec![0u8; 65_536];
    let from_bug: aead::Error = <Sm4Ccm<U16, U13> as Aead>::encrypt(
        &ccm1613,
        &nonce13.into(),
        Payload {
            msg: &too_long,
            aad: b"",
        },
    )
    .expect_err("2^16 bytes exceeds the 2-byte length field's ceiling");

    assert_eq!(
        from_attack, from_bug,
        "an attack and a caller bug are the same aead::Error",
    );
    println!("cost: a tampered tag and an oversized message are indistinguishable ({from_attack})");

    // ---- 6. Which surface to reach for ----
    println!("\nuse the traits for ecosystem fit: code already bounded on AeadInOut");
    println!("  now takes SM4-GCM/CCM next to AES-GCM and ChaCha20Poly1305, no glue");
    println!("keep mode_gcm / mode_ccm for hot paths (each trait call re-runs the SM4");
    println!("  key schedule), truncated GCM tags, and non-96-bit GCM nonces");
    println!("SM4-XTS has no aead type at all: it is confidentiality-only, no tag");

    println!("\nOK");
}
