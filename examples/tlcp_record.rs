//! TLCP record protection (GB/T 38636-2020 §6.3) — the protect/deprotect
//! primitives that wrap a TLCP session's application data once the key
//! schedule has produced a key block. Requires the `tlcp` feature.
//! Run: cargo run --features tlcp --example tlcp_record
//! Safety: §9 rule 2. Uniqueness of nonces / IVs / counters, §9 rule 3. Authentication.
//!
//! These are record-layer *building blocks*, not a TLCP stack: no 5-byte
//! header framing, no fragmentation, no sequence-number bookkeeping, no I/O.
//! `type` / `version` / `seq` ride in as explicit parameters because they are
//! bound into the MAC (CBC) / AAD (GCM). The caller owns the sequence number
//! and must never reuse a `(direction_key, seq)` pair.

use gm_crypto_rs_demo::os_rng;
use gmcrypto_core::tlcp::key_schedule::{
    derive_key_block, derive_master_secret, TlcpRole, MASTER_SECRET_LEN,
};
use gmcrypto_core::tlcp::record::{
    deprotect_cbc, protect_cbc, RecordKeysCbc, CBC_KEY_BLOCK_LEN, TLCP_RECORD_VERSION,
};

/// TLS content type for `application_data` (TLCP follows the TLS registry).
const APPLICATION_DATA: u8 = 0x17;
/// TLS content type for `handshake` — used here only to show type-binding.
const HANDSHAKE: u8 = 0x16;

fn main() {
    println!("== TLCP record protection (GB/T 38636 §6.3) ==\n");

    // DEMO ONLY: fixed 48-byte pre-master secret for reproducible demo output.
    // Production: establish it fresh per handshake via the TLCP key exchange (SM2 encryption or the ECDHE/SM2-KX suites) — never hard-code; TLCP pins it to 48 bytes.
    // Reusing this risks: anyone with the source derives every session key, defeating the whole handshake.
    let pre_master = [0x5au8; 48];

    // DEMO ONLY: fixed 32-byte client/server randoms for reproducible demo output.
    // Production: each is a fresh 32-byte random drawn per handshake (sent in the clear in ClientHello / ServerHello) — public, but must be unique per session.
    // Reusing this (pre_master, randoms) triple risks: identical session keys across handshakes, collapsing forward secrecy and enabling replay.
    let client_random = [0x11u8; 32];
    let server_random = [0x22u8; 32];

    // ---- 1. Key block -> directional record keys (the bridge from the key schedule) ----
    // Same PRF the tlcp_key_schedule example walks; here we carve a 128-byte
    // CBC-suite key block (an HMAC-SM3 MAC key + an SM4 key per direction).
    let mut master = [0u8; MASTER_SECRET_LEN];
    derive_master_secret(&pre_master, &client_random, &server_random, &mut master);
    let mut key_block = [0u8; CBC_KEY_BLOCK_LEN];
    derive_key_block(&master, &client_random, &server_random, &mut key_block);

    // We model the client->server channel: the client writes with its own
    // half, the server reads with that same half. The two directions get
    // distinct keys, so a record can never be replayed back the way it came.
    let client_keys = RecordKeysCbc::from_key_block(TlcpRole::Client, &key_block);

    // ---- 2. protect: application data -> a protected record ----
    let plaintext: &[u8] = b"GET / HTTP/1.1\r\nHost: tlcp.example\r\n\r\n";
    let mut rng = os_rng();
    let record = protect_cbc(
        &client_keys,
        0, // seq — first record on this key
        APPLICATION_DATA,
        TLCP_RECORD_VERSION,
        plaintext,
        &mut rng,
    )
    .expect("plaintext within the 2^14 record limit");
    println!("plaintext  {} bytes", plaintext.len());
    println!(
        "record     {} bytes (MAC-then-encrypt + explicit per-record IV)\n",
        record.len()
    );

    // ---- 3. deprotect round-trips under the SAME (seq, type, version) ----
    let recovered = deprotect_cbc(
        &client_keys,
        0,
        APPLICATION_DATA,
        TLCP_RECORD_VERSION,
        &record,
    )
    .expect("authentic record deprotects");
    assert_eq!(recovered, plaintext, "record round-trips to the plaintext");
    println!("round-trip OK: recovered == plaintext");

    // ---- 4. The MAC binds (seq, type, version); any mismatch -> the single None ----
    // deprotect_cbc is Lucky13-hardened: one constant-time failure mode, and no
    // plaintext ever escapes on failure. We assert the *rejection*, never bytes.
    assert!(
        deprotect_cbc(
            &client_keys,
            1,
            APPLICATION_DATA,
            TLCP_RECORD_VERSION,
            &record
        )
        .is_none(),
        "wrong seq is rejected (seq is MAC-bound)",
    );
    assert!(
        deprotect_cbc(&client_keys, 0, HANDSHAKE, TLCP_RECORD_VERSION, &record).is_none(),
        "wrong content type is rejected (type is MAC-bound)",
    );
    let mut tampered = record.clone();
    *tampered.last_mut().expect("non-empty record") ^= 1;
    assert!(
        deprotect_cbc(
            &client_keys,
            0,
            APPLICATION_DATA,
            TLCP_RECORD_VERSION,
            &tampered
        )
        .is_none(),
        "a flipped ciphertext byte is rejected",
    );
    println!("rejected: wrong seq / wrong type / tampered byte (one failure mode)");

    // ---- 5. (key, seq) uniqueness: same plaintext, distinct seq -> distinct records ----
    // The explicit IV already randomizes CBC output, but seq MUST still advance
    // per record — reusing a (direction_key, seq) pair is catastrophic.
    let rec_seq0 = protect_cbc(
        &client_keys,
        0,
        APPLICATION_DATA,
        TLCP_RECORD_VERSION,
        plaintext,
        &mut rng,
    )
    .expect("seq 0");
    let rec_seq1 = protect_cbc(
        &client_keys,
        1,
        APPLICATION_DATA,
        TLCP_RECORD_VERSION,
        plaintext,
        &mut rng,
    )
    .expect("seq 1");
    assert_ne!(
        rec_seq0, rec_seq1,
        "identical plaintext under distinct seq yields distinct records"
    );
    assert_eq!(
        deprotect_cbc(
            &client_keys,
            1,
            APPLICATION_DATA,
            TLCP_RECORD_VERSION,
            &rec_seq1
        )
        .as_deref(),
        Some(plaintext),
        "each record still deprotects under its own seq",
    );
    println!("seq advances per record (never reuse a (key, seq) pair)\n");

    // ---- 6. SM4-GCM suite (needs `sm4-aead` on top of `tlcp`) ----
    #[cfg(feature = "sm4-aead")]
    {
        use gmcrypto_core::tlcp::record::{
            deprotect_gcm, protect_gcm, RecordKeysGcm, GCM_KEY_BLOCK_LEN,
        };
        // The GCM suite carves a leaner 40-byte block (an SM4 key + a 4-byte
        // implicit salt per direction); the nonce is salt || seq, so protect_gcm
        // is deterministic and takes no RNG — which is exactly why reusing a
        // (key, seq) pair here repeats the nonce and is catastrophic.
        let mut gcm_block = [0u8; GCM_KEY_BLOCK_LEN];
        derive_key_block(&master, &client_random, &server_random, &mut gcm_block);
        let gcm_keys = RecordKeysGcm::from_key_block(TlcpRole::Client, &gcm_block);

        let rec = protect_gcm(
            &gcm_keys,
            0,
            APPLICATION_DATA,
            TLCP_RECORD_VERSION,
            plaintext,
        )
        .expect("gcm protect");
        let back = deprotect_gcm(&gcm_keys, 0, APPLICATION_DATA, TLCP_RECORD_VERSION, &rec)
            .expect("gcm deprotect");
        assert_eq!(back, plaintext, "GCM record round-trips");
        let mut bad = rec.clone();
        *bad.last_mut().expect("non-empty record") ^= 1;
        assert!(
            deprotect_gcm(&gcm_keys, 0, APPLICATION_DATA, TLCP_RECORD_VERSION, &bad).is_none(),
            "GCM tag rejects a tampered record",
        );
        println!("SM4-GCM suite: record round-trips, tag rejects tampering");
    }
    #[cfg(not(feature = "sm4-aead"))]
    println!("SM4-GCM suite: skipped (enable `--features \"tlcp sm4-aead\"`)");

    println!("\nOK");
}
