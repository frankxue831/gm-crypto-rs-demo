//! TLCP key schedule (GB/T 38636-2020 §6.5) — the TLS-1.2-style PRF over
//! HMAC-SM3 that derives a TLCP session's keys. Requires the `tlcp` feature.
//! Run: cargo run --features tlcp --example tlcp_key_schedule
//! Safety: §9 rule 1. Randomness, §9 rule 6. Key management.
//!
//! These are key-schedule *building blocks*, not a TLCP implementation: there
//! is no handshake state machine, no record framing, no I/O. You feed in the
//! pre-master secret and the two handshake randoms and carve out the session
//! keys; the surrounding protocol is the caller's job.

use gm_crypto_rs_demo::encode_hex;
use gmcrypto_core::sm3;
use gmcrypto_core::tlcp::key_schedule::{
    derive_key_block, derive_master_secret, finished_verify_data, TlcpRole,
    FINISHED_VERIFY_DATA_LEN, MASTER_SECRET_LEN,
};

fn main() {
    println!("== TLCP key schedule (GB/T 38636 §6.5) ==\n");

    // DEMO ONLY: fixed 48-byte pre-master secret for reproducible demo output.
    // Production: establish it fresh per handshake via the TLCP key exchange (SM2 encryption or the ECDHE/SM2-KX suites) — never hard-code; TLCP pins it to 48 bytes.
    // Reusing this risks: anyone with the source derives every session key, defeating the whole handshake.
    let pre_master = [0x5au8; 48];

    // DEMO ONLY: fixed 32-byte client/server randoms for reproducible demo output.
    // Production: each is a fresh 32-byte random drawn per handshake (sent in the clear in ClientHello / ServerHello) — public, but must be unique per session.
    // Reusing this (pre_master, randoms) triple risks: identical session keys across handshakes, collapsing forward secrecy and enabling replay.
    let client_random = [0x11u8; 32];
    let server_random = [0x22u8; 32];

    // ---- 1. Master secret: PRF(pre_master, "master secret", c_rand || s_rand) ----
    let mut master = [0u8; MASTER_SECRET_LEN];
    derive_master_secret(&pre_master, &client_random, &server_random, &mut master);
    println!(
        "master secret ({MASTER_SECRET_LEN} bytes) = {}",
        encode_hex(&master)
    );

    // The PRF is deterministic: same inputs -> same 48 bytes, every time.
    let mut master_again = [0u8; MASTER_SECRET_LEN];
    derive_master_secret(
        &pre_master,
        &client_random,
        &server_random,
        &mut master_again,
    );
    assert_eq!(
        master, master_again,
        "master-secret derivation is deterministic"
    );

    // ---- 2. Key block: PRF(master, "key expansion", s_rand || c_rand) ----
    // NOTE the seed order FLIPS vs the master secret (server random first) —
    // the SDK handles that internally; you pass (client_random, server_random)
    // in the same argument order both times.
    //
    // The caller carves the key block per cipher suite. For a GCM suite the
    // layout is 2 x (0-byte MAC key + 16-byte key + 4-byte IV salt) = 40 bytes,
    // in this fixed order: client key, server key, client IV salt, server IV salt.
    const KEY_LEN: usize = 16;
    const IV_SALT_LEN: usize = 4;
    let mut key_block = [0u8; 2 * (KEY_LEN + IV_SALT_LEN)];
    derive_key_block(&master, &client_random, &server_random, &mut key_block);

    let (client_key, rest) = key_block.split_at(KEY_LEN);
    let (server_key, rest) = rest.split_at(KEY_LEN);
    let (client_iv_salt, server_iv_salt) = rest.split_at(IV_SALT_LEN);
    println!("client key       = {}", encode_hex(client_key));
    println!("server key       = {}", encode_hex(server_key));
    println!("client IV salt   = {}", encode_hex(client_iv_salt));
    println!("server IV salt   = {}", encode_hex(server_iv_salt));
    assert_ne!(
        client_key, server_key,
        "the two directions get distinct keys"
    );

    // ---- 3. Finished verify_data: PRF(master, label, SM3(transcript))[0..12] ----
    // The caller hashes the handshake transcript (every message up to, but not
    // including, this Finished); the key schedule turns that into the 12-byte
    // verify_data each side puts in its Finished message.
    let transcript_hash = sm3::hash(b"...all handshake messages so far...");

    let mut client_finished = [0u8; FINISHED_VERIFY_DATA_LEN];
    finished_verify_data(
        &master,
        TlcpRole::Client,
        &transcript_hash,
        &mut client_finished,
    );
    let mut server_finished = [0u8; FINISHED_VERIFY_DATA_LEN];
    finished_verify_data(
        &master,
        TlcpRole::Server,
        &transcript_hash,
        &mut server_finished,
    );
    println!("client Finished  = {}", encode_hex(&client_finished));
    println!("server Finished  = {}", encode_hex(&server_finished));

    // Role separation: the label differs ("client finished" vs "server
    // finished"), so the two verify_data values must differ even over the
    // identical transcript — otherwise either side could replay the other's.
    assert_ne!(
        client_finished, server_finished,
        "client and server Finished must differ (distinct PRF labels)"
    );

    println!("\nOK");
}
