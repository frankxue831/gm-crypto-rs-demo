//! SM4's raw block primitive behind the RustCrypto `cipher` 0.5 traits — the
//! interop surface behind the `cipher-traits` feature.
//! Run: cargo run --features cipher-traits --example sm4_cipher_traits
//! Safety: §9 rule 3. Authentication, §9 rule 7. Pick the right tool.
//!
//! The traits add no cryptography, so this example's job is to *prove* that,
//! map the sharp edges, and be blunt about what a bare block cipher is not: a
//! mode. For real encryption see `sm4_cbc_ctr` (CBC / CTR) and `sm4_aead`
//! (GCM — the default choice). `cipher` is a companion crate you declare
//! yourself; gmcrypto-core does not re-export it.

use cipher::array::typenum::Unsigned;
use cipher::array::Array;
use cipher::consts::U16;
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, Key, KeyInit, KeySizeUser};
use gm_crypto_rs_demo::{encode_hex, DEMO_SM4_KEY};
use gmcrypto_core::sm4::Sm4Cipher;

fn main() {
    println!("== SM4 block primitive via the RustCrypto `cipher` traits ==\n");

    // DEMO ONLY: reuses the crate-wide `DEMO_SM4_KEY` so this example's block
    // output is reproducible and comparable with `sm4_cbc_ctr`'s raw-block section.
    // Production: derive per-session keys via a KDF or unwrap a KEK-wrapped DEK; never hard-code.
    // Reusing this risks: anyone with the source can decrypt every block produced with it.
    let key = DEMO_SM4_KEY;
    let plaintext_block = [0x37u8; 16];

    // ---- 1. UFCS is not a style choice here — the names genuinely collide ----
    // `Sm4Cipher` carries inherent `new` / `encrypt_block` / `decrypt_block`,
    // and inherent methods win over trait methods. The two differ in argument
    // type, so the plain form is not merely ambiguous to a reader — it decides
    // which type you have to hand the call.
    //   inherent: Sm4Cipher::new(&[u8; 16])      encrypt_block(&mut [u8; 16])
    //   trait:    KeyInit::new(&Key<Sm4Cipher>)  encrypt_block(&mut Array<u8, U16>)
    // (This is the collision `sm4_aead_traits` does *not* have: `Sm4Gcm` and
    // `Sm4Ccm` carry no inherent methods at all.)
    let sized: &Key<Sm4Cipher> = &Array::from(key);
    let via_trait = <Sm4Cipher as KeyInit>::new(sized);
    let via_slice = <Sm4Cipher as KeyInit>::new_from_slice(&key).expect("16-byte SM4 key");
    let inherent = Sm4Cipher::new(&key);

    // Unlike HMAC-SM3's variable-length key, SM4's is fixed — so here `KeySize`
    // really is the length your key has to be, and a wrong one is an error
    // rather than a silent rehash.
    assert_eq!(<Sm4Cipher as KeySizeUser>::KeySize::USIZE, 16);
    assert_eq!(<Sm4Cipher as BlockSizeUser>::BlockSize::USIZE, 16);
    assert!(
        <Sm4Cipher as KeyInit>::new_from_slice(&key[..15]).is_err(),
        "a 15-byte key is rejected, not padded or truncated",
    );
    println!("UFCS: KeyInit::new takes Array<u8, U16>, the inherent new takes &[u8; 16]");
    println!("  key size 16, block size 16, both fixed by the type");

    // ---- 2. Byte-identical to the inherent path ----
    // Nothing is pinned to a constant: the expected bytes are recomputed
    // through the inherent API on every run, so this catches drift in *either*
    // path. (`sm4_cbc_ctr` is where the published GB/T 32907 vector is checked.)
    let mut expected = plaintext_block;
    inherent.encrypt_block(&mut expected);

    for (label, cipher) in [("KeyInit::new", &via_trait), ("new_from_slice", &via_slice)] {
        let mut block = Array::from(plaintext_block);
        <Sm4Cipher as BlockCipherEncrypt>::encrypt_block(cipher, &mut block);
        assert_eq!(
            block.as_slice(),
            expected.as_slice(),
            "{label}: trait encrypt_block == inherent encrypt_block",
        );
        <Sm4Cipher as BlockCipherDecrypt>::decrypt_block(cipher, &mut block);
        assert_eq!(block.as_slice(), &plaintext_block, "{label}: round-trips");
    }
    println!(
        "block: trait output == inherent output ({})",
        encode_hex(&expected)
    );
    println!("  and both constructors produce the same cipher");

    // ---- 3. The multi-block path, and what it does *not* buy you ----
    // cipher 0.5 uses a rank-2 backend: `encrypt_blocks` hands a backend to a
    // closure. `Sm4Cipher`'s backend declares `ParBlocksSize = U1`, so the
    // default fan-out calls `encrypt_block` once per block — the trait surface
    // reaches no wider-than-one-block work. If you enabled `sm4-bitsliced-simd`
    // upstream expecting the trait path to pick up SIMD batching, it does not;
    // the inherent `Sm4Cipher::encrypt_blocks` is where batching lives.
    let blocks_pt: [[u8; 16]; 4] = [[0xa0; 16], [0xa1; 16], [0xa2; 16], [0xa3; 16]];
    let mut inherent_blocks = blocks_pt;
    inherent.encrypt_blocks(&mut inherent_blocks);

    let mut trait_blocks: [Array<u8, U16>; 4] = blocks_pt.map(Array::from);
    <Sm4Cipher as BlockCipherEncrypt>::encrypt_blocks(&via_trait, &mut trait_blocks);
    for (got, want) in trait_blocks.iter().zip(inherent_blocks.iter()) {
        assert_eq!(got.as_slice(), want, "multi-block trait path == inherent");
    }
    <Sm4Cipher as BlockCipherDecrypt>::decrypt_blocks(&via_trait, &mut trait_blocks);
    for (got, want) in trait_blocks.iter().zip(blocks_pt.iter()) {
        assert_eq!(got.as_slice(), want, "multi-block round-trips");
    }
    println!("blocks: encrypt_blocks matches inherent, and is U1-at-a-time underneath");

    // ---- 4. A block cipher is not a mode, and this one is ECB ----
    // `encrypt_blocks` over more than one block is exactly ECB: each block is
    // enciphered independently under the same key, so equal plaintext blocks
    // produce equal ciphertext blocks. That is a real leak, not a technicality
    // — it is why the ECB penguin is a picture of a penguin. The trait surface
    // makes this easier to reach for by accident than the inherent API does,
    // because `encrypt_blocks` looks like bulk encryption.
    let repeated: [[u8; 16]; 3] = [[0x5a; 16], [0x5a; 16], [0xff; 16]];
    let mut ecb: [Array<u8, U16>; 3] = repeated.map(Array::from);
    <Sm4Cipher as BlockCipherEncrypt>::encrypt_blocks(&via_trait, &mut ecb);
    assert_eq!(
        ecb[0], ecb[1],
        "identical plaintext blocks encipher identically — the ECB leak",
    );
    assert_ne!(
        ecb[1], ecb[2],
        "a different block is a different ciphertext"
    );
    println!("\nleak: two identical plaintext blocks -> identical ciphertext blocks");
    println!("  {} (block 0)", encode_hex(ecb[0].as_slice()));
    println!("  {} (block 1, same input)", encode_hex(ecb[1].as_slice()));
    println!("  this is ECB. It hides no structure, and it authenticates nothing.");

    // ---- 5. Which surface to reach for ----
    println!("\nuse the traits for ecosystem fit: `C: BlockCipherEncrypt` code takes");
    println!("  SM4 next to AES, so a generic mode/KDF construction just works");
    println!("keep Sm4Cipher's inherent methods for plain arrays and batched blocks");
    println!("use neither for actual data: reach for sm4::mode_gcm (authenticated),");
    println!("  or mode_cbc / mode_ctr with a separate MAC — see sm4_aead, sm4_cbc_ctr");

    println!("\nOK");
}
