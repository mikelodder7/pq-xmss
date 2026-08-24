//! XMSS (eXtended Merkle Signature Scheme) implementation in Rust.
//!
//! Implements the XMSS and XMSS^MT hash-based signature schemes from RFC 8391.
//!
//! # Examples
//!
//! ## Sign and verify with XMSS
//!
//! XMSS uses one Merkle tree and provides smaller signatures than XMSS^MT. A
//! signing key is stateful: each successful signing operation advances its
//! one-time index.
//!
//! ```rust
//! use pq_xmss::{KeyPair, XmssSha2_10_256};
//!
//! let mut keypair = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng())?;
//! let message = b"release manifest";
//! let state_before = keypair.signing_key().as_ref().to_vec();
//!
//! let signature = keypair.signing_key().sign_detached(message)?;
//! keypair
//!     .verifying_key()
//!     .verify_detached(&signature, message)?;
//!
//! // Signing advanced the compact, authoritative key state.
//! assert_ne!(state_before, keypair.signing_key().as_ref());
//! # Ok::<(), pq_xmss::Error>(())
//! ```
//!
//! ## Persist and resume an XMSS^MT key
//!
//! XMSS^MT divides its total height among several smaller trees. This permits
//! much larger signing capacities and faster key generation at the cost of
//! larger signatures. Persist the advanced compact state atomically before
//! distributing or otherwise relying on a signature.
//!
//! ```rust
//! use pq_xmss::{KeyPair, SigningKey, XmssMtSha2_20_2_256};
//!
//! type Params = XmssMtSha2_20_2_256;
//! let mut keypair = KeyPair::<Params>::generate(&mut rand::rng())?;
//! let verifying_key = keypair.verifying_key().clone();
//!
//! let first = keypair.signing_key().sign_detached(b"first approval")?;
//! let persisted_state = keypair.signing_key().as_ref().to_vec();
//! // Atomically replace the previously stored state with `persisted_state`
//! // before making `first` externally visible.
//! verifying_key.verify_detached(&first, b"first approval")?;
//!
//! // After a restart, reconstruct the in-memory traversal cache from the
//! // compact state. Do not retain or use the older SigningKey concurrently.
//! drop(keypair);
//! let mut resumed = SigningKey::<Params>::try_from(persisted_state.as_slice())?;
//! let second = resumed.sign_detached(b"second approval")?;
//! verifying_key.verify_detached(&second, b"second approval")?;
//! # Ok::<(), pq_xmss::Error>(())
//! ```
//!
//! ## Select a parameter set at runtime
//!
//! With `alloc` or `std`, boxed keys provide the same stateful behavior while
//! validating the digest width and complete parameter set at runtime.
//! The boxed API is optional; prefer generic keys when the parameter set is
//! known at compile time.
//!
//! ```rust
//! use pq_xmss::{BoxedKeyPair, ParameterSet};
//!
//! let parameter_set = ParameterSet::from_name("XMSSMT-SHA2_20/2_256")?;
//! let mut keypair = BoxedKeyPair::generate(parameter_set, &mut rand::rng())?;
//!
//! let signed = keypair.signing_key().sign(b"attached message")?;
//! assert_eq!(keypair.verifying_key().verify(&signed)?, b"attached message");
//!
//! let message = b"detached message";
//! let detached = keypair.signing_key().sign_detached(message)?;
//! keypair
//!     .verifying_key()
//!     .verify_detached(&detached, message)?;
//! # Ok::<(), pq_xmss::Error>(())
//! ```
//!
//! Generic and boxed keys use the same compact key and signature formats.
//! Decoding a boxed key or signature additionally requires its [`ParameterSet`]
//! because the raw signature bytes do not contain complete runtime type
//! information.
//!
//! ## `no_std`
//!
//! This crate supports `no_std` targets with a global allocator. Disable
//! default features and enable `alloc`:
//!
//! ```toml
//! [dependencies]
//! pq-xmss = { version = "0.1", default-features = false, features = ["alloc"] }
//! ```
//!
//! Key generation requires the caller to provide a cryptographically secure
//! random number generator. Allocator-free targets are not currently
//! supported.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(not(feature = "alloc"))]
compile_error!("pq-xmss currently requires the `alloc` or `std` feature");

#[cfg(feature = "alloc")]
mod boxed;
mod error;
#[doc = include_str!("../docs/extra-depths.md")]
pub mod extra_depths {}
mod hash;
mod hash_address;
mod params;
#[cfg(feature = "pkcs8")]
mod pkcs8;
mod utils;
mod wots;
mod xmss;
mod xmss_commons;
mod xmss_core;

pub use error::{Error, XmssResult};
pub use hash::FixedDigest;

#[cfg(feature = "alloc")]
pub use boxed::{
    BoxedDetachedSignature, BoxedKeyPair, BoxedSignature, BoxedSigningKey, BoxedVerifyingKey,
};

pub use params::{
    DigestOutputSize,
    ParameterSet,
    XmssMtSha2_20_2_192,
    // XMSSMT multi-tree parameter sets
    XmssMtSha2_20_2_256,
    XmssMtSha2_20_2_512,
    XmssMtSha2_20_4_192,
    XmssMtSha2_20_4_256,
    XmssMtSha2_20_4_512,
    XmssMtSha2_40_2_192,
    XmssMtSha2_40_2_256,
    XmssMtSha2_40_2_512,
    XmssMtSha2_40_4_192,
    XmssMtSha2_40_4_256,
    XmssMtSha2_40_4_512,
    XmssMtSha2_40_8_192,
    XmssMtSha2_40_8_256,
    XmssMtSha2_40_8_512,
    XmssMtSha2_60_3_192,
    XmssMtSha2_60_3_256,
    XmssMtSha2_60_3_512,
    XmssMtSha2_60_6_192,
    XmssMtSha2_60_6_256,
    XmssMtSha2_60_6_512,
    XmssMtSha2_60_12_192,
    XmssMtSha2_60_12_256,
    XmssMtSha2_60_12_512,
    XmssMtShake_20_2_256,
    XmssMtShake_20_2_512,
    XmssMtShake_20_4_256,
    XmssMtShake_20_4_512,
    XmssMtShake_40_2_256,
    XmssMtShake_40_2_512,
    XmssMtShake_40_4_256,
    XmssMtShake_40_4_512,
    XmssMtShake_40_8_256,
    XmssMtShake_40_8_512,
    XmssMtShake_60_3_256,
    XmssMtShake_60_3_512,
    XmssMtShake_60_6_256,
    XmssMtShake_60_6_512,
    XmssMtShake_60_12_256,
    XmssMtShake_60_12_512,
    XmssMtShake256_20_2_192,
    XmssMtShake256_20_2_256,
    XmssMtShake256_20_4_192,
    XmssMtShake256_20_4_256,
    XmssMtShake256_40_2_192,
    XmssMtShake256_40_2_256,
    XmssMtShake256_40_4_192,
    XmssMtShake256_40_4_256,
    XmssMtShake256_40_8_192,
    XmssMtShake256_40_8_256,
    XmssMtShake256_60_3_192,
    XmssMtShake256_60_3_256,
    XmssMtShake256_60_6_192,
    XmssMtShake256_60_6_256,
    XmssMtShake256_60_12_192,
    XmssMtShake256_60_12_256,
    XmssParameter,
    // XMSS single-tree parameter sets
    XmssSha2_10_192,
    XmssSha2_10_256,
    XmssSha2_10_512,
    XmssSha2_16_192,
    XmssSha2_16_256,
    XmssSha2_16_512,
    XmssSha2_20_192,
    XmssSha2_20_256,
    XmssSha2_20_512,
    XmssShake_10_256,
    XmssShake_10_512,
    XmssShake_16_256,
    XmssShake_16_512,
    XmssShake_20_256,
    XmssShake_20_512,
    XmssShake256_10_192,
    XmssShake256_10_256,
    XmssShake256_16_192,
    XmssShake256_16_256,
    XmssShake256_20_192,
    XmssShake256_20_256,
};

#[cfg(feature = "extra-depths")]
pub use params::{
    H1, H2, H3, H4, H5, H6, H7, H8, H9, H11, H12, H13, H14, H15, H17, H18, H19, H21, H22, H23, H24,
    XmssSha2_192, XmssSha2_256, XmssSha2_512, XmssShake_256, XmssShake_512, XmssShake256_192,
    XmssShake256_256, XmssTreeDepth,
};

pub use xmss::{DetachedSignature, KeyPair, Signature, SigningKey, VerifyingKey};

#[cfg(test)]
mod tests {
    use std::{format, string::ToString, sync::OnceLock, vec, vec::Vec};

    use super::*;

    // Instrumenting the standard trees multiplies coverage runtime dramatically.
    // Full test runs use the standardized height, while coverage uses the same
    // control-flow paths with a small tree.
    #[cfg(all(coverage, feature = "extra-depths"))]
    type TestParams = XmssSha2_256<H2>;
    #[cfg(not(all(coverage, feature = "extra-depths")))]
    type TestParams = XmssSha2_10_256;

    fn xmss_test_keypair() -> KeyPair<TestParams> {
        static KEYPAIR: OnceLock<KeyPair<TestParams>> = OnceLock::new();
        KEYPAIR
            .get_or_init(|| KeyPair::<TestParams>::generate(&mut rand::rng()).unwrap())
            .clone()
    }

    fn xmssmt_test_keypair() -> KeyPair<XmssMtSha2_20_2_256> {
        static KEYPAIR: OnceLock<KeyPair<XmssMtSha2_20_2_256>> = OnceLock::new();
        KEYPAIR
            .get_or_init(|| KeyPair::<XmssMtSha2_20_2_256>::generate(&mut rand::rng()).unwrap())
            .clone()
    }

    #[test]
    fn test_xmss_sign_verify() {
        let mut kp = xmss_test_keypair();

        let message = b"test message";
        let sig = kp.signing_key().sign(message).unwrap();

        let recovered = kp.verifying_key().verify(&sig).unwrap();
        assert_eq!(recovered, message);
    }

    #[test]
    fn test_xmss_bad_signature() {
        let mut kp = xmss_test_keypair();

        let message = b"test message";
        let sig = kp.signing_key().sign(message).unwrap();

        // Corrupt the signature.
        let mut sig_bytes = sig.as_ref().to_vec();
        sig_bytes[10] ^= 0xFF;
        let bad_sig = Signature::<TestParams>::try_from(sig_bytes).unwrap();

        let result = kp.verifying_key().verify(&bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_xmssmt_sha2_20_2_256_sign_verify() {
        let mut kp = xmssmt_test_keypair();

        let message = b"test message for xmssmt";
        let sig = kp.signing_key().sign(message).unwrap();

        let recovered = kp.verifying_key().verify(&sig).unwrap();
        assert_eq!(recovered, message);
    }

    #[test]
    fn test_xmssmt_key_encoding_roundtrip() {
        let kp = xmssmt_test_keypair();
        let signing_key =
            SigningKey::<XmssMtSha2_20_2_256>::try_from(kp.signing_key_ref().as_ref()).unwrap();
        let verifying_key =
            VerifyingKey::<XmssMtSha2_20_2_256>::try_from(kp.verifying_key().as_ref()).unwrap();

        assert_eq!(signing_key, *kp.signing_key_ref());
        assert_eq!(verifying_key, *kp.verifying_key());
    }

    #[cfg(feature = "extra-depths")]
    #[test]
    fn test_extra_depth_sizes_and_capacities() {
        fn check<D: XmssTreeDepth>() {
            assert_eq!(D::MAX_SIGNATURES, 1 << D::HEIGHT);

            assert_eq!(XmssSha2_192::<D>::SK_LEN, 104);
            assert_eq!(XmssSha2_192::<D>::VK_LEN, 52);
            assert_eq!(XmssSha2_192::<D>::SIG_LEN, 1252 + 24 * D::HEIGHT as usize);

            assert_eq!(XmssSha2_256::<D>::SK_LEN, 136);
            assert_eq!(XmssSha2_256::<D>::VK_LEN, 68);
            assert_eq!(XmssSha2_256::<D>::SIG_LEN, 2180 + 32 * D::HEIGHT as usize);

            assert_eq!(XmssSha2_512::<D>::SK_LEN, 264);
            assert_eq!(XmssSha2_512::<D>::VK_LEN, 132);
            assert_eq!(XmssSha2_512::<D>::SIG_LEN, 8452 + 64 * D::HEIGHT as usize);

            assert_eq!(XmssShake_256::<D>::SIG_LEN, XmssSha2_256::<D>::SIG_LEN);
            assert_eq!(XmssShake_512::<D>::SIG_LEN, XmssSha2_512::<D>::SIG_LEN);
            assert_eq!(XmssShake256_192::<D>::SIG_LEN, XmssSha2_192::<D>::SIG_LEN);
            assert_eq!(XmssShake256_256::<D>::SIG_LEN, XmssSha2_256::<D>::SIG_LEN);
        }

        check::<H1>();
        check::<H2>();
        check::<H3>();
        check::<H4>();
        check::<H5>();
        check::<H6>();
        check::<H7>();
        check::<H8>();
        check::<H9>();
        check::<H11>();
        check::<H12>();
        check::<H13>();
        check::<H14>();
        check::<H15>();
        check::<H17>();
        check::<H18>();
        check::<H19>();
        check::<H21>();
        check::<H22>();
        check::<H23>();
        check::<H24>();
    }

    #[cfg(feature = "extra-depths")]
    #[test]
    fn test_extra_depth_h1_roundtrip_and_exhaustion() {
        type Params = XmssSha2_256<H1>;

        let mut kp = KeyPair::<Params>::generate(&mut rand::rng()).unwrap();
        assert_eq!(kp.verifying_key().as_ref().len(), Params::VK_LEN);
        assert_eq!(&kp.verifying_key().as_ref()[..4], &[0xff, 0x01, 0x00, 0x01]);

        let signing_key = SigningKey::<Params>::try_from(kp.signing_key_ref().as_ref()).unwrap();
        let verifying_key = VerifyingKey::<Params>::try_from(kp.verifying_key().as_ref()).unwrap();
        assert_eq!(signing_key, *kp.signing_key_ref());
        assert_eq!(verifying_key, *kp.verifying_key());

        let first = kp.signing_key().sign_detached(b"first").unwrap();
        assert_eq!(first.as_ref().len(), Params::SIG_LEN);
        kp.verifying_key()
            .verify_detached(&first, b"first")
            .unwrap();
        assert_eq!(&kp.signing_key().as_ref()[4..8], &[0, 0, 0, 1]);

        let second = kp.signing_key().sign_detached(b"second").unwrap();
        kp.verifying_key()
            .verify_detached(&second, b"second")
            .unwrap();
        assert_eq!(&kp.signing_key().as_ref()[4..8], &[0xff; 4]);
        assert!(kp.signing_key().as_ref()[8..].iter().all(|byte| *byte == 0));

        assert!(matches!(
            kp.signing_key().sign_detached(b"exhausted"),
            Err(Error::KeyExhausted)
        ));
    }

    #[cfg(feature = "extra-depths")]
    #[test]
    fn test_extra_depth_parameter_ids_are_unique() {
        let ids = [
            XmssSha2_256::<H1>::OID,
            XmssSha2_256::<H2>::OID,
            XmssSha2_256::<H3>::OID,
            XmssSha2_256::<H4>::OID,
            XmssSha2_256::<H5>::OID,
            XmssSha2_256::<H6>::OID,
            XmssSha2_256::<H7>::OID,
            XmssSha2_256::<H8>::OID,
            XmssSha2_256::<H9>::OID,
            XmssSha2_256::<H11>::OID,
            XmssSha2_256::<H12>::OID,
            XmssSha2_256::<H13>::OID,
            XmssSha2_256::<H14>::OID,
            XmssSha2_256::<H15>::OID,
            XmssSha2_256::<H17>::OID,
            XmssSha2_256::<H18>::OID,
            XmssSha2_256::<H19>::OID,
            XmssSha2_256::<H21>::OID,
            XmssSha2_256::<H22>::OID,
            XmssSha2_256::<H23>::OID,
            XmssSha2_256::<H24>::OID,
        ];

        for (position, id) in ids.iter().enumerate() {
            assert_eq!(
                id & 0xff,
                [
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 17, 18, 19, 21, 22, 23, 24
                ][position]
            );
            assert_eq!(ids.iter().filter(|candidate| *candidate == id).count(), 1);
        }

        assert_ne!(XmssSha2_256::<H1>::OID, XmssShake256_256::<H1>::OID);
    }

    #[test]
    fn test_multiple_signatures() {
        let mut kp = xmss_test_keypair();

        for i in 0..3 {
            let msg = format!("message {}", i);
            let sig = kp.signing_key().sign(msg.as_bytes()).unwrap();
            let recovered = kp.verifying_key().verify(&sig).unwrap();
            assert_eq!(recovered, msg.as_bytes());
        }
    }

    #[cfg(feature = "extra-depths")]
    #[test]
    fn test_compact_key_reload_matches_in_memory_traversal() {
        type Params = XmssSha2_256<H3>;

        let seed: Vec<u8> = (0u8..Params::SEED_LEN as u8).collect();
        let mut keypair = KeyPair::<Params>::from_seed(&seed).unwrap();
        let verifying_key = keypair.verifying_key().clone();

        for index in 0u32..8 {
            let persisted = keypair.signing_key().as_ref().to_vec();
            assert_eq!(persisted.len(), Params::SK_LEN);
            let mut reloaded = SigningKey::<Params>::try_from(persisted).unwrap();
            let message = index.to_be_bytes();

            let cached_signature = keypair.signing_key().sign_detached(&message).unwrap();
            let rebuilt_signature = reloaded.sign_detached(&message).unwrap();
            assert_eq!(cached_signature, rebuilt_signature);
            verifying_key
                .verify_detached(&cached_signature, &message)
                .unwrap();
        }

        assert!(matches!(
            keypair.signing_key().sign_detached(b"exhausted"),
            Err(Error::KeyExhausted)
        ));
    }

    #[test]
    fn test_xmss_sign_detached_verify() {
        let mut kp = xmss_test_keypair();

        let message = b"detached test message";
        let sig = kp.signing_key().sign_detached(message).unwrap();

        // A detached signature should not contain the message.
        let full_sig = kp.signing_key().sign(b"another").unwrap();
        assert!(sig.as_ref().len() < full_sig.as_ref().len());

        kp.verifying_key().verify_detached(&sig, message).unwrap();

        // Verification of the wrong message should fail.
        assert!(
            kp.verifying_key()
                .verify_detached(&sig, b"wrong message")
                .is_err()
        );
    }

    #[test]
    fn test_large_detached_message() {
        let mut keypair = xmss_test_keypair();
        let message = vec![0x5a; 1024 * 1024];

        let signature = keypair.signing_key().sign_detached(&message).unwrap();
        assert_eq!(signature.as_ref().len(), TestParams::SIG_LEN);
        keypair
            .verifying_key()
            .verify_detached(&signature, &message)
            .unwrap();
    }

    #[cfg(feature = "extra-depths")]
    #[test]
    fn test_streaming_message_hash_for_every_hash_family() {
        fn roundtrip<P: XmssParameter>() {
            let seed = vec![0x3c; P::SEED_LEN];
            let mut keypair = KeyPair::<P>::from_seed(&seed).unwrap();
            let message = b"streamed message hash";
            let signature = keypair.signing_key().sign_detached(message).unwrap();
            keypair
                .verifying_key()
                .verify_detached(&signature, message)
                .unwrap();
        }

        roundtrip::<XmssSha2_192<H1>>();
        roundtrip::<XmssSha2_256<H1>>();
        roundtrip::<XmssSha2_512<H1>>();
        roundtrip::<XmssShake_256<H1>>();
        roundtrip::<XmssShake_512<H1>>();
        roundtrip::<XmssShake256_192<H1>>();
        roundtrip::<XmssShake256_256<H1>>();
    }

    #[test]
    fn test_xmss_verify_truncated_signature() {
        let mut kp = xmss_test_keypair();

        let sig = kp.signing_key().sign(b"test message").unwrap();

        // Truncate the signature so that it is too short.
        let short_bytes = &sig.as_ref()[..sig.as_ref().len() / 2];
        let short_sig = Signature::<TestParams>::try_from(short_bytes).unwrap();

        assert!(kp.verifying_key().verify(&short_sig).is_err());
    }

    #[cfg(not(all(coverage, feature = "extra-depths")))]
    #[test]
    fn test_key_exhaustion() {
        let mut kp = xmss_test_keypair();

        // Modify the index to be at the last valid position (2^10 - 1 = 1023).
        let mut sk_bytes = kp.signing_key().as_ref().to_vec();
        // The big-endian index occupies bytes[4..8], after the OID.
        sk_bytes[4] = 0x00;
        sk_bytes[5] = 0x00;
        sk_bytes[6] = 0x03;
        sk_bytes[7] = 0xFF; // 1023
        let mut last_sk = SigningKey::<XmssSha2_10_256>::try_from(sk_bytes).unwrap();

        // Signing at the last index should succeed.
        let sig = last_sk.sign(b"last message").unwrap();
        let recovered = kp.verifying_key().verify(&sig).unwrap();
        assert_eq!(recovered, b"last message");

        // Signing again should fail with KeyExhausted.
        let result = last_sk.sign(b"one more");
        assert!(result.is_err());
    }

    #[test]
    fn test_deterministic_keygen() {
        // Sequential seed pattern: SK_SEED || SK_PRF || PUB_SEED.
        let seed: Vec<u8> = (0u8..96).collect();

        let kp1 = KeyPair::<TestParams>::from_seed(&seed).unwrap();
        let mut kp2 = KeyPair::<TestParams>::from_seed(&seed).unwrap();

        // Same seed must produce identical keys.
        assert_eq!(kp1.verifying_key(), kp2.verifying_key());

        // Sign with one and verify with the other's public key.
        let sig = kp2.signing_key().sign(b"deterministic test").unwrap();
        let recovered = kp1.verifying_key().verify(&sig).unwrap();
        assert_eq!(recovered, b"deterministic test");
    }

    #[test]
    fn test_verifying_key_from_signing_key() {
        let kp = xmss_test_keypair();

        // Derive the verifying key from the signing key.
        let derived_pk = VerifyingKey::from(kp.signing_key_ref());
        assert_eq!(kp.verifying_key(), &derived_pk);
    }

    #[test]
    fn test_fixed_digest_output_sizes() {
        let output_192 = <XmssSha2_10_192 as FixedDigest>::digest(b"fixed output").unwrap();
        let output_256 = <XmssSha2_10_256 as FixedDigest>::digest(b"fixed output").unwrap();
        let output_512 = <XmssSha2_10_512 as FixedDigest>::digest(b"fixed output").unwrap();

        assert_eq!(output_192.len(), 24);
        assert_eq!(output_256.len(), 32);
        assert_eq!(output_512.len(), 64);
        assert_eq!(&output_192[..], &output_256[..24]);
    }

    #[test]
    fn test_runtime_parameter_set_metadata() {
        let parameter_set = ParameterSet::from_name("XMSSMT-SHA2_40/8_256").unwrap();
        assert!(!parameter_set.is_xmss());
        assert_eq!(parameter_set.digest_output_size().bytes(), 32);
        assert_eq!(parameter_set.total_height(), 40);
        assert_eq!(parameter_set.layers(), 8);
        assert_eq!(parameter_set.tree_height(), 5);
        assert_eq!(parameter_set.signature_len(), 18_469);
        assert_eq!(parameter_set.to_string(), "XMSSMT-SHA2_40/8_256");

        let xmss = ParameterSet::from_name("XMSS-SHA2_10_192").unwrap();
        assert!(xmss.is_xmss());
        assert_eq!(xmss.digest_output_size(), DigestOutputSize::Bytes24);
        assert_eq!(xmss.digest_output_size().bytes(), 24);
    }

    #[cfg(not(coverage))]
    #[test]
    fn test_boxed_xmssmt_sign_reload_and_verify() {
        let parameter_set = ParameterSet::from_name("XMSSMT-SHA2_20/2_256").unwrap();
        let seed = vec![0x5a; 96];
        let mut keypair = BoxedKeyPair::from_seed(parameter_set, &seed).unwrap();
        let verifying_key = keypair.verifying_key().clone();
        assert_eq!(verifying_key.parameter_set(), parameter_set);
        assert_eq!(keypair.signing_key().parameter_set(), parameter_set);
        assert_eq!(keypair.signing_key().verifying_key(), verifying_key);

        let first = keypair
            .signing_key()
            .sign_detached(b"first runtime signature")
            .unwrap();
        verifying_key
            .verify_detached(&first, b"first runtime signature")
            .unwrap();
        assert_eq!(first.parameter_set(), parameter_set);

        let decoded_signature =
            BoxedDetachedSignature::try_from_bytes(parameter_set, first.as_ref()).unwrap();
        let decoded_verifying_key =
            BoxedVerifyingKey::try_from_bytes(parameter_set, verifying_key.as_ref()).unwrap();
        decoded_verifying_key
            .verify_detached(&decoded_signature, b"first runtime signature")
            .unwrap();

        let other_parameter_set = ParameterSet::from_name("XMSSMT-SHAKE_20/2_256").unwrap();
        let other_signature =
            BoxedDetachedSignature::try_from_bytes(other_parameter_set, first.as_ref()).unwrap();
        assert!(matches!(
            verifying_key.verify_detached(&other_signature, b"first runtime signature"),
            Err(Error::ParameterSetMismatch)
        ));

        let persisted = keypair.signing_key().as_ref().to_vec();
        drop(keypair);
        let mut resumed = BoxedSigningKey::try_from_bytes(parameter_set, &persisted).unwrap();
        let second = resumed.sign_detached(b"second runtime signature").unwrap();
        verifying_key
            .verify_detached(&second, b"second runtime signature")
            .unwrap();
        assert_ne!(first.as_ref(), second.as_ref());

        let attached = resumed.sign(b"attached runtime signature").unwrap();
        assert_eq!(attached.parameter_set(), parameter_set);
        let decoded_attached =
            BoxedSignature::try_from_bytes(parameter_set, attached.as_ref()).unwrap();
        assert_eq!(
            verifying_key.verify(&decoded_attached).unwrap(),
            b"attached runtime signature"
        );

        let trait_verifying_key = signature::Keypair::verifying_key(&resumed);
        assert_eq!(trait_verifying_key, verifying_key);
    }

    /// Decodes a hex string to bytes. Panics on invalid input (test-only).
    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
            .collect()
    }

    /// KAT verification test using the liboqs XMSS-SHA2_10_256 known-answer test vectors.
    #[test]
    fn test_kat_xmss_sha2_10_256_verify() {
        let pk_hex = "00000001B901B8D9332FE458EB6DE87AF74655D0B5AD936A66FDB6AC9D1B8CF25BB6DB8404562AD35E8ECAFAAFDA16981CDAA147606BEEA62801342AF13C8B5535F72F94";
        let msg_hex = "B338DD755D5618C464AB331F14DE3DD4A358BBA00D28FB35236741E902F7B248CE";
        let sm_hex = concat!(
            "00000000404DFF9B9F3931FE6158FFF355A8EE715C9BC6A87FE6627928F3CA10",
            "55FA7010C534B0D4C6FFDF4DBFE00E72405EFE83BBCF19AA2030A8CB16380848",
            "2B6376FF8CE01FB8090F4842896A1EA5E9282F35CACD245A4B9DE9FE84E93158",
            "51D68A72B3ECB9F440937C8BA4AC3F0429246CBC2777E8B92D84F4BA49FAB894",
            "65FCB0FC8017E582746F531B4697925154A22E2D6A0F1B81913438000C295153",
            "D7ADCA8F852C50D360F65F887479E9631A2CA30FE3AD92E7BF648643835F4F8C",
            "C081A6C951B83B77608A08C021821DA61962CFCC8E97D75441921D39C5AD5375",
            "43EFBAF0345DC70826E6E950929570C72E51619600C58D932A72657B19AF163E",
            "0B8F7AAF2949A5EB26C517909E0E663E36753491182975206009107509DFFC89",
            "8D308B903E84A8B29718BF7125397AFF5467D53CF8F36EB945B6B98D48E81C01",
            "74A0E03541D24369CF8EDDA4288FFA615D16FBC7355CFC0966BA9256E5B8A44D",
            "A95760DFB61301B10FD3E82436E267DB089773E43B984297D1E0D395DCC77FCF",
            "ECCEFEBD4B80B3F241872EA251DA466CA6C5324346F4B5E6886654A86592641A",
            "8C32AC554261B2D9130462C976B039E593F873AD1712820FF3E723FE57F13775",
            "1AB3CA8B5B20D28D1B9384DF1D710AC39FAF699989418B7856C2034C695A693E",
            "CC336EB472DE5049C743089529695B028F2F72BE0893E59169E9A2376C64BC5C",
            "CAC5482E5A6E9C88D710A3FF8F23C206B09D314BF50568228B1BACF1CE330D52",
            "9BD3793D7C7CD9EC770C111D9681D6F1B97D908CBBD436444853FEB47F234D31",
            "F5E92B9E0465D67AC0FE48859126BEFA7F7D121A67C2C2970B37B8081B4E73C5",
            "A21A41F60160A61FAFBD48649A3D2032C1679A67F348E3E25275FCD9AF650937",
            "FEB0A30F25878CEED7D6CA693518B5A2F5418135EA9316EFFDECDB1DFFC9EE3A",
            "62EFF0E66F3D05BD9D5F8679B536BB6D39792B28DF2481A6EECB9BEE40B11A10",
            "D39A90EA1AAC47BF956FBFE9B0427B599B9BC024F326515E71615419423FEC3F",
            "19F621D49B6EED59F129A6B1411B7B1AFCF073095D57B03F25A16F946ED716BF",
            "705F567A151BE85B8E8195CC2F070BFD482702182B8A4A43ED942F6BD3CBF9DE",
            "7E8AEB17C41E1C009C94FF4A2050E3731088B75474B38DC52BADF53C7DCD3FB9",
            "8D023649FC4799CE060ADDACEC7CD4E656074E631C1CB8AEF88EFEE0817C2E3D",
            "79E287F4510E48DFB7E23CB49D6FCA39A1E0F471F16A8BB65AF02150D059036D",
            "00386DD287BEA4D52FB263B57AE5ADD901CADE838B1D7347D9E47EAF6456148C",
            "6C4E44B0FA3DFCF5C9CEC2D80AD509A65AEF0E3E663B7F31BCA437311BA799D",
            "4C2ACC138F85D73CB40792FF03F8F20427D951444990CA3976A71368A7DC1455",
            "E880722F06F02163BC712E852A914F22E5675EB9B1C6C8B7FD20A8880AD2EEF9",
            "7982C065C937BD3639357E4C7450CBDA0B51CCA8E3E078DC760FD99EBF646B82",
            "369576539B2BD5B2C866ED5AE94423A5CE18C685352398D01C983F080D7BEB8A",
            "9243AAA9AC1DDCC1B058B92BEAD301E8F3B8F5EF71EEE7966302B44D2E26D2A0",
            "2393713E5D4D3FEF42196FAA368274C78C2932D22840ECA6018CE7D16B19A072",
            "7CB1966EB28B57D137C5264CC2E627F24A3BAD50EA4F75C7BD8998709C01ED5A",
            "CFFF0891934E94DA2CACCA212FB48BE3F9EAA310547E73C388D881F36AE21EFE",
            "DD23744F6B07C5D6D2776C191ED41E607316F61BBEF7A20E1A03150AE833D189",
            "52AE35188FBFDFA55C12A388836717BB2BDD97E89121C56C3B53E8198242315C",
            "9E438512E0C8354A3E599CB7217AE688647A72985606BBD0720F6FA5C5B6F70E",
            "88234EE54C6DB0A41106C866564650829FE4B232635B06B18240C9F86369C75B",
            "2F7D237211A380C43F95D362E0680D9EA2CA47E1DC8C49703E22650B765F847A",
            "D86BE25A3B7630D640A0097632DF13F600E8A025DD9A1FC67B0EB09C1CA9FA39",
            "23896927DEE1E3CC0C81F4B82E43B89CACC69C9B8ADCA1670F7D4E50DB7BCD94",
            "C2115E75F2BFD2336DA5A304D0F3455927360BF5040E95D1454106F2A8A7CD27",
            "D5510E7B5BE7B5B9EDEFDC3D4249D655C51F4C1DBA0F359BE4769AB66EDBC802",
            "824E9AB866E8EEAA2FEB1CC855F0A745AAC84A610DF0238112C6519F8E7346C4",
            "5331A6036F84D5B6250F4B5BC0A2A6A31DAF9C60EB13C20CC649A18E27A6C98B",
            "82F08E21706A8BDF338CC69C1679D25ECFF733A721211C1F6DD28091AAA9C93B",
            "047EFCD2C8A55F2DA65E616F07DCC0F44081D4E359C1688A00F062EC925D2443",
            "2862B547BB70F2AF126A3DABA5C918B224DE444B8733E6FA601B3D349307E945",
            "83D0EC976AEDA2B90972324B3ACE8C7B79A67723AEA037E12DA9EFA9CA9668A4",
            "F5FDADFB9EEE13398921F5023E354A6894825431DBA7317E6A6F69F0E77294BC",
            "D02D7616E75AC31EC528FC070B8C34027C4E9CD0672903412FCA6B723650D56A",
            "F562069312FC7EF1891A77E1A3F29D810C205EE212E75863F3B8B1ED216DF888",
            "ADD07AFF45F1B5C01196329311414797CD5F67FFC54AAD04C803FF7E83C2E8BA",
            "224CE83695BB7916AC42B1861F5CB527FDBCD82DBFA31C5ACF981D841420383750",
            "4263C96A0015841FBCC721F96D50A86D6E096AB54AF9980F06CEE6341C78D658",
            "3F6BAE8081B3C44B0F10FB7300874B5011FF0F97C52F975A31355884C2F12B6F",
            "FEE20E8371D38183C9D04977BFA037C9BD4DD7F7CE203FD7FAD3852B3C2AE9D0",
            "78ADEC70DB1A7140EF1114EBB03E8DE03237E0A27FF510015AC76FCEFE4EBD4C",
            "3A1B6C67DB2A82FE2B1BF18723DB0F29FE4AD47B2EEF22AC3C6661CFA7DA747",
            "6D23B470FA2E0441B6473EBD291791F09B4ADA70A5286EB05167BD59BFD8C464",
            "27413D60692382EFB7882F60DC53AAAFDF2014CA7D27F8FA93C187A8371B4179",
            "6557AE739912E5991C713532E81FA57F9BA562E1D3026D2D2D7373D99871BC62",
            "768AD70D3DB184EABED83E30C11C9BC62F3340923A0082B987EC45CC7BD1DB4B",
            "2B15E8AD3EAD74E96D8C20D85617BBEDC0BDAF8ED48B7EE8D7C42990028EC066",
            "9AFC0861C22F2E9109F9BB35426BDDB4A69EB8F45CD5B226F92E8026F1E62DE1",
            "DE435A4FC0CAEDA91C38A88F0037BDB296CD7B07FF040B1E08F02711E946B307",
            "A5A38487F53070985B8E28BE6CCE809F34100F0CA780996CD38E91BA7773BB63",
            "2D0BE7978F3AF3A92B961BD3A8759590726D6C1811F9E0BCA87377334E7C1F12",
            "FE37401CA0200823938C816ED98981521470F7F2CCDD69D85E7530EBF39E3A59",
            "2B1C09BC6C352C3FDB108FB26E7ACD3D5A4FC0442962E2C09651AC0D026E370F",
            "1EE1A8219C4833D70793D6E581FD25B0E95FAB1EDA67232C2FA12C4E379A6627",
            "E75AD408C1D2526005F2567CED8608E88CF53064FCDC58007198ADFA860F9FED",
            "1DF80EFACC768A0A063E1AFEE6DF1BE3483105B1C45EB50BF7863B4278422CEB",
            "A9001EA00299AC0415BF28A9C49CC2E92FC15565B547538A027886C6EB0D83B7",
            "1138CE1A",
        );

        let pk_bytes = hex_decode(pk_hex);
        let msg_bytes = hex_decode(msg_hex);
        let sm_bytes = hex_decode(sm_hex);

        assert_eq!(pk_bytes.len(), 68); // 4 OID + 32 root + 32 PUB_SEED
        assert_eq!(msg_bytes.len(), 33);
        assert_eq!(sm_bytes.len(), 2500);

        let pk = VerifyingKey::<XmssSha2_10_256>::try_from(pk_bytes.as_slice())
            .expect("failed to parse KAT public key");
        let sig = DetachedSignature::<XmssSha2_10_256>::try_from(sm_bytes.as_slice())
            .expect("failed to parse KAT signature");

        pk.verify_detached(&sig, &msg_bytes)
            .expect("KAT verification failed — signature should be valid");

        // Also verify that a corrupted message fails.
        let mut bad_msg = msg_bytes.clone();
        bad_msg[0] ^= 0xFF;
        assert!(
            pk.verify_detached(&sig, &bad_msg).is_err(),
            "KAT verification should fail with corrupted message"
        );
    }

    #[cfg(feature = "serde")]
    mod serde_tests {
        use super::*;

        #[test]
        fn test_signing_key_serde_json_roundtrip() {
            let mut kp = xmss_test_keypair();
            let sk = kp.signing_key();

            let json = serde_json::to_string(&*sk).unwrap();
            let sk2: SigningKey<TestParams> = serde_json::from_str(&json).unwrap();
            assert_eq!(*sk, sk2);
        }

        #[test]
        fn test_verifying_key_serde_json_roundtrip() {
            let kp = xmss_test_keypair();
            let pk = kp.verifying_key();

            let json = serde_json::to_string(pk).unwrap();
            let pk2: VerifyingKey<TestParams> = serde_json::from_str(&json).unwrap();
            assert_eq!(*pk, pk2);
        }

        #[test]
        fn test_signature_serde_json_roundtrip() {
            let mut kp = xmss_test_keypair();
            let sig = kp.signing_key().sign(b"test message").unwrap();

            let json = serde_json::to_string(&sig).unwrap();
            let sig2: Signature<TestParams> = serde_json::from_str(&json).unwrap();
            assert_eq!(sig, sig2);
        }

        #[test]
        fn test_signing_key_postcard_roundtrip() {
            let mut kp = xmss_test_keypair();
            let sk = kp.signing_key();

            let bytes = postcard::to_allocvec(&*sk).unwrap();
            let sk2: SigningKey<TestParams> = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(*sk, sk2);
        }

        #[test]
        fn test_verifying_key_postcard_roundtrip() {
            let kp = xmss_test_keypair();
            let pk = kp.verifying_key();

            let bytes = postcard::to_allocvec(pk).unwrap();
            let pk2: VerifyingKey<TestParams> = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(*pk, pk2);
        }

        #[test]
        fn test_signature_postcard_roundtrip() {
            let mut kp = xmss_test_keypair();
            let sig = kp.signing_key().sign(b"test message").unwrap();

            let bytes = postcard::to_allocvec(&sig).unwrap();
            let sig2: Signature<TestParams> = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(sig, sig2);
        }
    }

    #[cfg(feature = "pkcs8")]
    mod pkcs8_tests {
        use super::*;
        use ::pkcs8::EncodePrivateKey;

        #[test]
        fn test_pkcs8_roundtrip() {
            let kp = xmss_test_keypair();
            let der = kp.to_pkcs8_der().expect("PKCS#8 encode failed");
            let kp2 = KeyPair::<TestParams>::from_pkcs8_der(der.as_bytes())
                .expect("PKCS#8 decode failed");
            assert_eq!(kp.verifying_key(), kp2.verifying_key());
        }

        #[test]
        fn test_pkcs8_rejects_mismatched_public_key() {
            let kp = xmss_test_keypair();
            let der = kp.to_pkcs8_der().expect("PKCS#8 encode failed");
            let mut bytes = der.as_bytes().to_vec();

            // The optional public-key BIT STRING is the final PKCS#8 field, so
            // changing its last data byte preserves valid DER while making it
            // inconsistent with the private key.
            *bytes.last_mut().expect("PKCS#8 encoding was empty") ^= 1;

            assert!(matches!(
                KeyPair::<TestParams>::from_pkcs8_der(&bytes),
                Err(Error::PublicKeyMismatch)
            ));
        }
    }
}
