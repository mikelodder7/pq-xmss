use alloc::{string::ToString, vec, vec::Vec};
use core::fmt;
#[cfg(feature = "extra-depths")]
use core::marker::PhantomData;
use core::str::FromStr;

use hybrid_array::ArraySize;
use hybrid_array::typenum::{U2, U3, U4, U5, U8, U24, U32, U64};

/// Type-level sum: `TSum<A, B>` = A + B.
type TSum<A, B> = <A as core::ops::Add<B>>::Output;
/// Type-level product: `TProd<A, B>` = A * B.
type TProd<A, B> = <A as core::ops::Mul<B>>::Output;

use crate::error::{Error, XmssResult};
use crate::hash::{CoreHash, FixedDigest, fixed_digest, fixed_digest_into, runtime_digest};
use crate::xmss_core::xmss_xmssmt_core_sk_bytes;

/// Hash function identifier for SHA-2.
pub(crate) const XMSS_SHA2: u32 = 0;
/// Hash function identifier for SHAKE128.
pub(crate) const XMSS_SHAKE128: u32 = 1;
/// Hash function identifier for SHAKE256.
pub(crate) const XMSS_SHAKE256: u32 = 2;

/// Length of the OID prefix in serialized keys, in bytes.
pub(crate) const XMSS_OID_LEN: usize = 4;

/// Defines an XMSS or XMSS^MT parameter set at compile time.
///
/// Applications normally select one of the concrete parameter types exported
/// by this crate. Use [`ParameterSet`] and the boxed key API when the choice
/// must instead be made at runtime.
#[allow(private_interfaces)]
pub trait XmssParameter: Sized + Clone + fmt::Debug + Default + 'static {
    /// Hash output length (`U24`, `U32`, or `U64`).
    type N: ArraySize + fmt::Debug + Clone + PartialEq + Eq;
    /// Hash implementation with an effective output size of [`Self::N`].
    type Hash: FixedDigest<OutputSize = Self::N>;
    /// Signing key length as a type-level unsigned integer.
    type SkLen: ArraySize + fmt::Debug + Clone + PartialEq + Eq;
    /// Verifying key length as a type-level unsigned integer.
    type VkLen: ArraySize + fmt::Debug + Clone + PartialEq + Eq;
    /// Seed length as a type-level unsigned integer.
    type SeedLen: ArraySize + fmt::Debug + Clone + PartialEq + Eq;

    /// Human-readable name, for example, `XMSS-SHA2_10_256`.
    const NAME: &'static str;

    /// Signing key length in bytes (including OID prefix).
    const SK_LEN: usize;
    /// Verifying key length in bytes (including OID prefix).
    const VK_LEN: usize;
    /// Detached signature length in bytes.
    const SIG_LEN: usize;
    /// Seed length in bytes (`3 * N`).
    const SEED_LEN: usize;
    /// Parameter-set identifier stored at the start of serialized keys.
    #[doc(hidden)]
    const OID: u32;
    /// Whether this is a single-tree XMSS parameter set.
    #[doc(hidden)]
    const IS_XMSS: bool;

    /// Builds the runtime `XmssParams` for internal computation.
    #[doc(hidden)]
    fn xmss_params() -> XmssParams;

    /// Allocates key buffers and writes this parameter set's identifier.
    #[doc(hidden)]
    fn init_keypair_buffers(seed: Option<&[u8]>) -> XmssResult<(XmssParams, Vec<u8>, Vec<u8>)> {
        let params = Self::xmss_params();
        let expected = params.get_seed_length();
        if let Some(seed) = seed {
            if seed.len() != expected {
                return Err(Error::InvalidSeedLength {
                    expected,
                    got: seed.len(),
                });
            }
        }

        let mut pk = vec![0u8; Self::VK_LEN];
        let mut sk = vec![0u8; Self::SK_LEN];
        let oid = Self::OID.to_be_bytes();
        pk[..XMSS_OID_LEN].copy_from_slice(&oid);
        sk[..XMSS_OID_LEN].copy_from_slice(&oid);

        Ok((params, pk, sk))
    }
}

// Constant helper functions used by the macro to compute sizes from (n, h, d).

const fn xmss_sk_len(n: usize, h: usize, d: usize) -> usize {
    let index_bytes = if d == 1 { 4 } else { h.div_ceil(8) };
    4 + index_bytes + 4 * n
}

const fn xmss_vk_len(n: usize) -> usize {
    4 + 2 * n
}

const fn xmss_sig_len(n: usize, h: usize, d: usize) -> usize {
    let index_bytes = if d == 1 { 4 } else { h.div_ceil(8) };
    let wots_len = 2 * n + 3;
    let wots_sig_bytes = wots_len * n;
    index_bytes + n + d * wots_sig_bytes + h * n
}

const fn xmss_seed_len(n: usize) -> usize {
    3 * n
}

macro_rules! define_xmss_parameter {
    ($name:ident, $str_name:expr, $oid:expr, N = $n_type:ty, IDX = $idx_type:ty, n = $n:expr, h = $h:expr, d = $d:expr) => {
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        #[allow(non_camel_case_types)]
        #[doc = concat!("Parameter set for `", $str_name, "`.")]
        pub struct $name;

        #[allow(private_interfaces)]
        impl XmssParameter for $name {
            type N = $n_type;
            type Hash = Self;
            type SkLen = TSum<TSum<U4, $idx_type>, TProd<$n_type, U4>>;
            type VkLen = TSum<U4, TProd<$n_type, U2>>;
            type SeedLen = TProd<$n_type, U3>;
            const NAME: &'static str = $str_name;
            const SK_LEN: usize = xmss_sk_len($n, $h, $d);
            const VK_LEN: usize = xmss_vk_len($n);
            const SIG_LEN: usize = xmss_sig_len($n, $h, $d);
            const SEED_LEN: usize = xmss_seed_len($n);
            const OID: u32 = $oid.raw_oid();
            const IS_XMSS: bool = $d == 1;

            #[allow(clippy::unwrap_used)]
            fn xmss_params() -> XmssParams {
                let mut params = XmssParams::default();
                $oid.initialize(&mut params).unwrap();
                params.hash = fixed_digest_into::<Self>;
                params
            }
        }

        impl FixedDigest for $name {
            type OutputSize = $n_type;

            fn digest(input: &[u8]) -> XmssResult<hybrid_array::Array<u8, Self::OutputSize>> {
                fixed_digest::<Self::OutputSize>($oid.hash_function(), input)
            }
        }
    };
}

// ---- XMSS single-tree parameter sets (d = 1) ----
define_xmss_parameter!(
    XmssSha2_10_256,
    "XMSS-SHA2_10_256",
    XmssOid::XmssSha2_10_256,
    N = U32,
    IDX = U4,
    n = 32,
    h = 10,
    d = 1
);
define_xmss_parameter!(
    XmssSha2_16_256,
    "XMSS-SHA2_16_256",
    XmssOid::XmssSha2_16_256,
    N = U32,
    IDX = U4,
    n = 32,
    h = 16,
    d = 1
);
define_xmss_parameter!(
    XmssSha2_20_256,
    "XMSS-SHA2_20_256",
    XmssOid::XmssSha2_20_256,
    N = U32,
    IDX = U4,
    n = 32,
    h = 20,
    d = 1
);
define_xmss_parameter!(
    XmssSha2_10_512,
    "XMSS-SHA2_10_512",
    XmssOid::XmssSha2_10_512,
    N = U64,
    IDX = U4,
    n = 64,
    h = 10,
    d = 1
);
define_xmss_parameter!(
    XmssSha2_16_512,
    "XMSS-SHA2_16_512",
    XmssOid::XmssSha2_16_512,
    N = U64,
    IDX = U4,
    n = 64,
    h = 16,
    d = 1
);
define_xmss_parameter!(
    XmssSha2_20_512,
    "XMSS-SHA2_20_512",
    XmssOid::XmssSha2_20_512,
    N = U64,
    IDX = U4,
    n = 64,
    h = 20,
    d = 1
);
define_xmss_parameter!(
    XmssShake_10_256,
    "XMSS-SHAKE_10_256",
    XmssOid::XmssShake_10_256,
    N = U32,
    IDX = U4,
    n = 32,
    h = 10,
    d = 1
);
define_xmss_parameter!(
    XmssShake_16_256,
    "XMSS-SHAKE_16_256",
    XmssOid::XmssShake_16_256,
    N = U32,
    IDX = U4,
    n = 32,
    h = 16,
    d = 1
);
define_xmss_parameter!(
    XmssShake_20_256,
    "XMSS-SHAKE_20_256",
    XmssOid::XmssShake_20_256,
    N = U32,
    IDX = U4,
    n = 32,
    h = 20,
    d = 1
);
define_xmss_parameter!(
    XmssShake_10_512,
    "XMSS-SHAKE_10_512",
    XmssOid::XmssShake_10_512,
    N = U64,
    IDX = U4,
    n = 64,
    h = 10,
    d = 1
);
define_xmss_parameter!(
    XmssShake_16_512,
    "XMSS-SHAKE_16_512",
    XmssOid::XmssShake_16_512,
    N = U64,
    IDX = U4,
    n = 64,
    h = 16,
    d = 1
);
define_xmss_parameter!(
    XmssShake_20_512,
    "XMSS-SHAKE_20_512",
    XmssOid::XmssShake_20_512,
    N = U64,
    IDX = U4,
    n = 64,
    h = 20,
    d = 1
);
define_xmss_parameter!(
    XmssSha2_10_192,
    "XMSS-SHA2_10_192",
    XmssOid::XmssSha2_10_192,
    N = U24,
    IDX = U4,
    n = 24,
    h = 10,
    d = 1
);
define_xmss_parameter!(
    XmssSha2_16_192,
    "XMSS-SHA2_16_192",
    XmssOid::XmssSha2_16_192,
    N = U24,
    IDX = U4,
    n = 24,
    h = 16,
    d = 1
);
define_xmss_parameter!(
    XmssSha2_20_192,
    "XMSS-SHA2_20_192",
    XmssOid::XmssSha2_20_192,
    N = U24,
    IDX = U4,
    n = 24,
    h = 20,
    d = 1
);
define_xmss_parameter!(
    XmssShake256_10_256,
    "XMSS-SHAKE256_10_256",
    XmssOid::XmssShake256_10_256,
    N = U32,
    IDX = U4,
    n = 32,
    h = 10,
    d = 1
);
define_xmss_parameter!(
    XmssShake256_16_256,
    "XMSS-SHAKE256_16_256",
    XmssOid::XmssShake256_16_256,
    N = U32,
    IDX = U4,
    n = 32,
    h = 16,
    d = 1
);
define_xmss_parameter!(
    XmssShake256_20_256,
    "XMSS-SHAKE256_20_256",
    XmssOid::XmssShake256_20_256,
    N = U32,
    IDX = U4,
    n = 32,
    h = 20,
    d = 1
);
define_xmss_parameter!(
    XmssShake256_10_192,
    "XMSS-SHAKE256_10_192",
    XmssOid::XmssShake256_10_192,
    N = U24,
    IDX = U4,
    n = 24,
    h = 10,
    d = 1
);
define_xmss_parameter!(
    XmssShake256_16_192,
    "XMSS-SHAKE256_16_192",
    XmssOid::XmssShake256_16_192,
    N = U24,
    IDX = U4,
    n = 24,
    h = 16,
    d = 1
);
define_xmss_parameter!(
    XmssShake256_20_192,
    "XMSS-SHAKE256_20_192",
    XmssOid::XmssShake256_20_192,
    N = U24,
    IDX = U4,
    n = 24,
    h = 20,
    d = 1
);

// ---- Non-standard XMSS single-tree depths ----

/// A curated non-standard XMSS tree depth.
///
/// Implementations of this sealed trait are available only with the
/// `extra-depths` feature. The selected height supports `2^HEIGHT` signatures.
#[cfg(feature = "extra-depths")]
pub trait XmssTreeDepth:
    extra_depth_sealed::Sealed + Clone + fmt::Debug + Default + PartialEq + Eq + 'static
{
    /// Merkle tree height.
    const HEIGHT: u32;
    /// Maximum number of signatures that a key pair can produce.
    const MAX_SIGNATURES: u32 = 1 << Self::HEIGHT;
}

#[cfg(feature = "extra-depths")]
mod extra_depth_sealed {
    pub trait Sealed {}
}

#[cfg(feature = "extra-depths")]
macro_rules! define_extra_depths {
    ($($(#[$doc:meta])* $name:ident = $height:literal),+ $(,)?) => {
        $(
            $(#[$doc])*
            #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
            pub struct $name;

            impl extra_depth_sealed::Sealed for $name {}

            impl XmssTreeDepth for $name {
                const HEIGHT: u32 = $height;
            }
        )+
    };
}

#[cfg(feature = "extra-depths")]
define_extra_depths!(
    /// Height 1: 2 signatures per key pair.
    H1 = 1,
    /// Height 2: 4 signatures per key pair.
    H2 = 2,
    /// Height 3: 8 signatures per key pair.
    H3 = 3,
    /// Height 4: 16 signatures per key pair.
    H4 = 4,
    /// Height 5: 32 signatures per key pair.
    H5 = 5,
    /// Height 6: 64 signatures per key pair.
    H6 = 6,
    /// Height 7: 128 signatures per key pair.
    H7 = 7,
    /// Height 8: 256 signatures per key pair.
    H8 = 8,
    /// Height 9: 512 signatures per key pair.
    H9 = 9,
    /// Height 11: 2,048 signatures per key pair.
    H11 = 11,
    /// Height 12: 4,096 signatures per key pair.
    H12 = 12,
    /// Height 13: 8,192 signatures per key pair.
    H13 = 13,
    /// Height 14: 16,384 signatures per key pair.
    H14 = 14,
    /// Height 15: 32,768 signatures per key pair.
    H15 = 15,
    /// Height 17: 131,072 signatures per key pair.
    H17 = 17,
    /// Height 18: 262,144 signatures per key pair.
    H18 = 18,
    /// Height 19: 524,288 signatures per key pair.
    H19 = 19,
    /// Height 21: 2,097,152 signatures per key pair.
    H21 = 21,
    /// Height 22: 4,194,304 signatures per key pair.
    H22 = 22,
    /// Height 23: 8,388,608 signatures per key pair.
    H23 = 23,
    /// Height 24: 16,777,216 signatures per key pair.
    H24 = 24,
);

/// Private-use prefix for non-standard single-tree parameter identifiers.
///
/// Layout: `0xff | family | 0x00 | height`. These values deliberately cannot
/// be mistaken for an RFC 8391 or NIST SP 800-208 parameter-set identifier.
#[cfg(feature = "extra-depths")]
const EXTRA_DEPTH_OID_PREFIX: u32 = 0xff00_0000;

#[cfg(feature = "extra-depths")]
const fn extra_depth_oid(family: u32, height: u32) -> u32 {
    EXTRA_DEPTH_OID_PREFIX | (family << 16) | height
}

#[cfg(feature = "extra-depths")]
fn extra_xmss_params(
    func: u32,
    n: u32,
    padding_len: u32,
    height: u32,
    hash: CoreHash,
) -> XmssParams {
    let wots_len = 2 * n + 3;
    XmssParams {
        hash,
        func,
        n,
        padding_len,
        wots_w: 16,
        wots_log_w: 4,
        wots_len1: 2 * n,
        wots_len2: 3,
        wots_len,
        wots_sig_bytes: wots_len * n,
        full_height: height,
        tree_height: height,
        d: 1,
        index_bytes: 4,
        sig_bytes: 4 + n + wots_len * n + height * n,
        pk_bytes: 2 * n,
        sk_bytes: (4 + 4 * n) as usize,
        bds_k: 0,
    }
}

#[cfg(feature = "extra-depths")]
macro_rules! define_extra_xmss_family {
    ($name:ident, $display:literal, $family:literal, $func:expr, $n_type:ty, $n:literal, $padding:literal) => {
        #[doc = concat!("Non-standard ", $display, " XMSS parameter set with a curated tree depth.")]
        #[doc = ""]
        #[doc = concat!("Combine `", stringify!($name), "` with one of the 21 types implementing [`XmssTreeDepth`].")]
        #[doc = "See the crate-level **Extra tree depths** guide for the complete list and examples."]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        #[allow(non_camel_case_types)]
        pub struct $name<D: XmssTreeDepth>(PhantomData<D>);

        #[allow(private_interfaces)]
        impl<D: XmssTreeDepth> XmssParameter for $name<D> {
            type N = $n_type;
            type Hash = Self;
            type SkLen = TSum<TSum<U4, U4>, TProd<$n_type, U4>>;
            type VkLen = TSum<U4, TProd<$n_type, U2>>;
            type SeedLen = TProd<$n_type, U3>;

            const NAME: &'static str = concat!($display, " with extra depth");
            const SK_LEN: usize = xmss_sk_len($n, D::HEIGHT as usize, 1);
            const VK_LEN: usize = xmss_vk_len($n);
            const SIG_LEN: usize = xmss_sig_len($n, D::HEIGHT as usize, 1);
            const SEED_LEN: usize = xmss_seed_len($n);
            const OID: u32 = extra_depth_oid($family, D::HEIGHT);
            const IS_XMSS: bool = true;

            fn xmss_params() -> XmssParams {
                extra_xmss_params(
                    $func,
                    $n,
                    $padding,
                    D::HEIGHT,
                    fixed_digest_into::<Self>,
                )
            }
        }

        impl<D: XmssTreeDepth> FixedDigest for $name<D> {
            type OutputSize = $n_type;

            fn digest(input: &[u8]) -> XmssResult<hybrid_array::Array<u8, Self::OutputSize>> {
                fixed_digest::<Self::OutputSize>($func, input)
            }
        }
    };
}

#[cfg(feature = "extra-depths")]
define_extra_xmss_family!(XmssSha2_256, "XMSS-SHA2-256", 1, XMSS_SHA2, U32, 32, 32);
#[cfg(feature = "extra-depths")]
define_extra_xmss_family!(XmssSha2_512, "XMSS-SHA2-512", 2, XMSS_SHA2, U64, 64, 64);
#[cfg(feature = "extra-depths")]
define_extra_xmss_family!(
    XmssShake_256,
    "XMSS-SHAKE-256",
    3,
    XMSS_SHAKE128,
    U32,
    32,
    32
);
#[cfg(feature = "extra-depths")]
define_extra_xmss_family!(
    XmssShake_512,
    "XMSS-SHAKE-512",
    4,
    XMSS_SHAKE256,
    U64,
    64,
    64
);
#[cfg(feature = "extra-depths")]
define_extra_xmss_family!(XmssSha2_192, "XMSS-SHA2-192", 5, XMSS_SHA2, U24, 24, 4);
#[cfg(feature = "extra-depths")]
define_extra_xmss_family!(
    XmssShake256_256,
    "XMSS-SHAKE256-256",
    6,
    XMSS_SHAKE256,
    U32,
    32,
    32
);
#[cfg(feature = "extra-depths")]
define_extra_xmss_family!(
    XmssShake256_192,
    "XMSS-SHAKE256-192",
    7,
    XMSS_SHAKE256,
    U24,
    24,
    4
);

// ---- XMSSMT multi-tree parameter sets ----
// SHA-2, n = 32
define_xmss_parameter!(
    XmssMtSha2_20_2_256,
    "XMSSMT-SHA2_20/2_256",
    XmssOid::XmssMtSha2_20_2_256,
    N = U32,
    IDX = U3,
    n = 32,
    h = 20,
    d = 2
);
define_xmss_parameter!(
    XmssMtSha2_20_4_256,
    "XMSSMT-SHA2_20/4_256",
    XmssOid::XmssMtSha2_20_4_256,
    N = U32,
    IDX = U3,
    n = 32,
    h = 20,
    d = 4
);
define_xmss_parameter!(
    XmssMtSha2_40_2_256,
    "XMSSMT-SHA2_40/2_256",
    XmssOid::XmssMtSha2_40_2_256,
    N = U32,
    IDX = U5,
    n = 32,
    h = 40,
    d = 2
);
define_xmss_parameter!(
    XmssMtSha2_40_4_256,
    "XMSSMT-SHA2_40/4_256",
    XmssOid::XmssMtSha2_40_4_256,
    N = U32,
    IDX = U5,
    n = 32,
    h = 40,
    d = 4
);
define_xmss_parameter!(
    XmssMtSha2_40_8_256,
    "XMSSMT-SHA2_40/8_256",
    XmssOid::XmssMtSha2_40_8_256,
    N = U32,
    IDX = U5,
    n = 32,
    h = 40,
    d = 8
);
define_xmss_parameter!(
    XmssMtSha2_60_3_256,
    "XMSSMT-SHA2_60/3_256",
    XmssOid::XmssMtSha2_60_3_256,
    N = U32,
    IDX = U8,
    n = 32,
    h = 60,
    d = 3
);
define_xmss_parameter!(
    XmssMtSha2_60_6_256,
    "XMSSMT-SHA2_60/6_256",
    XmssOid::XmssMtSha2_60_6_256,
    N = U32,
    IDX = U8,
    n = 32,
    h = 60,
    d = 6
);
define_xmss_parameter!(
    XmssMtSha2_60_12_256,
    "XMSSMT-SHA2_60/12_256",
    XmssOid::XmssMtSha2_60_12_256,
    N = U32,
    IDX = U8,
    n = 32,
    h = 60,
    d = 12
);
// SHA-2, n = 64
define_xmss_parameter!(
    XmssMtSha2_20_2_512,
    "XMSSMT-SHA2_20/2_512",
    XmssOid::XmssMtSha2_20_2_512,
    N = U64,
    IDX = U3,
    n = 64,
    h = 20,
    d = 2
);
define_xmss_parameter!(
    XmssMtSha2_20_4_512,
    "XMSSMT-SHA2_20/4_512",
    XmssOid::XmssMtSha2_20_4_512,
    N = U64,
    IDX = U3,
    n = 64,
    h = 20,
    d = 4
);
define_xmss_parameter!(
    XmssMtSha2_40_2_512,
    "XMSSMT-SHA2_40/2_512",
    XmssOid::XmssMtSha2_40_2_512,
    N = U64,
    IDX = U5,
    n = 64,
    h = 40,
    d = 2
);
define_xmss_parameter!(
    XmssMtSha2_40_4_512,
    "XMSSMT-SHA2_40/4_512",
    XmssOid::XmssMtSha2_40_4_512,
    N = U64,
    IDX = U5,
    n = 64,
    h = 40,
    d = 4
);
define_xmss_parameter!(
    XmssMtSha2_40_8_512,
    "XMSSMT-SHA2_40/8_512",
    XmssOid::XmssMtSha2_40_8_512,
    N = U64,
    IDX = U5,
    n = 64,
    h = 40,
    d = 8
);
define_xmss_parameter!(
    XmssMtSha2_60_3_512,
    "XMSSMT-SHA2_60/3_512",
    XmssOid::XmssMtSha2_60_3_512,
    N = U64,
    IDX = U8,
    n = 64,
    h = 60,
    d = 3
);
define_xmss_parameter!(
    XmssMtSha2_60_6_512,
    "XMSSMT-SHA2_60/6_512",
    XmssOid::XmssMtSha2_60_6_512,
    N = U64,
    IDX = U8,
    n = 64,
    h = 60,
    d = 6
);
define_xmss_parameter!(
    XmssMtSha2_60_12_512,
    "XMSSMT-SHA2_60/12_512",
    XmssOid::XmssMtSha2_60_12_512,
    N = U64,
    IDX = U8,
    n = 64,
    h = 60,
    d = 12
);
// SHAKE, n = 32
define_xmss_parameter!(
    XmssMtShake_20_2_256,
    "XMSSMT-SHAKE_20/2_256",
    XmssOid::XmssMtShake_20_2_256,
    N = U32,
    IDX = U3,
    n = 32,
    h = 20,
    d = 2
);
define_xmss_parameter!(
    XmssMtShake_20_4_256,
    "XMSSMT-SHAKE_20/4_256",
    XmssOid::XmssMtShake_20_4_256,
    N = U32,
    IDX = U3,
    n = 32,
    h = 20,
    d = 4
);
define_xmss_parameter!(
    XmssMtShake_40_2_256,
    "XMSSMT-SHAKE_40/2_256",
    XmssOid::XmssMtShake_40_2_256,
    N = U32,
    IDX = U5,
    n = 32,
    h = 40,
    d = 2
);
define_xmss_parameter!(
    XmssMtShake_40_4_256,
    "XMSSMT-SHAKE_40/4_256",
    XmssOid::XmssMtShake_40_4_256,
    N = U32,
    IDX = U5,
    n = 32,
    h = 40,
    d = 4
);
define_xmss_parameter!(
    XmssMtShake_40_8_256,
    "XMSSMT-SHAKE_40/8_256",
    XmssOid::XmssMtShake_40_8_256,
    N = U32,
    IDX = U5,
    n = 32,
    h = 40,
    d = 8
);
define_xmss_parameter!(
    XmssMtShake_60_3_256,
    "XMSSMT-SHAKE_60/3_256",
    XmssOid::XmssMtShake_60_3_256,
    N = U32,
    IDX = U8,
    n = 32,
    h = 60,
    d = 3
);
define_xmss_parameter!(
    XmssMtShake_60_6_256,
    "XMSSMT-SHAKE_60/6_256",
    XmssOid::XmssMtShake_60_6_256,
    N = U32,
    IDX = U8,
    n = 32,
    h = 60,
    d = 6
);
define_xmss_parameter!(
    XmssMtShake_60_12_256,
    "XMSSMT-SHAKE_60/12_256",
    XmssOid::XmssMtShake_60_12_256,
    N = U32,
    IDX = U8,
    n = 32,
    h = 60,
    d = 12
);
// SHAKE, n = 64
define_xmss_parameter!(
    XmssMtShake_20_2_512,
    "XMSSMT-SHAKE_20/2_512",
    XmssOid::XmssMtShake_20_2_512,
    N = U64,
    IDX = U3,
    n = 64,
    h = 20,
    d = 2
);
define_xmss_parameter!(
    XmssMtShake_20_4_512,
    "XMSSMT-SHAKE_20/4_512",
    XmssOid::XmssMtShake_20_4_512,
    N = U64,
    IDX = U3,
    n = 64,
    h = 20,
    d = 4
);
define_xmss_parameter!(
    XmssMtShake_40_2_512,
    "XMSSMT-SHAKE_40/2_512",
    XmssOid::XmssMtShake_40_2_512,
    N = U64,
    IDX = U5,
    n = 64,
    h = 40,
    d = 2
);
define_xmss_parameter!(
    XmssMtShake_40_4_512,
    "XMSSMT-SHAKE_40/4_512",
    XmssOid::XmssMtShake_40_4_512,
    N = U64,
    IDX = U5,
    n = 64,
    h = 40,
    d = 4
);
define_xmss_parameter!(
    XmssMtShake_40_8_512,
    "XMSSMT-SHAKE_40/8_512",
    XmssOid::XmssMtShake_40_8_512,
    N = U64,
    IDX = U5,
    n = 64,
    h = 40,
    d = 8
);
define_xmss_parameter!(
    XmssMtShake_60_3_512,
    "XMSSMT-SHAKE_60/3_512",
    XmssOid::XmssMtShake_60_3_512,
    N = U64,
    IDX = U8,
    n = 64,
    h = 60,
    d = 3
);
define_xmss_parameter!(
    XmssMtShake_60_6_512,
    "XMSSMT-SHAKE_60/6_512",
    XmssOid::XmssMtShake_60_6_512,
    N = U64,
    IDX = U8,
    n = 64,
    h = 60,
    d = 6
);
define_xmss_parameter!(
    XmssMtShake_60_12_512,
    "XMSSMT-SHAKE_60/12_512",
    XmssOid::XmssMtShake_60_12_512,
    N = U64,
    IDX = U8,
    n = 64,
    h = 60,
    d = 12
);
// SHA-2, n = 24
define_xmss_parameter!(
    XmssMtSha2_20_2_192,
    "XMSSMT-SHA2_20/2_192",
    XmssOid::XmssMtSha2_20_2_192,
    N = U24,
    IDX = U3,
    n = 24,
    h = 20,
    d = 2
);
define_xmss_parameter!(
    XmssMtSha2_20_4_192,
    "XMSSMT-SHA2_20/4_192",
    XmssOid::XmssMtSha2_20_4_192,
    N = U24,
    IDX = U3,
    n = 24,
    h = 20,
    d = 4
);
define_xmss_parameter!(
    XmssMtSha2_40_2_192,
    "XMSSMT-SHA2_40/2_192",
    XmssOid::XmssMtSha2_40_2_192,
    N = U24,
    IDX = U5,
    n = 24,
    h = 40,
    d = 2
);
define_xmss_parameter!(
    XmssMtSha2_40_4_192,
    "XMSSMT-SHA2_40/4_192",
    XmssOid::XmssMtSha2_40_4_192,
    N = U24,
    IDX = U5,
    n = 24,
    h = 40,
    d = 4
);
define_xmss_parameter!(
    XmssMtSha2_40_8_192,
    "XMSSMT-SHA2_40/8_192",
    XmssOid::XmssMtSha2_40_8_192,
    N = U24,
    IDX = U5,
    n = 24,
    h = 40,
    d = 8
);
define_xmss_parameter!(
    XmssMtSha2_60_3_192,
    "XMSSMT-SHA2_60/3_192",
    XmssOid::XmssMtSha2_60_3_192,
    N = U24,
    IDX = U8,
    n = 24,
    h = 60,
    d = 3
);
define_xmss_parameter!(
    XmssMtSha2_60_6_192,
    "XMSSMT-SHA2_60/6_192",
    XmssOid::XmssMtSha2_60_6_192,
    N = U24,
    IDX = U8,
    n = 24,
    h = 60,
    d = 6
);
define_xmss_parameter!(
    XmssMtSha2_60_12_192,
    "XMSSMT-SHA2_60/12_192",
    XmssOid::XmssMtSha2_60_12_192,
    N = U24,
    IDX = U8,
    n = 24,
    h = 60,
    d = 12
);
// SHAKE256, n = 32
define_xmss_parameter!(
    XmssMtShake256_20_2_256,
    "XMSSMT-SHAKE256_20/2_256",
    XmssOid::XmssMtShake256_20_2_256,
    N = U32,
    IDX = U3,
    n = 32,
    h = 20,
    d = 2
);
define_xmss_parameter!(
    XmssMtShake256_20_4_256,
    "XMSSMT-SHAKE256_20/4_256",
    XmssOid::XmssMtShake256_20_4_256,
    N = U32,
    IDX = U3,
    n = 32,
    h = 20,
    d = 4
);
define_xmss_parameter!(
    XmssMtShake256_40_2_256,
    "XMSSMT-SHAKE256_40/2_256",
    XmssOid::XmssMtShake256_40_2_256,
    N = U32,
    IDX = U5,
    n = 32,
    h = 40,
    d = 2
);
define_xmss_parameter!(
    XmssMtShake256_40_4_256,
    "XMSSMT-SHAKE256_40/4_256",
    XmssOid::XmssMtShake256_40_4_256,
    N = U32,
    IDX = U5,
    n = 32,
    h = 40,
    d = 4
);
define_xmss_parameter!(
    XmssMtShake256_40_8_256,
    "XMSSMT-SHAKE256_40/8_256",
    XmssOid::XmssMtShake256_40_8_256,
    N = U32,
    IDX = U5,
    n = 32,
    h = 40,
    d = 8
);
define_xmss_parameter!(
    XmssMtShake256_60_3_256,
    "XMSSMT-SHAKE256_60/3_256",
    XmssOid::XmssMtShake256_60_3_256,
    N = U32,
    IDX = U8,
    n = 32,
    h = 60,
    d = 3
);
define_xmss_parameter!(
    XmssMtShake256_60_6_256,
    "XMSSMT-SHAKE256_60/6_256",
    XmssOid::XmssMtShake256_60_6_256,
    N = U32,
    IDX = U8,
    n = 32,
    h = 60,
    d = 6
);
define_xmss_parameter!(
    XmssMtShake256_60_12_256,
    "XMSSMT-SHAKE256_60/12_256",
    XmssOid::XmssMtShake256_60_12_256,
    N = U32,
    IDX = U8,
    n = 32,
    h = 60,
    d = 12
);
// SHAKE256, n = 24
define_xmss_parameter!(
    XmssMtShake256_20_2_192,
    "XMSSMT-SHAKE256_20/2_192",
    XmssOid::XmssMtShake256_20_2_192,
    N = U24,
    IDX = U3,
    n = 24,
    h = 20,
    d = 2
);
define_xmss_parameter!(
    XmssMtShake256_20_4_192,
    "XMSSMT-SHAKE256_20/4_192",
    XmssOid::XmssMtShake256_20_4_192,
    N = U24,
    IDX = U3,
    n = 24,
    h = 20,
    d = 4
);
define_xmss_parameter!(
    XmssMtShake256_40_2_192,
    "XMSSMT-SHAKE256_40/2_192",
    XmssOid::XmssMtShake256_40_2_192,
    N = U24,
    IDX = U5,
    n = 24,
    h = 40,
    d = 2
);
define_xmss_parameter!(
    XmssMtShake256_40_4_192,
    "XMSSMT-SHAKE256_40/4_192",
    XmssOid::XmssMtShake256_40_4_192,
    N = U24,
    IDX = U5,
    n = 24,
    h = 40,
    d = 4
);
define_xmss_parameter!(
    XmssMtShake256_40_8_192,
    "XMSSMT-SHAKE256_40/8_192",
    XmssOid::XmssMtShake256_40_8_192,
    N = U24,
    IDX = U5,
    n = 24,
    h = 40,
    d = 8
);
define_xmss_parameter!(
    XmssMtShake256_60_3_192,
    "XMSSMT-SHAKE256_60/3_192",
    XmssOid::XmssMtShake256_60_3_192,
    N = U24,
    IDX = U8,
    n = 24,
    h = 60,
    d = 3
);
define_xmss_parameter!(
    XmssMtShake256_60_6_192,
    "XMSSMT-SHAKE256_60/6_192",
    XmssOid::XmssMtShake256_60_6_192,
    N = U24,
    IDX = U8,
    n = 24,
    h = 60,
    d = 6
);
define_xmss_parameter!(
    XmssMtShake256_60_12_192,
    "XMSSMT-SHAKE256_60/12_192",
    XmssOid::XmssMtShake256_60_12_192,
    N = U24,
    IDX = U8,
    n = 24,
    h = 60,
    d = 12
);

/// Offset added to XMSSMT raw OID values to produce unique discriminants.
/// XMSS OIDs use `0x0000_XXXX`; XMSSMT OIDs use `0x0001_XXXX`.
const XMSSMT_OID_OFFSET: u32 = 0x0001_0000;

/// XMSS parameter set derived from an OID.
#[derive(Clone, Copy, Debug)]
pub(crate) struct XmssParams {
    pub(crate) hash: CoreHash,
    pub(crate) func: u32,
    pub(crate) n: u32,
    pub(crate) padding_len: u32,
    pub(crate) wots_w: u32,
    pub(crate) wots_log_w: u32,
    pub(crate) wots_len1: u32,
    pub(crate) wots_len2: u32,
    pub(crate) wots_len: u32,
    pub(crate) wots_sig_bytes: u32,
    pub(crate) full_height: u32,
    pub(crate) tree_height: u32,
    pub(crate) d: u32,
    pub(crate) index_bytes: u32,
    pub(crate) sig_bytes: u32,
    pub(crate) pk_bytes: u32,
    pub(crate) sk_bytes: usize,
    pub(crate) bds_k: u32,
}

fn invalid_core_hash(_out: &mut [u8], _input: &[u8]) -> XmssResult<()> {
    Err(Error::Hash { n: 0, func: 0 })
}

impl Default for XmssParams {
    fn default() -> Self {
        Self {
            hash: invalid_core_hash,
            func: 0,
            n: 0,
            padding_len: 0,
            wots_w: 0,
            wots_log_w: 0,
            wots_len1: 0,
            wots_len2: 0,
            wots_len: 0,
            wots_sig_bytes: 0,
            full_height: 0,
            tree_height: 0,
            d: 0,
            index_bytes: 0,
            sig_bytes: 0,
            pk_bytes: 0,
            sk_bytes: 0,
            bds_k: 0,
        }
    }
}

impl XmssParams {
    /// Returns the length of the seed required for key generation.
    pub(crate) fn get_seed_length(&self) -> usize {
        self.n as usize * 3
    }
}

/// A supported XMSS digest output size selected at runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DigestOutputSize {
    /// A 192-bit (24-byte) output.
    Bytes24,
    /// A 256-bit (32-byte) output.
    Bytes32,
    /// A 512-bit (64-byte) output.
    Bytes64,
}

impl DigestOutputSize {
    /// Returns the output size in bytes.
    pub const fn bytes(self) -> usize {
        match self {
            Self::Bytes24 => 24,
            Self::Bytes32 => 32,
            Self::Bytes64 => 64,
        }
    }
}

/// A standardized XMSS or XMSS^MT parameter set selected at runtime.
///
/// This is the runtime counterpart to the compile-time types implementing
/// [`XmssParameter`]. It accepts only parameter sets registered by RFC 8391 or
/// NIST SP 800-208. Non-standard `extra-depths` types remain compile-time only.
/// Names use the specification spelling, such as `XMSS-SHA2_10_256` or
/// `XMSSMT-SHA2_20/2_256`.
///
/// # Example
///
/// ```rust
/// use pq_xmss::{DigestOutputSize, ParameterSet};
///
/// let parameters = ParameterSet::from_name("XMSSMT-SHA2_40/8_256")?;
/// assert!(!parameters.is_xmss());
/// assert_eq!(parameters.digest_output_size(), DigestOutputSize::Bytes32);
/// assert_eq!(parameters.total_height(), 40);
/// assert_eq!(parameters.layers(), 8);
/// assert_eq!(parameters.tree_height(), 5);
/// # Ok::<(), pq_xmss::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ParameterSet(XmssOid);

impl ParameterSet {
    /// Parses a standardized parameter-set name.
    pub fn from_name(name: &str) -> XmssResult<Self> {
        name.parse()
    }

    /// Returns whether this parameter set is single-tree XMSS.
    pub const fn is_xmss(self) -> bool {
        self.0.is_xmss()
    }

    /// Returns its effective digest output size.
    pub fn digest_output_size(self) -> DigestOutputSize {
        match self.params().n {
            24 => DigestOutputSize::Bytes24,
            32 => DigestOutputSize::Bytes32,
            64 => DigestOutputSize::Bytes64,
            _ => DigestOutputSize::Bytes32,
        }
    }

    /// Returns the total Merkle-tree height.
    pub fn total_height(self) -> u32 {
        self.params().full_height
    }

    /// Returns the number of XMSS layers.
    pub fn layers(self) -> u32 {
        self.params().d
    }

    /// Returns the height of each XMSS tree.
    pub fn tree_height(self) -> u32 {
        self.params().tree_height
    }

    /// Returns the detached-signature length in bytes.
    pub fn signature_len(self) -> usize {
        self.params().sig_bytes as usize
    }

    pub(crate) fn params(self) -> XmssParams {
        let mut params = XmssParams::default();
        // `ParameterSet` can only contain a registered `XmssOid`.
        if self.0.initialize(&mut params).is_err() {
            return XmssParams::default();
        }
        params
    }

    pub(crate) const fn raw_oid(self) -> u32 {
        self.0.raw_oid()
    }
}

impl FromStr for ParameterSet {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        XmssOid::from_str(name).map(Self)
    }
}

impl fmt::Display for ParameterSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// All supported XMSS and XMSSMT parameter set OIDs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u32)]
#[allow(non_camel_case_types, missing_docs)]
pub(crate) enum XmssOid {
    // ---- XMSS (single-tree, d = 1) ----
    XmssSha2_10_256 = 0x0000_0001,
    XmssSha2_16_256 = 0x0000_0002,
    XmssSha2_20_256 = 0x0000_0003,
    XmssSha2_10_512 = 0x0000_0004,
    XmssSha2_16_512 = 0x0000_0005,
    XmssSha2_20_512 = 0x0000_0006,
    XmssShake_10_256 = 0x0000_0007,
    #[default]
    XmssShake_16_256 = 0x0000_0008,
    XmssShake_20_256 = 0x0000_0009,
    XmssShake_10_512 = 0x0000_000a,
    XmssShake_16_512 = 0x0000_000b,
    XmssShake_20_512 = 0x0000_000c,
    XmssSha2_10_192 = 0x0000_000d,
    XmssSha2_16_192 = 0x0000_000e,
    XmssSha2_20_192 = 0x0000_000f,
    XmssShake256_10_256 = 0x0000_0010,
    XmssShake256_16_256 = 0x0000_0011,
    XmssShake256_20_256 = 0x0000_0012,
    XmssShake256_10_192 = 0x0000_0013,
    XmssShake256_16_192 = 0x0000_0014,
    XmssShake256_20_192 = 0x0000_0015,

    // ---- XMSSMT (multi-tree, d > 1) ----
    XmssMtSha2_20_2_256 = XMSSMT_OID_OFFSET | 0x01,
    XmssMtSha2_20_4_256 = XMSSMT_OID_OFFSET | 0x02,
    XmssMtSha2_40_2_256 = XMSSMT_OID_OFFSET | 0x03,
    XmssMtSha2_40_4_256 = XMSSMT_OID_OFFSET | 0x04,
    XmssMtSha2_40_8_256 = XMSSMT_OID_OFFSET | 0x05,
    XmssMtSha2_60_3_256 = XMSSMT_OID_OFFSET | 0x06,
    XmssMtSha2_60_6_256 = XMSSMT_OID_OFFSET | 0x07,
    XmssMtSha2_60_12_256 = XMSSMT_OID_OFFSET | 0x08,
    XmssMtSha2_20_2_512 = XMSSMT_OID_OFFSET | 0x09,
    XmssMtSha2_20_4_512 = XMSSMT_OID_OFFSET | 0x0a,
    XmssMtSha2_40_2_512 = XMSSMT_OID_OFFSET | 0x0b,
    XmssMtSha2_40_4_512 = XMSSMT_OID_OFFSET | 0x0c,
    XmssMtSha2_40_8_512 = XMSSMT_OID_OFFSET | 0x0d,
    XmssMtSha2_60_3_512 = XMSSMT_OID_OFFSET | 0x0e,
    XmssMtSha2_60_6_512 = XMSSMT_OID_OFFSET | 0x0f,
    XmssMtSha2_60_12_512 = XMSSMT_OID_OFFSET | 0x10,
    XmssMtShake_20_2_256 = XMSSMT_OID_OFFSET | 0x11,
    XmssMtShake_20_4_256 = XMSSMT_OID_OFFSET | 0x12,
    XmssMtShake_40_2_256 = XMSSMT_OID_OFFSET | 0x13,
    XmssMtShake_40_4_256 = XMSSMT_OID_OFFSET | 0x14,
    XmssMtShake_40_8_256 = XMSSMT_OID_OFFSET | 0x15,
    XmssMtShake_60_3_256 = XMSSMT_OID_OFFSET | 0x16,
    XmssMtShake_60_6_256 = XMSSMT_OID_OFFSET | 0x17,
    XmssMtShake_60_12_256 = XMSSMT_OID_OFFSET | 0x18,
    XmssMtShake_20_2_512 = XMSSMT_OID_OFFSET | 0x19,
    XmssMtShake_20_4_512 = XMSSMT_OID_OFFSET | 0x1a,
    XmssMtShake_40_2_512 = XMSSMT_OID_OFFSET | 0x1b,
    XmssMtShake_40_4_512 = XMSSMT_OID_OFFSET | 0x1c,
    XmssMtShake_40_8_512 = XMSSMT_OID_OFFSET | 0x1d,
    XmssMtShake_60_3_512 = XMSSMT_OID_OFFSET | 0x1e,
    XmssMtShake_60_6_512 = XMSSMT_OID_OFFSET | 0x1f,
    XmssMtShake_60_12_512 = XMSSMT_OID_OFFSET | 0x20,
    XmssMtSha2_20_2_192 = XMSSMT_OID_OFFSET | 0x21,
    XmssMtSha2_20_4_192 = XMSSMT_OID_OFFSET | 0x22,
    XmssMtSha2_40_2_192 = XMSSMT_OID_OFFSET | 0x23,
    XmssMtSha2_40_4_192 = XMSSMT_OID_OFFSET | 0x24,
    XmssMtSha2_40_8_192 = XMSSMT_OID_OFFSET | 0x25,
    XmssMtSha2_60_3_192 = XMSSMT_OID_OFFSET | 0x26,
    XmssMtSha2_60_6_192 = XMSSMT_OID_OFFSET | 0x27,
    XmssMtSha2_60_12_192 = XMSSMT_OID_OFFSET | 0x28,
    XmssMtShake256_20_2_256 = XMSSMT_OID_OFFSET | 0x29,
    XmssMtShake256_20_4_256 = XMSSMT_OID_OFFSET | 0x2a,
    XmssMtShake256_40_2_256 = XMSSMT_OID_OFFSET | 0x2b,
    XmssMtShake256_40_4_256 = XMSSMT_OID_OFFSET | 0x2c,
    XmssMtShake256_40_8_256 = XMSSMT_OID_OFFSET | 0x2d,
    XmssMtShake256_60_3_256 = XMSSMT_OID_OFFSET | 0x2e,
    XmssMtShake256_60_6_256 = XMSSMT_OID_OFFSET | 0x2f,
    XmssMtShake256_60_12_256 = XMSSMT_OID_OFFSET | 0x30,
    XmssMtShake256_20_2_192 = XMSSMT_OID_OFFSET | 0x31,
    XmssMtShake256_20_4_192 = XMSSMT_OID_OFFSET | 0x32,
    XmssMtShake256_40_2_192 = XMSSMT_OID_OFFSET | 0x33,
    XmssMtShake256_40_4_192 = XMSSMT_OID_OFFSET | 0x34,
    XmssMtShake256_40_8_192 = XMSSMT_OID_OFFSET | 0x35,
    XmssMtShake256_60_3_192 = XMSSMT_OID_OFFSET | 0x36,
    XmssMtShake256_60_6_192 = XMSSMT_OID_OFFSET | 0x37,
    XmssMtShake256_60_12_192 = XMSSMT_OID_OFFSET | 0x38,
}

impl XmssOid {
    const fn hash_function(self) -> u32 {
        let raw = self.raw_oid();
        if self.is_xmss() {
            match raw {
                0x01..=0x06 | 0x0d..=0x0f => XMSS_SHA2,
                0x07..=0x09 => XMSS_SHAKE128,
                0x0a..=0x0c | 0x10..=0x15 => XMSS_SHAKE256,
                _ => u32::MAX,
            }
        } else {
            match raw {
                0x01..=0x10 | 0x21..=0x28 => XMSS_SHA2,
                0x11..=0x18 => XMSS_SHAKE128,
                0x19..=0x20 | 0x29..=0x38 => XMSS_SHAKE256,
                _ => u32::MAX,
            }
        }
    }

    /// Returns `true` if this is an XMSS (single-tree) parameter set.
    pub(crate) const fn is_xmss(self) -> bool {
        (self as u32) < XMSSMT_OID_OFFSET
    }

    /// Returns the raw OID value used in the serialized key format.
    pub(crate) const fn raw_oid(self) -> u32 {
        let v = self as u32;
        if v >= XMSSMT_OID_OFFSET {
            v - XMSSMT_OID_OFFSET
        } else {
            v
        }
    }

    /// Initializes the given `XmssParams` structure with all parameters
    /// derived from this OID.
    pub(crate) fn initialize(&self, params: &mut XmssParams) -> XmssResult<()> {
        let raw = self.raw_oid();

        if self.is_xmss() {
            params.func = match raw {
                0x01..=0x06 | 0x0d..=0x0f => XMSS_SHA2,
                0x07..=0x09 => XMSS_SHAKE128,
                0x0a..=0x0c | 0x10..=0x15 => XMSS_SHAKE256,
                _ => return Err(Error::InvalidOid(raw)),
            };

            match raw {
                0x0d..=0x0f | 0x13..=0x15 => {
                    params.n = 24;
                    params.padding_len = 4;
                }
                0x01..=0x03 | 0x07..=0x09 | 0x10..=0x12 => {
                    params.n = 32;
                    params.padding_len = 32;
                }
                0x04..=0x06 | 0x0a..=0x0c => {
                    params.n = 64;
                    params.padding_len = 64;
                }
                _ => return Err(Error::InvalidOid(raw)),
            }

            params.full_height = match raw {
                0x01 | 0x04 | 0x07 | 0x0a | 0x0d | 0x10 | 0x13 => 10,
                0x02 | 0x05 | 0x08 | 0x0b | 0x0e | 0x11 | 0x14 => 16,
                0x03 | 0x06 | 0x09 | 0x0c | 0x0f | 0x12 | 0x15 => 20,
                _ => return Err(Error::InvalidOid(raw)),
            };

            params.d = 1;
        } else {
            params.func = match raw {
                0x01..=0x10 | 0x21..=0x28 => XMSS_SHA2,
                0x11..=0x18 => XMSS_SHAKE128,
                0x19..=0x20 | 0x29..=0x38 => XMSS_SHAKE256,
                _ => return Err(Error::InvalidOid(raw)),
            };

            match raw {
                0x21..=0x28 | 0x31..=0x38 => {
                    params.n = 24;
                    params.padding_len = 4;
                }
                0x01..=0x08 | 0x11..=0x18 | 0x29..=0x30 => {
                    params.n = 32;
                    params.padding_len = 32;
                }
                0x09..=0x10 | 0x19..=0x20 => {
                    params.n = 64;
                    params.padding_len = 64;
                }
                _ => return Err(Error::InvalidOid(raw)),
            }

            params.full_height = match raw {
                0x01 | 0x02 | 0x09 | 0x0a | 0x11 | 0x12 | 0x19 | 0x1a | 0x21 | 0x22 | 0x29
                | 0x2a | 0x31 | 0x32 => 20,
                0x03 | 0x04 | 0x05 | 0x0b | 0x0c | 0x0d | 0x13 | 0x14 | 0x15 | 0x1b | 0x1c
                | 0x1d | 0x23 | 0x24 | 0x25 | 0x2b | 0x2c | 0x2d | 0x33 | 0x34 | 0x35 => 40,
                0x06 | 0x07 | 0x08 | 0x0e | 0x0f | 0x10 | 0x16 | 0x17 | 0x18 | 0x1e | 0x1f
                | 0x20 | 0x26 | 0x27 | 0x28 | 0x2e | 0x2f | 0x30 | 0x36 | 0x37 | 0x38 => 60,
                _ => return Err(Error::InvalidOid(raw)),
            };

            params.d = match raw {
                0x01 | 0x03 | 0x09 | 0x0b | 0x11 | 0x13 | 0x19 | 0x1b | 0x21 | 0x23 | 0x29
                | 0x2b | 0x31 | 0x33 => 2,
                0x02 | 0x04 | 0x0a | 0x0c | 0x12 | 0x14 | 0x1a | 0x1c | 0x22 | 0x24 | 0x2a
                | 0x2c | 0x32 | 0x34 => 4,
                0x05 | 0x0d | 0x15 | 0x1d | 0x25 | 0x2d | 0x35 => 8,
                0x06 | 0x0e | 0x16 | 0x1e | 0x26 | 0x2e | 0x36 => 3,
                0x07 | 0x0f | 0x17 | 0x1f | 0x27 | 0x2f | 0x37 => 6,
                0x08 | 0x10 | 0x18 | 0x20 | 0x28 | 0x30 | 0x38 => 12,
                _ => return Err(Error::InvalidOid(raw)),
            };
        }

        params.wots_w = 16;
        params.bds_k = 0;

        // Compute derived parameters.
        params.tree_height = params.full_height / params.d;

        match params.wots_w {
            4 => {
                params.wots_log_w = 2;
                params.wots_len1 = 8 * params.n / params.wots_log_w;
                params.wots_len2 = 5;
            }
            16 => {
                params.wots_log_w = 4;
                params.wots_len1 = 8 * params.n / params.wots_log_w;
                params.wots_len2 = 3;
            }
            256 => {
                params.wots_log_w = 8;
                params.wots_len1 = 8 * params.n / params.wots_log_w;
                params.wots_len2 = 2;
            }
            _ => return Err(Error::InvalidParams(params.wots_w)),
        }

        params.wots_len = params.wots_len1 + params.wots_len2;
        params.wots_sig_bytes = params.wots_len * params.n;

        if params.d == 1 {
            params.index_bytes = 4;
        } else {
            params.index_bytes = params.full_height.div_ceil(8);
        }

        params.sig_bytes = params.index_bytes
            + params.n
            + params.d * params.wots_sig_bytes
            + params.full_height * params.n;

        params.pk_bytes = 2 * params.n;
        params.sk_bytes = xmss_xmssmt_core_sk_bytes(params);
        params.hash = runtime_digest(params.func, params.n)?;

        Ok(())
    }
}

impl TryFrom<u32> for XmssOid {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0000_0001 => Ok(Self::XmssSha2_10_256),
            0x0000_0002 => Ok(Self::XmssSha2_16_256),
            0x0000_0003 => Ok(Self::XmssSha2_20_256),
            0x0000_0004 => Ok(Self::XmssSha2_10_512),
            0x0000_0005 => Ok(Self::XmssSha2_16_512),
            0x0000_0006 => Ok(Self::XmssSha2_20_512),
            0x0000_0007 => Ok(Self::XmssShake_10_256),
            0x0000_0008 => Ok(Self::XmssShake_16_256),
            0x0000_0009 => Ok(Self::XmssShake_20_256),
            0x0000_000a => Ok(Self::XmssShake_10_512),
            0x0000_000b => Ok(Self::XmssShake_16_512),
            0x0000_000c => Ok(Self::XmssShake_20_512),
            0x0000_000d => Ok(Self::XmssSha2_10_192),
            0x0000_000e => Ok(Self::XmssSha2_16_192),
            0x0000_000f => Ok(Self::XmssSha2_20_192),
            0x0000_0010 => Ok(Self::XmssShake256_10_256),
            0x0000_0011 => Ok(Self::XmssShake256_16_256),
            0x0000_0012 => Ok(Self::XmssShake256_20_256),
            0x0000_0013 => Ok(Self::XmssShake256_10_192),
            0x0000_0014 => Ok(Self::XmssShake256_16_192),
            0x0000_0015 => Ok(Self::XmssShake256_20_192),

            v if v >= XMSSMT_OID_OFFSET => match v - XMSSMT_OID_OFFSET {
                0x01 => Ok(Self::XmssMtSha2_20_2_256),
                0x02 => Ok(Self::XmssMtSha2_20_4_256),
                0x03 => Ok(Self::XmssMtSha2_40_2_256),
                0x04 => Ok(Self::XmssMtSha2_40_4_256),
                0x05 => Ok(Self::XmssMtSha2_40_8_256),
                0x06 => Ok(Self::XmssMtSha2_60_3_256),
                0x07 => Ok(Self::XmssMtSha2_60_6_256),
                0x08 => Ok(Self::XmssMtSha2_60_12_256),
                0x09 => Ok(Self::XmssMtSha2_20_2_512),
                0x0a => Ok(Self::XmssMtSha2_20_4_512),
                0x0b => Ok(Self::XmssMtSha2_40_2_512),
                0x0c => Ok(Self::XmssMtSha2_40_4_512),
                0x0d => Ok(Self::XmssMtSha2_40_8_512),
                0x0e => Ok(Self::XmssMtSha2_60_3_512),
                0x0f => Ok(Self::XmssMtSha2_60_6_512),
                0x10 => Ok(Self::XmssMtSha2_60_12_512),
                0x11 => Ok(Self::XmssMtShake_20_2_256),
                0x12 => Ok(Self::XmssMtShake_20_4_256),
                0x13 => Ok(Self::XmssMtShake_40_2_256),
                0x14 => Ok(Self::XmssMtShake_40_4_256),
                0x15 => Ok(Self::XmssMtShake_40_8_256),
                0x16 => Ok(Self::XmssMtShake_60_3_256),
                0x17 => Ok(Self::XmssMtShake_60_6_256),
                0x18 => Ok(Self::XmssMtShake_60_12_256),
                0x19 => Ok(Self::XmssMtShake_20_2_512),
                0x1a => Ok(Self::XmssMtShake_20_4_512),
                0x1b => Ok(Self::XmssMtShake_40_2_512),
                0x1c => Ok(Self::XmssMtShake_40_4_512),
                0x1d => Ok(Self::XmssMtShake_40_8_512),
                0x1e => Ok(Self::XmssMtShake_60_3_512),
                0x1f => Ok(Self::XmssMtShake_60_6_512),
                0x20 => Ok(Self::XmssMtShake_60_12_512),
                0x21 => Ok(Self::XmssMtSha2_20_2_192),
                0x22 => Ok(Self::XmssMtSha2_20_4_192),
                0x23 => Ok(Self::XmssMtSha2_40_2_192),
                0x24 => Ok(Self::XmssMtSha2_40_4_192),
                0x25 => Ok(Self::XmssMtSha2_40_8_192),
                0x26 => Ok(Self::XmssMtSha2_60_3_192),
                0x27 => Ok(Self::XmssMtSha2_60_6_192),
                0x28 => Ok(Self::XmssMtSha2_60_12_192),
                0x29 => Ok(Self::XmssMtShake256_20_2_256),
                0x2a => Ok(Self::XmssMtShake256_20_4_256),
                0x2b => Ok(Self::XmssMtShake256_40_2_256),
                0x2c => Ok(Self::XmssMtShake256_40_4_256),
                0x2d => Ok(Self::XmssMtShake256_40_8_256),
                0x2e => Ok(Self::XmssMtShake256_60_3_256),
                0x2f => Ok(Self::XmssMtShake256_60_6_256),
                0x30 => Ok(Self::XmssMtShake256_60_12_256),
                0x31 => Ok(Self::XmssMtShake256_20_2_192),
                0x32 => Ok(Self::XmssMtShake256_20_4_192),
                0x33 => Ok(Self::XmssMtShake256_40_2_192),
                0x34 => Ok(Self::XmssMtShake256_40_4_192),
                0x35 => Ok(Self::XmssMtShake256_40_8_192),
                0x36 => Ok(Self::XmssMtShake256_60_3_192),
                0x37 => Ok(Self::XmssMtShake256_60_6_192),
                0x38 => Ok(Self::XmssMtShake256_60_12_192),
                _ => Err(Error::InvalidOid(value)),
            },

            _ => Err(Error::InvalidOid(value)),
        }
    }
}

impl FromStr for XmssOid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // XMSS
            "XMSS-SHA2_10_256" => Ok(Self::XmssSha2_10_256),
            "XMSS-SHA2_16_256" => Ok(Self::XmssSha2_16_256),
            "XMSS-SHA2_20_256" => Ok(Self::XmssSha2_20_256),
            "XMSS-SHA2_10_512" => Ok(Self::XmssSha2_10_512),
            "XMSS-SHA2_16_512" => Ok(Self::XmssSha2_16_512),
            "XMSS-SHA2_20_512" => Ok(Self::XmssSha2_20_512),
            "XMSS-SHAKE_10_256" => Ok(Self::XmssShake_10_256),
            "XMSS-SHAKE_16_256" => Ok(Self::XmssShake_16_256),
            "XMSS-SHAKE_20_256" => Ok(Self::XmssShake_20_256),
            "XMSS-SHAKE_10_512" => Ok(Self::XmssShake_10_512),
            "XMSS-SHAKE_16_512" => Ok(Self::XmssShake_16_512),
            "XMSS-SHAKE_20_512" => Ok(Self::XmssShake_20_512),
            "XMSS-SHA2_10_192" => Ok(Self::XmssSha2_10_192),
            "XMSS-SHA2_16_192" => Ok(Self::XmssSha2_16_192),
            "XMSS-SHA2_20_192" => Ok(Self::XmssSha2_20_192),
            "XMSS-SHAKE256_10_256" => Ok(Self::XmssShake256_10_256),
            "XMSS-SHAKE256_16_256" => Ok(Self::XmssShake256_16_256),
            "XMSS-SHAKE256_20_256" => Ok(Self::XmssShake256_20_256),
            "XMSS-SHAKE256_10_192" => Ok(Self::XmssShake256_10_192),
            "XMSS-SHAKE256_16_192" => Ok(Self::XmssShake256_16_192),
            "XMSS-SHAKE256_20_192" => Ok(Self::XmssShake256_20_192),
            // XMSSMT
            "XMSSMT-SHA2_20/2_256" => Ok(Self::XmssMtSha2_20_2_256),
            "XMSSMT-SHA2_20/4_256" => Ok(Self::XmssMtSha2_20_4_256),
            "XMSSMT-SHA2_40/2_256" => Ok(Self::XmssMtSha2_40_2_256),
            "XMSSMT-SHA2_40/4_256" => Ok(Self::XmssMtSha2_40_4_256),
            "XMSSMT-SHA2_40/8_256" => Ok(Self::XmssMtSha2_40_8_256),
            "XMSSMT-SHA2_60/3_256" => Ok(Self::XmssMtSha2_60_3_256),
            "XMSSMT-SHA2_60/6_256" => Ok(Self::XmssMtSha2_60_6_256),
            "XMSSMT-SHA2_60/12_256" => Ok(Self::XmssMtSha2_60_12_256),
            "XMSSMT-SHA2_20/2_512" => Ok(Self::XmssMtSha2_20_2_512),
            "XMSSMT-SHA2_20/4_512" => Ok(Self::XmssMtSha2_20_4_512),
            "XMSSMT-SHA2_40/2_512" => Ok(Self::XmssMtSha2_40_2_512),
            "XMSSMT-SHA2_40/4_512" => Ok(Self::XmssMtSha2_40_4_512),
            "XMSSMT-SHA2_40/8_512" => Ok(Self::XmssMtSha2_40_8_512),
            "XMSSMT-SHA2_60/3_512" => Ok(Self::XmssMtSha2_60_3_512),
            "XMSSMT-SHA2_60/6_512" => Ok(Self::XmssMtSha2_60_6_512),
            "XMSSMT-SHA2_60/12_512" => Ok(Self::XmssMtSha2_60_12_512),
            "XMSSMT-SHAKE_20/2_256" => Ok(Self::XmssMtShake_20_2_256),
            "XMSSMT-SHAKE_20/4_256" => Ok(Self::XmssMtShake_20_4_256),
            "XMSSMT-SHAKE_40/2_256" => Ok(Self::XmssMtShake_40_2_256),
            "XMSSMT-SHAKE_40/4_256" => Ok(Self::XmssMtShake_40_4_256),
            "XMSSMT-SHAKE_40/8_256" => Ok(Self::XmssMtShake_40_8_256),
            "XMSSMT-SHAKE_60/3_256" => Ok(Self::XmssMtShake_60_3_256),
            "XMSSMT-SHAKE_60/6_256" => Ok(Self::XmssMtShake_60_6_256),
            "XMSSMT-SHAKE_60/12_256" => Ok(Self::XmssMtShake_60_12_256),
            "XMSSMT-SHAKE_20/2_512" => Ok(Self::XmssMtShake_20_2_512),
            "XMSSMT-SHAKE_20/4_512" => Ok(Self::XmssMtShake_20_4_512),
            "XMSSMT-SHAKE_40/2_512" => Ok(Self::XmssMtShake_40_2_512),
            "XMSSMT-SHAKE_40/4_512" => Ok(Self::XmssMtShake_40_4_512),
            "XMSSMT-SHAKE_40/8_512" => Ok(Self::XmssMtShake_40_8_512),
            "XMSSMT-SHAKE_60/3_512" => Ok(Self::XmssMtShake_60_3_512),
            "XMSSMT-SHAKE_60/6_512" => Ok(Self::XmssMtShake_60_6_512),
            "XMSSMT-SHAKE_60/12_512" => Ok(Self::XmssMtShake_60_12_512),
            "XMSSMT-SHA2_20/2_192" => Ok(Self::XmssMtSha2_20_2_192),
            "XMSSMT-SHA2_20/4_192" => Ok(Self::XmssMtSha2_20_4_192),
            "XMSSMT-SHA2_40/2_192" => Ok(Self::XmssMtSha2_40_2_192),
            "XMSSMT-SHA2_40/4_192" => Ok(Self::XmssMtSha2_40_4_192),
            "XMSSMT-SHA2_40/8_192" => Ok(Self::XmssMtSha2_40_8_192),
            "XMSSMT-SHA2_60/3_192" => Ok(Self::XmssMtSha2_60_3_192),
            "XMSSMT-SHA2_60/6_192" => Ok(Self::XmssMtSha2_60_6_192),
            "XMSSMT-SHA2_60/12_192" => Ok(Self::XmssMtSha2_60_12_192),
            "XMSSMT-SHAKE256_20/2_256" => Ok(Self::XmssMtShake256_20_2_256),
            "XMSSMT-SHAKE256_20/4_256" => Ok(Self::XmssMtShake256_20_4_256),
            "XMSSMT-SHAKE256_40/2_256" => Ok(Self::XmssMtShake256_40_2_256),
            "XMSSMT-SHAKE256_40/4_256" => Ok(Self::XmssMtShake256_40_4_256),
            "XMSSMT-SHAKE256_40/8_256" => Ok(Self::XmssMtShake256_40_8_256),
            "XMSSMT-SHAKE256_60/3_256" => Ok(Self::XmssMtShake256_60_3_256),
            "XMSSMT-SHAKE256_60/6_256" => Ok(Self::XmssMtShake256_60_6_256),
            "XMSSMT-SHAKE256_60/12_256" => Ok(Self::XmssMtShake256_60_12_256),
            "XMSSMT-SHAKE256_20/2_192" => Ok(Self::XmssMtShake256_20_2_192),
            "XMSSMT-SHAKE256_20/4_192" => Ok(Self::XmssMtShake256_20_4_192),
            "XMSSMT-SHAKE256_40/2_192" => Ok(Self::XmssMtShake256_40_2_192),
            "XMSSMT-SHAKE256_40/4_192" => Ok(Self::XmssMtShake256_40_4_192),
            "XMSSMT-SHAKE256_40/8_192" => Ok(Self::XmssMtShake256_40_8_192),
            "XMSSMT-SHAKE256_60/3_192" => Ok(Self::XmssMtShake256_60_3_192),
            "XMSSMT-SHAKE256_60/6_192" => Ok(Self::XmssMtShake256_60_6_192),
            "XMSSMT-SHAKE256_60/12_192" => Ok(Self::XmssMtShake256_60_12_192),
            _ => Err(Error::InvalidParameterSet(s.to_string())),
        }
    }
}

impl fmt::Display for XmssOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::XmssSha2_10_256 => "XMSS-SHA2_10_256",
            Self::XmssSha2_16_256 => "XMSS-SHA2_16_256",
            Self::XmssSha2_20_256 => "XMSS-SHA2_20_256",
            Self::XmssSha2_10_512 => "XMSS-SHA2_10_512",
            Self::XmssSha2_16_512 => "XMSS-SHA2_16_512",
            Self::XmssSha2_20_512 => "XMSS-SHA2_20_512",
            Self::XmssShake_10_256 => "XMSS-SHAKE_10_256",
            Self::XmssShake_16_256 => "XMSS-SHAKE_16_256",
            Self::XmssShake_20_256 => "XMSS-SHAKE_20_256",
            Self::XmssShake_10_512 => "XMSS-SHAKE_10_512",
            Self::XmssShake_16_512 => "XMSS-SHAKE_16_512",
            Self::XmssShake_20_512 => "XMSS-SHAKE_20_512",
            Self::XmssSha2_10_192 => "XMSS-SHA2_10_192",
            Self::XmssSha2_16_192 => "XMSS-SHA2_16_192",
            Self::XmssSha2_20_192 => "XMSS-SHA2_20_192",
            Self::XmssShake256_10_256 => "XMSS-SHAKE256_10_256",
            Self::XmssShake256_16_256 => "XMSS-SHAKE256_16_256",
            Self::XmssShake256_20_256 => "XMSS-SHAKE256_20_256",
            Self::XmssShake256_10_192 => "XMSS-SHAKE256_10_192",
            Self::XmssShake256_16_192 => "XMSS-SHAKE256_16_192",
            Self::XmssShake256_20_192 => "XMSS-SHAKE256_20_192",
            Self::XmssMtSha2_20_2_256 => "XMSSMT-SHA2_20/2_256",
            Self::XmssMtSha2_20_4_256 => "XMSSMT-SHA2_20/4_256",
            Self::XmssMtSha2_40_2_256 => "XMSSMT-SHA2_40/2_256",
            Self::XmssMtSha2_40_4_256 => "XMSSMT-SHA2_40/4_256",
            Self::XmssMtSha2_40_8_256 => "XMSSMT-SHA2_40/8_256",
            Self::XmssMtSha2_60_3_256 => "XMSSMT-SHA2_60/3_256",
            Self::XmssMtSha2_60_6_256 => "XMSSMT-SHA2_60/6_256",
            Self::XmssMtSha2_60_12_256 => "XMSSMT-SHA2_60/12_256",
            Self::XmssMtSha2_20_2_512 => "XMSSMT-SHA2_20/2_512",
            Self::XmssMtSha2_20_4_512 => "XMSSMT-SHA2_20/4_512",
            Self::XmssMtSha2_40_2_512 => "XMSSMT-SHA2_40/2_512",
            Self::XmssMtSha2_40_4_512 => "XMSSMT-SHA2_40/4_512",
            Self::XmssMtSha2_40_8_512 => "XMSSMT-SHA2_40/8_512",
            Self::XmssMtSha2_60_3_512 => "XMSSMT-SHA2_60/3_512",
            Self::XmssMtSha2_60_6_512 => "XMSSMT-SHA2_60/6_512",
            Self::XmssMtSha2_60_12_512 => "XMSSMT-SHA2_60/12_512",
            Self::XmssMtShake_20_2_256 => "XMSSMT-SHAKE_20/2_256",
            Self::XmssMtShake_20_4_256 => "XMSSMT-SHAKE_20/4_256",
            Self::XmssMtShake_40_2_256 => "XMSSMT-SHAKE_40/2_256",
            Self::XmssMtShake_40_4_256 => "XMSSMT-SHAKE_40/4_256",
            Self::XmssMtShake_40_8_256 => "XMSSMT-SHAKE_40/8_256",
            Self::XmssMtShake_60_3_256 => "XMSSMT-SHAKE_60/3_256",
            Self::XmssMtShake_60_6_256 => "XMSSMT-SHAKE_60/6_256",
            Self::XmssMtShake_60_12_256 => "XMSSMT-SHAKE_60/12_256",
            Self::XmssMtShake_20_2_512 => "XMSSMT-SHAKE_20/2_512",
            Self::XmssMtShake_20_4_512 => "XMSSMT-SHAKE_20/4_512",
            Self::XmssMtShake_40_2_512 => "XMSSMT-SHAKE_40/2_512",
            Self::XmssMtShake_40_4_512 => "XMSSMT-SHAKE_40/4_512",
            Self::XmssMtShake_40_8_512 => "XMSSMT-SHAKE_40/8_512",
            Self::XmssMtShake_60_3_512 => "XMSSMT-SHAKE_60/3_512",
            Self::XmssMtShake_60_6_512 => "XMSSMT-SHAKE_60/6_512",
            Self::XmssMtShake_60_12_512 => "XMSSMT-SHAKE_60/12_512",
            Self::XmssMtSha2_20_2_192 => "XMSSMT-SHA2_20/2_192",
            Self::XmssMtSha2_20_4_192 => "XMSSMT-SHA2_20/4_192",
            Self::XmssMtSha2_40_2_192 => "XMSSMT-SHA2_40/2_192",
            Self::XmssMtSha2_40_4_192 => "XMSSMT-SHA2_40/4_192",
            Self::XmssMtSha2_40_8_192 => "XMSSMT-SHA2_40/8_192",
            Self::XmssMtSha2_60_3_192 => "XMSSMT-SHA2_60/3_192",
            Self::XmssMtSha2_60_6_192 => "XMSSMT-SHA2_60/6_192",
            Self::XmssMtSha2_60_12_192 => "XMSSMT-SHA2_60/12_192",
            Self::XmssMtShake256_20_2_256 => "XMSSMT-SHAKE256_20/2_256",
            Self::XmssMtShake256_20_4_256 => "XMSSMT-SHAKE256_20/4_256",
            Self::XmssMtShake256_40_2_256 => "XMSSMT-SHAKE256_40/2_256",
            Self::XmssMtShake256_40_4_256 => "XMSSMT-SHAKE256_40/4_256",
            Self::XmssMtShake256_40_8_256 => "XMSSMT-SHAKE256_40/8_256",
            Self::XmssMtShake256_60_3_256 => "XMSSMT-SHAKE256_60/3_256",
            Self::XmssMtShake256_60_6_256 => "XMSSMT-SHAKE256_60/6_256",
            Self::XmssMtShake256_60_12_256 => "XMSSMT-SHAKE256_60/12_256",
            Self::XmssMtShake256_20_2_192 => "XMSSMT-SHAKE256_20/2_192",
            Self::XmssMtShake256_20_4_192 => "XMSSMT-SHAKE256_20/4_192",
            Self::XmssMtShake256_40_2_192 => "XMSSMT-SHAKE256_40/2_192",
            Self::XmssMtShake256_40_4_192 => "XMSSMT-SHAKE256_40/4_192",
            Self::XmssMtShake256_40_8_192 => "XMSSMT-SHAKE256_40/8_192",
            Self::XmssMtShake256_60_3_192 => "XMSSMT-SHAKE256_60/3_192",
            Self::XmssMtShake256_60_6_192 => "XMSSMT-SHAKE256_60/6_192",
            Self::XmssMtShake256_60_12_192 => "XMSSMT-SHAKE256_60/12_192",
        };
        f.write_str(s)
    }
}
