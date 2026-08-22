use hybrid_array::{Array, ArraySize};
use sha2::{Digest, Sha256, Sha512};
use shake::{
    Shake128, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroize;

use crate::error::{Error, XmssResult};
use crate::hash_address::set_key_and_mask;
use crate::params::{XMSS_SHA2, XMSS_SHAKE128, XMSS_SHAKE256, XmssParams};
use crate::utils::ull_to_bytes;

const XMSS_HASH_PADDING_F: u64 = 0;
const XMSS_HASH_PADDING_H: u64 = 1;
const XMSS_HASH_PADDING_HASH: u64 = 2;
const XMSS_HASH_PADDING_PRF: u64 = 3;
const XMSS_HASH_PADDING_PRF_KEYGEN: u64 = 4;
const MAX_N: usize = 64;
const MAX_HASH_PREFIX: usize = 4 * MAX_N;
const MAX_PRF_INPUT: usize = 2 * MAX_N + 32;
const MAX_PRF_KEYGEN_INPUT: usize = 4 * MAX_N;
const MAX_THASH_H_INPUT: usize = 4 * MAX_N;
const MAX_THASH_F_INPUT: usize = 3 * MAX_N;

/// A hash function with an XMSS-specific, fixed output size.
///
/// The output size is the effective XMSS value `n`, so this trait also covers
/// truncated SHA-256/192 and fixed-length SHAKE outputs. Standard parameter
/// types implement this trait, allowing digest-sized values such as traversal
/// roots to remain fixed-size arrays.
///
/// # Example
///
/// ```rust
/// use pq_xmss::{FixedDigest, XmssSha2_10_192};
///
/// let output = XmssSha2_10_192::digest(b"fixed-size input")?;
/// assert_eq!(output.len(), 24);
/// # Ok::<(), pq_xmss::Error>(())
/// ```
pub trait FixedDigest {
    /// Fixed output size (`U24`, `U32`, or `U64`).
    type OutputSize: ArraySize;

    /// Hashes `input` into an output whose length is fixed by the type.
    fn digest(input: &[u8]) -> XmssResult<Array<u8, Self::OutputSize>>;
}

pub(crate) type CoreHash = fn(&mut [u8], &[u8]) -> XmssResult<()>;

pub(crate) fn fixed_digest<N: ArraySize>(func: u32, input: &[u8]) -> XmssResult<Array<u8, N>> {
    let mut output = Array::<u8, N>::default();
    let n = u32::try_from(N::USIZE).map_err(|_| Error::Hash { n: u32::MAX, func })?;
    core_hash_by_id(func, n, &mut output, input)?;
    Ok(output)
}

pub(crate) fn fixed_digest_into<D: FixedDigest>(out: &mut [u8], input: &[u8]) -> XmssResult<()> {
    let output = D::digest(input)?;
    if out.len() < output.len() {
        return Err(Error::InvalidDigestLength {
            expected: output.len(),
            got: out.len(),
        });
    }
    out[..output.len()].copy_from_slice(&output);
    Ok(())
}

pub(crate) fn addr_to_bytes(bytes: &mut [u8], addr: &[u32; 8]) {
    for i in 0..8 {
        ull_to_bytes(&mut bytes[i * 4..i * 4 + 4], addr[i] as u64);
    }
}

fn core_hash_by_id(func: u32, n: u32, out: &mut [u8], input: &[u8]) -> XmssResult<()> {
    core_hash_parts_by_id(func, n, out, &[input])
}

fn core_hash_parts_by_id(func: u32, n: u32, out: &mut [u8], inputs: &[&[u8]]) -> XmssResult<()> {
    let output_len = n as usize;
    if out.len() < output_len {
        return Err(Error::InvalidDigestLength {
            expected: output_len,
            got: out.len(),
        });
    }

    if n == 24 && func == XMSS_SHA2 {
        let mut hasher = Sha256::new();
        for input in inputs {
            Digest::update(&mut hasher, input);
        }
        let result = hasher.finalize();
        out[..24].copy_from_slice(&result[..24]);
    } else if n == 24 && func == XMSS_SHAKE256 {
        let mut hasher = Shake256::default();
        for input in inputs {
            Update::update(&mut hasher, input);
        }
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..24]);
    } else if n == 32 && func == XMSS_SHA2 {
        let mut hasher = Sha256::new();
        for input in inputs {
            Digest::update(&mut hasher, input);
        }
        let result = hasher.finalize();
        out[..32].copy_from_slice(&result);
    } else if n == 32 && func == XMSS_SHAKE128 {
        let mut hasher = Shake128::default();
        for input in inputs {
            Update::update(&mut hasher, input);
        }
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..32]);
    } else if n == 32 && func == XMSS_SHAKE256 {
        let mut hasher = Shake256::default();
        for input in inputs {
            Update::update(&mut hasher, input);
        }
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..32]);
    } else if n == 64 && func == XMSS_SHA2 {
        let mut hasher = Sha512::new();
        for input in inputs {
            Digest::update(&mut hasher, input);
        }
        let result = hasher.finalize();
        out[..64].copy_from_slice(&result);
    } else if n == 64 && func == XMSS_SHAKE256 {
        let mut hasher = Shake256::default();
        for input in inputs {
            Update::update(&mut hasher, input);
        }
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..64]);
    } else {
        return Err(Error::Hash { n, func });
    }
    Ok(())
}

fn core_hash(params: &XmssParams, out: &mut [u8], input: &[u8]) -> XmssResult<()> {
    (params.hash)(out, input)
}

pub(crate) fn runtime_digest(func: u32, n: u32) -> XmssResult<CoreHash> {
    match (func, n) {
        (XMSS_SHA2, 24) => Ok(|out, input| core_hash_by_id(XMSS_SHA2, 24, out, input)),
        (XMSS_SHAKE256, 24) => Ok(|out, input| core_hash_by_id(XMSS_SHAKE256, 24, out, input)),
        (XMSS_SHA2, 32) => Ok(|out, input| core_hash_by_id(XMSS_SHA2, 32, out, input)),
        (XMSS_SHAKE128, 32) => Ok(|out, input| core_hash_by_id(XMSS_SHAKE128, 32, out, input)),
        (XMSS_SHAKE256, 32) => Ok(|out, input| core_hash_by_id(XMSS_SHAKE256, 32, out, input)),
        (XMSS_SHA2, 64) => Ok(|out, input| core_hash_by_id(XMSS_SHA2, 64, out, input)),
        (XMSS_SHAKE256, 64) => Ok(|out, input| core_hash_by_id(XMSS_SHAKE256, 64, out, input)),
        _ => Err(Error::Hash { n, func }),
    }
}

/// Computes `PRF(key, input)` for a key of `params.n` bytes and a 32-byte input.
pub(crate) fn prf(
    params: &XmssParams,
    out: &mut [u8],
    input: &[u8; 32],
    key: &[u8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let padding_len = params.padding_len as usize;
    let buf_len = padding_len + n + 32;
    let mut storage = [0u8; MAX_PRF_INPUT];
    let buf = storage
        .get_mut(..buf_len)
        .ok_or(Error::InvalidDigestLength {
            expected: MAX_PRF_INPUT,
            got: buf_len,
        })?;

    ull_to_bytes(&mut buf[..padding_len], XMSS_HASH_PADDING_PRF);
    buf[padding_len..padding_len + n].copy_from_slice(&key[..n]);
    buf[padding_len + n..padding_len + n + 32].copy_from_slice(input);

    let result = core_hash(params, out, buf);
    storage.zeroize();
    result
}

/// Computes `PRF_keygen(key, input)` for a key of `params.n` bytes and an input
/// of `32 + params.n` bytes.
pub(crate) fn prf_keygen(
    params: &XmssParams,
    out: &mut [u8],
    input: &[u8],
    key: &[u8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let padding_len = params.padding_len as usize;
    let buf_len = padding_len + 2 * n + 32;
    let mut storage = [0u8; MAX_PRF_KEYGEN_INPUT];
    let buf = storage
        .get_mut(..buf_len)
        .ok_or(Error::InvalidDigestLength {
            expected: MAX_PRF_KEYGEN_INPUT,
            got: buf_len,
        })?;

    ull_to_bytes(&mut buf[..padding_len], XMSS_HASH_PADDING_PRF_KEYGEN);
    buf[padding_len..padding_len + n].copy_from_slice(&key[..n]);
    buf[padding_len + n..padding_len + n + n + 32].copy_from_slice(&input[..n + 32]);

    let result = core_hash(params, out, buf);
    storage.zeroize();
    result
}

/// Computes the message hash using R, the public root, the index of the leaf
/// node, and a borrowed message without concatenating the hash inputs.
pub(crate) fn hash_message(
    params: &XmssParams,
    out: &mut [u8],
    r: &[u8],
    root: &[u8],
    idx: u64,
    message: &[u8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let padding_len = params.padding_len as usize;
    let prefix_len = padding_len + 3 * n;
    let mut storage = [0u8; MAX_HASH_PREFIX];
    let prefix = storage
        .get_mut(..prefix_len)
        .ok_or(Error::InvalidDigestLength {
            expected: MAX_HASH_PREFIX,
            got: prefix_len,
        })?;

    ull_to_bytes(&mut prefix[..padding_len], XMSS_HASH_PADDING_HASH);
    prefix[padding_len..padding_len + n].copy_from_slice(&r[..n]);
    prefix[padding_len + n..padding_len + 2 * n].copy_from_slice(&root[..n]);
    ull_to_bytes(&mut prefix[padding_len + 2 * n..padding_len + 3 * n], idx);

    let result = core_hash_parts_by_id(params.func, params.n, out, &[prefix, message]);
    storage.zeroize();
    result
}

/// Computes the tree hash for internal nodes from two `n`-byte inputs.
pub(crate) fn thash_h(
    params: &XmssParams,
    out: &mut [u8],
    input: &[u8],
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let padding_len = params.padding_len as usize;
    let buf_len = padding_len + 3 * n;
    let mut buf_storage = [0u8; MAX_THASH_H_INPUT];
    let buf = buf_storage
        .get_mut(..buf_len)
        .ok_or(Error::InvalidDigestLength {
            expected: MAX_THASH_H_INPUT,
            got: buf_len,
        })?;
    let mut bitmask_storage = [0u8; 2 * MAX_N];
    let bitmask = bitmask_storage
        .get_mut(..2 * n)
        .ok_or(Error::InvalidDigestLength {
            expected: 2 * MAX_N,
            got: 2 * n,
        })?;
    let mut addr_as_bytes = [0u8; 32];

    ull_to_bytes(&mut buf[..padding_len], XMSS_HASH_PADDING_H);

    set_key_and_mask(addr, 0);
    addr_to_bytes(&mut addr_as_bytes, addr);
    prf(
        params,
        &mut buf[padding_len..padding_len + n],
        &addr_as_bytes,
        pub_seed,
    )?;

    set_key_and_mask(addr, 1);
    addr_to_bytes(&mut addr_as_bytes, addr);
    prf(params, &mut bitmask[..n], &addr_as_bytes, pub_seed)?;

    set_key_and_mask(addr, 2);
    addr_to_bytes(&mut addr_as_bytes, addr);
    prf(params, &mut bitmask[n..2 * n], &addr_as_bytes, pub_seed)?;

    for i in 0..2 * n {
        buf[padding_len + n + i] = input[i] ^ bitmask[i];
    }

    core_hash(params, out, buf)
}

/// Computes the tree hash for WOTS chains from a single `n`-byte input.
pub(crate) fn thash_f(
    params: &XmssParams,
    out: &mut [u8],
    input: &[u8],
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let padding_len = params.padding_len as usize;
    let buf_len = padding_len + 2 * n;
    let mut buf_storage = [0u8; MAX_THASH_F_INPUT];
    let buf = buf_storage
        .get_mut(..buf_len)
        .ok_or(Error::InvalidDigestLength {
            expected: MAX_THASH_F_INPUT,
            got: buf_len,
        })?;
    let mut bitmask_storage = [0u8; MAX_N];
    let bitmask = bitmask_storage
        .get_mut(..n)
        .ok_or(Error::InvalidDigestLength {
            expected: MAX_N,
            got: n,
        })?;
    let mut addr_as_bytes = [0u8; 32];

    ull_to_bytes(&mut buf[..padding_len], XMSS_HASH_PADDING_F);

    set_key_and_mask(addr, 0);
    addr_to_bytes(&mut addr_as_bytes, addr);
    prf(
        params,
        &mut buf[padding_len..padding_len + n],
        &addr_as_bytes,
        pub_seed,
    )?;

    set_key_and_mask(addr, 1);
    addr_to_bytes(&mut addr_as_bytes, addr);
    prf(params, bitmask, &addr_as_bytes, pub_seed)?;

    for i in 0..n {
        buf[padding_len + n + i] = input[i] ^ bitmask[i];
    }

    core_hash(params, out, buf)
}
