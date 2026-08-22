//! Alloc-backed XMSS keys with a parameter set selected at runtime.

use alloc::{boxed::Box, vec, vec::Vec};

use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, XmssResult};
use crate::params::{ParameterSet, XMSS_OID_LEN, XmssParams};
use crate::{xmss_commons, xmss_core};

/// An alloc-backed XMSS signing key whose parameter set is selected at runtime.
///
/// Like the generic [`crate::SigningKey`], this type intentionally does not
/// implement `Clone`: duplicating its state could reuse a one-time index.
/// Each successful signing operation advances both the compact key bytes and
/// the unpacked traversal cache held in memory. Persist the compact bytes
/// returned by [`AsRef::as_ref`] after signing if the key will be used by a
/// later process, and never use two keys decoded from the same compact state
/// concurrently.
///
/// Decoding reconstructs only the active authentication paths, roots, and
/// reusable upper-layer WOTS signatures. The cache is not serialized and does
/// not contain complete Merkle trees.
pub struct BoxedSigningKey {
    bytes: Box<[u8]>,
    parameter_set: ParameterSet,
    params: XmssParams,
    traversal: xmss_core::BoxedTraversalState,
}

impl core::fmt::Debug for BoxedSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BoxedSigningKey")
            .field("parameter_set", &self.parameter_set)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl BoxedSigningKey {
    fn new(
        bytes: Box<[u8]>,
        parameter_set: ParameterSet,
        params: XmssParams,
        traversal: xmss_core::BoxedTraversalState,
    ) -> Self {
        Self {
            bytes,
            parameter_set,
            params,
            traversal,
        }
    }

    /// Decodes compact signing-key bytes for `parameter_set` and reconstructs
    /// the in-memory traversal cache.
    ///
    /// The bytes use the same format as [`crate::SigningKey`]. The caller must
    /// supply the matching runtime parameter set; it is not inferred solely
    /// from the serialized identifier because XMSS and XMSS^MT identifier
    /// spaces overlap.
    pub fn try_from_bytes(parameter_set: ParameterSet, value: &[u8]) -> XmssResult<Self> {
        validate_oid(parameter_set, value)?;
        let params = parameter_set.params();
        let expected = XMSS_OID_LEN + params.sk_bytes;
        if value.len() != expected {
            return Err(Error::InvalidKeyLength {
                expected,
                got: value.len(),
            });
        }
        let bytes: Box<[u8]> = value.into();
        let traversal =
            xmss_core::BoxedTraversalState::from_compact_key(&params, &bytes[XMSS_OID_LEN..])?;
        Ok(Self::new(bytes, parameter_set, params, traversal))
    }

    /// Returns the runtime-selected parameter set.
    pub const fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    /// Derives the corresponding verifying key.
    pub fn verifying_key(&self) -> BoxedVerifyingKey {
        let n = self.params.n as usize;
        let idx_bytes = self.params.index_bytes as usize;
        let root_start = XMSS_OID_LEN + idx_bytes + 2 * n;
        let mut bytes = vec![0u8; XMSS_OID_LEN + 2 * n];
        bytes[..XMSS_OID_LEN].copy_from_slice(&self.bytes[..XMSS_OID_LEN]);
        bytes[XMSS_OID_LEN..].copy_from_slice(&self.bytes[root_start..root_start + 2 * n]);
        BoxedVerifyingKey {
            bytes: bytes.into_boxed_slice(),
            parameter_set: self.parameter_set,
            params: self.params,
        }
    }

    /// Signs `message`, returning the signature followed by the message.
    ///
    /// The in-memory one-time key index and traversal state are advanced before
    /// this method returns. Persistence of the updated compact key is the
    /// caller's responsibility. The borrowed message is hashed without first
    /// constructing a temporary signature-and-message buffer.
    pub fn sign(&mut self, message: &[u8]) -> XmssResult<BoxedSignature> {
        let bytes = self
            .traversal
            .sign(&self.params, &mut self.bytes[XMSS_OID_LEN..], message)?;
        Ok(BoxedSignature {
            bytes,
            parameter_set: self.parameter_set,
        })
    }

    /// Signs `message`, returning only the detached signature.
    ///
    /// The in-memory one-time key index and traversal state are advanced before
    /// this method returns. Persistence of the updated compact key is the
    /// caller's responsibility. The borrowed message is hashed without first
    /// constructing a temporary signature-and-message buffer.
    pub fn sign_detached(&mut self, message: &[u8]) -> XmssResult<BoxedDetachedSignature> {
        let signed =
            self.traversal
                .sign_detached(&self.params, &mut self.bytes[XMSS_OID_LEN..], message)?;
        Ok(BoxedDetachedSignature {
            bytes: signed.into_boxed_slice(),
            parameter_set: self.parameter_set,
        })
    }
}

impl signature::Keypair for BoxedSigningKey {
    type VerifyingKey = BoxedVerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        BoxedSigningKey::verifying_key(self)
    }
}

impl AsRef<[u8]> for BoxedSigningKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for BoxedSigningKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.traversal.zeroize();
    }
}

/// An alloc-backed XMSS verifying key selected at runtime.
///
/// It provides the same inherent `verify` and `verify_detached` operations as
/// [`crate::VerifyingKey`].
#[derive(Clone, Debug)]
pub struct BoxedVerifyingKey {
    bytes: Box<[u8]>,
    parameter_set: ParameterSet,
    params: XmssParams,
}

impl PartialEq for BoxedVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.parameter_set == other.parameter_set && self.bytes == other.bytes
    }
}

impl Eq for BoxedVerifyingKey {}

impl BoxedVerifyingKey {
    /// Decodes verifying-key bytes for `parameter_set`.
    ///
    /// The bytes use the same compact format as [`crate::VerifyingKey`].
    pub fn try_from_bytes(parameter_set: ParameterSet, value: &[u8]) -> XmssResult<Self> {
        validate_oid(parameter_set, value)?;
        let params = parameter_set.params();
        let expected = XMSS_OID_LEN + params.pk_bytes as usize;
        if value.len() != expected {
            return Err(Error::InvalidKeyLength {
                expected,
                got: value.len(),
            });
        }
        Ok(Self {
            bytes: value.into(),
            parameter_set,
            params,
        })
    }

    /// Returns the runtime-selected parameter set.
    pub const fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    /// Verifies a signature containing an appended message.
    ///
    /// Returns the verified message on success.
    pub fn verify(&self, signature: &BoxedSignature) -> XmssResult<Vec<u8>> {
        if signature.parameter_set != self.parameter_set {
            return Err(Error::ParameterSetMismatch);
        }
        let mut message = Vec::new();
        xmss_commons::xmssmt_core_sign_open(
            &self.params,
            &mut message,
            &signature.bytes,
            &self.bytes[XMSS_OID_LEN..],
        )?;
        Ok(message)
    }

    /// Verifies a detached signature against `message` without concatenating
    /// them into a temporary buffer.
    pub fn verify_detached(
        &self,
        signature: &BoxedDetachedSignature,
        message: &[u8],
    ) -> XmssResult<()> {
        if signature.parameter_set != self.parameter_set {
            return Err(Error::ParameterSetMismatch);
        }
        xmss_commons::xmssmt_core_verify_detached(
            &self.params,
            &signature.bytes,
            message,
            &self.bytes[XMSS_OID_LEN..],
        )
    }
}

impl AsRef<[u8]> for BoxedVerifyingKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// An alloc-backed signature with an appended message, selected at runtime.
///
/// Its byte representation is identical to [`crate::Signature`]. The
/// parameter set is retained in memory but is not added to the signature bytes,
/// so decoding requires an explicit [`ParameterSet`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoxedSignature {
    bytes: Vec<u8>,
    parameter_set: ParameterSet,
}

impl BoxedSignature {
    /// Decodes a signature with an appended message for `parameter_set`.
    pub fn try_from_bytes(parameter_set: ParameterSet, value: &[u8]) -> XmssResult<Self> {
        let minimum = parameter_set.signature_len();
        if value.len() < minimum {
            return Err(Error::InvalidSignatureLength {
                expected: minimum,
                got: value.len(),
            });
        }
        Ok(Self {
            bytes: value.to_vec(),
            parameter_set,
        })
    }

    /// Returns the runtime-selected parameter set.
    pub const fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

impl AsRef<[u8]> for BoxedSignature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// An alloc-backed detached signature selected at runtime.
///
/// Its byte representation is identical to [`crate::DetachedSignature`]. The
/// parameter set is retained in memory but is not added to the signature bytes,
/// so decoding requires an explicit [`ParameterSet`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoxedDetachedSignature {
    bytes: Box<[u8]>,
    parameter_set: ParameterSet,
}

impl BoxedDetachedSignature {
    /// Decodes a detached signature for `parameter_set`.
    pub fn try_from_bytes(parameter_set: ParameterSet, value: &[u8]) -> XmssResult<Self> {
        let expected = parameter_set.signature_len();
        if value.len() != expected {
            return Err(Error::InvalidSignatureLength {
                expected,
                got: value.len(),
            });
        }
        Ok(Self {
            bytes: value.into(),
            parameter_set,
        })
    }

    /// Returns the runtime-selected parameter set.
    pub const fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

impl AsRef<[u8]> for BoxedDetachedSignature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// An alloc-backed XMSS key pair selected at runtime.
///
/// This type intentionally does not implement `Clone` because it contains a
/// stateful [`BoxedSigningKey`].
#[derive(Debug)]
pub struct BoxedKeyPair {
    signing_key: BoxedSigningKey,
    verifying_key: BoxedVerifyingKey,
}

impl BoxedKeyPair {
    /// Generates a key pair for `parameter_set`.
    pub fn generate<R: rand::CryptoRng>(
        parameter_set: ParameterSet,
        rng: &mut R,
    ) -> XmssResult<Self> {
        let params = parameter_set.params();
        let (mut pk, mut sk) = key_buffers(parameter_set, &params);
        let traversal = xmss_core::BoxedTraversalState::keypair(
            &params,
            &mut pk[XMSS_OID_LEN..],
            &mut sk[XMSS_OID_LEN..],
            rng,
        )?;
        Ok(Self::new(parameter_set, params, pk, sk, traversal))
    }

    /// Deterministically generates a key pair from a `3 * n` byte seed.
    ///
    /// A seed recreates the initial index-zero state; it must not be used to
    /// restore a key after signatures have been issued. Restore the advanced
    /// compact bytes with [`BoxedSigningKey::try_from_bytes`] instead.
    pub fn from_seed(parameter_set: ParameterSet, seed: &[u8]) -> XmssResult<Self> {
        let params = parameter_set.params();
        let expected = params.get_seed_length();
        if seed.len() != expected {
            return Err(Error::InvalidSeedLength {
                expected,
                got: seed.len(),
            });
        }
        let (mut pk, mut sk) = key_buffers(parameter_set, &params);
        let seed = Zeroizing::new(seed.to_vec());
        let traversal = xmss_core::BoxedTraversalState::seed_keypair(
            &params,
            &mut pk[XMSS_OID_LEN..],
            &mut sk[XMSS_OID_LEN..],
            &seed,
        )?;
        Ok(Self::new(parameter_set, params, pk, sk, traversal))
    }

    fn new(
        parameter_set: ParameterSet,
        params: XmssParams,
        pk: Vec<u8>,
        sk: Vec<u8>,
        traversal: xmss_core::BoxedTraversalState,
    ) -> Self {
        Self {
            signing_key: BoxedSigningKey::new(
                sk.into_boxed_slice(),
                parameter_set,
                params,
                traversal,
            ),
            verifying_key: BoxedVerifyingKey {
                bytes: pk.into_boxed_slice(),
                parameter_set,
                params,
            },
        }
    }

    /// Returns the mutable signing key.
    pub fn signing_key(&mut self) -> &mut BoxedSigningKey {
        &mut self.signing_key
    }

    /// Returns the verifying key.
    pub const fn verifying_key(&self) -> &BoxedVerifyingKey {
        &self.verifying_key
    }
}

fn validate_oid(parameter_set: ParameterSet, value: &[u8]) -> XmssResult<()> {
    if value.len() < XMSS_OID_LEN {
        return Err(Error::InvalidKeyLength {
            expected: XMSS_OID_LEN,
            got: value.len(),
        });
    }
    let mut oid = [0u8; XMSS_OID_LEN];
    oid.copy_from_slice(&value[..XMSS_OID_LEN]);
    let oid = u32::from_be_bytes(oid);
    if oid != parameter_set.raw_oid() {
        return Err(Error::InvalidOid(oid));
    }
    Ok(())
}

fn key_buffers(parameter_set: ParameterSet, params: &XmssParams) -> (Vec<u8>, Vec<u8>) {
    let mut pk = vec![0u8; XMSS_OID_LEN + params.pk_bytes as usize];
    let mut sk = vec![0u8; XMSS_OID_LEN + params.sk_bytes];
    let oid = parameter_set.raw_oid().to_be_bytes();
    pk[..XMSS_OID_LEN].copy_from_slice(&oid);
    sk[..XMSS_OID_LEN].copy_from_slice(&oid);
    (pk, sk)
}
