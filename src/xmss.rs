use core::marker::PhantomData;

use hybrid_array::Array;
use zeroize::Zeroize;

use crate::error::{Error, XmssResult};
use crate::params::{XMSS_OID_LEN, XmssParameter, XmssParams};
use crate::xmss_commons;
use crate::xmss_core;

/// Parses the parameter-set identifier from the first bytes of a key.
fn parse_oid(bytes: &[u8]) -> XmssResult<u32> {
    if bytes.len() < XMSS_OID_LEN {
        return Err(Error::InvalidOid(0));
    }
    let mut raw_oid = [0u8; XMSS_OID_LEN];
    raw_oid.copy_from_slice(&bytes[..XMSS_OID_LEN]);
    Ok(u32::from_be_bytes(raw_oid))
}

// ---------------------------------------------------------------------------
// SigningKey<P>
// ---------------------------------------------------------------------------

/// An XMSS signing key (secret key).
///
/// The encoded bytes contain the compact, authoritative signing index and
/// secret seeds. Authentication paths and other traversal data are reconstructed
/// when the key is decoded and are not included in [`AsRef`] or optional key
/// encodings.
///
/// Every signing operation advances this in-memory key before returning. The
/// caller is responsible for atomically persisting the updated compact bytes
/// when the key will be used again after the current process ends. An exhausted
/// key may instead be removed from persistent storage. The caller must prevent
/// concurrent use of multiple keys decoded from the same compact state.
///
/// This type intentionally does not implement [`Clone`]. Cloning a stateful
/// signing key would create two independent values at the same one-time index;
/// signing with both would reuse one-time key material and compromise security.
///
/// # Performance
///
/// Key generation and decoding reconstruct the active Merkle trees. Sequential
/// signing retains only their current authentication paths and incrementally
/// updates changed nodes; XMSS^MT also reuses unchanged upper-layer WOTS
/// signatures. The cache does not retain complete trees. Subtree rollovers can
/// therefore be slower than neighboring signatures because the next active
/// subtree must be constructed.
pub struct SigningKey<P: XmssParameter> {
    bytes: Array<u8, P::SkLen>,
    params: XmssParams,
    traversal: xmss_core::TraversalState,
    _marker: PhantomData<P>,
}

// Tests reuse an expensive generated tree. Keep this implementation out of the
// published API because cloning a stateful signing key can reuse a one-time
// signature index.
#[cfg(test)]
impl<P: XmssParameter> Clone for SigningKey<P> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            params: self.params,
            traversal: self.traversal.clone(),
            _marker: PhantomData,
        }
    }
}

impl<P: XmssParameter> core::fmt::Debug for SigningKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("parameter_set", &P::NAME)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl<P: XmssParameter> Drop for SigningKey<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<P: XmssParameter> Zeroize for SigningKey<P> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        self.traversal.zeroize();
    }
}

impl<P: XmssParameter> AsRef<[u8]> for SigningKey<P> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<P: XmssParameter> TryFrom<&[u8]> for SigningKey<P> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let oid = parse_oid(value)?;
        if oid != P::OID {
            return Err(Error::InvalidOid(oid));
        }
        let params = P::xmss_params();
        if value.len() != P::SK_LEN {
            return Err(Error::InvalidKeyLength {
                expected: P::SK_LEN,
                got: value.len(),
            });
        }
        let bytes = Array::try_from(value).map_err(|_| Error::InvalidKeyLength {
            expected: P::SK_LEN,
            got: value.len(),
        })?;
        let traversal =
            xmss_core::TraversalState::from_compact_key(&params, &bytes[XMSS_OID_LEN..])?;
        Ok(Self {
            bytes,
            params,
            traversal,
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> TryFrom<Vec<u8>> for SigningKey<P> {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        SigningKey::<P>::try_from(value.as_slice())
    }
}

impl<P: XmssParameter> TryFrom<&Vec<u8>> for SigningKey<P> {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        SigningKey::<P>::try_from(value.as_slice())
    }
}

impl<P: XmssParameter> TryFrom<Box<[u8]>> for SigningKey<P> {
    type Error = Error;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        SigningKey::<P>::try_from(value.as_ref())
    }
}

#[cfg(test)]
impl<P: XmssParameter> PartialEq for SigningKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

#[cfg(test)]
impl<P: XmssParameter> Eq for SigningKey<P> {}

#[cfg(test)]
impl<P: XmssParameter> core::hash::Hash for SigningKey<P> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.bytes[..].hash(state);
    }
}

#[cfg(feature = "serde")]
impl<P: XmssParameter> serdect::serde::Serialize for SigningKey<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.bytes, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, P: XmssParameter> serdect::serde::Deserialize<'de> for SigningKey<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::try_from(bytes).map_err(serdect::serde::de::Error::custom)
    }
}

impl<P: XmssParameter> SigningKey<P> {
    pub(crate) fn new(
        bytes: Array<u8, P::SkLen>,
        params: XmssParams,
        traversal: xmss_core::TraversalState,
    ) -> Self {
        Self {
            bytes,
            params,
            traversal,
            _marker: PhantomData,
        }
    }

    /// Signs a message, returning the signature followed by the message.
    ///
    /// The in-memory one-time key index and traversal state are advanced before
    /// this method returns. Persistence of the updated compact key is the
    /// caller's responsibility.
    pub fn sign(&mut self, m: &[u8]) -> XmssResult<Signature<P>> {
        xmss_core::xmssmt_core_sign(
            &self.params,
            &mut self.bytes[XMSS_OID_LEN..],
            &mut self.traversal,
            m,
        )
        .map(|bytes| Signature {
            bytes,
            _marker: PhantomData,
        })
    }

    /// Signs a message, returning only the detached signature.
    ///
    /// The in-memory one-time key index and traversal state are advanced before
    /// this method returns. Persistence of the updated compact key is the
    /// caller's responsibility.
    pub fn sign_detached(&mut self, m: &[u8]) -> XmssResult<DetachedSignature<P>> {
        let mut sm = xmss_core::xmssmt_core_sign(
            &self.params,
            &mut self.bytes[XMSS_OID_LEN..],
            &mut self.traversal,
            m,
        )?;
        let sig_bytes = sm.len() - m.len();
        sm.truncate(sig_bytes);
        Ok(DetachedSignature {
            bytes: sm.into_boxed_slice(),
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> signature::SignerMut<DetachedSignature<P>> for SigningKey<P> {
    fn try_sign(&mut self, msg: &[u8]) -> Result<DetachedSignature<P>, signature::Error> {
        self.sign_detached(msg).map_err(|_| signature::Error::new())
    }
}

impl<P: XmssParameter> signature::Keypair for SigningKey<P> {
    type VerifyingKey = VerifyingKey<P>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        VerifyingKey::from(self)
    }
}

// ---------------------------------------------------------------------------
// VerifyingKey<P>
// ---------------------------------------------------------------------------

/// An XMSS verifying key (public key).
#[derive(Clone, Debug)]
pub struct VerifyingKey<P: XmssParameter> {
    bytes: Array<u8, P::VkLen>,
    params: XmssParams,
    _marker: PhantomData<P>,
}

impl<P: XmssParameter> AsRef<[u8]> for VerifyingKey<P> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<P: XmssParameter> TryFrom<&[u8]> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let oid = parse_oid(value)?;
        if oid != P::OID {
            return Err(Error::InvalidOid(oid));
        }
        let params = P::xmss_params();
        if value.len() != P::VK_LEN {
            return Err(Error::InvalidKeyLength {
                expected: P::VK_LEN,
                got: value.len(),
            });
        }
        let bytes = Array::try_from(value).map_err(|_| Error::InvalidKeyLength {
            expected: P::VK_LEN,
            got: value.len(),
        })?;
        Ok(Self {
            bytes,
            params,
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> TryFrom<Vec<u8>> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        VerifyingKey::<P>::try_from(value.as_slice())
    }
}

impl<P: XmssParameter> TryFrom<&Vec<u8>> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        VerifyingKey::<P>::try_from(value.as_slice())
    }
}

impl<P: XmssParameter> TryFrom<Box<[u8]>> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        VerifyingKey::<P>::try_from(value.as_ref())
    }
}

impl<P: XmssParameter> PartialEq for VerifyingKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

impl<P: XmssParameter> Eq for VerifyingKey<P> {}

impl<P: XmssParameter> core::hash::Hash for VerifyingKey<P> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.bytes[..].hash(state);
    }
}

#[cfg(feature = "serde")]
impl<P: XmssParameter> serdect::serde::Serialize for VerifyingKey<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.bytes, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, P: XmssParameter> serdect::serde::Deserialize<'de> for VerifyingKey<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::try_from(bytes).map_err(serdect::serde::de::Error::custom)
    }
}

impl<P: XmssParameter> VerifyingKey<P> {
    pub(crate) fn new(bytes: Array<u8, P::VkLen>, params: XmssParams) -> Self {
        Self {
            bytes,
            params,
            _marker: PhantomData,
        }
    }

    /// Verifies a given message-signature pair.
    /// Returns the verified message on success.
    pub fn verify(&self, signature: &Signature<P>) -> XmssResult<Vec<u8>> {
        let mut m = Vec::new();
        xmss_commons::xmssmt_core_sign_open(
            &self.params,
            &mut m,
            &signature.bytes,
            &self.bytes[XMSS_OID_LEN..],
        )?;
        Ok(m)
    }

    /// Verifies a detached signature against the provided message.
    pub fn verify_detached(&self, signature: &DetachedSignature<P>, m: &[u8]) -> XmssResult<()> {
        let mut sm = Vec::with_capacity(signature.bytes.len() + m.len());
        sm.extend_from_slice(&signature.bytes);
        sm.extend_from_slice(m);
        let mut msg = Vec::new();
        xmss_commons::xmssmt_core_sign_open(
            &self.params,
            &mut msg,
            &sm,
            &self.bytes[XMSS_OID_LEN..],
        )?;
        Ok(())
    }
}

impl<P: XmssParameter> From<&SigningKey<P>> for VerifyingKey<P> {
    fn from(sk: &SigningKey<P>) -> Self {
        let n = sk.params.n as usize;
        let idx_bytes = sk.params.index_bytes as usize;

        // Secret key after OID: [idx || SK_SEED || SK_PRF || root || PUB_SEED].
        let root_start = XMSS_OID_LEN + idx_bytes + 2 * n;

        // Public key: [OID || root || PUB_SEED].
        let mut pk = Array::<u8, P::VkLen>::default();
        pk[..XMSS_OID_LEN].copy_from_slice(&sk.bytes[..XMSS_OID_LEN]);
        pk[XMSS_OID_LEN..].copy_from_slice(&sk.bytes[root_start..root_start + 2 * n]);

        VerifyingKey {
            bytes: pk,
            params: sk.params,
            _marker: PhantomData,
        }
    }
}

impl<P: XmssParameter> signature::Verifier<DetachedSignature<P>> for VerifyingKey<P> {
    fn verify(&self, msg: &[u8], signature: &DetachedSignature<P>) -> Result<(), signature::Error> {
        self.verify_detached(signature, msg)
            .map_err(|_| signature::Error::new())
    }
}

// ---------------------------------------------------------------------------
// Signature<P>
// ---------------------------------------------------------------------------

/// An XMSS signature (signature + message, variable length).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature<P: XmssParameter> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

impl<P: XmssParameter> AsRef<[u8]> for Signature<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: XmssParameter> TryFrom<&[u8]> for Signature<P> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Signature {
            bytes: value.to_vec(),
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> TryFrom<Vec<u8>> for Signature<P> {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Signature {
            bytes: value,
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> TryFrom<&Vec<u8>> for Signature<P> {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Signature::<P>::try_from(value.as_slice())
    }
}

impl<P: XmssParameter> TryFrom<Box<[u8]>> for Signature<P> {
    type Error = Error;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        Signature::<P>::try_from(value.as_ref())
    }
}

impl<P: XmssParameter> From<Signature<P>> for Vec<u8> {
    fn from(sig: Signature<P>) -> Vec<u8> {
        sig.bytes
    }
}

#[cfg(feature = "serde")]
impl<P: XmssParameter> serdect::serde::Serialize for Signature<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.bytes, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, P: XmssParameter> serdect::serde::Deserialize<'de> for Signature<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::try_from(bytes).map_err(serdect::serde::de::Error::custom)
    }
}

impl<P: XmssParameter> signature::SignatureEncoding for Signature<P> {
    type Repr = Vec<u8>;
}

// ---------------------------------------------------------------------------
// DetachedSignature<P>
// ---------------------------------------------------------------------------

/// A fixed-size detached XMSS signature (without appended message).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DetachedSignature<P: XmssParameter> {
    bytes: Box<[u8]>,
    _marker: PhantomData<P>,
}

impl<P: XmssParameter> AsRef<[u8]> for DetachedSignature<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: XmssParameter> TryFrom<&[u8]> for DetachedSignature<P> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != P::SIG_LEN {
            return Err(Error::InvalidSignatureLength {
                expected: P::SIG_LEN,
                got: value.len(),
            });
        }
        Ok(DetachedSignature {
            bytes: value.into(),
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> TryFrom<Vec<u8>> for DetachedSignature<P> {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != P::SIG_LEN {
            return Err(Error::InvalidSignatureLength {
                expected: P::SIG_LEN,
                got: value.len(),
            });
        }
        Ok(DetachedSignature {
            bytes: value.into_boxed_slice(),
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> TryFrom<&Vec<u8>> for DetachedSignature<P> {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        DetachedSignature::<P>::try_from(value.as_slice())
    }
}

impl<P: XmssParameter> TryFrom<Box<[u8]>> for DetachedSignature<P> {
    type Error = Error;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        if value.len() != P::SIG_LEN {
            return Err(Error::InvalidSignatureLength {
                expected: P::SIG_LEN,
                got: value.len(),
            });
        }
        Ok(DetachedSignature {
            bytes: value,
            _marker: PhantomData,
        })
    }
}

impl<P: XmssParameter> From<DetachedSignature<P>> for Vec<u8> {
    fn from(sig: DetachedSignature<P>) -> Vec<u8> {
        sig.bytes.into_vec()
    }
}

impl<P: XmssParameter> From<DetachedSignature<P>> for Box<[u8]> {
    fn from(sig: DetachedSignature<P>) -> Box<[u8]> {
        sig.bytes
    }
}

#[cfg(feature = "serde")]
impl<P: XmssParameter> serdect::serde::Serialize for DetachedSignature<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.bytes, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, P: XmssParameter> serdect::serde::Deserialize<'de> for DetachedSignature<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::try_from(bytes).map_err(serdect::serde::de::Error::custom)
    }
}

impl<P: XmssParameter> signature::SignatureEncoding for DetachedSignature<P> {
    type Repr = Box<[u8]>;
}

// ---------------------------------------------------------------------------
// KeyPair<P>
// ---------------------------------------------------------------------------

/// An XMSS key pair containing both signing and verifying keys.
///
/// This type intentionally does not implement [`Clone`]. Duplicating a
/// stateful signing key could allow both copies to use the same one-time index.
#[derive(Debug)]
pub struct KeyPair<P: XmssParameter> {
    signing_key: SigningKey<P>,
    verifying_key: VerifyingKey<P>,
}

#[cfg(test)]
impl<P: XmssParameter> Clone for KeyPair<P> {
    fn clone(&self) -> Self {
        Self {
            signing_key: self.signing_key.clone(),
            verifying_key: self.verifying_key.clone(),
        }
    }
}

impl<P: XmssParameter> KeyPair<P> {
    #[cfg(feature = "pkcs8")]
    pub(crate) fn new(signing_key: SigningKey<P>, verifying_key: VerifyingKey<P>) -> Self {
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Generates a random key pair for the parameter set `P`.
    pub fn generate<R: rand::CryptoRng>(rng: &mut R) -> XmssResult<Self> {
        let (params, mut pk, mut sk) = P::init_keypair_buffers(None)?;
        let traversal = xmss_core::xmssmt_core_keypair(
            &params,
            &mut pk[XMSS_OID_LEN..],
            &mut sk[XMSS_OID_LEN..],
            rng,
        )?;
        let pk_array = Array::<u8, P::VkLen>::try_from(pk.as_slice()).map_err(|_| {
            Error::InvalidKeyLength {
                expected: P::VK_LEN,
                got: pk.len(),
            }
        })?;
        let sk_array = Array::<u8, P::SkLen>::try_from(sk.as_slice()).map_err(|_| {
            Error::InvalidKeyLength {
                expected: P::SK_LEN,
                got: sk.len(),
            }
        })?;
        Ok(Self {
            verifying_key: VerifyingKey::new(pk_array, params),
            signing_key: SigningKey::new(sk_array, params, traversal),
        })
    }

    /// Generates a key pair from a deterministic seed.
    /// The seed must be `P::SEED_LEN` bytes (`3 * n`).
    pub fn from_seed(seed: &[u8]) -> XmssResult<Self> {
        let (params, mut pk, mut sk) = P::init_keypair_buffers(Some(seed))?;
        let traversal = xmss_core::xmssmt_core_seed_keypair(
            &params,
            &mut pk[XMSS_OID_LEN..],
            &mut sk[XMSS_OID_LEN..],
            seed,
        )?;
        let pk_array = Array::<u8, P::VkLen>::try_from(pk.as_slice()).map_err(|_| {
            Error::InvalidKeyLength {
                expected: P::VK_LEN,
                got: pk.len(),
            }
        })?;
        let sk_array = Array::<u8, P::SkLen>::try_from(sk.as_slice()).map_err(|_| {
            Error::InvalidKeyLength {
                expected: P::SK_LEN,
                got: sk.len(),
            }
        })?;
        Ok(Self {
            verifying_key: VerifyingKey::new(pk_array, params),
            signing_key: SigningKey::new(sk_array, params, traversal),
        })
    }

    /// Returns a mutable reference to the signing key.
    pub fn signing_key(&mut self) -> &mut SigningKey<P> {
        &mut self.signing_key
    }

    /// Returns a reference to the verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey<P> {
        &self.verifying_key
    }

    /// Returns an immutable reference to the signing key.
    #[cfg(any(feature = "pkcs8", test))]
    pub(crate) fn signing_key_ref(&self) -> &SigningKey<P> {
        &self.signing_key
    }
}
