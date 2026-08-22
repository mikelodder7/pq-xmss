use alloc::string::String;

/// Error type used throughout this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The OID value is not recognized.
    #[error("Invalid OID: 0x{0:08x}")]
    InvalidOid(u32),
    /// The parameter set name is not recognized.
    #[error("Invalid parameter set: {0}")]
    InvalidParameterSet(String),
    /// A key or signature uses a different parameter set than expected.
    #[error("Parameter sets do not match")]
    ParameterSetMismatch,
    /// The in-memory traversal cache is inconsistent with the compact key.
    #[error("In-memory traversal state is inconsistent")]
    TraversalState,
    /// The Winternitz parameter value is not supported.
    #[error("Invalid parameters: unsupported Winternitz parameter w={0}")]
    InvalidParams(u32),
    /// All one-time signatures have been used.
    #[error("Key exhausted: all one-time signatures have been used")]
    KeyExhausted,
    /// The provided seed has an incorrect length.
    #[error("Invalid seed length: expected {expected}, got {got}")]
    InvalidSeedLength {
        /// Expected seed length in bytes.
        expected: usize,
        /// Actual seed length in bytes.
        got: usize,
    },
    /// Signature verification failed.
    #[error("Signature verification failed")]
    VerificationFailed,
    /// The hash function configuration is not supported.
    #[error("Hash function error: unsupported n={n} with func={func}")]
    Hash {
        /// The hash output length parameter.
        n: u32,
        /// The hash function identifier.
        func: u32,
    },
    /// A digest output has an incorrect length.
    #[error("Invalid digest length: expected {expected}, got {got}")]
    InvalidDigestLength {
        /// Expected digest length in bytes.
        expected: usize,
        /// Actual digest length in bytes.
        got: usize,
    },
    /// The provided key has an incorrect length.
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length in bytes.
        got: usize,
    },
    /// The public key embedded in a private-key encoding does not match it.
    #[cfg(feature = "pkcs8")]
    #[error("Embedded public key does not match the private key")]
    PublicKeyMismatch,
    /// The provided signature has an incorrect length.
    #[error("Invalid signature length: expected {expected}, got {got}")]
    InvalidSignatureLength {
        /// Expected signature length in bytes.
        expected: usize,
        /// Actual signature length in bytes.
        got: usize,
    },
    /// A PKCS#8 error.
    #[cfg(feature = "pkcs8")]
    #[error("PKCS#8 error: {0}")]
    Pkcs8(pkcs8::Error),
}

/// Result type used throughout this crate.
pub type XmssResult<T> = Result<T, Error>;

#[cfg(feature = "pkcs8")]
impl From<pkcs8::Error> for Error {
    fn from(err: pkcs8::Error) -> Self {
        Self::Pkcs8(err)
    }
}

#[cfg(feature = "pkcs8")]
impl From<pkcs8::KeyError> for Error {
    fn from(err: pkcs8::KeyError) -> Self {
        Self::Pkcs8(err.into())
    }
}
