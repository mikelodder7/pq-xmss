# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-22

### Added

- Optional `extra-depths` support for curated XMSS tree heights 1–9, 11–15,
  17–19, and 21–24 across every single-tree combination of hash function and
  output size.
- A complete guide to the extra tree depths, including capacity and size tables,
  interoperability guidance, and runnable examples.
- A dependency-free benchmark comparing warm signing with compact-key
  reconstruction before every signature.
- The initial `pq-xmss` release.
- `no_std` support on targets with an allocator through the `alloc` feature.
- A `FixedDigest` abstraction with type-level 24-, 32-, and 64-byte XMSS
  outputs.
- Alloc-backed runtime parameter selection through `ParameterSet`,
  `BoxedKeyPair`, `BoxedSigningKey`, `BoxedVerifyingKey`, and
  boxed attached and detached signatures.
- Matching inherent attached and detached sign/verify methods across the
  compile-time and runtime-selected key APIs.

### Changed

- Renamed the package from `xmss` to `pq-xmss` and updated the project URLs.
- Cached authentication-path traversal state in memory while preserving the
  compact signing-key format used by raw, serde, and PKCS#8 encodings. Warm
  signing now updates changed nodes incrementally and XMSS^MT reuses unchanged
  upper-layer WOTS signatures.
- Standardized the Apache-2.0 and MIT license notices.
- Removed `Clone` from signing keys and key pairs to prevent accidental forks
  that could reuse a one-time signature index.
- PKCS#8 decoding now rejects an embedded public key that does not match the
  private key.
- Authentication-tree roots and cached root messages now use fixed-size digest
  arrays instead of variable-length vectors.
- Detached signing and verification now stream borrowed message bytes instead
  of allocating combined signature-and-message buffers.
- Small bounded hash and WOTS workspaces now use fixed scratch arrays, and
  retained authentication paths and WOTS signatures use exact-length boxed
  slices. This reduces allocation churn and cache metadata without discarding
  the upper-layer signatures that make warm XMSS^MT signing fast.
- Expanded README and API documentation covering state persistence, runtime
  parameter selection, `no_std`, XMSS versus XMSS^MT selection, and traversal
  performance.

[Unreleased]: https://github.com/RustCrypto/pq-xmss/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/RustCrypto/pq-xmss/releases/tag/v0.1.0
