# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-21

### Added

- Optional `extra-depths` support for curated XMSS tree heights 1–9, 11–15,
  17–19, and 21–24 across every single-tree combination of hash function and
  output size.
- A complete guide to the extra tree depths, including capacity and size tables,
  interoperability guidance, and runnable examples.
- A dependency-free benchmark comparing warm signing with compact-key
  reconstruction before every signature.
- The initial `pq-xmss` release.

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

[Unreleased]: https://github.com/RustCrypto/pq-xmss/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/RustCrypto/pq-xmss/releases/tag/v0.1.0
