# [RustCrypto]: XMSS

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
[![Downloads][downloads-image]][crate-link]
![build](https://github.com/RustCrypto/pq-xmss/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/RustCrypto/pq-xmss/branch/master/graph/badge.svg)](https://codecov.io/gh/RustCrypto/pq-xmss)
![MSRV][msrv-image]

Pure Rust implementation of the XMSS (eXtended Merkle Signature Scheme)
and XMSS^MT (Multi-Tree) signature schemes as described in [RFC 8391] and
[NIST SP 800-208].

## ⚠️ Security Warning

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

## About

XMSS is a stateful hash-based digital signature scheme that is believed to be
resistant to attacks by quantum computers. It is standardized in [RFC 8391] and
approved by NIST in [SP 800-208].

This crate provides:

- XMSS (single-tree) and XMSS^MT (multi-tree) signature schemes
- SHA-256, SHA-512, SHAKE128, and SHAKE256 hash function support
- 93 parameter sets covering tree heights of 10, 16, 20, 40, and 60
- Hash output sizes of 192, 256, and 512 bits
- Optional `serde` support for serialization and deserialization
- Optional `pkcs8` support for PKCS#8 and SPKI key encoding
- No `unsafe` code—zero `unsafe` blocks
- Constant-time operations for signature verification
- Automatic zeroization of secret key material on drop

## Usage

```rust
use pq_xmss::{KeyPair, XmssSha2_10_256};

fn main() -> Result<(), pq_xmss::Error> {
    // Generate a key pair.
    let mut keypair = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng())?;

    // Sign a message.
    let message = b"test message";
    let signature = keypair.signing_key().sign(message)?;

    // Verify the signature and recover the message.
    let recovered = keypair.verifying_key().verify(&signature)?;
    assert_eq!(recovered, message);

    // Detached signatures are also supported.
    let signature = keypair.signing_key().sign_detached(message)?;
    keypair
        .verifying_key()
        .verify_detached(&signature, message)?;

    Ok(())
}
```

## State Management

Every signing call advances the key held in memory, so subsequent calls on the
same `SigningKey` do not reuse a one-time index. Authentication-path traversal
data is cached only in memory; serialization, PKCS#8, and `AsRef<[u8]>` retain
the existing compact key format. Decoding that compact form reconstructs the
cache for its stored index once; subsequent signatures update it incrementally.

The caller chooses how to persist that compact state, such as a keychain, file,
or database. If the key will be used after a restart, replace the stored state
atomically before relying on the signature. If all indices have been consumed,
the exhausted key can instead be removed from storage. The caller must also
prevent two live `SigningKey` values from being created from the same compact
state and used concurrently. `SigningKey` and `KeyPair` intentionally do not
implement `Clone`, since cloned stateful keys could reuse a one-time index.

### Traversal Performance

The in-memory cache retains the authentication path and root for each active
XMSS or XMSS^MT layer. It does not retain complete Merkle trees, so its retained
memory grows with the number of layers and tree height rather than the number
of leaves.

| Operation | Traversal work |
| --- | --- |
| Key generation | Builds each active tree and initializes its cache |
| Compact-key decoding | Rebuilds each active tree for the stored index |
| Sequential signing | Recomputes only changed authentication-path nodes |
| XMSS^MT signing | Reuses unchanged upper-layer WOTS signatures |
| Subtree rollover | Builds the next active subtree |

Consequently, generation and decoding remain cold operations whose cost grows
exponentially with the per-layer tree height. Warm sequential signing avoids a
full-tree traversal on every call. Some index boundaries still require more
work than neighboring signatures, and a subtree rollover incurs another cold
tree build. The cache is an incremental traversal optimization rather than a
full BDS implementation.

## Supported Parameter Sets

### XMSS (Single-Tree)

| Parameter Set | Hash | `n` (bytes) | Tree Height | Maximum Signatures |
| --- | --- | --- | --- | --- |
| `XmssSha2_10_256` | SHA-256 | 32 | 10 | 1,024 |
| `XmssSha2_16_256` | SHA-256 | 32 | 16 | 65,536 |
| `XmssSha2_20_256` | SHA-256 | 32 | 20 | 1,048,576 |
| `XmssSha2_10_512` | SHA-512 | 64 | 10 | 1,024 |
| `XmssSha2_16_512` | SHA-512 | 64 | 16 | 65,536 |
| `XmssSha2_20_512` | SHA-512 | 64 | 20 | 1,048,576 |
| `XmssSha2_10_192` | SHA-256 | 24 | 10 | 1,024 |
| `XmssSha2_16_192` | SHA-256 | 24 | 16 | 65,536 |
| `XmssSha2_20_192` | SHA-256 | 24 | 20 | 1,048,576 |
| `XmssShake_10_256` | SHAKE128 | 32 | 10 | 1,024 |
| `XmssShake_16_256` | SHAKE128 | 32 | 16 | 65,536 |
| `XmssShake_20_256` | SHAKE128 | 32 | 20 | 1,048,576 |
| `XmssShake_10_512` | SHAKE256 | 64 | 10 | 1,024 |
| `XmssShake_16_512` | SHAKE256 | 64 | 16 | 65,536 |
| `XmssShake_20_512` | SHAKE256 | 64 | 20 | 1,048,576 |
| `XmssShake256_10_256` | SHAKE256 | 32 | 10 | 1,024 |
| `XmssShake256_16_256` | SHAKE256 | 32 | 16 | 65,536 |
| `XmssShake256_20_256` | SHAKE256 | 32 | 20 | 1,048,576 |
| `XmssShake256_10_192` | SHAKE256 | 24 | 10 | 1,024 |
| `XmssShake256_16_192` | SHAKE256 | 24 | 16 | 65,536 |
| `XmssShake256_20_192` | SHAKE256 | 24 | 20 | 1,048,576 |

With the `extra-depths` feature, every single-tree combination of hash function
and output size also supports 21 curated heights between 1 and 24. See the
[extra tree depths guide](docs/extra-depths.md) for every depth and family,
size formulas, interoperability and state-management guidance, and three
runnable examples.

### XMSS^MT (Multi-Tree)

Multi-tree parameter sets follow the naming convention
`XmssMt[Hash]_[TotalHeight]_[Layers]_[Bits]`, for example,
`XmssMtSha2_20_2_256`.

Total tree heights of 20, 40, and 60 are supported with 2, 3, 4, 6, 8, or 12
layers where applicable, across SHA-256, SHA-512, SHAKE128, and SHAKE256 hash
functions.

See the [API documentation][docs-link] for a complete list of all 72 XMSS^MT
parameter sets.

## Features

| Feature | Description |
| --- | --- |
| `extra-depths` | Enables non-standard single-tree heights 1–9, 11–15, 17–19, and 21–24 |
| `pkcs8` | Enables PKCS#8 and SPKI key encoding and decoding |
| `serde` | Enables `serde` serialization and deserialization via `serdect` |

## Benchmarking

Run the dependency-free signing benchmark with:

```text
cargo bench --bench signing --features extra-depths
```

It reports key generation, compact-key decoding, warm sequential signing, and
decoding before every signature. The last comparison measures the effect of
retaining traversal state in memory.

A representative release-mode run produced the following average times per
operation. Results vary by machine, so run the benchmark when choosing a
parameter set.

| Parameter set | Generate | Decode | Warm sign | Reload + sign | Speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| XMSS SHA2 H8 | 141.5 ms | 146.0 ms | 3.28 ms | 156.0 ms | 47.6× |
| XMSS SHA2 H10 | 613.5 ms | 632.1 ms | 3.88 ms | 611.8 ms | 157.9× |
| XMSSMT SHA2 20/2 | 1,235.6 ms | 1,214.8 ms | 1.72 ms | 1,230.0 ms | 714.5× |

“Reload + sign” deliberately decodes the updated compact key before every
signature, approximating the previous full-tree-per-signature behavior.

## Minimum Supported Rust Version

This crate uses Rust 2024 edition and requires **Rust 1.85 or newer**.

## License

Licensed under

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/pq-xmss?logo=rust
[crate-link]: https://crates.io/crates/pq-xmss
[docs-image]: https://docs.rs/pq-xmss/badge.svg
[docs-link]: https://docs.rs/pq-xmss/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[downloads-image]: https://img.shields.io/crates/d/pq-xmss.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto
[RFC 8391]: https://www.rfc-editor.org/rfc/rfc8391
[NIST SP 800-208]: https://csrc.nist.gov/pubs/sp/800/208/final
