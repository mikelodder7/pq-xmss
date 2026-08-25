# XMSS

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
[![Downloads][downloads-image]][crate-link]
![build](https://github.com/mikelodder7/pq-xmss/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/mikelodder7/pq-xmss/branch/master/graph/badge.svg)](https://codecov.io/gh/mikelodder7/pq-xmss)
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
- 93 standardized parameter sets, plus 147 optional private-use XMSS sets
- Hash output sizes of 192, 256, and 512 bits
- Optional `serde` support for compile-time key and signature types
- Optional `pkcs8` support for compile-time PKCS#8 and SPKI key encoding
- Optional runtime parameter selection through alloc-backed boxed key types
- `no_std` support on targets with a global allocator
- No `unsafe` code—zero `unsafe` blocks
- Constant-time operations for signature verification
- Automatic zeroization of secret key material on drop

## Usage

```rust
use pq_xmss::{H10, KeyPair, XmssSha2_256};

fn main() -> Result<(), pq_xmss::Error> {
    // Generate a key pair.
    let mut keypair = KeyPair::<XmssSha2_256<H10>>::generate(&mut rand::rng())?;

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
same `SigningKey` do not reuse a one-time index. XMSS requires
authentication-path traversal data, which is cached only in memory for
performance. Serialization, PKCS#8, and `AsRef<[u8]>` retain the compact key
format. Decoding that compact form reconstructs the cache for its stored index
once; subsequent signatures update it incrementally. This pays the tree-build
cost once when loading a `SigningKey` and substantially reduces warm signing
time.

The caller chooses how to persist the key, such as in a keychain, file, or
database. If the key will be used after a restart, atomically replace the stored
state before relying on the signature. If all indices have been consumed, the
exhausted key can instead be removed from storage. The caller must also prevent
two live `SigningKey` values from being created from the same compact state and
used concurrently. `SigningKey` and `KeyPair` intentionally do not implement
`Clone`, since cloned stateful keys could reuse a one-time index.

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

| Parameter family | Hash | `n` (bytes) | Standard depths |
| --- | --- | ---: | --- |
| `XmssSha2_192<D>` | SHA-256 | 24 | `H10`, `H16`, `H20` |
| `XmssSha2_256<D>` | SHA-256 | 32 | `H10`, `H16`, `H20` |
| `XmssSha2_512<D>` | SHA-512 | 64 | `H10`, `H16`, `H20` |
| `XmssShake_256<D>` | SHAKE128 | 32 | `H10`, `H16`, `H20` |
| `XmssShake_512<D>` | SHAKE256 | 64 | `H10`, `H16`, `H20` |
| `XmssShake256_192<D>` | SHAKE256 | 24 | `H10`, `H16`, `H20` |
| `XmssShake256_256<D>` | SHAKE256 | 32 | `H10`, `H16`, `H20` |

The standard markers provide 1,024, 65,536, and 1,048,576 signatures,
respectively. Existing concrete names such as `XmssSha2_10_256` remain
available for compatibility. With the `extra-depths` feature, every family also
supports the remaining depth markers between 1 and 24.
See the [extra tree depths guide](docs/extra-depths.md) for every depth and
family, size formulas, interoperability and state-management guidance, and
three runnable examples.

### XMSS^MT (Multi-Tree)

Multi-tree parameter sets follow the naming convention
`XmssMt[Hash]_[TotalHeight]_[Layers]_[Bits]`, for example,
`XmssMtSha2_20_2_256`.

Total tree heights of 20, 40, and 60 are supported with 2, 3, 4, 6, 8, or 12
layers where applicable, across SHA-256, SHA-512, SHAKE128, and SHAKE256 hash
functions.

See the [API documentation][docs-link] for a complete list of all 72 XMSS^MT
parameter sets.

#### Choosing XMSS or XMSS^MT

Use XMSS when smaller signatures, faster verification, and a simpler tree
structure matter most. Its single tree is a good fit when the required signing
capacity is modest and generating the selected tree height is affordable. For
example, `XmssSha2_256<H10>` permits 1,024 signatures from one key.

Use XMSS^MT when a key needs a much larger signing capacity or when generating
a single tree at the desired total height would be impractical. XMSS^MT divides
the total height across several smaller trees, making key generation much
faster for the same total height. The tradeoff is a larger signature and more
verification work because the signature contains one WOTS+ signature per
layer. For SHA2-256, an XMSS height-20 signature is approximately 2,820 bytes,
compared with 4,963 bytes for XMSS^MT 20/2 and 9,251 bytes for XMSS^MT 20/4.

As a practical starting point, use `XmssSha2_256<H10>` for up to 1,024 compact
signatures and `XmssMtSha2_20_2_256` for a long-lived key with up to 2^20
signatures. Height-40 and height-60 XMSS^MT parameter sets are best reserved for
applications that genuinely require their enormous capacities. XMSS^MT does
not inherently provide greater cryptographic security than XMSS with the same
hash function and output size; its principal advantages are capacity and key
generation performance. Both variants require the same careful, persistent
state management. [RFC 8391] similarly recommends considering XMSS^MT when
more signatures or faster key generation are required.

### Runtime-selected parameter sets

The generic key types provide compile-time parameter validation. Applications
that select a standardized parameter set from configuration can instead use
the alloc-backed boxed API:

```rust
use pq_xmss::{BoxedKeyPair, ParameterSet};

fn main() -> Result<(), pq_xmss::Error> {
    let parameter_set = ParameterSet::from_name("XMSSMT-SHA2_20/2_256")?;
    let mut keypair = BoxedKeyPair::generate(parameter_set, &mut rand::rng())?;
    let message = b"runtime-selected signature";
    let signature = keypair.signing_key().sign_detached(message)?;
    keypair
        .verifying_key()
        .verify_detached(&signature, message)?;
    Ok(())
}
```

The boxed API is optional. Prefer `SigningKey<P>` and the other generic types
when the parameter set is known at compile time. Use `BoxedSigningKey` when a
standardized parameter set must be selected at runtime, such as from
configuration, protocol negotiation, or heterogeneous database records.

The two APIs expose the same inherent signing and verification operations:

| Compile-time API | Runtime-selected API |
| --- | --- |
| `SigningKey::sign` | `BoxedSigningKey::sign` |
| `SigningKey::sign_detached` | `BoxedSigningKey::sign_detached` |
| `VerifyingKey::verify` | `BoxedVerifyingKey::verify` |
| `VerifyingKey::verify_detached` | `BoxedVerifyingKey::verify_detached` |

`ParameterSet` accepts only the standardized parameter sets implemented by the
crate. Internally, boxed signing keys dispatch to traversal states with fixed
24-, 32-, or 64-byte digest outputs; arbitrary digest lengths are rejected.
As with generic signing keys, boxed signing keys intentionally do not implement
`Clone`, and the advanced compact state must be persisted atomically. Generic
and boxed keys use the same compact key and signature formats. Because raw
boxed signature bytes do not identify their parameter set, decoding a
`BoxedSignature` or `BoxedDetachedSignature` requires the corresponding
`ParameterSet`.

The generic types integrate with the `signature` crate through `SignerMut`,
`Verifier`, and `SignatureEncoding`. Runtime-selected signature wrappers cannot
satisfy `SignatureEncoding`'s parameter-free decoding requirement without
adding metadata to the wire format, so boxed consumers use the inherent methods
shown above.

Parameter types also implement `FixedDigest`, which exposes the effective XMSS
digest size at the type level:

```rust
use pq_xmss::{FixedDigest, H10, XmssSha2_192};

let output = XmssSha2_192::<H10>::digest(b"XMSS input")?;
assert_eq!(output.len(), 24);
# Ok::<(), pq_xmss::Error>(())
```

## `no_std` support

The crate supports `no_std` targets with a global allocator. Disable default
features and enable `alloc` explicitly:

```toml
[dependencies]
pq-xmss = { version = "0.2.0", default-features = false, features = ["alloc"] }
```

Tree construction retains only linear-height stacks and authentication paths,
not complete Merkle trees. Available RAM still matters: the largest XMSS^MT
parameter sets have signatures and traversal caches around 100 KiB. The caller
must supply a cryptographically secure RNG to key generation; the `no_std`
library does not access operating-system randomness.

The crate does not currently support allocator-free targets. Enabling
`extra-depths`, `pkcs8`, or `serde` without default features therefore also
requires `alloc`.

## Features

| Feature | Description |
| --- | --- |
| `alloc` | Enables heap-backed keys, signatures, traversal state, and runtime parameter selection; required when `std` is disabled |
| `extra-depths` | Adds the non-standard single-tree depth markers between 1 and 24; `H10`, `H16`, and `H20` are always available |
| `pkcs8` | Enables PKCS#8 and SPKI encoding and decoding for compile-time key types |
| `serde` | Enables `serde` serialization and deserialization for compile-time key and signature types via `serdect` |
| `std` | Enables standard-library support and implies `alloc` (enabled by default) |

## Benchmarking

Run the dependency-free signing benchmark with:

```text
cargo bench --bench signing --features extra-depths
```

It reports key generation, compact-key decoding, warm sequential signing, and
decoding before every signature. The last comparison measures the effect of
retaining traversal state in memory.

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

[RFC 8391]: https://www.rfc-editor.org/rfc/rfc8391
[NIST SP 800-208]: https://csrc.nist.gov/pubs/sp/800/208/final
