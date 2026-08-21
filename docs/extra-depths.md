# Extra tree depths

The `extra-depths` Cargo feature adds non-standard, single-tree XMSS parameter
sets for applications that need a signature capacity not offered by the
standardized tree heights. This does not impact the security as XMSS security is
a function of the hash used and not its height.

```toml
[dependencies]
pq-xmss = { version = "*", features = ["extra-depths"] }
```

Each parameter set combines a generic parameter family, which selects a hash
function and output size, with a depth marker:

```text
XmssSha2_256<H4>
│              └── tree depth: 4 (16 signatures)
└───────────────── family: SHA-256 with n = 32 bytes
```

## Available depths

The depth controls key-generation cost, signature capacity, and the length of
the authentication path included in each signature. A key can create at most
`2^height` signatures.

| Marker | Height | Maximum signatures |
| --- | ---: | ---: |
| `H1` | 1 | 2 |
| `H2` | 2 | 4 |
| `H3` | 3 | 8 |
| `H4` | 4 | 16 |
| `H5` | 5 | 32 |
| `H6` | 6 | 64 |
| `H7` | 7 | 128 |
| `H8` | 8 | 256 |
| `H9` | 9 | 512 |
| `H11` | 11 | 2,048 |
| `H12` | 12 | 4,096 |
| `H13` | 13 | 8,192 |
| `H14` | 14 | 16,384 |
| `H15` | 15 | 32,768 |
| `H17` | 17 | 131,072 |
| `H18` | 18 | 262,144 |
| `H19` | 19 | 524,288 |
| `H21` | 21 | 2,097,152 |
| `H22` | 22 | 4,194,304 |
| `H23` | 23 | 8,388,608 |
| `H24` | 24 | 16,777,216 |

Heights 10, 16, and 20 already have standardized concrete parameter types,
such as `XmssSha2_10_256`, so they do not have extra-depth marker types. The
feature stops at height 24 because key generation grows exponentially with the
height; choose the smallest capacity that meets the application's lifetime
requirements.

## Available families

Every depth marker above can be used with every family below, for 147 extra
parameter sets. In the signature-size formulas, `h` is the selected height.

| Generic family | Hash | `n` (bytes) | Secret key | Public key | Detached signature |
| --- | --- | ---: | ---: | ---: | ---: |
| `XmssSha2_192<D>` | SHA-256 | 24 | 104 bytes | 52 bytes | `1,252 + 24h` bytes |
| `XmssSha2_256<D>` | SHA-256 | 32 | 136 bytes | 68 bytes | `2,180 + 32h` bytes |
| `XmssSha2_512<D>` | SHA-512 | 64 | 264 bytes | 132 bytes | `8,452 + 64h` bytes |
| `XmssShake_256<D>` | SHAKE128 | 32 | 136 bytes | 68 bytes | `2,180 + 32h` bytes |
| `XmssShake_512<D>` | SHAKE256 | 64 | 264 bytes | 132 bytes | `8,452 + 64h` bytes |
| `XmssShake256_192<D>` | SHAKE256 | 24 | 104 bytes | 52 bytes | `1,252 + 24h` bytes |
| `XmssShake256_256<D>` | SHAKE256 | 32 | 136 bytes | 68 bytes | `2,180 + 32h` bytes |

The public and secret key lengths do not change with tree height. Each level in
the authentication path adds `n` bytes to a detached signature.

Tree generation and compact-key decoding rebuild the tree and therefore grow
exponentially with the selected depth. Once a key is resident in memory,
sequential signatures reuse its authentication-path cache and update only the
nodes that change. This makes warm signing substantially cheaper, but it does
not remove the cold-load cost or occasional boundary spikes. Prefer the
smallest depth that supplies the required signature capacity.

## Example: sign and verify with a small tree

`H1` is useful for tests or workflows that need exactly two signatures:

```rust
# #[cfg(feature = "extra-depths")]
# fn main() -> Result<(), pq_xmss::Error> {
use pq_xmss::{H1, KeyPair, XmssSha2_256, XmssTreeDepth};

type Params = XmssSha2_256<H1>;
assert_eq!(H1::MAX_SIGNATURES, 2);

let mut keypair = KeyPair::<Params>::generate(&mut rand::rng())?;
let message = b"approve release";
let signature = keypair.signing_key().sign_detached(message)?;
keypair.verifying_key().verify_detached(&signature, message)?;
# Ok(())
# }
# #[cfg(not(feature = "extra-depths"))]
# fn main() {}
```

## Example: select a different family and deterministic seed

The depth type is independent of the parameter family. This example selects a
SHAKE256 family with a 192-bit output and a height-four tree:

```rust
# #[cfg(feature = "extra-depths")]
# fn main() -> Result<(), pq_xmss::Error> {
use pq_xmss::{H4, KeyPair, XmssParameter, XmssShake256_192};

type Params = XmssShake256_192<H4>;
let seed = vec![0x42; Params::SEED_LEN];
let mut keypair = KeyPair::<Params>::from_seed(&seed)?;

let signed_message = keypair.signing_key().sign(b"deterministic key")?;
let recovered = keypair.verifying_key().verify(&signed_message)?;
assert_eq!(recovered, b"deterministic key");
# Ok(())
# }
# #[cfg(not(feature = "extra-depths"))]
# fn main() {}
```

A deterministic seed recreates only the initial key state. It must not be used
to restart signing from index zero after any signatures have been issued.

## Example: save and resume signing state

XMSS is stateful. Every signing call updates the key in memory. If the key will
be used after a restart, persist it and replace the
previous state atomically before relying on the signature. Restoring an older
copy can reuse a one-time key and compromise security. If any index is reused,
the entire `SigningKey` is considered compromised. An exhausted key
can instead be removed without persisting its exhausted state.

```rust
# #[cfg(feature = "extra-depths")]
# fn main() -> Result<(), pq_xmss::Error> {
use pq_xmss::{H2, KeyPair, SigningKey, XmssSha2_256};

type Params = XmssSha2_256<H2>;
let mut keypair = KeyPair::<Params>::generate(&mut rand::rng())?;
let verifying_key = keypair.verifying_key().clone();

let first = keypair.signing_key().sign_detached(b"first")?;
verifying_key.verify_detached(&first, b"first")?;

// Store these bytes securely and atomically after signing.
let saved_state = keypair.signing_key().as_ref().to_vec();
let mut signing_key = SigningKey::<Params>::try_from(saved_state.as_slice())?;

let second = signing_key.sign_detached(b"second")?;
verifying_key.verify_detached(&second, b"second")?;
# Ok(())
# }
# #[cfg(not(feature = "extra-depths"))]
# fn main() {}
```

## Interoperability

These parameter sets are not assigned identifiers by RFC 8391 or NIST
SP 800-208. Serialized keys use a crate-defined private-use identifier with the
layout `0xff | family | 0x00 | height`. They interoperate only with
implementations that adopt the same encoding. Prefer a standardized height
when cross-implementation compatibility is required.
