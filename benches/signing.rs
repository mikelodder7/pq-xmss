//! Signing and compact-state reconstruction benchmarks.

use std::hint::black_box;
use std::time::{Duration, Instant};

use pq_xmss::{
    H8, KeyPair, SigningKey, XmssMtSha2_20_2_256, XmssParameter, XmssResult, XmssSha2_10_256,
    XmssSha2_256,
};

struct Measurements {
    cold_sign: Duration,
    decode: Duration,
    generate: Duration,
    name: &'static str,
    warm_sign: Duration,
}

fn average_duration<E>(
    iterations: u32,
    mut operation: impl FnMut() -> Result<(), E>,
) -> Result<Duration, E> {
    let started = Instant::now();
    for _ in 0..iterations {
        operation()?;
    }
    Ok(started.elapsed() / iterations)
}

fn measure<P: XmssParameter>(
    name: &'static str,
    generation_iterations: u32,
    signing_iterations: u32,
) -> XmssResult<Measurements> {
    let generate = average_duration(generation_iterations, || {
        black_box(KeyPair::<P>::generate(&mut rand::rng())?);
        Ok::<(), pq_xmss::Error>(())
    })?;

    let mut keypair = KeyPair::<P>::generate(&mut rand::rng())?;
    let compact = keypair.signing_key().as_ref().to_vec();

    let decode = average_duration(generation_iterations, || {
        black_box(SigningKey::<P>::try_from(black_box(compact.as_slice()))?);
        Ok::<(), pq_xmss::Error>(())
    })?;

    let warm_sign = average_duration(signing_iterations, || {
        black_box(
            keypair
                .signing_key()
                .sign_detached(black_box(b"benchmark message"))?,
        );
        Ok::<(), pq_xmss::Error>(())
    })?;

    let mut persisted = compact;
    let cold_sign = average_duration(signing_iterations, || {
        let mut signing_key = SigningKey::<P>::try_from(black_box(persisted.as_slice()))?;
        black_box(signing_key.sign_detached(black_box(b"benchmark message"))?);
        persisted.clear();
        persisted.extend_from_slice(signing_key.as_ref());
        Ok::<(), pq_xmss::Error>(())
    })?;

    Ok(Measurements {
        cold_sign,
        decode,
        generate,
        name,
        warm_sign,
    })
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn main() -> XmssResult<()> {
    let measurements = [
        measure::<XmssSha2_256<H8>>("XMSS-SHA2_8_256", 3, 16)?,
        measure::<XmssSha2_10_256>("XMSS-SHA2_10_256", 3, 8)?,
        measure::<XmssMtSha2_20_2_256>("XMSSMT-SHA2_20/2_256", 2, 4)?,
    ];

    println!(
        "{:<24} {:>12} {:>12} {:>14} {:>14} {:>10}",
        "parameter set", "generate", "decode", "warm sign", "reload+sign", "speedup"
    );
    for measurement in measurements {
        let speedup = measurement.cold_sign.as_secs_f64() / measurement.warm_sign.as_secs_f64();
        println!(
            "{:<24} {:>9.3} ms {:>9.3} ms {:>11.3} ms {:>11.3} ms {:>9.1}x",
            measurement.name,
            milliseconds(measurement.generate),
            milliseconds(measurement.decode),
            milliseconds(measurement.warm_sign),
            milliseconds(measurement.cold_sign),
            speedup,
        );
    }

    Ok(())
}
