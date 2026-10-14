//! The key derivation of a new safe (PLAN.md §5): Argon2id, 64 MiB, two
//! lanes, as many iterations as take about a second on the machine that
//! creates it, capped so a phone can still open it (docs/SPIKE-0.md §3:
//! ~22 ms per iteration on the dev laptop; the cap holds until phase 2
//! measures a real phone).

use std::time::{Duration, Instant};

use keepass::config::KdfConfig;

pub const MEMORY: u64 = 64 * 1024 * 1024;
pub const LANES: u32 = 2;
pub const TARGET: Duration = Duration::from_secs(1);
pub const MIN_ITERATIONS: u64 = 2;
pub const MAX_ITERATIONS: u64 = 40;

pub fn argon2id(iterations: u64) -> KdfConfig {
    KdfConfig::Argon2id {
        iterations,
        memory: MEMORY,
        parallelism: LANES,
        version: argon2::Version::Version13,
    }
}

/// Time `iterations` rounds of exactly the hash a save will run.
pub fn measure(iterations: u32) -> Duration {
    let config = argon2::Config {
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
        mem_cost: (MEMORY / 1024) as u32,
        time_cost: iterations,
        lanes: LANES,
        secret: &[],
        ad: &[],
        hash_length: 32,
        thread_mode: argon2::ThreadMode::Parallel,
    };
    let start = Instant::now();
    let _ = argon2::hash_raw(b"calibration", &[0u8; 32], &config);
    start.elapsed()
}

/// Iterations that take about `target` here, within the limits.
pub fn calibrate(target: Duration) -> u64 {
    let probe = 4u32;
    let per = measure(probe).as_secs_f64() / f64::from(probe);
    let n = if per > 0.0 {
        (target.as_secs_f64() / per) as u64
    } else {
        MAX_ITERATIONS
    };
    n.clamp(MIN_ITERATIONS, MAX_ITERATIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_stays_in_bounds() {
        let n = calibrate(TARGET);
        assert!((MIN_ITERATIONS..=MAX_ITERATIONS).contains(&n));
        assert_eq!(calibrate(Duration::ZERO), MIN_ITERATIONS);
        assert_eq!(calibrate(Duration::from_secs(3600)), MAX_ITERATIONS);
    }
}
