//! SplitMix64 (Steele, Lea and Flood 2014; constants from Vigna's reference splitmix64.c),
//! specified here so a generated tree never changes with a dependency upgrade. Independent
//! streams come from `stream(seed, label)`: adding a storyline or a day never shifts the
//! numbers any other part of the generator draws.

use uuid::Uuid;

const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(GOLDEN);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (`n > 0`) by a 128-bit multiply; the bias is below 2^-40 for the
    /// small `n` the generator uses.
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "below(0)");
        ((u128::from(self.next_u64()) * u128::from(n)) >> 64) as u64
    }

    /// Uniform in `lo..=hi`.
    pub fn range(&mut self, lo: i64, hi: i64) -> i64 {
        assert!(lo <= hi, "range({lo}, {hi})");
        lo + self.below((hi - lo) as u64 + 1) as i64
    }

    /// Uniform in `[0, 1)` with 53 random bits.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }

    /// Fisher–Yates.
    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            v.swap(i, j);
        }
    }

    /// A version-4 UUID drawn from this stream.
    pub fn uuid(&mut self) -> Uuid {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.next_u64().to_be_bytes());
        b[8..].copy_from_slice(&self.next_u64().to_be_bytes());
        uuid::Builder::from_random_bytes(b).into_uuid()
    }

    /// Poisson count with mean `lambda`: Knuth's method below 30, a rounded normal
    /// approximation (Box–Muller) above.
    pub fn poisson(&mut self, lambda: f64) -> u64 {
        if lambda <= 0.0 {
            return 0;
        }
        if lambda < 30.0 {
            let limit = (-lambda).exp();
            let (mut k, mut p) = (0u64, 1.0f64);
            loop {
                p *= self.unit();
                if p <= limit {
                    return k;
                }
                k += 1;
            }
        }
        let (u1, u2) = (self.unit().max(f64::MIN_POSITIVE), self.unit());
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        (lambda + z * lambda.sqrt()).round().max(0.0) as u64
    }

    /// `n` lower-case hex digits.
    pub fn hex(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from_digit(self.below(16) as u32, 16).expect("hex digit"))
            .collect()
    }

    /// `n` decimal digits (the first may be 0).
    pub fn digits(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from_digit(self.below(10) as u32, 10).expect("digit"))
            .collect()
    }
}

/// FNV-1a 64 of `label`.
fn fnv1a(label: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in label.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// The stream named `label` under `seed`.
pub fn stream(seed: u64, label: &str) -> Rng {
    let mut r = Rng::new(seed ^ fnv1a(label));
    r.next_u64();
    r
}
