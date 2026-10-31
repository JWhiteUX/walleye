//! Small, self-contained PRNG (xoshiro256** seeded with SplitMix64).
//!
//! We do not use the `rand` crate: its algorithms and value streams may change
//! between versions, and fixtures must be byte-identical for a given seed.

#[derive(Debug, Clone)]
pub struct Rng {
    s: [u64; 4],
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut st = seed;
        Rng {
            s: [
                splitmix(&mut st),
                splitmix(&mut st),
                splitmix(&mut st),
                splitmix(&mut st),
            ],
        }
    }

    /// Independent child stream; consumes one value from `self`.
    pub fn fork(&mut self) -> Rng {
        Rng::new(self.next_u64())
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    pub fn next_u16(&mut self) -> u16 {
        (self.next_u64() >> 48) as u16
    }

    /// Uniform in `0..n` (0 when `n == 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        ((u128::from(self.next_u64()) * u128::from(n)) >> 64) as u64
    }

    /// Uniform in `lo..=hi`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.below(hi - lo + 1)
    }

    /// Uniform in `[0, 1)`.
    pub fn f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    /// Uniform in `[lo, hi)`.
    pub fn uniform(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.f64()
    }

    pub fn chance(&mut self, p: f64) -> bool {
        self.f64() < p
    }

    /// Exponential with the given mean.
    pub fn exp(&mut self, mean: f64) -> f64 {
        -mean * (1.0 - self.f64()).ln()
    }

    /// Log-normal size: `median * exp(sigma * N(0,1))`, clamped to `[lo, hi]`.
    pub fn lognormal(&mut self, median: f64, sigma: f64, lo: f64, hi: f64) -> f64 {
        (median * (sigma * self.normal()).exp()).clamp(lo, hi)
    }

    /// Standard normal (Box-Muller).
    pub fn normal(&mut self) -> f64 {
        let u1 = 1.0 - self.f64();
        let u2 = self.f64();
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        let mut chunks = buf.chunks_exact_mut(8);
        for c in &mut chunks {
            c.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let v = self.next_u64().to_le_bytes();
            let n = rem.len();
            rem.copy_from_slice(&v[..n]);
        }
    }

    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        self.fill(&mut b);
        b
    }

    pub fn vec(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.fill(&mut v);
        v
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }

    /// Index chosen with probability proportional to `weights[i]`.
    pub fn weighted(&mut self, weights: &[u32]) -> usize {
        let total: u64 = weights.iter().map(|&w| u64::from(w)).sum();
        let mut x = self.below(total.max(1));
        for (i, &w) in weights.iter().enumerate() {
            if x < u64::from(w) {
                return i;
            }
            x -= u64::from(w);
        }
        weights.len().saturating_sub(1)
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            items.swap(i, j);
        }
    }

    /// Random string over `alphabet`.
    pub fn string(&mut self, alphabet: &[u8], len: usize) -> String {
        (0..len).map(|_| char::from(*self.pick(alphabet))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut c = Rng::new(43);
        assert_ne!(Rng::new(42).next_u64(), c.next_u64());
    }

    #[test]
    fn below_and_range_stay_in_bounds() {
        let mut r = Rng::new(1);
        for _ in 0..10_000 {
            assert!(r.below(7) < 7);
            let v = r.range(3, 5);
            assert!((3..=5).contains(&v));
            let f = r.f64();
            assert!((0.0..1.0).contains(&f));
        }
    }

    #[test]
    fn weighted_respects_zero_weights() {
        let mut r = Rng::new(9);
        for _ in 0..1000 {
            assert_ne!(r.weighted(&[5, 0, 5]), 1);
        }
    }
}
