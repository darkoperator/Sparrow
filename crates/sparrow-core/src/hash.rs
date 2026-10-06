//! SHA-256 for the hot paths (a file's hash and each record's raw-bytes hash at ingest, their re-check in `verify`):
//! `ring`'s implementation, which uses the CPU's SHA-2 instructions. The `sha2` crate (0.10) hashes in software on
//! aarch64 unless built with its `asm` feature: about 345 MB/s against ring's 2.4 GB/s on an M2, 18 s of a 104 s
//! ingest of the 1M-row perf tree (docs: reports/ingest-profile.md). Same digest, same lowercase hex.

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

/// SHA-256 over data fed in pieces: the same digest as [`sha256_hex`] of the concatenation.
pub struct Sha256Stream(ring::digest::Context);

impl Default for Sha256Stream {
    fn default() -> Self {
        Sha256Stream(ring::digest::Context::new(&ring::digest::SHA256))
    }
}

impl Sha256Stream {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// Lowercase hex digest.
    pub fn finish_hex(self) -> String {
        hex::encode(self.0.finish().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn reference(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    /// A deterministic byte sequence (xorshift), so the test needs no RNG crate.
    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn known_vectors() {
        // FIPS 180-2 examples.
        for (input, want) in [
            (
                &b""[..],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                &b"abc"[..],
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                &b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"[..],
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            assert_eq!(sha256_hex(input), want);
            assert_eq!(reference(input), want);
        }
    }

    #[test]
    fn equals_sha2_on_random_inputs_one_shot_and_streamed() {
        let lengths = [
            0usize, 1, 55, 56, 63, 64, 65, 127, 128, 1000, 4095, 4096, 65_537, 1_048_577,
        ];
        for (i, &len) in lengths.iter().enumerate() {
            let data = pseudo_random(len, 0x9E37_79B9_7F4A_7C15 ^ i as u64);
            let want = reference(&data);
            assert_eq!(sha256_hex(&data), want, "len {len}");
            // Streamed in uneven pieces.
            for piece in [1usize, 7, 64, 1000, 1 << 20] {
                let mut s = Sha256Stream::new();
                for chunk in data.chunks(piece) {
                    s.update(chunk);
                }
                assert_eq!(s.finish_hex(), want, "len {len} piece {piece}");
            }
        }
    }
}
