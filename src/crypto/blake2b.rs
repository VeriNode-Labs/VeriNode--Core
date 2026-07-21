//! Minimal, dependency-free BLAKE2b-256 (RFC 7693).
//!
//! Hand-rolled so the crate stays `no_std` and pulls in no extra dependencies,
//! following the same pattern as [`crate::crypto::sha256`].  Only the 256-bit
//! output variant is exposed, which is all that the nonce generator needs.
//!
//! This implementation covers the non-keyed, non-personalized variant
//! (`h = 32`, no key, no salt, no personalization).

/// BLAKE2b initialisation vector (from RFC 7693, Appendix C).
const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// BLAKE2 sigma permutation table (RFC 7693, Table 2).
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Compute BLAKE2b-256 of `input` (no key, no salt, no personalization).
///
/// Returns a 32-byte digest.  The output is deterministic and is used by the
/// proof-of-connectivity nonce generator to bind nonces to their epoch.
pub fn blake2b_256(input: &[u8]) -> [u8; 32] {
    // Parameter block: h=32 (0x20), key length=0, fanout=1, max depth=1.
    // p[0] = 0x0101_0020  (digest_length=32, key_length=0, fanout=1, depth=1)
    let param_block: u64 = 0x0000_0000_0101_0020;

    let mut h = IV;
    h[0] ^= param_block;

    let mut counter_lo: u64 = 0;
    let mut counter_hi: u64 = 0;

    let total = input.len();

    if total == 0 {
        // Empty input: single final block of all zeros.
        let block = [0u8; 128];
        compress(&mut h, &block, 0, 0, true);
    } else {
        let mut offset = 0usize;
        loop {
            let remaining = total - offset;
            let is_last = remaining <= 128;
            let take = if is_last { remaining } else { 128 };

            let mut block = [0u8; 128];
            block[..take].copy_from_slice(&input[offset..offset + take]);

            let new_lo = counter_lo.wrapping_add(take as u64);
            if new_lo < counter_lo {
                counter_hi = counter_hi.wrapping_add(1);
            }
            counter_lo = new_lo;

            compress(&mut h, &block, counter_lo, counter_hi, is_last);
            offset += take;

            if is_last {
                break;
            }
        }
    }

    // Extract the first 32 bytes of the state (little-endian u64 words).
    let mut out = [0u8; 32];
    for (i, word) in h[..4].iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// BLAKE2b compression function F.
fn compress(h: &mut [u64; 8], block: &[u8; 128], t_lo: u64, t_hi: u64, last_block: bool) {
    // Decode message words (little-endian).
    let mut m = [0u64; 16];
    for (i, w) in m.iter_mut().enumerate() {
        let base = i * 8;
        *w = u64::from_le_bytes([
            block[base],
            block[base + 1],
            block[base + 2],
            block[base + 3],
            block[base + 4],
            block[base + 5],
            block[base + 6],
            block[base + 7],
        ]);
    }

    // Initialise working variables.
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t_lo;
    v[13] ^= t_hi;
    if last_block {
        v[14] = !v[14];
    }

    // 12 rounds.
    for round in 0..12 {
        let s = &SIGMA[round];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    // Finalize.
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// The BLAKE2b G mixing function.
#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test: BLAKE2b-256 of the empty string.
    ///
    /// Reference value from the official BLAKE2 test vectors
    /// (https://blake2.net/blake2b-test-vectors-ok.txt), truncated to 32 bytes.
    #[test]
    fn test_empty_input_known_answer() {
        let got = blake2b_256(&[]);
        // BLAKE2b-256("") = 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
        let expected: [u8; 32] = [
            0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99,
            0xda, 0xa1, 0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd,
            0xf1, 0x2f, 0xe3, 0xa8,
        ];
        assert_eq!(got, expected);
    }

    /// BLAKE2b-256 must be deterministic.
    #[test]
    fn test_deterministic() {
        let input = b"epoch-scoped nonce";
        assert_eq!(blake2b_256(input), blake2b_256(input));
    }

    /// Different inputs must produce different digests.
    #[test]
    fn test_distinct_inputs_distinct_outputs() {
        let a = blake2b_256(b"epoch:1");
        let b = blake2b_256(b"epoch:2");
        assert_ne!(a, b);
    }
}
