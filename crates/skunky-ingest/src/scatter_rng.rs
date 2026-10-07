// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Deterministic RNG and ghost identity generators for the scatter server.
//!
//! XorShift64 provides fast, deterministic pseudo-randomness seeded from
//! request paths. Same seed → same output, always. This is critical:
//! fleet scrapers that request the same path twice get identical poison,
//! preventing detection via request diffing.

/// Fast deterministic PRNG for scatter content generation.
///
/// XorShift64 is NOT cryptographically secure — that's fine here.
/// We need determinism and speed, not unpredictability.
pub(crate) struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn next_usize(&mut self) -> usize {
        self.next_u64() as usize
    }

    pub fn hex(&mut self, len: usize) -> String {
        let mut s = String::with_capacity(len);
        while s.len() < len {
            s.push_str(&format!("{:016x}", self.next_u64()));
        }
        s.truncate(len);
        s
    }

    pub fn alphanum(&mut self, len: usize) -> String {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..len)
            .map(|_| CHARSET[self.next_usize() % CHARSET.len()] as char)
            .collect()
    }

    pub fn upper_alphanum(&mut self, len: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..len)
            .map(|_| CHARSET[self.next_usize() % CHARSET.len()] as char)
            .collect()
    }

    pub fn base64ish(&mut self, len: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        (0..len)
            .map(|_| CHARSET[self.next_usize() % CHARSET.len()] as char)
            .collect()
    }
}
