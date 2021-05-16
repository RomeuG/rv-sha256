#![no_std]
#![feature(core_intrinsics)]
#![feature(test)]

use core::default::Default;
use core::convert::TryInto;

use core::ptr::write_bytes;

// constants
const I: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// choose
#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    ((x) & (y)) ^ (!(x) & (z))
}

// majority
#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))
}

#[inline(always)]
fn ep0(x: u32) -> u32 {
    u32::rotate_right(u32::rotate_right(u32::rotate_right(x, 9) ^ x, 11) ^ x, 2)
}

#[inline(always)]
fn ep1(x: u32) -> u32 {
    u32::rotate_right(u32::rotate_right(u32::rotate_right(x, 14) ^ x, 5) ^ x, 6)
}

#[inline(always)]
fn sig0(x: i32) -> i32 {
    i32::rotate_right(x, 7) ^ i32::rotate_right(x, 18) ^ (((x as u32) >> 3) as i32)
}

#[inline(always)]
fn sig1(x: i32) -> i32 {
    i32::rotate_right(x, 17) ^ i32::rotate_right(x, 19) ^ (((x as u32) >> 10) as i32)
}

/// This struct represents a SHA256 state, which includes the result.
pub struct Sha256 {
    // This field will have the hashing result.
    pub hash: [u8; 32],
    data: [u8; 64],
    state: [u32; 8],
    len: u32,
    nbits: u32,
}

impl Sha256 {
    fn transform(&mut self) {
        let mut w: [u32; 64] = [0; 64];

        let mut j: usize = 0;
        // for i in 0..16 {
        for item in w.iter_mut().take(16) {
            *item = ((self.data[j] as u32) << 24)
                | ((self.data[j + 1] as u32) << 16)
                | ((self.data[j + 2] as u32) << 8)
                | (self.data[j + 3] as u32);

            j += 4;
        }

        for i in 16..64 {
            w[i] = sig1(w[i-2] as i32).wrapping_add(w[i-7] as i32).wrapping_add(sig0(w[i-15] as i32)).wrapping_add(w[i-16] as i32) as u32;
        }

        let mut a: u32 = self.state[0];
        let mut b: u32 = self.state[1];
        let mut c: u32 = self.state[2];
        let mut d: u32 = self.state[3];
        let mut e: u32 = self.state[4];
        let mut f: u32 = self.state[5];
        let mut g: u32 = self.state[6];
        let mut h: u32 = self.state[7];


        for i in 0..64 {
            let temp1 = h.wrapping_add(ep1(e)).wrapping_add(ch(e,f,g)).wrapping_add(K[i]).wrapping_add(w[i]);
            let temp2 = ep0(a).wrapping_add(maj(a,b,c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    ///
    /// Updates hash with new value
    ///
    /// # Arguments
    ///
    /// * `data` - Data as *[u8]
    ///
    pub fn update(&mut self, data: &[u8]) {
        let len = data.len();

        for item in data.iter().take(len) {
            self.data[self.len as usize] = *item;
            self.len += 1;

            if self.len == 64 {
                self.transform();

                self.nbits += 512;
                self.len = 0;
            }
        }
    }

    ///
    /// Generates final hash
    ///
    pub fn finalize(&mut self) {
        let mut current_length: usize = self.len as usize;

        self.data[current_length] = 0x80;
        current_length += 1;

        if self.len < 56 {
            while current_length < 56 {
                self.data[current_length] = 0x00;
                current_length += 1;
            }
        } else {
            while current_length < 64 {
                self.data[current_length] = 0x00;
                current_length += 1;
            }

            self.transform();

            unsafe {
                write_bytes(self.data.as_mut_ptr(), 0x0, 56);
            }
        }

        self.nbits += self.len * 8;

        self.data[63] = self.nbits as u8;
        self.data[62] = self.nbits.checked_shr(8).unwrap_or(0) as u8;
        self.data[61] = self.nbits.checked_shr(16).unwrap_or(0) as u8;
        self.data[60] = self.nbits.checked_shr(24).unwrap_or(0) as u8;
        self.data[59] = self.nbits.checked_shr(32).unwrap_or(0) as u8;
        self.data[58] = self.nbits.checked_shr(40).unwrap_or(0) as u8;
        self.data[57] = self.nbits.checked_shr(48).unwrap_or(0) as u8;
        self.data[56] = self.nbits.checked_shr(56).unwrap_or(0) as u8;

        self.transform();

        for i in 0..4 {
            self.hash[i] = ((self.state[0] >> (24 - i * 8)) & 0x000000ff) as u8;
            self.hash[i + 4] = ((self.state[1] >> (24 - i * 8)) & 0x000000ff) as u8;
            self.hash[i + 8] = ((self.state[2] >> (24 - i * 8)) & 0x000000ff) as u8;
            self.hash[i + 12] = ((self.state[3] >> (24 - i * 8)) & 0x000000ff) as u8;
            self.hash[i + 16] = ((self.state[4] >> (24 - i * 8)) & 0x000000ff) as u8;
            self.hash[i + 20] = ((self.state[5] >> (24 - i * 8)) & 0x000000ff) as u8;
            self.hash[i + 24] = ((self.state[6] >> (24 - i * 8)) & 0x000000ff) as u8;
            self.hash[i + 28] = ((self.state[7] >> (24 - i * 8)) & 0x000000ff) as u8;
        }
    }

    ///
    /// Receives string as bytes.
    /// Returns String
    ///
    /// # Arguments
    ///
    /// * `data` - Data as &[u8]
    ///
    /// # Example
    ///
    /// ``` rust
    /// use std::env;
    ///
    /// use sha256::Sha256;
    ///
    /// /// convert bytes to hex string
    /// /// code taken from hex project: https://docs.rs/crate/hex/0.1.0/source/src/lib.rs
    /// fn to_hex_string(data: &[u8]) -> String {
    ///     static CHARS: &'static [u8] = b"0123456789abcdef";
    ///
    ///     let bytes = data.as_ref();
    ///     let mut v = Vec::with_capacity(bytes.len() * 2);
    ///     for &byte in bytes.iter() {
    ///         v.push(CHARS[(byte >> 4) as usize]);
    ///         v.push(CHARS[(byte & 0xf) as usize]);
    ///     }
    ///
    ///     unsafe {
    ///         String::from_utf8_unchecked(v)
    ///     }
    /// }
    ///
    /// fn main() {
    ///     let args: Vec<String> = env::args().collect();
    ///
    ///     if args.len() == 2 {
    ///         let text = &args[1];
    ///         let hash = Sha256::digest(text.as_bytes());
    ///
    ///         println!("{}", to_hex_string(&hash));
    ///     }
    /// }
    /// ```
    ///
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut sha256 = Self::default();
        sha256.update(data);
        sha256.finalize();

        sha256.hash
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self {
            data: [0; 64],
            state: [I[0], I[1], I[2], I[3], I[4], I[5], I[6], I[7]],
            hash: [0; 32],
            len: 0,
            nbits: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate test;
    use test::Bencher;

    #[test]
    fn sha256_32bytes() {
        let hash = Sha256::digest("wqvDrDLilCUevxUw5fWEuVc6y6ElCrHg".as_bytes());
        assert_eq!(hash, [0xad, 0xc8, 0x24, 0x3e, 0xfd, 0x7a, 0xef, 0x68, 0x20, 0xce, 0xdc, 0xe0, 0xc9, 0xc8, 0xbe, 0x26, 0x13, 0x0a, 0xc5, 0x77, 0xde, 0x8c, 0x62, 0x1c, 0x9c, 0xa8, 0x0d, 0xd4, 0xaf, 0x19, 0x77, 0xf8]);
    }

    #[test]
    fn sha256_64bytes() {
        let hash = Sha256::digest("K7CN3VzXyY63NXmW15TKA4O6vJtVrLc7I0B5qHRtBir5PkwSt6xgJopOCunPk2ky".as_bytes());
        assert_eq!(hash, [0x59, 0xd5, 0x93, 0xea, 0x4e, 0x90, 0xce, 0x36, 0x60, 0x7d, 0xc3, 0x39, 0x96, 0x9a, 0x6c, 0xe4, 0x07, 0x7b, 0xb2, 0xda, 0x86, 0x09, 0x27, 0x25, 0xfe, 0x94, 0xdb, 0xf8, 0xb1, 0x1f, 0x3e, 0x09]);
    }

    #[test]
    fn sha256_128bytes() {
        let hash = Sha256::digest("KAjb6sifm7DwdyJyMXT3np6WZVfXJiEskX1fN7V8YOatxuRkpHYZmqDXY2Kn2pfnV63l0bodaXjRdVF5m2z1bC7QpdQi3UHRI9KAqWs0vO0QjT5XtkTXKlaRK4CiBsT1".as_bytes());
        assert_eq!(hash, [0x64, 0x4c, 0xb0, 0x9c, 0x0d, 0x42, 0x26, 0x6c, 0x3a, 0x15, 0x82, 0x6c, 0xec, 0xaf, 0x91, 0x93, 0xfa, 0x05, 0x9d, 0x10, 0x22, 0xed, 0xd6, 0xdb, 0x3a, 0x5a, 0x4c, 0xb7, 0x19, 0x03, 0x12, 0x24]);
    }

    #[test]
    fn sha256_256bytes() {
        let hash = Sha256::digest("QnpFg2P1SEQ0L9tcNwBROCW7jVtFeMt0RuF7QODKkgD75CPDi1pAB1GtMcq0G1pmNE6J3IuPpF33uPtOs4sNwU7lKcnF8SU016PKWPeVEpuKQ2ksT9enIf1hVrzlypOkhFTFhIS28IT9OQZ3BS3693487mSb6QNuuaBCD8yNWWlo74c79EFWUWNaAmRcSxVaNcbDa80SovlnL8lyO2yS7XlmE7rPmLI4IvPtko3QguI4Th2JPrVnM7QCCjMgvlIO".as_bytes());
        assert_eq!(hash, [0x68, 0x7f, 0x3b, 0x1d, 0xe7, 0x47, 0x02, 0x47, 0x55, 0xb3, 0x6f, 0x87, 0xd4, 0x1f, 0x02, 0x66, 0x07, 0xd1, 0x20, 0x57, 0x18, 0x4a, 0xf4, 0x68, 0xb0, 0x39, 0xad, 0x28, 0x41, 0xed, 0x43, 0xe4]);
    }

    #[bench]
    fn bench_sha256_32bytes(b: &mut Bencher) {
        b.iter(|| {
            Sha256::digest("wqvDrDLilCUevxUw5fWEuVc6y6ElCrHg".as_bytes());
        });
    }

    #[bench]
    fn bench_sha256_64bytes(b: &mut Bencher) {
        b.iter(|| {
            Sha256::digest("K7CN3VzXyY63NXmW15TKA4O6vJtVrLc7I0B5qHRtBir5PkwSt6xgJopOCunPk2ky".as_bytes());
        });
    }

    #[bench]
    fn bench_sha256_128bytes(b: &mut Bencher) {
        b.iter(|| {
            Sha256::digest("KAjb6sifm7DwdyJyMXT3np6WZVfXJiEskX1fN7V8YOatxuRkpHYZmqDXY2Kn2pfnV63l0bodaXjRdVF5m2z1bC7QpdQi3UHRI9KAqWs0vO0QjT5XtkTXKlaRK4CiBsT1".as_bytes());
        });
    }

    #[bench]
    fn bench_sha256_256bytes(b: &mut Bencher) {
        b.iter(|| {
            Sha256::digest("QnpFg2P1SEQ0L9tcNwBROCW7jVtFeMt0RuF7QODKkgD75CPDi1pAB1GtMcq0G1pmNE6J3IuPpF33uPtOs4sNwU7lKcnF8SU016PKWPeVEpuKQ2ksT9enIf1hVrzlypOkhFTFhIS28IT9OQZ3BS3693487mSb6QNuuaBCD8yNWWlo74c79EFWUWNaAmRcSxVaNcbDa80SovlnL8lyO2yS7XlmE7rPmLI4IvPtko3QguI4Th2JPrVnM7QCCjMgvlIO".as_bytes());
        });
    }
}

