#![no_std]
#![feature(core_intrinsics)]

#![feature(test)]
#[allow(soft_unstable)]
extern crate test;
use test::Bencher;

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
    u32::rotate_right(x, 2)
        ^ u32::rotate_right(x, 13)
        ^ u32::rotate_right(x, 22)
}

#[inline(always)]
fn ep1(x: u32) -> u32 {
    u32::rotate_right(x, 6)
        ^ u32::rotate_right(x, 11)
        ^ u32::rotate_right(x, 25)
}

#[inline(always)]
fn sig0(x: i32) -> i32 {
    i32::rotate_right(x, 7) ^ i32::rotate_right(x, 18) ^ (((x as u32) >> 3) as i32)
}

#[inline(always)]
fn sig1(x: i32) -> i32 {
    i32::rotate_right(x, 17) ^ i32::rotate_right(x, 19) ^ (((x as u32) >> 10) as i32)
}

pub struct Sha256 {
    data: [u8; 64],
    state: [u32; 8],
    pub hash: [u8; 32],
    len: u32,
    nbits: u32,
}

impl Sha256 {
    pub fn transform(&mut self) {
        let mut m: [u32; 64] = [0; 64];

        let mut j: usize = 0;
        for i in 0..16 {
            m[i] = ((self.data[j] as u32) << 24)
                | ((self.data[j + 1] as u32) << 16)
                | ((self.data[j + 2] as u32) << 8)
                | (self.data[j + 3] as u32);

            j += 4;
        }

        for i in 16..64 {
            m[i] = sig1(m[i-2] as i32).wrapping_add(m[i-7] as i32).wrapping_add(sig0(m[i-15] as i32)).wrapping_add(m[i-16] as i32) as u32;
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
            let temp1 = h.wrapping_add(ep1(e)).wrapping_add(ch(e,f,g)).wrapping_add(K[i]).wrapping_add(m[i]);
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

    pub fn update(&mut self, msg: &[u8]) {
        let len = msg.len();

        for i in 0..len {

            self.data[self.len as usize] = msg[i];
            self.len += 1;

            if self.len == 64 {
                self.transform();

                self.nbits += 512;
                self.len = 0;
            }
        }

    }

    pub fn finalize(&mut self) {
        let mut current_length: usize = self.len.try_into().ok().unwrap();

        if self.len < 56 {
            self.data[current_length] = 0x80;
            current_length += 1;

            while current_length < 56 {
                self.data[current_length] = 0x00;
                current_length += 1;
            }
        } else {
            self.data[current_length] = 0x80;
            current_length += 1;

            while current_length < 64 {
                self.data[current_length] = 0x00;
                current_length += 1;
            }

            self.transform();
            unsafe {
                write_bytes(&mut self.data as *mut _, 0x0, 56);
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

    #[test]
    fn it_works() {
        let mut sha256 = Sha256::default();
        sha256.update("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_bytes());
        sha256.finalize();

        assert_eq!(sha256.hash, sha256.hash[1..]);
    }

    #[bench]
    fn bench_add_two(b: &mut Bencher) {
        b.iter(|| {
            let mut sha256 = Sha256::default();
            sha256.update("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_bytes());
            sha256.finalize();
        });
    }
}

