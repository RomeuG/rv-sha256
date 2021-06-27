use crate::utils::*;

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
            w[i] = sig1(w[i - 2] as i32)
                .wrapping_add(w[i - 7] as i32)
                .wrapping_add(sig0(w[i - 15] as i32))
                .wrapping_add(w[i - 16] as i32) as u32;
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
            let temp1 = h
                .wrapping_add(ep1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let temp2 = ep0(a).wrapping_add(maj(a, b, c));

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

        for index in 0..len {
            self.data[self.len as usize] = data[index];

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

            // TODO(romeu): actually not needed?
            // unsafe {
            //     write_bytes(self.data.as_mut_ptr(), 0x0, 56);
            // }
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
    /// use sha256::sha256::Sha256;
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
