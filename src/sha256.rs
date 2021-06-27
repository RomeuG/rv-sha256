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

macro_rules! SHA256_FUNCTION_16 {
    ($self:ident,$a:expr,$b:expr,$c:expr,$d:expr,$e:expr,$f:expr,$g:expr,$h:expr,$i:expr,$w:expr,$j:expr) => {
        $w = (($self.data[$j] as u32) << 24)
            | (($self.data[$j + 1] as u32) << 16)
            | (($self.data[$j + 2] as u32) << 8)
            | ($self.data[$j + 3] as u32);

        let temp1 = $h
            .wrapping_add(ep1($e))
            .wrapping_add(ch($e, $f, $g))
            .wrapping_add(K[$i])
            .wrapping_add($w);
        let temp2 = ep0($a).wrapping_add(maj($a, $b, $c));

        $h = $g;
        $g = $f;
        $f = $e;
        $e = $d.wrapping_add(temp1);
        $d = $c;
        $c = $b;
        $b = $a;
        $a = temp1.wrapping_add(temp2);
    };
}

macro_rules! SHA256_FUNCTION_48 {
    ($a:expr,$b:expr,$c:expr,$d:expr,$e:expr,$f:expr,$g:expr,$h:expr,$w1:expr,$w2:expr,$w3:expr,$w4:expr,$i:expr) => {
        $w1 = sig1($w2 as i32)
            .wrapping_add($w3 as i32)
            .wrapping_add(sig0($w4 as i32))
            .wrapping_add($w1 as i32) as u32;

        let temp1 = $h
            .wrapping_add(ep1($e))
            .wrapping_add(ch($e, $f, $g))
            .wrapping_add(K[$i])
            .wrapping_add($w1);
        let temp2 = ep0($a).wrapping_add(maj($a, $b, $c));

        $h = $g;
        $g = $f;
        $f = $e;
        $e = $d.wrapping_add(temp1);
        $d = $c;
        $c = $b;
        $b = $a;
        $a = temp1.wrapping_add(temp2);
    };
}

impl Sha256 {
    fn transform(&mut self) {
        let mut w0: u32;
        let mut w1: u32;
        let mut w2: u32;
        let mut w3: u32;
        let mut w4: u32;
        let mut w5: u32;
        let mut w6: u32;
        let mut w7: u32;
        let mut w8: u32;
        let mut w9: u32;
        let mut w10: u32;
        let mut w11: u32;
        let mut w12: u32;
        let mut w13: u32;
        let mut w14: u32;
        let mut w15: u32;

        let mut a: u32 = self.state[0];
        let mut b: u32 = self.state[1];
        let mut c: u32 = self.state[2];
        let mut d: u32 = self.state[3];
        let mut e: u32 = self.state[4];
        let mut f: u32 = self.state[5];
        let mut g: u32 = self.state[6];
        let mut h: u32 = self.state[7];

        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 0, w0, 0);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 1, w1, 4);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 2, w2, 8);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 3, w3, 12);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 4, w4, 16);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 5, w5, 20);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 6, w6, 24);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 7, w7, 28);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 8, w8, 32);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 9, w9, 36);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 10, w10, 40);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 11, w11, 44);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 12, w12, 48);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 13, w13, 52);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 14, w14, 56);
        SHA256_FUNCTION_16!(self, a, b, c, d, e, f, g, h, 15, w15, 60);

        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w0, w14, w9, w1, 16);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w1, w15, w10, w2, 17);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w2, w0, w11, w3, 18);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w3, w1, w12, w4, 19);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w4, w2, w13, w5, 20);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w5, w3, w14, w6, 21);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w6, w4, w15, w7, 22);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w7, w5, w0, w8, 23);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w8, w6, w1, w9, 24);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w9, w7, w2, w10, 25);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w10, w8, w3, w11, 26);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w11, w9, w4, w12, 27);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w12, w10, w5, w13, 28);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w13, w11, w6, w14, 29);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w14, w12, w7, w15, 30);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w15, w13, w8, w0, 31);

        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w0, w14, w9, w1, 32);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w1, w15, w10, w2, 33);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w2, w0, w11, w3, 34);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w3, w1, w12, w4, 35);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w4, w2, w13, w5, 36);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w5, w3, w14, w6, 37);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w6, w4, w15, w7, 38);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w7, w5, w0, w8, 39);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w8, w6, w1, w9, 40);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w9, w7, w2, w10, 41);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w10, w8, w3, w11, 42);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w11, w9, w4, w12, 43);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w12, w10, w5, w13, 44);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w13, w11, w6, w14, 45);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w14, w12, w7, w15, 46);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w15, w13, w8, w0, 47);

        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w0, w14, w9, w1, 48);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w1, w15, w10, w2, 49);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w2, w0, w11, w3, 50);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w3, w1, w12, w4, 51);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w4, w2, w13, w5, 52);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w5, w3, w14, w6, 53);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w6, w4, w15, w7, 54);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w7, w5, w0, w8, 55);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w8, w6, w1, w9, 56);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w9, w7, w2, w10, 57);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w10, w8, w3, w11, 58);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w11, w9, w4, w12, 59);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w12, w10, w5, w13, 60);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w13, w11, w6, w14, 61);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w14, w12, w7, w15, 62);
        SHA256_FUNCTION_48!(a, b, c, d, e, f, g, h, w15, w13, w8, w0, 63);

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
