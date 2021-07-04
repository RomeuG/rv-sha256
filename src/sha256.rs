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

macro_rules! SHA256_W_ASSIGN {
    ($self:ident,$i:expr,$w:expr) => {
        // NOTE: better performance!
        $w = u32::from_be_bytes(unsafe { *(&$self.data[$i] as *const u8 as *const [u8; 4]) });
    };
}

macro_rules! SHA256_FUNCTION_16 {
    ($self:ident,$a:expr,$b:expr,$c:expr,$d:expr,$e:expr,$f:expr,$g:expr,$h:expr,$i:expr,$w:expr,$j:expr) => {
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

        SHA256_W_ASSIGN!(self, 0, w0);
        SHA256_W_ASSIGN!(self, 4, w1);
        SHA256_W_ASSIGN!(self, 8, w2);
        SHA256_W_ASSIGN!(self, 12, w3);
        SHA256_W_ASSIGN!(self, 16, w4);
        SHA256_W_ASSIGN!(self, 20, w5);
        SHA256_W_ASSIGN!(self, 24, w6);
        SHA256_W_ASSIGN!(self, 28, w7);
        SHA256_W_ASSIGN!(self, 32, w8);
        SHA256_W_ASSIGN!(self, 36, w9);
        SHA256_W_ASSIGN!(self, 40, w10);
        SHA256_W_ASSIGN!(self, 44, w11);
        SHA256_W_ASSIGN!(self, 48, w12);
        SHA256_W_ASSIGN!(self, 52, w13);
        SHA256_W_ASSIGN!(self, 56, w14);
        SHA256_W_ASSIGN!(self, 60, w15);

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

        self.hash[0] = (self.state[0] >> 24) as u8;
        self.hash[1] = (self.state[0] >> 16) as u8;
        self.hash[2] = (self.state[0] >> 8) as u8;
        self.hash[3] = (self.state[0]) as u8;

        self.hash[4] = (self.state[1] >> 24) as u8;
        self.hash[5] = (self.state[1] >> 16) as u8;
        self.hash[6] = (self.state[1] >> 8) as u8;
        self.hash[7] = (self.state[1]) as u8;

        self.hash[8] = (self.state[2] >> 24) as u8;
        self.hash[9] = (self.state[2] >> 16) as u8;
        self.hash[10] = (self.state[2] >> 8) as u8;
        self.hash[11] = (self.state[2]) as u8;

        self.hash[12] = (self.state[3] >> 24) as u8;
        self.hash[13] = (self.state[3] >> 16) as u8;
        self.hash[14] = (self.state[3] >> 8) as u8;
        self.hash[15] = (self.state[3]) as u8;

        self.hash[16] = (self.state[4] >> 24) as u8;
        self.hash[17] = (self.state[4] >> 16) as u8;
        self.hash[18] = (self.state[4] >> 8) as u8;
        self.hash[19] = (self.state[4]) as u8;

        self.hash[20] = (self.state[5] >> 24) as u8;
        self.hash[21] = (self.state[5] >> 16) as u8;
        self.hash[22] = (self.state[5] >> 8) as u8;
        self.hash[23] = (self.state[5]) as u8;

        self.hash[24] = (self.state[6] >> 24) as u8;
        self.hash[25] = (self.state[6] >> 16) as u8;
        self.hash[26] = (self.state[6] >> 8) as u8;
        self.hash[27] = (self.state[6]) as u8;

        self.hash[28] = (self.state[7] >> 24) as u8;
        self.hash[29] = (self.state[7] >> 16) as u8;
        self.hash[30] = (self.state[7] >> 8) as u8;
        self.hash[31] = (self.state[7]) as u8;
    }

    ///
    /// Receives string as array of bytes.
    /// Returns [u8; 32]
    ///
    /// # Arguments
    ///
    /// * `data` - Data as &[u8]
    ///
    pub fn digest(input: &[u8]) -> [u8; 32] {
        let mut sha256 = Self::default();
        sha256.update(input);
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
