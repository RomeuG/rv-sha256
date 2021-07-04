use crate::utils::*;
use core::arch::x86_64::*;

#[inline(always)]
pub fn rotate_right_avx2(x: __m256i, n: i32) -> __m256i {
    macro_rules! slli {
        ($amt_const:expr) => {
            unsafe { _mm256_slli_epi32(x, $amt_const) }
        };
    }

    macro_rules! srli {
        ($amt_const:expr) => {
            unsafe { _mm256_srli_epi32(x, $amt_const) }
        };
    }

    let left_n = 32 - n;
    let left = constify_imm8!(n, srli);
    let right = constify_imm8!(left_n, slli);

    unsafe { _mm256_or_si256(left, right) }
}

// choose
#[inline(always)]
fn ch_avx2(x: __m256i, y: __m256i, z: __m256i) -> __m256i {
    unsafe { _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z)) }
}

// majority
#[inline(always)]
fn maj_avx2(x: __m256i, y: __m256i, z: __m256i) -> __m256i {
    unsafe {
        _mm256_xor_si256(
            _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_and_si256(x, z)),
            _mm256_and_si256(y, z),
        )
    }
}

#[inline(always)]
fn ep0_avx2(x: __m256i) -> __m256i {
    unsafe {
        rotate_right_avx2(
            _mm256_xor_si256(
                rotate_right_avx2(_mm256_xor_si256(rotate_right_avx2(x, 9), x), 11),
                x,
            ),
            2,
        )
    }
}

#[inline(always)]
fn ep1_avx2(x: __m256i) -> __m256i {
    unsafe {
        rotate_right_avx2(
            _mm256_xor_si256(
                rotate_right_avx2(_mm256_xor_si256(rotate_right_avx2(x, 14), x), 5),
                x,
            ),
            6,
        )
    }
}

#[inline(always)]
fn sig0_avx2(x: __m256i) -> __m256i {
    macro_rules! srli {
        ($amt_const:expr) => {
            _mm256_srli_epi32(x, $amt_const)
        };
    }

    unsafe {
        let a = rotate_right_avx2(x, 7);
        let b = rotate_right_avx2(x, 18);
        let c = constify_imm8!(3, srli);

        _mm256_xor_si256(_mm256_xor_si256(a, b), c)
    }
}

#[inline(always)]
fn sig1_avx2(x: __m256i) -> __m256i {
    macro_rules! srli {
        ($amt_const:expr) => {
            _mm256_srli_epi32(x, $amt_const)
        };
    }

    unsafe {
        let a = rotate_right_avx2(x, 17);
        let b = rotate_right_avx2(x, 19);
        let c = constify_imm8!(10, srli);

        _mm256_xor_si256(_mm256_xor_si256(a, b), c)
    }
}

macro_rules! SHA256_W_ASSIGN {
    ($self:ident,$i:expr,$w:expr) => {
        $w = unsafe {
            _mm256_set_epi32(
                i32::from_be_bytes(*(&$self.data[0][$i] as *const u8 as *const [u8; 4])),
                i32::from_be_bytes(*(&$self.data[1][$i] as *const u8 as *const [u8; 4])),
                i32::from_be_bytes(*(&$self.data[2][$i] as *const u8 as *const [u8; 4])),
                i32::from_be_bytes(*(&$self.data[3][$i] as *const u8 as *const [u8; 4])),
                i32::from_be_bytes(*(&$self.data[4][$i] as *const u8 as *const [u8; 4])),
                i32::from_be_bytes(*(&$self.data[5][$i] as *const u8 as *const [u8; 4])),
                i32::from_be_bytes(*(&$self.data[6][$i] as *const u8 as *const [u8; 4])),
                i32::from_be_bytes(*(&$self.data[7][$i] as *const u8 as *const [u8; 4])),
            )
        }
    };
}

macro_rules! SHA256_FUNCTION_16 {
    ($self:ident,$a:expr,$b:expr,$c:expr,$d:expr,$e:expr,$f:expr,$g:expr,$h:expr,$i:expr,$w:expr,$j:expr) => {
        unsafe {
            let temp1 = _mm256_add_epi32(
                $h,
                _mm256_add_epi32(
                    ep1_avx2($e),
                    _mm256_add_epi32(
                        ch_avx2($e, $f, $g),
                        _mm256_add_epi32($w, _mm256_set1_epi32(K[$i] as i32)),
                    ),
                ),
            );

            let temp2 = _mm256_add_epi32(ep0_avx2($a), maj_avx2($a, $b, $c));

            $h = $g;
            $g = $f;
            $f = $e;

            $e = _mm256_add_epi32($d, temp1);

            $d = $c;
            $c = $b;
            $b = $a;

            $a = _mm256_add_epi32(temp1, temp2);
        }
    };
}

macro_rules! SHA256_FUNCTION_48 {
    ($a:expr,$b:expr,$c:expr,$d:expr,$e:expr,$f:expr,$g:expr,$h:expr,$w1:expr,$w2:expr,$w3:expr,$w4:expr,$i:expr) => {
        unsafe {
            $w1 = _mm256_add_epi32(
                sig1_avx2($w2),
                _mm256_add_epi32($w3, _mm256_add_epi32(sig0_avx2($w4), $w1)),
            );

            let temp1 = _mm256_add_epi32(
                $h,
                _mm256_add_epi32(
                    ep1_avx2($e),
                    _mm256_add_epi32(
                        ch_avx2($e, $f, $g),
                        _mm256_add_epi32($w1, _mm256_set1_epi32(K[$i] as i32)),
                    ),
                ),
            );

            let temp2 = _mm256_add_epi32(ep0_avx2($a), maj_avx2($a, $b, $c));

            $h = $g;
            $g = $f;
            $f = $e;

            $e = _mm256_add_epi32($d, temp1);

            $d = $c;
            $c = $b;
            $b = $a;

            $a = _mm256_add_epi32(temp1, temp2);
        }
    };
}

pub struct Sha256Avx2 {
    pub hash: [[u8; 32]; 8],
    data: [[u8; 64]; 8],
    state: [__m256i; 8],
    len: u32,
    nbits: u32,
}

impl Sha256Avx2 {
    fn transform(&mut self) {
        let mut w0: __m256i;
        let mut w1: __m256i;
        let mut w2: __m256i;
        let mut w3: __m256i;
        let mut w4: __m256i;
        let mut w5: __m256i;
        let mut w6: __m256i;
        let mut w7: __m256i;
        let mut w8: __m256i;
        let mut w9: __m256i;
        let mut w10: __m256i;
        let mut w11: __m256i;
        let mut w12: __m256i;
        let mut w13: __m256i;
        let mut w14: __m256i;
        let mut w15: __m256i;

        let mut a: __m256i = self.state[0];
        let mut b: __m256i = self.state[1];
        let mut c: __m256i = self.state[2];
        let mut d: __m256i = self.state[3];
        let mut e: __m256i = self.state[4];
        let mut f: __m256i = self.state[5];
        let mut g: __m256i = self.state[6];
        let mut h: __m256i = self.state[7];

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

        self.state[0] = unsafe { _mm256_add_epi32(self.state[0], a) };
        self.state[1] = unsafe { _mm256_add_epi32(self.state[1], b) };
        self.state[2] = unsafe { _mm256_add_epi32(self.state[2], c) };
        self.state[3] = unsafe { _mm256_add_epi32(self.state[3], d) };
        self.state[4] = unsafe { _mm256_add_epi32(self.state[4], e) };
        self.state[5] = unsafe { _mm256_add_epi32(self.state[5], f) };
        self.state[6] = unsafe { _mm256_add_epi32(self.state[6], g) };
        self.state[7] = unsafe { _mm256_add_epi32(self.state[7], h) };
    }

    ///
    /// Updates hashes with new value
    ///
    /// # Arguments
    ///
    /// * `data` - Data as *[u8]
    ///
    #[inline(always)]
    pub fn update1(&mut self, data: &[u8]) {
        self.update(data, data, data, data, data, data, data, data);
    }

    ///
    /// Updates hashes with new values
    ///
    /// # Arguments
    ///
    /// * `data1` - Data as *[u8]
    /// * `data2` - Data as *[u8]
    ///
    #[inline(always)]
    pub fn update2(&mut self, data1: &[u8], data2: &[u8]) {
        self.update(data1, data2, data2, data2, data2, data2, data2, data2);
    }

    ///
    /// Updates hashes with new values
    ///
    /// # Arguments
    ///
    /// * `data1` - Data as *[u8]
    /// * `data2` - Data as *[u8]
    /// * `data3` - Data as *[u8]
    ///
    #[inline(always)]
    pub fn update3(&mut self, data1: &[u8], data2: &[u8], data3: &[u8]) {
        self.update(data1, data2, data3, data3, data3, data3, data3, data3);
    }

    ///
    /// Updates hashes with new values
    ///
    /// # Arguments
    ///
    /// * `data1` - Data as *[u8]
    /// * `data2` - Data as *[u8]
    /// * `data3` - Data as *[u8]
    /// * `data4` - Data as *[u8]
    ///
    #[inline(always)]
    pub fn update4(&mut self, data1: &[u8], data2: &[u8], data3: &[u8], data4: &[u8]) {
        self.update(data1, data2, data3, data4, data4, data4, data4, data4);
    }

    ///
    /// Updates hashes with new values
    ///
    /// # Arguments
    ///
    /// * `data1` - Data as *[u8]
    /// * `data2` - Data as *[u8]
    /// * `data3` - Data as *[u8]
    /// * `data4` - Data as *[u8]
    /// * `data5` - Data as *[u8]
    ///
    #[inline(always)]
    pub fn update5(
        &mut self,
        data1: &[u8],
        data2: &[u8],
        data3: &[u8],
        data4: &[u8],
        data5: &[u8],
    ) {
        self.update(data1, data2, data3, data4, data5, data5, data5, data5);
    }

    ///
    /// Updates hashes with new values
    ///
    /// # Arguments
    ///
    /// * `data1` - Data as *[u8]
    /// * `data2` - Data as *[u8]
    /// * `data3` - Data as *[u8]
    /// * `data4` - Data as *[u8]
    /// * `data5` - Data as *[u8]
    /// * `data6` - Data as *[u8]
    ///
    #[inline(always)]
    pub fn update6(
        &mut self,
        data1: &[u8],
        data2: &[u8],
        data3: &[u8],
        data4: &[u8],
        data5: &[u8],
        data6: &[u8],
    ) {
        self.update(data1, data2, data3, data4, data5, data6, data6, data6);
    }

    ///
    /// Updates hashes with new values
    ///
    /// # Arguments
    ///
    /// * `data1` - Data as *[u8]
    /// * `data2` - Data as *[u8]
    /// * `data3` - Data as *[u8]
    /// * `data4` - Data as *[u8]
    /// * `data5` - Data as *[u8]
    /// * `data6` - Data as *[u8]
    /// * `data7` - Data as *[u8]
    ///
    #[inline(always)]
    pub fn update7(
        &mut self,
        data1: &[u8],
        data2: &[u8],
        data3: &[u8],
        data4: &[u8],
        data5: &[u8],
        data6: &[u8],
        data7: &[u8],
    ) {
        self.update(data1, data2, data3, data4, data5, data6, data7, data7);
    }

    ///
    /// Updates hashes with new values
    ///
    /// # Arguments
    ///
    /// * `data1` - Data as *[u8]
    /// * `data2` - Data as *[u8]
    /// * `data3` - Data as *[u8]
    /// * `data4` - Data as *[u8]
    /// * `data5` - Data as *[u8]
    /// * `data6` - Data as *[u8]
    /// * `data7` - Data as *[u8]
    /// * `data8` - Data as *[u8]
    ///
    #[inline(always)]
    pub fn update8(
        &mut self,
        data1: &[u8],
        data2: &[u8],
        data3: &[u8],
        data4: &[u8],
        data5: &[u8],
        data6: &[u8],
        data7: &[u8],
        data8: &[u8],
    ) {
        self.update(data1, data2, data3, data4, data5, data6, data7, data8);
    }

    fn update(
        &mut self,
        data1: &[u8],
        data2: &[u8],
        data3: &[u8],
        data4: &[u8],
        data5: &[u8],
        data6: &[u8],
        data7: &[u8],
        data8: &[u8],
    ) {
        let len = data1.len();

        for index in 0..len {
            self.data[0][self.len as usize] = data1[index];
            self.data[1][self.len as usize] = data2[index];
            self.data[2][self.len as usize] = data3[index];
            self.data[3][self.len as usize] = data4[index];
            self.data[4][self.len as usize] = data5[index];
            self.data[5][self.len as usize] = data6[index];
            self.data[6][self.len as usize] = data7[index];
            self.data[7][self.len as usize] = data8[index];

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

        self.data[0][current_length] = 0x80;
        self.data[1][current_length] = 0x80;
        self.data[2][current_length] = 0x80;
        self.data[3][current_length] = 0x80;
        self.data[4][current_length] = 0x80;
        self.data[5][current_length] = 0x80;
        self.data[6][current_length] = 0x80;
        self.data[7][current_length] = 0x80;

        current_length += 1;

        if self.len < 56 {
            while current_length < 56 {
                self.data[0][current_length] = 0x00;
                self.data[1][current_length] = 0x00;
                self.data[2][current_length] = 0x00;
                self.data[3][current_length] = 0x00;
                self.data[4][current_length] = 0x00;
                self.data[5][current_length] = 0x00;
                self.data[6][current_length] = 0x00;
                self.data[7][current_length] = 0x00;

                current_length += 1;
            }
        } else {
            while current_length < 64 {
                self.data[0][current_length] = 0x00;
                self.data[1][current_length] = 0x00;
                self.data[2][current_length] = 0x00;
                self.data[3][current_length] = 0x00;
                self.data[4][current_length] = 0x00;
                self.data[5][current_length] = 0x00;
                self.data[6][current_length] = 0x00;
                self.data[7][current_length] = 0x00;

                current_length += 1;
            }

            self.transform();
        }

        self.nbits += self.len * 8;

        for index in 0..8 {
            self.data[index][63] = self.nbits as u8;
            self.data[index][62] = self.nbits.checked_shr(8).unwrap_or(0) as u8;
            self.data[index][61] = self.nbits.checked_shr(16).unwrap_or(0) as u8;
            self.data[index][60] = self.nbits.checked_shr(24).unwrap_or(0) as u8;
            self.data[index][59] = self.nbits.checked_shr(32).unwrap_or(0) as u8;
            self.data[index][58] = self.nbits.checked_shr(40).unwrap_or(0) as u8;
            self.data[index][57] = self.nbits.checked_shr(48).unwrap_or(0) as u8;
            self.data[index][56] = self.nbits.checked_shr(56).unwrap_or(0) as u8;
        }

        self.transform();

        let state_a = unsafe { core::mem::transmute::<&__m256i, &[u32; 8]>(&self.state[0]) };
        let state_b = unsafe { core::mem::transmute::<&__m256i, &[u32; 8]>(&self.state[1]) };
        let state_c = unsafe { core::mem::transmute::<&__m256i, &[u32; 8]>(&self.state[2]) };
        let state_d = unsafe { core::mem::transmute::<&__m256i, &[u32; 8]>(&self.state[3]) };
        let state_e = unsafe { core::mem::transmute::<&__m256i, &[u32; 8]>(&self.state[4]) };
        let state_f = unsafe { core::mem::transmute::<&__m256i, &[u32; 8]>(&self.state[5]) };
        let state_g = unsafe { core::mem::transmute::<&__m256i, &[u32; 8]>(&self.state[6]) };
        let state_h = unsafe { core::mem::transmute::<&__m256i, &[u32; 8]>(&self.state[7]) };

        for i in 0..8 {
            self.hash[7 - i][0] = (state_a[i] >> 24) as u8;
            self.hash[7 - i][1] = (state_a[i] >> 16) as u8;
            self.hash[7 - i][2] = (state_a[i] >> 8) as u8;
            self.hash[7 - i][3] = (state_a[i]) as u8;

            self.hash[7 - i][4] = (state_b[i] >> 24) as u8;
            self.hash[7 - i][5] = (state_b[i] >> 16) as u8;
            self.hash[7 - i][6] = (state_b[i] >> 8) as u8;
            self.hash[7 - i][7] = (state_b[i]) as u8;

            self.hash[7 - i][8] = (state_c[i] >> 24) as u8;
            self.hash[7 - i][9] = (state_c[i] >> 16) as u8;
            self.hash[7 - i][10] = (state_c[i] >> 8) as u8;
            self.hash[7 - i][11] = (state_c[i]) as u8;

            self.hash[7 - i][12] = (state_d[i] >> 24) as u8;
            self.hash[7 - i][13] = (state_d[i] >> 16) as u8;
            self.hash[7 - i][14] = (state_d[i] >> 8) as u8;
            self.hash[7 - i][15] = (state_d[i]) as u8;

            self.hash[7 - i][16] = (state_e[i] >> 24) as u8;
            self.hash[7 - i][17] = (state_e[i] >> 16) as u8;
            self.hash[7 - i][18] = (state_e[i] >> 8) as u8;
            self.hash[7 - i][19] = (state_e[i]) as u8;

            self.hash[7 - i][20] = (state_f[i] >> 24) as u8;
            self.hash[7 - i][21] = (state_f[i] >> 16) as u8;
            self.hash[7 - i][22] = (state_f[i] >> 8) as u8;
            self.hash[7 - i][23] = (state_f[i]) as u8;

            self.hash[7 - i][24] = (state_g[i] >> 24) as u8;
            self.hash[7 - i][25] = (state_g[i] >> 16) as u8;
            self.hash[7 - i][26] = (state_g[i] >> 8) as u8;
            self.hash[7 - i][27] = (state_g[i]) as u8;

            self.hash[7 - i][28] = (state_h[i] >> 24) as u8;
            self.hash[7 - i][29] = (state_h[i] >> 16) as u8;
            self.hash[7 - i][30] = (state_h[i] >> 8) as u8;
            self.hash[7 - i][31] = (state_h[i]) as u8;
        }
    }

    ///
    /// Receives string as array of bytes.
    /// Returns [[u8; 32]; 8]
    ///
    /// # Arguments
    ///
    /// * `input` - Data as &[u8]
    ///
    pub fn digest(input: &[u8]) -> [[u8; 32]; 8] {
        let mut object = Self::default();
        object.update1(input);
        object.finalize();
        object.hash
    }

    ///
    /// Receives string as array of bytes.
    /// Returns [[u8; 32]; 8]
    ///
    /// # Arguments
    ///
    /// * `input1` - Data as &[u8]
    /// * `input2` - Data as &[u8]
    ///
    pub fn digest2(input1: &[u8], input2: &[u8]) -> [[u8; 32]; 8] {
        let mut object = Self::default();
        object.update2(input1, input2);
        object.finalize();
        object.hash
    }

    ///
    /// Receives string as array of bytes.
    /// Returns [[u8; 32]; 8]
    ///
    /// # Arguments
    ///
    /// * `input1` - Data as &[u8]
    /// * `input2` - Data as &[u8]
    /// * `input3` - Data as &[u8]
    ///
    pub fn digest3(input1: &[u8], input2: &[u8], input3: &[u8]) -> [[u8; 32]; 8] {
        let mut object = Self::default();
        object.update3(input1, input2, input3);
        object.finalize();
        object.hash
    }

    ///
    /// Receives string as array of bytes.
    /// Returns [[u8; 32]; 8]
    ///
    /// # Arguments
    ///
    /// * `input1` - Data as &[u8]
    /// * `input2` - Data as &[u8]
    /// * `input3` - Data as &[u8]
    /// * `input4` - Data as &[u8]
    ///
    pub fn digest4(input1: &[u8], input2: &[u8], input3: &[u8], input4: &[u8]) -> [[u8; 32]; 8] {
        let mut object = Self::default();
        object.update4(input1, input2, input3, input4);
        object.finalize();
        object.hash
    }

    ///
    /// Receives string as array of bytes.
    /// Returns [[u8; 32]; 8]
    ///
    /// # Arguments
    ///
    /// * `input1` - Data as &[u8]
    /// * `input2` - Data as &[u8]
    /// * `input3` - Data as &[u8]
    /// * `input4` - Data as &[u8]
    /// * `input5` - Data as &[u8]
    ///
    pub fn digest5(
        input1: &[u8],
        input2: &[u8],
        input3: &[u8],
        input4: &[u8],
        input5: &[u8],
    ) -> [[u8; 32]; 8] {
        let mut object = Self::default();
        object.update5(input1, input2, input3, input4, input5);
        object.finalize();
        object.hash
    }

    ///
    /// Receives string as array of bytes.
    /// Returns [[u8; 32]; 8]
    ///
    /// # Arguments
    ///
    /// * `input1` - Data as &[u8]
    /// * `input2` - Data as &[u8]
    /// * `input3` - Data as &[u8]
    /// * `input4` - Data as &[u8]
    /// * `input5` - Data as &[u8]
    /// * `input6` - Data as &[u8]
    ///
    pub fn digest6(
        input1: &[u8],
        input2: &[u8],
        input3: &[u8],
        input4: &[u8],
        input5: &[u8],
        input6: &[u8],
    ) -> [[u8; 32]; 8] {
        let mut object = Self::default();
        object.update6(input1, input2, input3, input4, input5, input6);
        object.finalize();
        object.hash
    }

    ///
    /// Receives string as array of bytes.
    /// Returns [[u8; 32]; 8]
    ///
    /// # Arguments
    ///
    /// * `input1` - Data as &[u8]
    /// * `input2` - Data as &[u8]
    /// * `input3` - Data as &[u8]
    /// * `input4` - Data as &[u8]
    /// * `input5` - Data as &[u8]
    /// * `input6` - Data as &[u8]
    /// * `input7` - Data as &[u8]
    ///
    pub fn digest7(
        input1: &[u8],
        input2: &[u8],
        input3: &[u8],
        input4: &[u8],
        input5: &[u8],
        input6: &[u8],
        input7: &[u8],
    ) -> [[u8; 32]; 8] {
        let mut object = Self::default();
        object.update7(input1, input2, input3, input4, input5, input6, input7);
        object.finalize();
        object.hash
    }

    ///
    /// Receives string as array of bytes.
    /// Returns [[u8; 32]; 8]
    ///
    /// # Arguments
    ///
    /// * `input1` - Data as &[u8]
    /// * `input2` - Data as &[u8]
    /// * `input3` - Data as &[u8]
    /// * `input4` - Data as &[u8]
    /// * `input5` - Data as &[u8]
    /// * `input6` - Data as &[u8]
    /// * `input7` - Data as &[u8]
    /// * `input8` - Data as &[u8]
    ///
    pub fn digest8(
        input1: &[u8],
        input2: &[u8],
        input3: &[u8],
        input4: &[u8],
        input5: &[u8],
        input6: &[u8],
        input7: &[u8],
        input8: &[u8],
    ) -> [[u8; 32]; 8] {
        let mut object = Self::default();
        object.update8(
            input1, input2, input3, input4, input5, input6, input7, input8,
        );
        object.finalize();
        object.hash
    }
}

impl Default for Sha256Avx2 {
    fn default() -> Self {
        Self {
            data: [[0; 64]; 8],
            state: [
                unsafe { _mm256_set1_epi32((I[0] as u32) as i32) },
                unsafe { _mm256_set1_epi32((I[1] as u32) as i32) },
                unsafe { _mm256_set1_epi32((I[2] as u32) as i32) },
                unsafe { _mm256_set1_epi32((I[3] as u32) as i32) },
                unsafe { _mm256_set1_epi32((I[4] as u32) as i32) },
                unsafe { _mm256_set1_epi32((I[5] as u32) as i32) },
                unsafe { _mm256_set1_epi32((I[6] as u32) as i32) },
                unsafe { _mm256_set1_epi32((I[7] as u32) as i32) },
            ],
            hash: [[0; 32]; 8],
            len: 0,
            nbits: 0,
        }
    }
}
