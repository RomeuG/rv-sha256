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
    unsafe {
        let a = _mm256_and_si256(x, y);
        let b = _mm256_andnot_si256(x, z);
        let c = _mm256_xor_si256(a, b);

        c
    }
}

// majority
#[inline(always)]
fn maj_avx2(x: __m256i, y: __m256i, z: __m256i) -> __m256i {
    unsafe {
        let a = _mm256_and_si256(x, y);
        let b = _mm256_and_si256(x, z);
        let c = _mm256_and_si256(y, z);

        let d = _mm256_xor_si256(a, b);
        let e = _mm256_xor_si256(d, c);
        e
    }
}

#[inline(always)]
fn ep0_avx2(x: __m256i) -> __m256i {
    unsafe {
        let r1 = rotate_right_avx2(x, 9);
        let r1_xor = _mm256_xor_si256(r1, x);

        let r2 = rotate_right_avx2(r1_xor, 11);
        let r2_xor = _mm256_xor_si256(r2, x);

        let r3 = rotate_right_avx2(r2_xor, 2);
        r3
    }
}

#[inline(always)]
fn ep1_avx2(x: __m256i) -> __m256i {
    unsafe {
        let r1 = rotate_right_avx2(x, 14);
        let r1_xor = _mm256_xor_si256(r1, x);

        let r2 = rotate_right_avx2(r1_xor, 5);
        let r2_xor = _mm256_xor_si256(r2, x);

        let r3 = rotate_right_avx2(r2_xor, 6);
        r3
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

        let xor1 = _mm256_xor_si256(a, b);
        let xor2 = _mm256_xor_si256(xor1, c);

        xor2
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

        let xor1 = _mm256_xor_si256(a, b);
        let xor2 = _mm256_xor_si256(xor1, c);

        xor2
    }
}

macro_rules! SHA256_W_ASSIGN {
    ($self:ident,$i:expr,$w:expr) => {
        $w = unsafe {
            _mm256_set_epi32(
                (($self.data[7][$i] as i32) << 24)
                    | (($self.data[7][$i + 1] as i32) << 16)
                    | (($self.data[7][$i + 2] as i32) << 8)
                    | ($self.data[7][$i + 3] as i32),
                (($self.data[6][$i] as i32) << 24)
                    | (($self.data[6][$i + 1] as i32) << 16)
                    | (($self.data[6][$i + 2] as i32) << 8)
                    | ($self.data[6][$i + 3] as i32),
                (($self.data[5][$i] as i32) << 24)
                    | (($self.data[5][$i + 1] as i32) << 16)
                    | (($self.data[5][$i + 2] as i32) << 8)
                    | ($self.data[5][$i + 3] as i32),
                (($self.data[4][$i] as i32) << 24)
                    | (($self.data[4][$i + 1] as i32) << 16)
                    | (($self.data[4][$i + 2] as i32) << 8)
                    | ($self.data[4][$i + 3] as i32),
                (($self.data[3][$i] as i32) << 24)
                    | (($self.data[3][$i + 1] as i32) << 16)
                    | (($self.data[3][$i + 2] as i32) << 8)
                    | ($self.data[3][$i + 3] as i32),
                (($self.data[2][$i] as i32) << 24)
                    | (($self.data[2][$i + 1] as i32) << 16)
                    | (($self.data[2][$i + 2] as i32) << 8)
                    | ($self.data[2][$i + 3] as i32),
                (($self.data[1][$i] as i32) << 24)
                    | (($self.data[1][$i + 1] as i32) << 16)
                    | (($self.data[1][$i + 2] as i32) << 8)
                    | ($self.data[1][$i + 3] as i32),
                (($self.data[0][$i] as i32) << 24)
                    | (($self.data[0][$i + 1] as i32) << 16)
                    | (($self.data[0][$i + 2] as i32) << 8)
                    | ($self.data[0][$i + 3] as i32),
            )
        }

        // $w = unsafe {
        //     _mm256_set_epi32(
        //         (self.data[7][index2_u] as i32)
        //             | ((self.data[7][index2_u + 1] as i32) << 8)
        //             | ((self.data[7][index2_u + 2] as i32) << 16)
        //             | ((self.data[7][index2_u + 3] as i32) << 24),
        //         (self.data[6][index2_u] as i32)
        //             | ((self.data[6][index2_u + 1] as i32) << 8)
        //             | ((self.data[6][index2_u + 2] as i32) << 16)
        //             | ((self.data[6][index2_u + 3] as i32) << 24),
        //         (self.data[5][index2_u] as i32)
        //             | ((self.data[5][index2_u + 1] as i32) << 8)
        //             | ((self.data[5][index2_u + 2] as i32) << 16)
        //             | ((self.data[5][index2_u + 3] as i32) << 24),
        //         (self.data[4][index2_u] as i32)
        //             | ((self.data[4][index2_u + 1] as i32) << 8)
        //             | ((self.data[4][index2_u + 2] as i32) << 16)
        //             | ((self.data[4][index2_u + 3] as i32) << 24),
        //         (self.data[3][index2_u] as i32)
        //             | ((self.data[3][index2_u + 1] as i32) << 8)
        //             | ((self.data[3][index2_u + 2] as i32) << 16)
        //             | ((self.data[3][index2_u + 3] as i32) << 24),
        //         (self.data[2][index2_u] as i32)
        //             | ((self.data[2][index2_u + 1] as i32) << 8)
        //             | ((self.data[2][index2_u + 2] as i32) << 16)
        //             | ((self.data[2][index2_u + 3] as i32) << 24),
        //         (self.data[1][index2_u] as i32)
        //             | ((self.data[1][index2_u + 1] as i32) << 8)
        //             | ((self.data[1][index2_u + 2] as i32) << 16)
        //             | ((self.data[1][index2_u + 3] as i32) << 24),
        //         (self.data[0][index2_u] as i32)
        //             | ((self.data[0][index2_u + 1] as i32) << 8)
        //             | ((self.data[0][index2_u + 2] as i32) << 16)
        //             | ((self.data[0][index2_u + 3] as i32) << 24),
        //     )
        // }
    };
}

macro_rules! SHA256_FUNCTION_16 {
    ($self:ident,$a:expr,$b:expr,$c:expr,$d:expr,$e:expr,$f:expr,$g:expr,$h:expr,$i:expr,$w:expr,$j:expr) => {
        let ch_res = ch_avx2($e, $f, $g);
        let maj_res = maj_avx2($a, $b, $c);
        let ep0_res = ep0_avx2($a);
        let ep1_res = ep1_avx2($e);

        unsafe {
            let mut t1 = _mm256_add_epi32($h, ep1_res);
            t1 = _mm256_add_epi32(t1, ch_res);
            t1 = _mm256_add_epi32(t1, _mm256_set1_epi32(K[$i] as i32));
            t1 = _mm256_add_epi32(t1, $w);

            let t2 = _mm256_add_epi32(ep0_res, maj_res);

            $h = $g;
            $g = $f;
            $f = $e;

            $e = _mm256_add_epi32($d, t1);

            $d = $c;
            $c = $b;
            $b = $a;

            $a = _mm256_add_epi32(t1, t2);
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

    pub fn update(
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

        for i in 0..4 {
            for j in 0..8 {
                let split_m256i =
                    unsafe { core::mem::transmute::<&__m256i, &[u32; 8]>(&self.state[j]) };

                let i2 = i + (j * 4);
                let shift = 24 - (i * 8);

                self.hash[0][i2] = ((split_m256i[j] >> shift) & 0x000000ff) as u8;
                self.hash[1][i2] = ((split_m256i[j] >> shift) & 0x000000ff) as u8;
                self.hash[2][i2] = ((split_m256i[j] >> shift) & 0x000000ff) as u8;
                self.hash[3][i2] = ((split_m256i[j] >> shift) & 0x000000ff) as u8;
                self.hash[4][i2] = ((split_m256i[j] >> shift) & 0x000000ff) as u8;
                self.hash[5][i2] = ((split_m256i[j] >> shift) & 0x000000ff) as u8;
                self.hash[6][i2] = ((split_m256i[j] >> shift) & 0x000000ff) as u8;
                self.hash[7][i2] = ((split_m256i[j] >> shift) & 0x000000ff) as u8;
            }
        }
    }

    pub fn digest(data: &[u8]) -> [[u8; 32]; 8] {
        let mut sha256 = Self::default();
        sha256.update(data, data, data, data, data, data, data, data);
        sha256.finalize();

        sha256.hash
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