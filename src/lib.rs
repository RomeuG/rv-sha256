#![no_std]
#![feature(core_intrinsics)]

use core::intrinsics;

// constants
const INIT_CONSTANTS: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

#[inline]
pub fn sqrtf32(f: f32) -> f32 {
    return unsafe { intrinsics::sqrtf32(f) };
}

#[inline]
pub fn sqrtf64(f: f64) -> f64 {
    return unsafe { intrinsics::sqrtf64(f) };
}

#[inline]
pub fn powf64(f: f64, n: f64) -> f64 {
    return unsafe { intrinsics::powf64(f, n) };
}

#[inline]
pub fn roundf64(f: f64) -> f64 {
    return unsafe { intrinsics::roundf64(f) };
}

#[inline]
pub fn floorf64(f: f64) -> u32 {
    return unsafe { intrinsics::floorf64(f) as u32 };
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_works() {
        let result = sqrtf64(2.0);
        let result2 = result % 1.0;
        let result3 = result2 * powf64(16.0, 8.0);
        let result4 = floorf64(result3);
        assert_eq!(result4, 1);
    }
}
