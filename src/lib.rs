#![no_std]
#![feature(stmt_expr_attributes)]
#![feature(core_intrinsics)]
#![feature(test)]

#[macro_use]
pub mod utils;
pub mod sha256;
pub mod sha256_avx2;

#[cfg(test)]
mod tests {
    use super::*;
    use sha256::Sha256;
    use sha256_avx2::Sha256Avx2;

    extern crate test;
    use test::Bencher;

    #[test]
    fn sha256_32bytes() {
        let hash = Sha256::digest("wqvDrDLilCUevxUw5fWEuVc6y6ElCrHg".as_bytes());
        assert_eq!(
            hash,
            [
                0xad, 0xc8, 0x24, 0x3e, 0xfd, 0x7a, 0xef, 0x68, 0x20, 0xce, 0xdc, 0xe0, 0xc9, 0xc8,
                0xbe, 0x26, 0x13, 0x0a, 0xc5, 0x77, 0xde, 0x8c, 0x62, 0x1c, 0x9c, 0xa8, 0x0d, 0xd4,
                0xaf, 0x19, 0x77, 0xf8
            ]
        );
    }

    #[test]
    fn sha256_64bytes() {
        let hash = Sha256::digest(
            "K7CN3VzXyY63NXmW15TKA4O6vJtVrLc7I0B5qHRtBir5PkwSt6xgJopOCunPk2ky".as_bytes(),
        );
        assert_eq!(
            hash,
            [
                0x59, 0xd5, 0x93, 0xea, 0x4e, 0x90, 0xce, 0x36, 0x60, 0x7d, 0xc3, 0x39, 0x96, 0x9a,
                0x6c, 0xe4, 0x07, 0x7b, 0xb2, 0xda, 0x86, 0x09, 0x27, 0x25, 0xfe, 0x94, 0xdb, 0xf8,
                0xb1, 0x1f, 0x3e, 0x09
            ]
        );
    }

    #[test]
    fn sha256_128bytes() {
        let hash = Sha256::digest("KAjb6sifm7DwdyJyMXT3np6WZVfXJiEskX1fN7V8YOatxuRkpHYZmqDXY2Kn2pfnV63l0bodaXjRdVF5m2z1bC7QpdQi3UHRI9KAqWs0vO0QjT5XtkTXKlaRK4CiBsT1".as_bytes());
        assert_eq!(
            hash,
            [
                0x64, 0x4c, 0xb0, 0x9c, 0x0d, 0x42, 0x26, 0x6c, 0x3a, 0x15, 0x82, 0x6c, 0xec, 0xaf,
                0x91, 0x93, 0xfa, 0x05, 0x9d, 0x10, 0x22, 0xed, 0xd6, 0xdb, 0x3a, 0x5a, 0x4c, 0xb7,
                0x19, 0x03, 0x12, 0x24
            ]
        );
    }

    #[test]
    fn sha256_256bytes() {
        let hash = Sha256::digest("QnpFg2P1SEQ0L9tcNwBROCW7jVtFeMt0RuF7QODKkgD75CPDi1pAB1GtMcq0G1pmNE6J3IuPpF33uPtOs4sNwU7lKcnF8SU016PKWPeVEpuKQ2ksT9enIf1hVrzlypOkhFTFhIS28IT9OQZ3BS3693487mSb6QNuuaBCD8yNWWlo74c79EFWUWNaAmRcSxVaNcbDa80SovlnL8lyO2yS7XlmE7rPmLI4IvPtko3QguI4Th2JPrVnM7QCCjMgvlIO".as_bytes());
        assert_eq!(
            hash,
            [
                0x68, 0x7f, 0x3b, 0x1d, 0xe7, 0x47, 0x02, 0x47, 0x55, 0xb3, 0x6f, 0x87, 0xd4, 0x1f,
                0x02, 0x66, 0x07, 0xd1, 0x20, 0x57, 0x18, 0x4a, 0xf4, 0x68, 0xb0, 0x39, 0xad, 0x28,
                0x41, 0xed, 0x43, 0xe4
            ]
        );
    }

    #[test]
    fn sha256_avx2_32bytes() {
        let hash = Sha256Avx2::digest("wqvDrDLilCUevxUw5fWEuVc6y6ElCrHg".as_bytes());
        assert_eq!(
            hash[0],
            [
                0xad, 0xc8, 0x24, 0x3e, 0xfd, 0x7a, 0xef, 0x68, 0x20, 0xce, 0xdc, 0xe0, 0xc9, 0xc8,
                0xbe, 0x26, 0x13, 0x0a, 0xc5, 0x77, 0xde, 0x8c, 0x62, 0x1c, 0x9c, 0xa8, 0x0d, 0xd4,
                0xaf, 0x19, 0x77, 0xf8
            ]
        );
    }

    #[test]
    fn sha256_avx2_64bytes() {
        let hash = Sha256Avx2::digest(
            "K7CN3VzXyY63NXmW15TKA4O6vJtVrLc7I0B5qHRtBir5PkwSt6xgJopOCunPk2ky".as_bytes(),
        );
        assert_eq!(
            hash[0],
            [
                0x59, 0xd5, 0x93, 0xea, 0x4e, 0x90, 0xce, 0x36, 0x60, 0x7d, 0xc3, 0x39, 0x96, 0x9a,
                0x6c, 0xe4, 0x07, 0x7b, 0xb2, 0xda, 0x86, 0x09, 0x27, 0x25, 0xfe, 0x94, 0xdb, 0xf8,
                0xb1, 0x1f, 0x3e, 0x09
            ]
        );
    }

    #[test]
    fn sha256_avx2_128bytes() {
        let hash = Sha256Avx2::digest("KAjb6sifm7DwdyJyMXT3np6WZVfXJiEskX1fN7V8YOatxuRkpHYZmqDXY2Kn2pfnV63l0bodaXjRdVF5m2z1bC7QpdQi3UHRI9KAqWs0vO0QjT5XtkTXKlaRK4CiBsT1".as_bytes());
        assert_eq!(
            hash[0],
            [
                0x64, 0x4c, 0xb0, 0x9c, 0x0d, 0x42, 0x26, 0x6c, 0x3a, 0x15, 0x82, 0x6c, 0xec, 0xaf,
                0x91, 0x93, 0xfa, 0x05, 0x9d, 0x10, 0x22, 0xed, 0xd6, 0xdb, 0x3a, 0x5a, 0x4c, 0xb7,
                0x19, 0x03, 0x12, 0x24
            ]
        );
    }

    #[test]
    fn sha256_avx2_256bytes() {
        let hash = Sha256Avx2::digest("QnpFg2P1SEQ0L9tcNwBROCW7jVtFeMt0RuF7QODKkgD75CPDi1pAB1GtMcq0G1pmNE6J3IuPpF33uPtOs4sNwU7lKcnF8SU016PKWPeVEpuKQ2ksT9enIf1hVrzlypOkhFTFhIS28IT9OQZ3BS3693487mSb6QNuuaBCD8yNWWlo74c79EFWUWNaAmRcSxVaNcbDa80SovlnL8lyO2yS7XlmE7rPmLI4IvPtko3QguI4Th2JPrVnM7QCCjMgvlIO".as_bytes());
        assert_eq!(
            hash[0],
            [
                0x68, 0x7f, 0x3b, 0x1d, 0xe7, 0x47, 0x02, 0x47, 0x55, 0xb3, 0x6f, 0x87, 0xd4, 0x1f,
                0x02, 0x66, 0x07, 0xd1, 0x20, 0x57, 0x18, 0x4a, 0xf4, 0x68, 0xb0, 0x39, 0xad, 0x28,
                0x41, 0xed, 0x43, 0xe4
            ]
        );
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
            Sha256::digest(
                "K7CN3VzXyY63NXmW15TKA4O6vJtVrLc7I0B5qHRtBir5PkwSt6xgJopOCunPk2ky".as_bytes(),
            );
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

    #[bench]
    fn bench_sha256_avx2_32bytes(b: &mut Bencher) {
        b.iter(|| {
            Sha256Avx2::digest("wqvDrDLilCUevxUw5fWEuVc6y6ElCrHg".as_bytes());
        });
    }

    #[bench]
    fn bench_sha256_avx2_64bytes(b: &mut Bencher) {
        b.iter(|| {
            Sha256Avx2::digest(
                "K7CN3VzXyY63NXmW15TKA4O6vJtVrLc7I0B5qHRtBir5PkwSt6xgJopOCunPk2ky".as_bytes(),
            );
        });
    }

    #[bench]
    fn bench_sha256_avx2_128bytes(b: &mut Bencher) {
        b.iter(|| {
                    Sha256Avx2::digest("KAjb6sifm7DwdyJyMXT3np6WZVfXJiEskX1fN7V8YOatxuRkpHYZmqDXY2Kn2pfnV63l0bodaXjRdVF5m2z1bC7QpdQi3UHRI9KAqWs0vO0QjT5XtkTXKlaRK4CiBsT1".as_bytes());
                });
    }

    #[bench]
    fn bench_sha256_avx2_256bytes(b: &mut Bencher) {
        b.iter(|| {
                    Sha256Avx2::digest("QnpFg2P1SEQ0L9tcNwBROCW7jVtFeMt0RuF7QODKkgD75CPDi1pAB1GtMcq0G1pmNE6J3IuPpF33uPtOs4sNwU7lKcnF8SU016PKWPeVEpuKQ2ksT9enIf1hVrzlypOkhFTFhIS28IT9OQZ3BS3693487mSb6QNuuaBCD8yNWWlo74c79EFWUWNaAmRcSxVaNcbDa80SovlnL8lyO2yS7XlmE7rPmLI4IvPtko3QguI4Th2JPrVnM7QCCjMgvlIO".as_bytes());
                });
    }
}
