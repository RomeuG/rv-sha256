SHA-256 in Rust
===============

This is an implementation of the SHA-256 Hashing Algorithm in Rust, without the use of the
Rust Standard Library.

This project uses the **nightly** version of Rust because of the SIMD instructions.

Examples
========

This is the content of `examples/sha256_example.rs`, using the normal SHA256
implementation with some changes:

```rust
use sha256::sha256::Sha256;

/// convert bytes to hex string
/// code taken from hex project: https://docs.rs/crate/hex/0.1.0/source/src/lib.rs
fn to_hex_string(data: &[u8]) -> String {
    static CHARS: &'static [u8] = b"0123456789abcdef";

    let bytes = data.as_ref();
    let mut v = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes.iter() {
        v.push(CHARS[(byte >> 4) as usize]);
        v.push(CHARS[(byte & 0xf) as usize]);
    }

    unsafe { String::from_utf8_unchecked(v) }
}

fn main() {
    let test_str1 = "this";
    let test_str2 = "this is";
    let test_str3 = "this is a";
    let test_str4 = "this is a test";
    let test_str5 = "this is a test string";
    let test_str6 = "this is a test string to";
    let test_str7 = "this is a test string to test";
    let test_str8 = "this is a test string to test md5";

    let hash1 = Sha256::digest(test_str1.as_bytes());
    let hash2 = Sha256::digest(test_str2.as_bytes());
    let hash3 = Sha256::digest(test_str3.as_bytes());
    let hash4 = Sha256::digest(test_str4.as_bytes());
    let hash5 = Sha256::digest(test_str5.as_bytes());
    let hash6 = Sha256::digest(test_str6.as_bytes());
    let hash7 = Sha256::digest(test_str7.as_bytes());
    let hash8 = Sha256::digest(test_str8.as_bytes());

    println!("{: <33} => {: <33}", test_str1, to_hex_string(&hash1));
    println!("{: <33} => {: <33}", test_str2, to_hex_string(&hash2));
    println!("{: <33} => {: <33}", test_str3, to_hex_string(&hash3));
    println!("{: <33} => {: <33}", test_str4, to_hex_string(&hash4));
    println!("{: <33} => {: <33}", test_str5, to_hex_string(&hash5));
    println!("{: <33} => {: <33}", test_str6, to_hex_string(&hash6));
    println!("{: <33} => {: <33}", test_str7, to_hex_string(&hash7));
    println!("{: <33} => {: <33}", test_str8, to_hex_string(&hash8));
}
```

If your CPU supports AVX2, you may want to take advantage of it by using the AVX2 specific
SHA256 struct, that is exemplified in `examples/sha256_avx2_example.rs`:

```rust
use sha256::sha256_avx2::Sha256Avx2;

/// convert bytes to hex string
/// code taken from hex project: https://docs.rs/crate/hex/0.1.0/source/src/lib.rs
fn to_hex_string(data: &[u8]) -> String {
    static CHARS: &'static [u8] = b"0123456789abcdef";

    let bytes = data.as_ref();
    let mut v = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes.iter() {
        v.push(CHARS[(byte >> 4) as usize]);
        v.push(CHARS[(byte & 0xf) as usize]);
    }

    unsafe { String::from_utf8_unchecked(v) }
}

fn main() {
    let test_strs = vec![
        "this is a test string 1",
        "this is a test string 2",
        "this is a test string 3",
        "this is a test string 4",
        "this is a test string 5",
        "this is a test string 6",
        "this is a test string 7",
        "this is a test string 8",
    ];

    let hash = Sha256Avx2::digest8(
        &test_strs[0].as_bytes(),
        &test_strs[1].as_bytes(),
        &test_strs[2].as_bytes(),
        &test_strs[3].as_bytes(),
        &test_strs[4].as_bytes(),
        &test_strs[5].as_bytes(),
        &test_strs[6].as_bytes(),
        &test_strs[7].as_bytes(),
    );

    for (i, digest) in hash.iter().enumerate() {
        println!("{} => {}", test_strs[i], to_hex_string(digest));
    }
}
```

Benchmarks
==========

```
test tests::bench_sha256_128bytes      ... bench:         700 ns/iter (+/- 15)
test tests::bench_sha256_256bytes      ... bench:       1,188 ns/iter (+/- 47)
test tests::bench_sha256_32bytes       ... bench:         240 ns/iter (+/- 6)
test tests::bench_sha256_64bytes       ... bench:         457 ns/iter (+/- 9)

test tests::bench_sha256_avx2_128bytes ... bench:       1,576 ns/iter (+/- 31)
test tests::bench_sha256_avx2_256bytes ... bench:       2,657 ns/iter (+/- 116)
test tests::bench_sha256_avx2_32bytes  ... bench:         575 ns/iter (+/- 20)
test tests::bench_sha256_avx2_64bytes  ... bench:       1,043 ns/iter (+/- 29)
```

On the AVX2 implementation
==========================

Thanks to the AVX2 implementation, it is possible to hash 8 strings at the same time. The
only limitation is that the size of all strings has to be the same. If there is any string
with a different size, then its result will be absolutely incorrect.

License
=======

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Contribution
============

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
