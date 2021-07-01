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
