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
    let test_str8 = "this is a test string to test sha256";

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
