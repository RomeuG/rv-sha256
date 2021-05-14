use std::env;

use sha256::{self, Sha256};

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

    unsafe {
        String::from_utf8_unchecked(v)
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 2 {
        let text = &args[1];
        let hash = Sha256::digest(text.as_bytes());

        println!("{}", to_hex_string(&hash));
    }
}
