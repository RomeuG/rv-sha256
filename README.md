SHA-256 in Rust
===============

This is an implementation of the SHA-256 Hashing Algorithm in Rust, without the use of the
Rust Standard Library.

This project uses the **nightly** version of Rust.

Example
=======

This is the content of `examples/main.rs`:

```rust
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
```

Benchmarks
==========

```
test tests::bench_sha256_128bytes ... bench:       1,040 ns/iter (+/- 73)
test tests::bench_sha256_256bytes ... bench:       1,758 ns/iter (+/- 76)
test tests::bench_sha256_32bytes  ... bench:         361 ns/iter (+/- 22)
test tests::bench_sha256_64bytes  ... bench:         678 ns/iter (+/- 45)
```

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