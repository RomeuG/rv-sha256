SHA-256 in Rust
===============

This is an implementation of the SHA-256 Hashing Algorithm in Rust, without the use of the
Rust Standard Library.

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

LICENSE
=======

Copyright 2021 Romeu Gomes

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
