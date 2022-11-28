## CITA-Trie

[![Latest Version](https://img.shields.io/crates/v/cita_trie.svg)](https://crates.io/crates/cita_trie)
[![](https://travis-ci.org/cryptape/cita-trie.svg?branch=master)](https://travis-ci.org/cryptape/cita-trie)
[![](https://img.shields.io/hexpm/l/plug.svg)](https://github.com/cryptape/cita-trie/blob/master/LICENSE)

Rust implementation of the Modified Patricia Tree (aka Trie),

The implementation is strongly inspired by [go-ethereum trie](https://github.com/ethereum/go-ethereum/tree/master/trie)

## Features

- Implementation of the Modified Patricia Tree
- Custom hash algorithm (Keccak is provided by default)
- Custom storage interface

## Example

```rust
use std::sync::Arc;

use hasher::{Hasher, HasherKeccak}; // https://crates.io/crates/hasher

use cita_trie::MemoryDB;
use cita_trie::{PatriciaTrie, Trie};

fn main() {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());

    let key = "test-key".as_bytes();
    let value = "test-value".as_bytes();

    let root = {
        let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
        trie.insert(key.to_vec(), value.to_vec()).unwrap();

        let v = trie.get(key).unwrap();
        assert_eq!(Some(value.to_vec()), v);
        trie.root().unwrap()
    };

    let mut trie = PatriciaTrie::from(Arc::clone(&memdb), Arc::clone(&hasher), &root).unwrap();

    let exists = trie.contains(key).unwrap();
    assert_eq!(exists, true);
    let removed = trie.remove(key).unwrap();
    assert_eq!(removed, true);
    let new_root = trie.root().unwrap();
    println!("new root = {:?}", new_root);

}

```

## Benchmark

```sh
cargo bench

Gnuplot not found, disabling plotting
insert one              time:   [1.6564 us 1.7287 us 1.7955 us]
                        change: [-2.2715% +1.5151% +5.1789%] (p = 0.42 > 0.05)
                        No change in performance detected.

insert 1k               time:   [1.1620 ms 1.1763 ms 1.1942 ms]
                        change: [-2.3339% +0.7190% +3.7809%] (p = 0.65 > 0.05)
                        No change in performance detected.
Found 16 outliers among 100 measurements (16.00%)
  9 (9.00%) high mild
  7 (7.00%) high severe

insert 10k              time:   [13.491 ms 13.677 ms 13.891 ms]
                        change: [-5.3670% -1.2847% +2.8328%] (p = 0.54 > 0.05)
                        No change in performance detected.
Found 10 outliers among 100 measurements (10.00%)
  9 (9.00%) high mild
  1 (1.00%) high severe

get based 10k           time:   [1.0707 us 1.0965 us 1.1270 us]
                        change: [-10.331% -6.5107% -2.6793%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 11 outliers among 100 measurements (11.00%)
  11 (11.00%) high mild

remove 1k               time:   [538.54 us 545.18 us 553.96 us]
                        change: [-7.3508% -0.7110% +7.0860%] (p = 0.86 > 0.05)
                        No change in performance detected.
Found 12 outliers among 100 measurements (12.00%)
  5 (5.00%) high mild
  7 (7.00%) high severe

remove 10k              time:   [5.7277 ms 5.7780 ms 5.8367 ms]
                        change: [-18.778% -5.4831% +10.503%] (p = 0.51 > 0.05)
                        No change in performance detected.
Found 11 outliers among 100 measurements (11.00%)
  1 (1.00%) high mild
  10 (10.00%) high severe
```

### Custom hash algorithm
See: https://crates.io/crates/hasher

### Custom storage

[Refer](https://github.com/cryptape/cita-trie/blob/master/src/db.rs)
