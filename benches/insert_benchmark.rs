use criterion::{criterion_group, criterion_main, Criterion};

use cita_trie::codec::RLPNodeCodec;
use cita_trie::db::MemoryDB;
use cita_trie::trie::{PatriciaTrie, Trie};
use std::sync::Arc;

fn insert_worse_case_benchmark(c: &mut Criterion) {
    c.bench_function("insert 100 items", |b| {
        b.iter(|| {
            let memdb = Arc::new(MemoryDB::new(true));
            let mut trie = PatriciaTrie::new(memdb, RLPNodeCodec::default());
            const N: usize = 100;
            let mut buf = Vec::new();
            for i in 0..N {
                buf.push(i as u8);
                trie.insert(&buf, b"testvalue").unwrap();
            }
        })
    });
}

criterion_group!(benches, insert_worse_case_benchmark);
criterion_main!(benches);
