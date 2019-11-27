use std::cell::RefCell;
use std::rc::Rc;

use criterion::{criterion_group, criterion_main, Criterion};

use hasher::HasherKeccak;
use uuid::Uuid;

use cita_trie::MemoryDB;
use cita_trie::{PatriciaTrie, Trie};

fn insert_worse_case_benchmark(c: &mut Criterion) {
    c.bench_function("cita-trie insert one", |b| {
        let mut trie = new_trie();

        b.iter(|| {
            let key = Uuid::new_v4().as_bytes().to_vec();
            let value = Uuid::new_v4().as_bytes().to_vec();
            trie.insert(key, value).unwrap()
        })
    });

    c.bench_function("cita-trie insert 1k", |b| {
        let mut trie = new_trie();

        let (keys, values) = random_data(1000);
        b.iter(|| {
            for i in 0..keys.len() {
                trie.insert(keys[i].clone(), values[i].clone()).unwrap()
            }
        });
    });

    c.bench_function("cita-trie insert 10k", |b| {
        let mut trie = new_trie();

        let (keys, values) = random_data(10000);
        b.iter(|| {
            for i in 0..keys.len() {
                trie.insert(keys[i].clone(), values[i].clone()).unwrap()
            }
        });
    });
}

fn random_data(n: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut keys = Vec::with_capacity(n);
    let mut values = Vec::with_capacity(n);
    for _ in 0..n {
        let key = Uuid::new_v4().as_bytes().to_vec();
        let value = Uuid::new_v4().as_bytes().to_vec();
        keys.push(key);
        values.push(value);
    }

    (keys, values)
}

fn new_trie() -> PatriciaTrie<MemoryDB, HasherKeccak> {
    PatriciaTrie::new(
        Rc::new(RefCell::new(MemoryDB::new(false))),
        Rc::new(RefCell::new(HasherKeccak::new())),
    )
}

criterion_group!(benches, insert_worse_case_benchmark);
criterion_main!(benches);
