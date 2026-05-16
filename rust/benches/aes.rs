//! Benchmarks via `criterion`. Rodar com `cargo bench`.
//!
//! Não compara contra implementações com AES-NI nem entre AES-128/192/256 —
//! o objetivo é mostrar o custo *relativo* do estilo didático em Rust. Para
//! comparar com a versão TS e com a `node:crypto` (que usa AES-NI), veja
//! `bench/bench.ts`.

use aes_rs::{cbc_encrypt, gcm_encrypt, Aes128};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn bench_block(c: &mut Criterion) {
    let cipher = Aes128::new(&[0u8; 16]);
    let block = [0u8; 16];

    let mut group = c.benchmark_group("aes-128");
    group.throughput(Throughput::Bytes(16));
    group.bench_function("encrypt_block", |b| {
        b.iter(|| cipher.encrypt(black_box(block)));
    });
    group.bench_function("decrypt_block", |b| {
        let ct = cipher.encrypt(block);
        b.iter(|| cipher.decrypt(black_box(ct)));
    });
    group.finish();
}

fn bench_cbc(c: &mut Criterion) {
    let cipher = Aes128::new(&[0u8; 16]);
    let iv = [0u8; 16];

    let mut group = c.benchmark_group("aes-128-cbc");
    for &size in &[64usize, 1024, 65536] {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("encrypt_{size}B"), |b| {
            b.iter(|| cbc_encrypt(&cipher, &iv, black_box(&data)));
        });
    }
    group.finish();
}

fn bench_gcm(c: &mut Criterion) {
    let cipher = Aes128::new(&[0u8; 16]);
    let iv = [0u8; 12];

    let mut group = c.benchmark_group("aes-128-gcm");
    for &size in &[64usize, 1024, 65536] {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("encrypt_{size}B"), |b| {
            b.iter(|| gcm_encrypt(&cipher, &iv, black_box(&data), &[]));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_block, bench_cbc, bench_gcm);
criterion_main!(benches);
