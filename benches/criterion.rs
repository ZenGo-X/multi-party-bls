use bls::threshold_bls::test::{keygen_t_n_parties, sign};

use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn threshold_bls(c: &mut Criterion) {
    c.bench_function("keygen t=1 n=2", |b| {
        b.iter(|| keygen_t_n_parties(black_box(1), 2))
    });
    c.bench_function("keygen t=2 n=3", |b| {
        b.iter(|| keygen_t_n_parties(black_box(2), 3))
    });
}

criterion_group!(benches, threshold_bls);
criterion_main!(benches);
