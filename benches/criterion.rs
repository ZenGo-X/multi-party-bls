use bls::threshold_bls::test::{keygen_t_n_parties, sign};

use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};

pub fn threshold_bls(c: &mut Criterion) {
    // Configure benchmarks
    let mut g = c.benchmark_group("bls-mpc");
    g.sampling_mode(SamplingMode::Linear);
    g.sample_size(45);

    // Measure keygen
    g.bench_function("keygen t=1 n=2", |b| {
        b.iter(|| black_box(keygen_t_n_parties(1, 2)))
    });
    g.bench_function("keygen t=2 n=3", |b| {
        b.iter(|| keygen_t_n_parties(black_box(2), 3))
    });

    // Measure sign
    let keygen_1_2 = keygen_t_n_parties(black_box(1), 2);
    let keygen_2_3 = keygen_t_n_parties(black_box(2), 3);
    let data_to_sign = b"Hello threshold World";
    let signers = &[0usize, 1, 2];

    g.bench_function("sign t=1 n=2", |b| {
        b.iter(|| sign(data_to_sign, 1, 2, &signers[..2], Some(keygen_1_2.clone())))
    });
    g.bench_function("sign t=2 n=3", |b| {
        b.iter(|| sign(data_to_sign, 2, 3, &signers[..3], Some(keygen_2_3.clone())))
    });
}

criterion_group!(benches, threshold_bls);
criterion_main!(benches);
