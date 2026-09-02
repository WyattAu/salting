use criterion::{Criterion, criterion_group, criterion_main};

fn bench_hash_password(c: &mut Criterion) {
    c.bench_function("hash_password_default", |b| {
        b.iter(|| salting::hash_password("benchmark-password-123").unwrap());
    });
}

fn bench_hash_password_low_memory(c: &mut Criterion) {
    let params = salting::Argon2Params::low_memory();
    c.bench_function("hash_password_low_memory", |b| {
        b.iter(|| salting::hash_password_with_params("benchmark-password-123", &params).unwrap());
    });
}

fn bench_verify_password(c: &mut Criterion) {
    let hash = salting::hash_password("benchmark-password-123").unwrap();
    c.bench_function("verify_password", |b| {
        b.iter(|| salting::verify_password("benchmark-password-123", &hash).unwrap());
    });
}

criterion_group!(
    benches,
    bench_hash_password,
    bench_hash_password_low_memory,
    bench_verify_password,
);
criterion_main!(benches);
