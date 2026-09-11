// Benchmarks compare `salting` (a DX wrapper) against the raw `argon2`
// crate at equivalent parameters, plus bcrypt/scrypt at their
// OWASP-recommended costs. Fixed, known-good inputs; unwrap failures
// abort the bench run visibly, which is the desired behavior here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use criterion::{Criterion, criterion_group, criterion_main};
use password_hash::{PasswordHasher, PasswordVerifier};

const PASSWORD: &str = "correct horse battery staple";

fn salting_default_params() -> salting::Argon2Params {
    salting::Argon2Params::default() // 64 MiB, t=3, p=4 — OWASP table row
}

fn raw_argon2_default_params() -> argon2::Argon2<'static> {
    let params = argon2::Params::new(65536, 3, 4, Some(32)).unwrap();
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

fn bench_salting_vs_raw_argon2(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2id_m65536_t3_p4");

    let params = salting_default_params();
    group.bench_function("hash/salting", |b| {
        b.iter(|| salting::hash_password_with_params(PASSWORD, &params).unwrap());
    });

    let raw = raw_argon2_default_params();
    group.bench_function("hash/raw_argon2", |b| {
        b.iter(|| raw.hash_password(PASSWORD.as_bytes()).unwrap());
    });

    let hash = salting::hash_password_with_params(PASSWORD, &params).unwrap();
    group.bench_function("verify/salting", |b| {
        b.iter(|| salting::verify_password(PASSWORD, &hash).unwrap());
    });

    let parsed = argon2::PasswordHash::new(&hash).unwrap();
    group.bench_function("verify/raw_argon2", |b| {
        b.iter(|| {
            argon2::Argon2::default()
                .verify_password(PASSWORD.as_bytes(), &parsed)
                .is_ok()
        });
    });

    // Pepper overhead: the secret rides along as the Argon2 `K` input, so
    // the wrapper's cost over raw argon2 should measure ~0.
    let pepper = salting::Pepper::new(b"benchmark-pepper-from-kms").unwrap();
    let peppered_hash = salting::hash_password_with_pepper(PASSWORD, &pepper).unwrap();
    group.bench_function("hash/salting_peppered", |b| {
        b.iter(|| salting::hash_password_with_pepper(PASSWORD, &pepper).unwrap());
    });
    group.bench_function("verify/salting_peppered", |b| {
        b.iter(|| salting::verify_password_with_pepper(PASSWORD, &peppered_hash, &pepper).unwrap());
    });

    group.finish();
}

fn bench_salting_low_memory(c: &mut Criterion) {
    let params = salting::Argon2Params::low_memory();
    c.bench_function("argon2id_m65536_t2_p1/salting_hash", |b| {
        b.iter(|| salting::hash_password_with_params(PASSWORD, &params).unwrap());
    });
}

/// OWASP-recommended bcrypt cost: 10.
fn bench_bcrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("bcrypt_cost10");
    group.bench_function("hash", |b| {
        b.iter(|| bcrypt::hash(PASSWORD, 10).unwrap());
    });
    let hash = bcrypt::hash(PASSWORD, 10).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| bcrypt::verify(PASSWORD, &hash).unwrap());
    });
    group.finish();
}

/// OWASP-recommended scrypt cost: N=2^17, r=8, p=1.
fn bench_scrypt(c: &mut Criterion) {
    let params = scrypt::Params::new(17, 8, 1, 32).unwrap();
    let salt = [0x42u8; 16]; // bench-only fixed salt
    let mut out = [0u8; 32];

    let mut group = c.benchmark_group("scrypt_n2^17_r8_p1");
    group.bench_function("hash", |b| {
        b.iter(|| scrypt::scrypt(PASSWORD.as_bytes(), &salt, &params, &mut out).unwrap());
    });
    // scrypt ships no PHC verify helper; verification is a re-derivation
    // plus a constant-time compare (the compare is ~0 next to the KDF).
    let expected = {
        let mut expect = [0u8; 32];
        scrypt::scrypt(PASSWORD.as_bytes(), &salt, &params, &mut expect).unwrap();
        expect
    };
    group.bench_function("verify", |b| {
        b.iter(|| {
            scrypt::scrypt(PASSWORD.as_bytes(), &salt, &params, &mut out).unwrap();
            out == expected
        });
    });
    group.finish();
}

criterion_group!(
    name = hash_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_salting_vs_raw_argon2, bench_salting_low_memory, bench_bcrypt, bench_scrypt
);
criterion_main!(hash_benches);
