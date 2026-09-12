// iai-callgrind benchmarks run once under Valgrind on fixed inputs; the
// harness measures instruction counts, so there is no "expected failure"
// recovery path — a panic aborts the run visibly, which is what we want.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

//! Deterministic gate for the README's **"wrapper overhead ≈ 0"** claim.
//!
//! The production OWASP parameters (64 MiB, t=3, p=4) cost billions of
//! instructions, all of them inside Argon2's memory-hard loop — far too
//! slow to run under Valgrind on every change, and the loop itself is
//! identical for wrapper and raw call. So this gate hashes at *small*
//! parameters (64 KiB, t=1, p=1 — otherwise identical inputs, same PHC
//! string format, salt generation included on both sides) and pins the
//! instruction counts of:
//!
//! - `wrapper_hash_small` vs `raw_hash_small` — the instruction delta is
//!   the wrapper's entire cost over the raw `argon2` crate (a few hundred
//!   instructions of string/format handling; measured 2026-09-12, see
//!   CLAIMS.md). Relative to a production hash (~10⁹ instructions), the
//!   overhead is ~10⁻⁵ % — that is the precise form of "≈ 0".
//! - `wrapper_verify_small` vs `raw_verify_small` — same for the verify
//!   path.
//!
//! Criterion (`benches/hash_bench.rs`) owns the wall-clock table at
//! production parameters; this file is the pass/fail gate. Locally
//! requires `valgrind`; without it, compile-check only:
//! `cargo bench --no-run --bench iai_hot_path`.

use std::hint::black_box;

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use password_hash::{PasswordHasher, PasswordVerifier};
use salting::Argon2Params;

const PASSWORD: &str = "correct horse battery staple";

/// 64 KiB, t=1, p=1: same code path as production, ~10³× cheaper so
/// Valgrind finishes in seconds.
fn small_params() -> Argon2Params {
    Argon2Params {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
        output_len: 32,
    }
}

fn raw_argon2_small() -> argon2::Argon2<'static> {
    let params = argon2::Params::new(64, 1, 1, Some(32)).unwrap();
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

fn setup_wrapper_hash() -> Argon2Params {
    small_params()
}

#[library_benchmark]
#[bench::small(setup = setup_wrapper_hash)]
fn wrapper_hash_small(params: Argon2Params) -> String {
    black_box(salting::hash_password_with_params(PASSWORD, &params).unwrap())
}

fn setup_raw() -> argon2::Argon2<'static> {
    raw_argon2_small()
}

#[library_benchmark]
#[bench::small(setup = setup_raw)]
fn raw_hash_small(raw: argon2::Argon2<'static>) -> String {
    black_box(raw.hash_password(PASSWORD.as_bytes()).unwrap().to_string())
}

// Verify against a hash of PASSWORD computed in setup (runs outside the
// measured region). The random salt inside the PHC string has fixed
// length, so the measured parse + verify path is deterministic.
fn setup_phc() -> String {
    salting::hash_password_with_params(PASSWORD, &small_params()).unwrap()
}

#[library_benchmark]
#[bench::small_phc(setup = setup_phc)]
fn wrapper_verify_small(phc: String) -> bool {
    black_box(salting::verify_password(PASSWORD, &phc).unwrap_or(false))
}

#[library_benchmark]
#[bench::small_phc(setup = setup_phc)]
fn raw_verify_small(phc: String) -> bool {
    let parsed = match argon2::PasswordHash::new(&phc) {
        Ok(p) => p,
        Err(_) => return false,
    };
    black_box(
        raw_argon2_small()
            .verify_password(PASSWORD.as_bytes(), &parsed)
            .is_ok(),
    )
}

library_benchmark_group!(
    name = iai_hot_path;
    benchmarks =
        wrapper_hash_small,
        raw_hash_small,
        wrapper_verify_small,
        raw_verify_small
);

main!(library_benchmark_groups = iai_hot_path);
