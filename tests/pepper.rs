//! End-to-end pepper flows through the public API only: rotation,
//! migration, and the peppered/unpeppered incompatibility boundary.
//!
//! Tests exercise real login-shaped flows directly; unwrap is fine here —
//! a panic is a test failure, not a production hazard.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use salting::{Argon2Params, Hasher, PasswordError, Pepper};

fn test_params() -> Argon2Params {
    Argon2Params {
        memory_kib: 32,
        iterations: 1,
        parallelism: 1,
        output_len: 32,
    }
}

/// Rotation runbook, end to end: hashes minted under the old pepper keep
/// verifying during the rollout, `needs_rehash` flags exactly them, and
/// freshly rehashed accounts verify under the new pepper alone.
#[test]
fn login_flow_with_pepper_rotation() {
    let old = Pepper::new("pepper-v1-from-kms").unwrap();
    let new = Pepper::new("pepper-v2-from-kms").unwrap();

    // Before the rotation: accounts are hashed with `old`.
    let legacy_hasher = Hasher::new()
        .with_params(test_params())
        .with_pepper(old.clone());
    let stored = legacy_hasher.hash("correct horse battery staple").unwrap();

    // After the rotation: logins run against a hasher carrying both
    // peppers; new signups hash with `new`.
    let rotated = Hasher::new()
        .with_params(test_params())
        .with_pepper(new.clone())
        .with_previous_pepper(old);

    // Old-cohort login: verifies, flagged for rehash-on-login.
    assert!(
        rotated
            .verify("correct horse battery staple", &stored)
            .unwrap()
    );
    assert!(
        rotated
            .needs_rehash("correct horse battery staple", &stored)
            .unwrap()
    );
    let upgraded = rotated.hash("correct horse battery staple").unwrap();

    // The upgraded hash verifies under the rotation config *and* under a
    // new-pepper-only config (safe to retire the old pepper afterward).
    assert!(
        rotated
            .verify("correct horse battery staple", &upgraded)
            .unwrap()
    );
    assert!(
        !rotated
            .needs_rehash("correct horse battery staple", &upgraded)
            .unwrap()
    );
    let new_only = Hasher::new().with_params(test_params()).with_pepper(new);
    assert!(
        new_only
            .verify("correct horse battery staple", &upgraded)
            .unwrap()
    );
    assert!(
        !new_only
            .verify("correct horse battery staple", &stored)
            .unwrap()
    );

    // Failed logins never flip the rehash flag.
    assert!(!rotated.verify("wrong password", &stored).unwrap());
    assert!(!rotated.needs_rehash("wrong password", &stored).unwrap());
}

/// Migration runbook, end to end: a deployment adopts pepper support with
/// `accept_unpeppered(true)`, legacy hashes keep verifying, and each
/// legacy login is an opportunity to rehash.
#[test]
fn login_flow_migrating_to_pepper() {
    // Legacy era: unpeppered hashes (e.g. from salting 1.0/1.1).
    let legacy_stored = Hasher::new()
        .with_params(test_params())
        .hash("correct horse battery staple")
        .unwrap();

    let pepper = Pepper::new("fresh pepper").unwrap();
    let migrating = Hasher::new()
        .with_params(test_params())
        .with_pepper(pepper.clone())
        .accept_unpeppered(true);

    assert!(
        migrating
            .verify("correct horse battery staple", &legacy_stored)
            .unwrap()
    );
    assert!(
        migrating
            .needs_rehash("correct horse battery staple", &legacy_stored)
            .unwrap()
    );

    let upgraded = migrating.hash("correct horse battery staple").unwrap();
    assert!(
        !migrating
            .needs_rehash("correct horse battery staple", &upgraded)
            .unwrap()
    );

    // After the migration window: `accept_unpeppered(false)` — legacy
    // hashes no longer verify, peppered ones do.
    let migrated = Hasher::new().with_params(test_params()).with_pepper(pepper);
    assert!(
        !migrated
            .verify("correct horse battery staple", &legacy_stored)
            .unwrap()
    );
    assert!(
        migrated
            .verify("correct horse battery staple", &upgraded)
            .unwrap()
    );
}

/// The convenience wrappers and the `Hasher` builder are the same
/// construction: peppered hashes verify via both, and a peppered hash is
/// never verifiable through the unpeppered `verify_password` family.
#[test]
fn free_functions_and_hasher_agree() {
    let pepper = Pepper::new("shared pepper").unwrap();
    let wrapped = salting::hash_password_with_pepper("correct horse battery staple", &pepper)
        .expect("hash_password_with_pepper");
    let via_hasher = Hasher::new()
        .with_pepper(pepper.clone())
        .hash("correct horse battery staple")
        .expect("Hasher::hash");

    assert!(
        salting::verify_password_with_pepper("correct horse battery staple", &wrapped, &pepper)
            .unwrap()
    );
    assert!(
        salting::verify_password_with_pepper("correct horse battery staple", &via_hasher, &pepper)
            .unwrap()
    );

    // Incompatibility boundary: unpeppered functions reject peppered
    // hashes (fail closed), and vice versa.
    assert!(!salting::verify_password("correct horse battery staple", &wrapped).unwrap());
    assert!(
        !salting::verify_password_with_pepper(
            "correct horse battery staple",
            &salting::hash_password("correct horse battery staple").unwrap(),
            &pepper
        )
        .unwrap()
    );
}

/// Hostile-hash hardening is inherited by the peppered verify path: the
/// same malformed and over-bound PHC strings fail closed, and the new
/// error variants keep their static Display strings.
#[test]
fn peppered_verify_rejects_hostile_hashes() {
    let pepper = Pepper::new("pepper").unwrap();
    for garbage in [
        "",
        "not-a-phc-string",
        "$argon2id$",
        "$argon2id$v=19$m=65536,t=3,p=4$",
        "$argon2id$v=19$m=999999,t=1,p=1$c2FsdA$cGFzc3dvcmQ",
        "$argon2id$v=19$m=0,t=1,p=1$c2FsdA$cGFzc3dvcmQ",
    ] {
        assert!(
            salting::verify_password_with_pepper("x", garbage, &pepper).is_err(),
            "expected Err for {garbage:?}"
        );
    }

    let hasher = Hasher::new()
        .with_params(test_params())
        .with_pepper(pepper.clone());
    assert!(
        hasher
            .verify("x", "$argon2id$v=19$m=999999,t=1,p=1$c2FsdA$cGFzc3dvcmQ")
            .is_err()
    );

    assert_eq!(
        PasswordError::PepperEmpty.to_string(),
        "pepper must not be empty"
    );
    assert_eq!(
        PasswordError::PepperTooLong {
            max: 1024,
            got: 1025
        }
        .to_string(),
        "pepper too long: got 1025 bytes, max 1024"
    );
}
