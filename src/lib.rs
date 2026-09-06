#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Opinionated Argon2id password hashing for Rust.
//!
//! Provides OWASP-recommended defaults, configurable parameters, and
//! PHC string format output using the [`argon2`] crate under the hood.
//!
//! # Quick Start
//!
//! ```rust
//! use salting::{hash_password, verify_password};
//!
//! let hash = hash_password("my secret password").unwrap();
//! assert!(verify_password("my secret password", &hash).unwrap());
//! ```
//!
//! # Password strength (feature flag)
//!
//! With the optional `strength` feature, the crate also provides
//! deterministic [`Policy`] checks and zxcvbn-based [`strength`]
//! estimation via [`check_password`]:
//!
//! ```rust
//! # #[cfg(feature = "strength")]
//! # fn main() {
//! use salting::{check_password, Policy};
//!
//! let result = check_password("Str0ng!Pass#12", &Policy::default(), &[]);
//! assert!(result.is_ok());
//! # }
//! # #[cfg(not(feature = "strength"))] fn main() {}
//! ```

mod error;

#[cfg(feature = "strength")]
pub mod strength;

pub use error::PasswordError;

#[cfg(feature = "strength")]
pub use strength::{Policy, PolicyError, Strength, check_password, strength};

use argon2::password_hash::{
    ParamsString, PasswordHasher, PasswordVerifier, SaltString, Value, rand_core::OsRng,
};
use argon2::{Algorithm, Argon2, Params, Version};

/// Upper bound on the PHC-embedded memory parameter (`m`, in KiB) accepted
/// by [`verify_password`] and [`verify_password_strict`]: 64 MiB, exactly
/// the OWASP-recommended default this crate hashes with. Generous for
/// every hash this crate produces, hard-capped far below memory-DoS
/// territory.
pub const MAX_PHC_MEMORY_KIB: u32 = 65536;

/// Upper bound on the PHC-embedded iteration parameter (`t`) accepted by
/// the verify functions: 16, well above the OWASP-recommended default of 3.
pub const MAX_PHC_ITERATIONS: u32 = 16;

/// Upper bound on the PHC-embedded parallelism parameter (`p`) accepted by
/// the verify functions: 8, twice the OWASP-recommended default of 4.
pub const MAX_PHC_PARALLELISM: u32 = 8;

/// Validate the cost parameters of a parsed PHC hash against the
/// documented bounds before any Argon2 work happens.
///
/// - Malformed encodings (empty, non-digit bytes, leading zeroes, values
///   beyond `u64`) are rejected with [`PasswordError::InvalidHashFormat`]
///   (REQ-SLT-108).
/// - Zero-valued `m`/`t`/`p` can never appear in a hash this crate
///   produces and are rejected with [`PasswordError::InvalidHashFormat`]
///   before allocation (REQ-SLT-108).
/// - In-range values above a bound are rejected with
///   [`PasswordError::ParamsExceeded`] (REQ-SLT-107).
///
/// Parameters absent from the string fall back to the `argon2` crate's
/// defaults (19456 KiB, t=2, p=1) inside its own verify path — within
/// bounds, so no bound check is needed for them. `keyid`/`data` carry no
/// allocation cost. The tag length is bounded by the input string itself
/// (allocation grows linearly with attacker input, never amplified).
fn validate_phc_params(params: &ParamsString) -> Result<(), PasswordError> {
    for (ident, value) in params.iter() {
        match ident.as_str() {
            "m" => check_cost_param(value, "m", MAX_PHC_MEMORY_KIB)?,
            "t" => check_cost_param(value, "t", MAX_PHC_ITERATIONS)?,
            "p" => check_cost_param(value, "p", MAX_PHC_PARALLELISM)?,
            _ => {}
        }
    }
    Ok(())
}

/// Check one cost parameter value against its bound (see
/// [`validate_phc_params`]).
fn check_cost_param(value: Value<'_>, param: &'static str, max: u32) -> Result<(), PasswordError> {
    let got = value
        .decimal()
        .map_err(|_| PasswordError::InvalidHashFormat)?;

    if got == 0 {
        return Err(PasswordError::InvalidHashFormat);
    }

    if got > max {
        return Err(PasswordError::ParamsExceeded { param, max, got });
    }

    Ok(())
}

/// Configurable parameters for Argon2id hashing.
///
/// Defaults follow the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
/// recommendations for a balance of security and performance.
#[derive(Debug, Clone)]
pub struct Argon2Params {
    /// Memory requirement in KiB.
    pub memory_kib: u32,
    /// Number of iterations (time cost).
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
    /// Length of the hash output in bytes.
    pub output_len: usize,
}

impl Default for Argon2Params {
    /// OWASP-recommended parameters for general-purpose password hashing.
    fn default() -> Self {
        Self {
            memory_kib: 65536, // 64 MiB
            iterations: 3,
            parallelism: 4,
            output_len: 32,
        }
    }
}

impl Argon2Params {
    /// Low-memory preset suitable for constrained environments.
    ///
    /// Uses 64 MiB memory, 2 iterations, and 1 thread of parallelism.
    /// Meets OWASP minimum recommendations.
    pub fn low_memory() -> Self {
        Self {
            memory_kib: 65536, // 64 MiB
            iterations: 2,
            parallelism: 1,
            output_len: 32,
        }
    }

    fn build_argon2(&self) -> Result<Argon2<'_>, PasswordError> {
        let params = Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(self.output_len),
        )
        .map_err(|_| PasswordError::HashFailed)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Hash a password using the default OWASP-recommended parameters.
///
/// Returns the password hash in PHC string format.
///
/// # Requirements
/// REQ-SLT-001, REQ-SLT-100
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    hash_password_with_params(password, &Argon2Params::default())
}

/// Hash a password using the provided parameters.
///
/// Returns the password hash in PHC string format.
///
/// # Requirements
/// REQ-SLT-002, REQ-SLT-100, REQ-SLT-104
pub fn hash_password_with_params(
    password: &str,
    params: &Argon2Params,
) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = params.build_argon2()?;

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| PasswordError::HashFailed)?
        .to_string();

    Ok(hash)
}

/// Verify a password against a stored PHC hash string.
///
/// Returns `true` if the password matches, `false` otherwise.
///
/// The cost parameters embedded in the hash string are validated against
/// the documented bounds ([`MAX_PHC_MEMORY_KIB`], [`MAX_PHC_ITERATIONS`],
/// [`MAX_PHC_PARALLELISM`]) **before** Argon2 allocates anything. A hash
/// with `m > 64 MiB`, `t > 16`, or `p > 8` was not produced by this crate
/// and is rejected with [`PasswordError::ParamsExceeded`] instead of being
/// honoured — this keeps verification memory bounded even when the stored
/// hash string is attacker-writable (e.g. after a database breach, or via
/// an import feature). Zero-valued or malformed `m`/`t`/`p` encodings are
/// rejected with [`PasswordError::InvalidHashFormat`].
///
/// # Errors
///
/// - [`PasswordError::InvalidHashFormat`] — malformed PHC string, or a
///   malformed / zero-valued cost parameter encoding.
/// - [`PasswordError::ParamsExceeded`] — an in-range cost parameter
///   exceeds the documented verification bound.
///
/// A wrong password is *not* an error: it returns `Ok(false)`.
///
/// # Requirements
/// REQ-SLT-001, REQ-SLT-101, REQ-SLT-102, REQ-SLT-103, REQ-SLT-107,
/// REQ-SLT-108
pub fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
    let parsed = argon2::PasswordHash::new(hash).map_err(|_| PasswordError::InvalidHashFormat)?;
    validate_phc_params(&parsed.params)?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify a password with strict error reporting.
///
/// Unlike [`verify_password`], this returns an error on mismatch instead of `false`.
///
/// The same parameter bounds apply (see [`verify_password`]): hashes with
/// out-of-bound or malformed cost parameters are rejected before Argon2
/// allocates.
///
/// # Errors
///
/// - [`PasswordError::VerificationFailed`] — the password does not match.
/// - [`PasswordError::InvalidHashFormat`] — malformed PHC string, or a
///   malformed / zero-valued cost parameter encoding.
/// - [`PasswordError::ParamsExceeded`] — an in-range cost parameter
///   exceeds the documented verification bound.
///
/// # Requirements
/// REQ-SLT-003, REQ-SLT-101, REQ-SLT-102, REQ-SLT-103, REQ-SLT-107,
/// REQ-SLT-108
pub fn verify_password_strict(password: &str, hash: &str) -> Result<(), PasswordError> {
    let parsed = argon2::PasswordHash::new(hash).map_err(|_| PasswordError::InvalidHashFormat)?;
    validate_phc_params(&parsed.params)?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| PasswordError::VerificationFailed)
}

// Tests exercise failure paths and invariants directly; unwrap/expect,
// slicing, and panicking asserts are acceptable here — violations
// surface as test failures, not production panics.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use std::time::{Duration, Instant};

    fn test_params() -> Argon2Params {
        Argon2Params {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        }
    }

    /// Replace the cost-parameter segment of a real PHC string produced
    /// by `test_params()` with attacker-chosen values.
    fn splice_params(hash: &str, m: u64, t: u64, p: u64) -> String {
        let prefix = "$argon2id$v=19$";
        let rest = &hash[prefix.len()..]; // "<params>$<salt>$<tag>"
        let tail = rest.split_once('$').map(|(_, tail)| tail).unwrap(); // "<salt>$<tag>"
        format!("{prefix}m={m},t={t},p={p}${tail}")
    }

    proptest! {
        #[test]
        fn hash_verify_roundtrip(password in "\\PC{1,256}") {
            let hash = hash_password_with_params(&password, &test_params()).unwrap();
            prop_assert!(verify_password(&password, &hash).unwrap());
        }

        #[test]
        fn hash_differs_each_time(password in "\\PC{1,256}") {
            let h1 = hash_password_with_params(&password, &test_params()).unwrap();
            let h2 = hash_password_with_params(&password, &test_params()).unwrap();
            prop_assert_ne!(h1, h2);
        }

        #[test]
        fn verify_wrong_password_fails(password in "\\PC{1,128}", wrong in "\\PC{1,128}") {
            prop_assume!(password != wrong);
            let hash = hash_password_with_params(&password, &test_params()).unwrap();
            prop_assert!(!verify_password(&wrong, &hash).unwrap());
        }

        /// REQ-SLT-107/108 fuzz-style: arbitrary PHC-ish strings must be
        /// classified into `Ok`/`Err` — never panic, never take long
        /// enough to indicate an Argon2 allocation.
        #[test]
        fn fuzz_arbitrary_phc_never_panics_or_lingers(
            s in "[-$a-zA-Z0-9=,.]{0,256}",
        ) {
            let start = Instant::now();
            let result = verify_password("probe", &s);
            prop_assert!(start.elapsed() < Duration::from_millis(100),
                "verify took too long on {s:?}");
            prop_assert!(
                matches!(
                    result,
                    Ok(_) | Err(PasswordError::InvalidHashFormat)
                        | Err(PasswordError::ParamsExceeded { .. })
                ),
                "unexpected classification for {s:?}: {result:?}"
            );
        }

        /// REQ-SLT-107/108 classification property: edited cost params on
        /// an otherwise-valid hash must classify deterministically —
        /// over-bound → `ParamsExceeded`, zero → `InvalidHashFormat`,
        /// in-bounds → normal verify outcome. Rejected params must never
        /// reach an Argon2 allocation (rejected cases finish in
        /// microseconds); in-bounds cases do real Argon2 work and get no
        /// tight time bound.
        #[test]
        fn fuzz_edited_params_are_classified(
            m in prop_oneof![Just(0u64), 65537u64..=200_000, 8u64..=6_144],
            t in prop_oneof![Just(0u64), 17u64..=100, 1u64..=4],
            p in prop_oneof![Just(0u64), 9u64..=64, 1u64..=2],
        ) {
            let base = hash_password_with_params("probe", &test_params()).unwrap();
            let forged = splice_params(&base, m, t, p);

            // The implementation checks params in PHC string order
            // (m, then t, then p); the first offending param decides the
            // error — zero/malformed before its own bound check,
            // over-bound as ParamsExceeded.
            let param_checks = [
                ("m", m, u64::from(MAX_PHC_MEMORY_KIB)),
                ("t", t, u64::from(MAX_PHC_ITERATIONS)),
                ("p", p, u64::from(MAX_PHC_PARALLELISM)),
            ];
            let mut offending = None;
            for (name, val, max) in param_checks {
                if val == 0 {
                    offending = Some("zero");
                    break;
                }
                if val > max {
                    offending = Some(name);
                    break;
                }
            }

            let start = Instant::now();
            let result = verify_password("probe", &forged);
            let elapsed = start.elapsed();

            match offending {
                Some(name @ ("m" | "t" | "p")) => {
                    prop_assert!(matches!(
                        result,
                        Err(PasswordError::ParamsExceeded { param, .. }) if param == name
                    ), "expected ParamsExceeded({name}) for {forged:?}, got {result:?}");
                    prop_assert!(elapsed < Duration::from_millis(100),
                        "rejected params took {elapsed:?} — allocation not avoided");
                }
                Some("zero") => {
                    prop_assert!(
                        matches!(result, Err(PasswordError::InvalidHashFormat)),
                        "expected InvalidHashFormat for {forged:?}, got {result:?}"
                    );
                    prop_assert!(elapsed < Duration::from_millis(100),
                        "rejected params took {elapsed:?} — allocation not avoided");
                }
                _ => {
                    // All params in bounds: normal verify outcome (the
                    // params rarely match the base hash, so usually
                    // `Ok(false)`).
                    prop_assert!(result.is_ok(),
                        "expected Ok(_) for {forged:?}, got {result:?}");
                }
            }
        }
    }
}

// Tests exercise failure paths and invariants directly; unwrap/expect,
// slicing, and panicking asserts are acceptable here — violations
// surface as test failures, not production panics.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn test_params() -> Argon2Params {
        Argon2Params {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        }
    }

    #[test]
    fn hash_and_verify() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash).unwrap());
        assert!(!verify_password("wrong password", &hash).unwrap());
    }

    #[test]
    fn low_memory_params() {
        // Pin the preset values: this is a documented public contract
        // (64 MiB, 2 iterations, 1 lane) and distinguishes the preset
        // from `Argon2Params::default()` (3 iterations, 4 lanes).
        let params = Argon2Params::low_memory();
        assert_eq!(params.memory_kib, 65_536);
        assert_eq!(params.iterations, 2);
        assert_eq!(params.parallelism, 1);
        assert_eq!(params.output_len, 32);

        let hash = hash_password_with_params("test", &params).unwrap();
        assert!(verify_password("test", &hash).unwrap());
    }

    #[test]
    fn strict_verify_fails_on_mismatch() {
        let hash = hash_password("secret").unwrap();
        assert!(verify_password_strict("secret", &hash).is_ok());
        assert!(matches!(
            verify_password_strict("wrong", &hash),
            Err(PasswordError::VerificationFailed)
        ));
    }

    /// REQ-SLT-103: corrupt or hostile PHC strings must yield
    /// `InvalidHashFormat`, never panic — the hash string is attacker-
    /// writable in some deployments (DB tampering).
    #[test]
    fn malformed_hash_rejected() {
        for garbage in [
            "",
            "not-a-phc-string",
            "$argon2id$",
            "$argon2id$v=19$m=65536,t=3,p=4$",
            "$argon2id$v=19$m=999999,t=1,p=1$c2FsdA$cGFzc3dvcmQ",
            "\u{0}\u{1}\u{2}",
        ] {
            assert!(
                matches!(
                    verify_password("x", garbage),
                    Err(PasswordError::InvalidHashFormat)
                ),
                "expected InvalidHashFormat for {garbage:?}"
            );
            assert!(verify_password_strict("x", garbage).is_err());
        }
    }

    /// REQ-SLT-104: parameter combinations Argon2 cannot honour must fail
    /// closed with `HashFailed`, never panic.
    #[test]
    fn invalid_params_fail_closed() {
        let too_short_output = Argon2Params {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
            output_len: 1, // below the 4-byte Argon2 minimum
        };
        assert!(matches!(
            hash_password_with_params("x", &too_short_output),
            Err(PasswordError::HashFailed)
        ));

        let zero_memory = Argon2Params {
            memory_kib: 0,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        };
        assert!(matches!(
            hash_password_with_params("x", &zero_memory),
            Err(PasswordError::HashFailed)
        ));
    }

    /// REQ-SLT-105: error Display strings are static and must never embed
    /// password material or hash content.
    #[test]
    fn error_display_contains_no_password_material() {
        let secret = "Sup3r-Secret-Password!";
        let hash = hash_password(secret).unwrap();

        let display_cases = [
            verify_password_strict("wrong", &hash)
                .unwrap_err()
                .to_string(),
            verify_password(secret, "garbage").unwrap_err().to_string(),
            hash_password_with_params(
                secret,
                &Argon2Params {
                    memory_kib: 0,
                    iterations: 1,
                    parallelism: 1,
                    output_len: 32,
                },
            )
            .unwrap_err()
            .to_string(),
        ];
        for msg in display_cases {
            assert!(!msg.contains(secret), "leaked password: {msg}");
            assert!(!msg.contains(&hash), "leaked hash: {msg}");
        }

        // REQ-SLT-107: ParamsExceeded Display carries only parameter
        // name and numbers — no secret material by construction.
        let msg = verify_password(
            "x",
            "$argon2id$v=19$m=999999,t=1,p=1$c2FsdDEyMzQ1Njc4$abcdefghijklmnopqrstuv",
        )
        .unwrap_err()
        .to_string();
        assert!(!msg.contains(secret), "leaked password: {msg}");
    }

    /// REQ-SLT-107 boundary: a hash produced with the crate defaults
    /// (m = 65536 KiB == `MAX_PHC_MEMORY_KIB`, t = 3, p = 4) sits exactly
    /// at the bounds and must still verify.
    #[test]
    fn default_hash_params_within_bounds() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(
            hash.contains("m=65536,t=3,p=4"),
            "unexpected default PHC: {hash}"
        );
        assert!(verify_password("correct horse battery staple", &hash).unwrap());
        assert!(verify_password_strict("correct horse battery staple", &hash).is_ok());
    }

    /// REQ-SLT-107: PHC cost parameters above the documented bounds are
    /// rejected with `ParamsExceeded` *before* Argon2 allocates. A forged
    /// `m=999999` (≈1 GiB) would otherwise be a memory-DoS primitive when
    /// hash strings are attacker-writable.
    #[test]
    fn phc_params_exceeding_bounds_rejected() {
        let base = hash_password_with_params("bound-test", &test_params()).unwrap();

        // (edited segment, expected param, expected got)
        let cases = [
            ("m=32,", "m=999999,", "m", 999999u32),
            ("m=32,", "m=65537,", "m", 65_537),
            ("t=1,", "t=17,", "t", 17),
            ("t=1,", "t=999999,", "t", 999_999),
            ("p=1$", "p=9$", "p", 9),
            ("p=1$", "p=999999$", "p", 999_999),
        ];

        for (old, new, param, got) in cases {
            let forged = base.replacen(old, new, 1);
            assert_ne!(forged, base, "edit {old:?} did not apply");

            let start = Instant::now();
            let result = verify_password("bound-test", &forged);
            let elapsed = start.elapsed();

            assert!(
                matches!(
                    result,
                    Err(PasswordError::ParamsExceeded {
                        param: p,
                        max,
                        got: g,
                    }) if p == param && g == got && max == match param {
                        "m" => MAX_PHC_MEMORY_KIB,
                        "t" => MAX_PHC_ITERATIONS,
                        _ => MAX_PHC_PARALLELISM,
                    }
                ),
                "expected ParamsExceeded for {forged:?}, got {result:?}"
            );

            let strict = verify_password_strict("bound-test", &forged);
            assert!(
                matches!(
                    strict,
                    Err(PasswordError::ParamsExceeded { param: p, .. }) if p == param
                ),
                "strict verify must also reject {forged:?}, got {strict:?}"
            );

            // Fast-fail proof: a genuine m=999999 verify would allocate
            // ~1 GiB and hash for seconds (or OOM). The reject path is
            // microseconds; the bound leaves wide margin for slow CI
            // while staying far below any real allocation.
            assert!(
                elapsed < Duration::from_millis(250),
                "rejecting {forged:?} took {elapsed:?} — allocation not avoided"
            );
        }
    }

    /// REQ-SLT-108: zero-valued cost parameters are rejected with
    /// `InvalidHashFormat` before Argon2 sees them. Argon2 0.5 itself
    /// rejects `t = 0` / `p = 0` / `m < 8` with an error (no panic, no
    /// hang — verified against the crate source), but the error used to
    /// surface as a bare mismatch; it must fail closed as `Err`.
    #[test]
    fn phc_zero_params_rejected() {
        let base = hash_password_with_params("zero-test", &test_params()).unwrap();

        for (old, new) in [("m=32,", "m=0,"), ("t=1,", "t=0,"), ("p=1$", "p=0$")] {
            let forged = base.replacen(old, new, 1);
            assert_ne!(forged, base, "edit {old:?} did not apply");
            assert!(
                matches!(
                    verify_password("zero-test", &forged),
                    Err(PasswordError::InvalidHashFormat)
                ),
                "expected InvalidHashFormat for {forged:?}"
            );
            assert!(
                matches!(
                    verify_password_strict("zero-test", &forged),
                    Err(PasswordError::InvalidHashFormat)
                ),
                "expected InvalidHashFormat (strict) for {forged:?}"
            );
        }
    }

    /// REQ-SLT-108: malformed cost-parameter encodings (negative-encoded,
    /// leading zeroes, empty) are rejected — never panic, never reach
    /// Argon2.
    #[test]
    fn phc_malformed_params_rejected() {
        let base = hash_password_with_params("malformed-test", &test_params()).unwrap();

        for (old, new) in [
            ("m=32,", "m=-1,"),
            ("m=32,", "m=01,"),
            ("m=32,", "m=,"),
            ("m=32,", "m=4294967296,"), // beyond u32: unparseable decimal
            ("t=1,", "t=-3,"),
            ("p=1$", "p=-1$"),
        ] {
            let forged = base.replacen(old, new, 1);
            assert_ne!(forged, base, "edit {old:?} did not apply");
            let result = verify_password("malformed-test", &forged);
            assert!(
                matches!(result, Err(PasswordError::InvalidHashFormat)),
                "expected InvalidHashFormat for {forged:?}, got {result:?}"
            );
            assert!(verify_password_strict("malformed-test", &forged).is_err());
        }
    }
}
