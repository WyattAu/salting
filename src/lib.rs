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

use argon2::password_hash::{PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng};
use argon2::{Algorithm, Argon2, Params, Version};

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
/// # Requirements
/// REQ-SLT-001, REQ-SLT-101, REQ-SLT-102, REQ-SLT-103
pub fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
    let parsed = argon2::PasswordHash::new(hash).map_err(|_| PasswordError::InvalidHashFormat)?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify a password with strict error reporting.
///
/// Unlike [`verify_password`], this returns an error on mismatch instead of `false`.
///
/// # Requirements
/// REQ-SLT-003, REQ-SLT-101, REQ-SLT-102, REQ-SLT-103
pub fn verify_password_strict(password: &str, hash: &str) -> Result<(), PasswordError> {
    let parsed = argon2::PasswordHash::new(hash).map_err(|_| PasswordError::InvalidHashFormat)?;

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

    fn test_params() -> Argon2Params {
        Argon2Params {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        }
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

    #[test]
    fn hash_and_verify() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash).unwrap());
        assert!(!verify_password("wrong password", &hash).unwrap());
    }

    #[test]
    fn low_memory_params() {
        let params = Argon2Params::low_memory();
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
    }
}
