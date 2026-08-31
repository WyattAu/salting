#![forbid(unsafe_code)]

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

mod error;

pub use error::PasswordError;

use argon2::password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString};
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

    fn build_argon2(&self) -> Argon2<'_> {
        let params = Params::new(self.memory_kib, self.iterations, self.parallelism, Some(self.output_len))
            .expect("valid Argon2 parameters");
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }
}

/// Hash a password using the default OWASP-recommended parameters.
///
/// Returns the password hash in PHC string format.
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    hash_password_with_params(password, &Argon2Params::default())
}

/// Hash a password using the provided parameters.
///
/// Returns the password hash in PHC string format.
pub fn hash_password_with_params(password: &str, params: &Argon2Params) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = params.build_argon2();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| PasswordError::HashFailed)?
        .to_string();

    Ok(hash)
}

/// Verify a password against a stored PHC hash string.
///
/// Returns `true` if the password matches, `false` otherwise.
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
pub fn verify_password_strict(password: &str, hash: &str) -> Result<(), PasswordError> {
    let parsed = argon2::PasswordHash::new(hash).map_err(|_| PasswordError::InvalidHashFormat)?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| PasswordError::VerificationFailed)
}

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
}
