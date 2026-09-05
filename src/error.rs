use thiserror::Error;

/// Errors that can occur during password hashing and verification.
#[derive(Debug, Error)]
pub enum PasswordError {
    /// Password hashing failed.
    #[error("password hashing failed")]
    HashFailed,

    /// Invalid hash format.
    #[error("invalid hash format")]
    InvalidHashFormat,

    /// Password verification failed.
    #[error("password verification failed")]
    VerificationFailed,

    /// A cost parameter embedded in a PHC hash string exceeds the
    /// documented verification bound.
    ///
    /// Rejected **before** any Argon2 allocation: a hash above the bounds
    /// was not produced by this crate, so verification fails closed rather
    /// than honouring attacker-chosen cost parameters (memory-DoS
    /// hardening; REQ-SLT-107).
    #[error("cost parameter '{param}' exceeds verification bound: got {got}, max {max}")]
    ParamsExceeded {
        /// Offending parameter identifier (`"m"`, `"t"`, or `"p"`).
        param: &'static str,
        /// Maximum accepted value for the parameter.
        max: u32,
        /// Value found in the hash string.
        got: u32,
    },
}
