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

    /// A [`Pepper`](crate::Pepper) was constructed from an empty secret.
    ///
    /// An empty pepper is indistinguishable from no pepper; hashing with
    /// one would silently produce unpeppered hashes. Rejected at
    /// construction so the mistake cannot reach the stored-hash column
    /// (REQ-SLT-300).
    #[error("pepper must not be empty")]
    PepperEmpty,

    /// A [`Pepper`](crate::Pepper) was constructed from a secret longer
    /// than the documented bound ([`MAX_PEPPER_LEN`](crate::MAX_PEPPER_LEN)).
    ///
    /// The bound is generous (1 KiB — practical peppers are 32–64 bytes);
    /// beyond it a "pepper" is almost certainly a configuration mistake
    /// (e.g. a JSON blob or a PEM block pasted whole).
    #[error("pepper too long: got {got} bytes, max {max}")]
    PepperTooLong {
        /// Maximum accepted length in bytes ([`MAX_PEPPER_LEN`](crate::MAX_PEPPER_LEN)).
        max: usize,
        /// Length of the rejected secret in bytes.
        got: usize,
    },
}
