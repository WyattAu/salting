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
}
