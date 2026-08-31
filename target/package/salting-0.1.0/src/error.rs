use thiserror::Error;

/// Errors that can occur during password hashing and verification.
#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("password hashing failed")]
    HashFailed,

    #[error("invalid hash format")]
    InvalidHashFormat,

    #[error("password verification failed")]
    VerificationFailed,
}
