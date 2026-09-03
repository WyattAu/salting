//! Password strength estimation and policy checking.
//!
//! This module is only available when the `strength` feature is enabled.
//! It provides two complementary layers:
//!
//! - [`Policy`]: deterministic composition rules (length, character classes).
//! - [`strength`]: probabilistic guessability estimation via [`zxcvbn`].
//!
//! [`check_password`] runs both, policy first (fail fast), then strength.

use thiserror::Error;

/// Errors returned when a password does not satisfy a [`Policy`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    /// Password is shorter than the policy minimum.
    #[error("password must be at least {min} characters (got {got})")]
    TooShort {
        /// Minimum required length.
        min: usize,
        /// Actual length.
        got: usize,
    },

    /// Password lacks an uppercase letter and the policy requires one.
    #[error("password must contain at least one uppercase letter")]
    MissingUppercase,

    /// Password lacks a lowercase letter and the policy requires one.
    #[error("password must contain at least one lowercase letter")]
    MissingLowercase,

    /// Password lacks a digit and the policy requires one.
    #[error("password must contain at least one digit")]
    MissingDigit,

    /// Password lacks a character from [`Policy::special_chars`].
    #[error("password must contain at least one special character")]
    MissingSpecialChar,
}

/// Deterministic composition rules for passwords.
///
/// Defaults follow common defense-sector guidance: at least 12 characters
/// with at least one uppercase letter, lowercase letter, digit, and special
/// character.
///
/// # Examples
///
/// ```
/// use salting::strength::Policy;
///
/// let policy = Policy::default();
/// assert!(policy.check("Str0ng!Pass#12").is_ok());
/// assert!(policy.check("short").is_err());
///
/// // Builder style: relax class requirements, tighten length.
/// let relaxed = Policy::default()
///     .min_length(24)
///     .require_uppercase(false)
///     .require_lowercase(false)
///     .require_digit(false)
///     .require_special(false);
/// assert!(relaxed.check("correct horse battery staple").is_ok());
/// ```
#[derive(Debug, Clone)]
pub struct Policy {
    /// Minimum password length.
    pub min_length: usize,
    /// Require at least one uppercase letter.
    pub require_uppercase: bool,
    /// Require at least one lowercase letter.
    pub require_lowercase: bool,
    /// Require at least one digit.
    pub require_digit: bool,
    /// Require at least one character from `special_chars`.
    pub require_special: bool,
    /// Characters accepted as "special".
    pub special_chars: &'static str,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            special_chars: "!@#$%^&*()-_+=[]{}|;':\",./<>?~`",
        }
    }
}

impl Policy {
    /// Set the minimum password length.
    pub fn min_length(mut self, min_length: usize) -> Self {
        self.min_length = min_length;
        self
    }

    /// Require (or not) at least one uppercase letter.
    pub fn require_uppercase(mut self, require: bool) -> Self {
        self.require_uppercase = require;
        self
    }

    /// Require (or not) at least one lowercase letter.
    pub fn require_lowercase(mut self, require: bool) -> Self {
        self.require_lowercase = require;
        self
    }

    /// Require (or not) at least one digit.
    pub fn require_digit(mut self, require: bool) -> Self {
        self.require_digit = require;
        self
    }

    /// Require (or not) at least one special character.
    pub fn require_special(mut self, require: bool) -> Self {
        self.require_special = require;
        self
    }

    /// Set the set of characters accepted as "special".
    pub fn special_chars(mut self, special_chars: &'static str) -> Self {
        self.special_chars = special_chars;
        self
    }

    /// Check a password against this policy.
    ///
    /// Checks run in a fixed order — length, uppercase, lowercase, digit,
    /// special — so the same password always yields the same error.
    pub fn check(&self, password: &str) -> Result<(), PolicyError> {
        let len = password.chars().count();
        if len < self.min_length {
            return Err(PolicyError::TooShort {
                min: self.min_length,
                got: len,
            });
        }
        if self.require_uppercase && !password.chars().any(char::is_uppercase) {
            return Err(PolicyError::MissingUppercase);
        }
        if self.require_lowercase && !password.chars().any(char::is_lowercase) {
            return Err(PolicyError::MissingLowercase);
        }
        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(PolicyError::MissingDigit);
        }
        if self.require_special && !password.chars().any(|c| self.special_chars.contains(c)) {
            return Err(PolicyError::MissingSpecialChar);
        }
        Ok(())
    }
}

/// Strength estimate for a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Strength {
    /// Guessability score from 0 (very weak) to 4 (very strong),
    /// derived from the estimated number of guesses.
    pub score: u8,
    /// Human-readable suggestions for improving the password.
    /// Empty when the password is already strong.
    pub feedback: Vec<String>,
}

/// Map log10(guesses) to the standard zxcvbn score buckets:
/// `< 10^3` → 0, `< 10^6` → 1, `< 10^8` → 2, `< 10^10` → 3, else 4.
fn score_from_guesses_log10(guesses_log10: f64) -> u8 {
    match guesses_log10 {
        g if g < 3.0 => 0,
        g if g < 6.0 => 1,
        g if g < 8.0 => 2,
        g if g < 10.0 => 3,
        _ => 4,
    }
}

/// Estimate password strength using zxcvbn.
///
/// `user_inputs` are strings related to the user (name, email, product
/// name, ...); matches against them lower the score.
///
/// This function never fails: if the password cannot be analyzed, a
/// score of 0 with feedback is returned.
pub fn strength(password: &str, user_inputs: &[&str]) -> Strength {
    match zxcvbn::zxcvbn(password, user_inputs) {
        Ok(estimate) => {
            let mut feedback = Vec::new();
            if let Some(fb) = estimate.feedback().as_ref() {
                if let Some(warning) = fb.warning() {
                    feedback.push(warning.to_string());
                }
                feedback.extend(fb.suggestions().iter().map(|s| s.to_string()));
            }
            Strength {
                score: score_from_guesses_log10(estimate.guesses_log10()),
                feedback,
            }
        }
        Err(_) => Strength {
            score: 0,
            feedback: vec![
                "password could not be analyzed and is treated as weak".to_string(),
            ],
        },
    }
}

/// Validate a password against a [`Policy`], then estimate its [`Strength`].
///
/// The policy check runs first and fails fast; strength is only estimated
/// for passwords that satisfy the policy. Note that a returned `Ok` does
/// not mean the password is strong — inspect [`Strength::score`] to decide
/// (e.g. reject scores ≤ 1).
pub fn check_password(
    password: &str,
    policy: &Policy,
    user_inputs: &[&str],
) -> Result<Strength, PolicyError> {
    policy.check(password)?;
    Ok(strength(password, user_inputs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_checks_are_deterministic_and_ordered() {
        let policy = Policy::default();

        // Same input always yields the same result.
        let expected = Err(PolicyError::TooShort { min: 12, got: 4 });
        for _ in 0..5 {
            assert_eq!(policy.check("aB3!"), expected);
        }

        // Fixed check order: length, uppercase, lowercase, digit, special.
        // A short password missing everything reports TooShort, not the
        // later class failures.
        assert_eq!(
            policy.check("ab!"),
            Err(PolicyError::TooShort { min: 12, got: 3 })
        );
        assert_eq!(policy.check("bcdefghij123!"), Err(PolicyError::MissingUppercase));
        assert_eq!(policy.check("BCDEFGHIJ123!"), Err(PolicyError::MissingLowercase));
        assert_eq!(policy.check("Bcdefghijab!"), Err(PolicyError::MissingDigit));
        assert_eq!(policy.check("Bcdefghij123"), Err(PolicyError::MissingSpecialChar));
    }

    #[test]
    fn each_policy_error_variant() {
        let policy = Policy::default();
        assert!(matches!(
            policy.check("short"),
            Err(PolicyError::TooShort { min: 12, got: 5 })
        ));
        assert_eq!(
            policy.check("bcdefghij123!"),
            Err(PolicyError::MissingUppercase)
        );
        assert_eq!(
            policy.check("BCDEFGHIJ123!"),
            Err(PolicyError::MissingLowercase)
        );
        assert_eq!(policy.check("Bcdefghijab!"), Err(PolicyError::MissingDigit));
        assert_eq!(
            policy.check("Bcdefghij123"),
            Err(PolicyError::MissingSpecialChar)
        );
        assert!(policy.check("Bcdefghij123!").is_ok());
    }

    #[test]
    fn policy_builder_customizes_rules() {
        let policy = Policy::default()
            .min_length(8)
            .require_uppercase(false)
            .require_lowercase(false)
            .require_digit(false)
            .require_special(false)
            .special_chars("?");
        assert!(policy.check("abcdefgh").is_ok());
        assert_eq!(
            policy.check("abcdefg"),
            Err(PolicyError::TooShort { min: 8, got: 7 })
        );
    }

    #[test]
    fn common_password_scores_zero_with_feedback() {
        let s = strength("password", &[]);
        assert_eq!(s.score, 0);
        assert!(!s.feedback.is_empty());
    }

    #[test]
    fn strong_passphrase_scores_higher_than_weak() {
        let weak = strength("password", &[]);
        let strong = strength("quartz-limpkin-vortex-blame", &[]);
        assert_eq!(weak.score, 0);
        assert!(strong.score >= 3, "expected >= 3, got {}", strong.score);
        assert!(strong.score > weak.score);
    }

    #[test]
    fn check_password_fails_fast_on_policy() {
        // "password" is both too short and trivially weak; the policy runs
        // first, so the error is TooShort — not a strength result.
        assert_eq!(
            check_password("password", &Policy::default(), &[]),
            Err(PolicyError::TooShort { min: 12, got: 8 })
        );
    }

    #[test]
    fn check_password_returns_strength_when_policy_passes() {
        let via_check = check_password("Bcdefghij123!", &Policy::default(), &[]).unwrap();
        assert_eq!(via_check, strength("Bcdefghij123!", &[]));
    }

    #[test]
    fn user_inputs_reduce_score() {
        let base = strength("crawlkitcrawlkit", &[]);
        let penalized = strength("crawlkitcrawlkit", &["crawlkit"]);
        assert!(penalized.score < base.score);
    }

    #[test]
    fn empty_password_scores_zero() {
        assert_eq!(strength("", &[]).score, 0);
    }
}
