//! Server-side pepper support: an application-wide secret mixed into
//! every hash, stored *separately* from the password database.
//!
//! # Why a pepper
//!
//! A salt is per-user and stored *with* the hash; it defeats precomputation
//! and rainbow tables. A pepper is *global* and stored *away* from the
//! database (env var, KMS, HSM). When an attacker exfiltrates **only** the
//! database — the single most common breach shape — peppered hashes are
//! useless for offline cracking: every guess requires a full Argon2 run per
//! candidate password *and* the pepper, which the attacker does not have.
//!
//! What a pepper does **not** protect against: full-server compromise (the
//! attacker reads the process environment / KMS too), SQL injection with
//! app-host access, or a pepper committed next to the DB credentials. See
//! the repository's `THREAT-MODEL.md` and `docs/PEPPER-MANAGEMENT.md` for
//! storage guidance (env var vs. KMS/HSM) and a rotation runbook.
//!
//! # Construction (precise)
//!
//! The pepper is fed as the **Argon2 secret key input** (`K` in
//! [RFC 9106](https://datatracker.ietf.org/doc/rfc9106/) — "application
//! specific key"), via `argon2::Argon2::new_with_secret`. This is the
//! mechanism Argon2 was explicitly designed for: the secret enters the
//! initial BLAKE2b absorb alongside the password, salt, and params, then
//! every compression block mixes it in. No pre-hashing, no concatenation
//! ambiguity, no extra dependencies.
//!
//! **Compatibility:** a hash produced *with* a pepper verifies only *with
//! that same pepper*, and never with the unpeppered verify functions
//! ([`verify_password`](crate::verify_password) et al.) — and vice versa.
//! The PHC string itself carries **no marker** distinguishing peppered from
//! unpeppered hashes (the Argon2 `keyid` PHC parameter could carry a label,
//! but it is attacker-writable on a stored hash, so this crate ignores it —
//! see `phc_unknown_param_ident_is_ignored_by_bounds_check`). Pepper
//! versioning is the application's job: track a `pepper_id` column, or use
//! [`Hasher::accept_unpeppered`] + [`Hasher::needs_rehash`] during
//! migration and rotation (recipes below).
//!
//! # Rotation and migration
//!
//! Rotation (pepper *A* → pepper *B*): serve logins with
//! [`Hasher::new().with_pepper(b)`][Hasher::with_pepper]
//! `.with_previous_pepper(a)`. [`Hasher::verify`] tries the current pepper
//! first, then the previous ones; [`Hasher::needs_rehash`] tells you when a
//! successful login still used a previous pepper — rehash with the current
//! one on the spot (rehash-on-login; no mass migration outage).
//!
//! Migration (unpeppered → peppered): add
//! [`.accept_unpeppered(true)`][Hasher::accept_unpeppered] so legacy hashes
//! verify too, and [`Hasher::needs_rehash`] flags them; every such login is
//! an opportunity to rehash with the pepper.
//!
//! # Examples
//!
//! Hash and verify with a pepper:
//!
//! ```
//! use salting::{hash_password_with_pepper, verify_password_with_pepper, Pepper};
//!
//! let pepper = Pepper::new(b"env(SALTING_PEPPER)-32-random-bytes")?;
//!
//! let hash = hash_password_with_pepper("correct horse battery staple", &pepper)?;
//! assert!(verify_password_with_pepper("correct horse battery staple", &hash, &pepper)?);
//!
//! // Wrong pepper → clean `Ok(false)`, never `Ok(true)`, never a panic:
//! let wrong = Pepper::new(b"some other server's pepper")?;
//! assert!(!verify_password_with_pepper("correct horse battery staple", &hash, &wrong)?);
//! # Ok::<(), salting::PasswordError>(())
//! ```
//!
//! Migration + rotation in one login flow:
//!
//! ```
//! use salting::{Hasher, Pepper};
//!
//! let current = Pepper::new(b"current pepper from KMS")?;
//! let previous = Pepper::new(b"retired pepper from KMS")?;
//!
//! // Accepts: current-pepper hashes, previous-pepper hashes (rotation),
//! // and pre-pepper legacy hashes (migration). Hashes with `current`.
//! let hasher = Hasher::new()
//!     .with_pepper(current)
//!     .with_previous_pepper(previous)
//!     .accept_unpeppered(true);
//!
//! # let stored = hasher.hash("correct horse battery staple")?;
//! if hasher.verify("correct horse battery staple", &stored)?
//!     && hasher.needs_rehash("correct horse battery staple", &stored)?
//! {
//!     let _upgraded = hasher.hash("correct horse battery staple")?; // write back
//! }
//! # Ok::<(), salting::PasswordError>(())
//! ```

use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::phc::{self, PasswordHash, SaltString};
use password_hash::{PasswordHasher, PasswordVerifier};
use zeroize::Zeroizing;

use crate::{Argon2Params, PasswordError};

/// Upper bound on the accepted [`Pepper`] length in bytes: 1 KiB.
///
/// Practical peppers are 32–64 bytes; the bound exists to catch
/// configuration mistakes (a whole JSON blob, a PEM block) early, and is
/// far below the `argon2` crate's own `MAX_SECRET_LEN` (2³²−1).
pub const MAX_PEPPER_LEN: usize = 1024;

/// Recommended [`Pepper`] length in bytes for [`Pepper::generate`].
///
/// 32 bytes (256 bits) — comfortably beyond any brute-force relevance for
/// an OS-CSPRNG-generated secret.
pub const RECOMMENDED_PEPPER_LEN: usize = 32;

/// A server-side secret mixed into password hashing, zeroized on drop.
///
/// Construct via [`Pepper::new`] (rejects empty secrets and secrets beyond
/// [`MAX_PEPPER_LEN`]) or [`Pepper::generate`] (OS CSPRNG). The inner
/// buffer is a [`Zeroizing`] `Vec`: dropping the `Pepper` overwrites the
/// key material in memory instead of leaving it for a later heap scan.
///
/// `Debug` output is redacted — the pepper never appears in logs or panic
/// messages. `Clone` is available for rotation setups that fan a pepper out
/// to several [`Hasher`]s; each clone is itself zeroized, but be aware a
/// clone is a second in-memory copy of the secret.
#[derive(Clone)]
pub struct Pepper {
    /// Wiped on drop by `Zeroizing`'s `Drop` impl.
    inner: Zeroizing<Vec<u8>>,
}

impl Pepper {
    /// Wrap a server-side secret as a [`Pepper`].
    ///
    /// Accepts anything convertible into a `Vec<u8>` (`&[u8]`, `&str`,
    /// `String`, `Vec<u8>`, ...). Empty secrets are rejected with
    /// [`PasswordError::PepperEmpty`] — an empty pepper would silently
    /// behave as *no* pepper — and secrets beyond [`MAX_PEPPER_LEN`] with
    /// [`PasswordError::PepperTooLong`] (REQ-SLT-300).
    ///
    /// ```
    /// use salting::Pepper;
    ///
    /// let pepper = Pepper::new("loaded-from-kms-or-env").unwrap();
    /// assert_eq!(pepper.as_bytes(), b"loaded-from-kms-or-env");
    /// ```
    ///
    /// # Errors
    ///
    /// - [`PasswordError::PepperEmpty`] — the secret is empty.
    /// - [`PasswordError::PepperTooLong`] — the secret exceeds
    ///   [`MAX_PEPPER_LEN`].
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, PasswordError> {
        let inner = Zeroizing::new(secret.into());
        if inner.is_empty() {
            return Err(PasswordError::PepperEmpty);
        }
        let got = inner.len();
        if got > MAX_PEPPER_LEN {
            return Err(PasswordError::PepperTooLong {
                max: MAX_PEPPER_LEN,
                got,
            });
        }
        Ok(Self { inner })
    }

    /// Generate a random [`Pepper`] of `byte_len` bytes from the OS CSPRNG.
    ///
    /// Use [`RECOMMENDED_PEPPER_LEN`] unless you have a reason not to. The
    /// generated bytes are the same kind of secret as one loaded from a
    /// KMS — persist it *before* hashing anything users will need to log
    /// in with later (a pepper that only exists in one process's memory
    /// cannot verify tomorrow's logins).
    ///
    /// ```
    /// use salting::{Pepper, RECOMMENDED_PEPPER_LEN};
    ///
    /// let pepper = Pepper::generate(RECOMMENDED_PEPPER_LEN).unwrap();
    /// assert_eq!(pepper.as_bytes().len(), RECOMMENDED_PEPPER_LEN);
    /// ```
    ///
    /// # Errors
    ///
    /// - [`PasswordError::PepperEmpty`] — `byte_len` is 0.
    /// - [`PasswordError::PepperTooLong`] — `byte_len` exceeds
    ///   [`MAX_PEPPER_LEN`].
    pub fn generate(byte_len: usize) -> Result<Self, PasswordError> {
        if byte_len == 0 {
            return Err(PasswordError::PepperEmpty);
        }
        if byte_len > MAX_PEPPER_LEN {
            return Err(PasswordError::PepperTooLong {
                max: MAX_PEPPER_LEN,
                got: byte_len,
            });
        }

        let mut inner = Zeroizing::new(vec![0u8; byte_len]);
        // Fill in 16-byte draws from `password_hash::generate_salt` (the
        // same OS-CSPRNG source this crate's salts use) — no new
        // dependencies. The final partial chunk is truncated to fit.
        {
            let buf = inner.as_mut_slice();
            let mut chunks = buf.chunks_exact_mut(phc::Salt::RECOMMENDED_LENGTH);
            for chunk in chunks.by_ref() {
                chunk.copy_from_slice(&password_hash::generate_salt());
            }
            for (dst, src) in chunks
                .into_remainder()
                .iter_mut()
                .zip(password_hash::generate_salt())
            {
                *dst = src;
            }
        }
        Ok(Self { inner })
    }

    /// Borrow the pepper bytes (for diagnostics and custom integrations).
    ///
    /// Prefer the provided hashing APIs ([`Hasher`],
    /// [`hash_password_with_pepper`]) so the pepper only ever enters an
    /// Argon2 `K` input.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}

impl fmt::Debug for Pepper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pepper(<redacted>)")
    }
}

/// OWASP-default password hashing and verification with optional pepper
/// support — a small builder around [`Argon2Params`] plus current and
/// previous peppers.
///
/// - [`Hasher::hash`] uses the configured [`Argon2Params`] and the
///   **current** pepper (if any), always with a fresh random salt.
/// - [`Hasher::verify`] parses and bounds-checks the PHC string once, then
///   tries the current pepper, then each previous pepper (rotation), and —
///   only if [`Hasher::accept_unpeppered`] is set — the unpeppered
///   construction (migration). The first match wins; a mismatch is
///   `Ok(false)`, never an error.
/// - [`Hasher::needs_rehash`] drives rehash-on-login: `true` exactly when
///   the hash verifies but *not* with the current pepper.
///
/// # Examples
///
/// ```
/// use salting::{Argon2Params, Hasher, Pepper};
///
/// // Plain OWASP-default hashing, no pepper — drop-in for `hash_password`:
/// let hasher = Hasher::new();
/// let hash = hasher.hash("correct horse battery staple")?;
/// assert!(hasher.verify("correct horse battery staple", &hash)?);
/// assert!(!hasher.needs_rehash("correct horse battery staple", &hash)?);
///
/// // Custom parameters and a pepper compose the same way:
/// # fn test_params() -> Argon2Params {
/// #     Argon2Params { memory_kib: 32, iterations: 1, parallelism: 1, output_len: 32 }
/// # }
/// let low_mem = Hasher::new()
///     .with_params(test_params())
///     .with_pepper(Pepper::new(b"from-kms")?);
/// let hash = low_mem.hash("correct horse battery staple")?;
/// assert!(low_mem.verify("correct horse battery staple", &hash)?);
/// # Ok::<(), salting::PasswordError>(())
/// ```
#[derive(Debug, Clone)]
pub struct Hasher {
    /// Cost parameters for hashing (verification always honors the
    /// PHC-embedded parameters).
    params: Argon2Params,
    /// Current pepper: used by `hash`, tried first by `verify`.
    pepper: Option<Pepper>,
    /// Previous peppers (most recent first): verify-only, for rotation.
    previous_peppers: Vec<Pepper>,
    /// Whether legacy *unpeppered* hashes verify (migration).
    accept_unpeppered: bool,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    /// A `Hasher` with OWASP-default [`Argon2Params`], no pepper, and
    /// legacy unpeppered hashes **not** accepted.
    #[must_use]
    pub fn new() -> Self {
        Self {
            params: Argon2Params::default(),
            pepper: None,
            previous_peppers: Vec::new(),
            accept_unpeppered: false,
        }
    }

    /// Set the cost parameters used by [`Hasher::hash`].
    ///
    /// Verification is unaffected: it honors the parameters embedded in
    /// each PHC string.
    #[must_use]
    pub fn with_params(mut self, params: Argon2Params) -> Self {
        self.params = params;
        self
    }

    /// Set the **current** pepper: [`Hasher::hash`] mixes it in,
    /// [`Hasher::verify`] tries it first.
    ///
    /// Replaces any previously-set current pepper (the retired one should
    /// move to [`Hasher::with_previous_pepper`]).
    #[must_use]
    pub fn with_pepper(mut self, pepper: Pepper) -> Self {
        self.pepper = Some(pepper);
        self
    }

    /// Add a **previous** pepper (most recent first): verify-only.
    ///
    /// During a rotation, hashes made with a previous pepper still verify
    /// while new hashes always use the current one. Verify cost is one
    /// Argon2 run per candidate pepper until the old cohort has fully
    /// rehashed — retire previous peppers once [`Hasher::needs_rehash`]
    /// stops returning `true` for real logins.
    #[must_use]
    pub fn with_previous_pepper(mut self, pepper: Pepper) -> Self {
        self.previous_peppers.push(pepper);
        self
    }

    /// Whether legacy **unpeppered** hashes verify (migration from
    /// pre-pepper deployments).
    ///
    /// Defaults to `false`: a peppered deployment that also accepted
    /// unpeppered hashes would let anyone who can *write* to the hash
    /// column swap in an unpeppered hash of a password they know. Turn this
    /// on only for the migration window, and retire it (plus rehash every
    /// account) once [`Hasher::needs_rehash`] is `false` for the whole
    /// user base.
    #[must_use]
    pub fn accept_unpeppered(mut self, accept: bool) -> Self {
        self.accept_unpeppered = accept;
        self
    }

    /// Hash a password with the configured parameters and the current
    /// pepper (if any), using a fresh random salt.
    ///
    /// The result is a PHC string; hashes produced *with* a pepper verify
    /// only through a `Hasher` carrying that same pepper — they are not
    /// compatible with the unpeppered [`crate::verify_password`] family,
    /// and vice versa (see the [module docs](self#construction-precise)).
    ///
    /// # Errors
    ///
    /// - [`PasswordError::HashFailed`] — the parameters are not valid
    ///   Argon2 parameters (REQ-SLT-104).
    ///
    /// # Requirements
    /// REQ-SLT-001, REQ-SLT-100, REQ-SLT-301
    pub fn hash(&self, password: &str) -> Result<String, PasswordError> {
        let salt = SaltString::generate();
        let hashed = match &self.pepper {
            Some(pepper) => argon2_with_secret(&self.params, pepper.as_bytes())?
                .hash_password_with_salt(password.as_bytes(), salt.as_ref().as_bytes()),
            None => self
                .params
                .build_argon2()?
                .hash_password_with_salt(password.as_bytes(), salt.as_ref().as_bytes()),
        };
        hashed
            .map(|h| h.to_string())
            .map_err(|_| PasswordError::HashFailed)
    }

    /// Verify a password against a stored PHC hash string.
    ///
    /// The PHC string is parsed and its cost parameters bounds-checked
    /// **once** (same memory-DoS hardening as [`crate::verify_password`]),
    /// then candidates are tried in order: current pepper, previous
    /// peppers (rotation), unpeppered construction (only when
    /// [`Hasher::accept_unpeppered`] is set). Cost: at most one Argon2 run
    /// per candidate.
    ///
    /// A wrong password (or wrong/missing pepper) is `Ok(false)` — never a
    /// panic, never `Ok(true)` (REQ-SLT-302).
    ///
    /// # Errors
    ///
    /// - [`PasswordError::InvalidHashFormat`] — malformed PHC string or
    ///   malformed / zero-valued cost parameters (REQ-SLT-103, REQ-SLT-108).
    /// - [`PasswordError::ParamsExceeded`] — an in-range cost parameter
    ///   exceeds the documented verification bound (REQ-SLT-107).
    ///
    /// # Requirements
    /// REQ-SLT-101, REQ-SLT-102, REQ-SLT-301, REQ-SLT-303, REQ-SLT-304
    pub fn verify(&self, password: &str, hash: &str) -> Result<bool, PasswordError> {
        let parsed = parse_and_validate(hash)?;
        let password = password.as_bytes();

        if let Some(current) = &self.pepper {
            if verify_with(&parsed, password, Some(current.as_bytes()))? {
                return Ok(true);
            }
        }
        for previous in &self.previous_peppers {
            if verify_with(&parsed, password, Some(previous.as_bytes()))? {
                return Ok(true);
            }
        }
        if self.accept_unpeppered {
            return verify_with(&parsed, password, None);
        }
        // No pepper configured at all: this Hasher *is* the unpeppered
        // construction — plain hashing mode, drop-in for
        // [`crate::verify_password`]. (The `accept_unpeppered` gate above
        // only matters once a pepper is configured.)
        if self.pepper.is_none() && self.previous_peppers.is_empty() {
            return verify_with(&parsed, password, None);
        }
        Ok(false)
    }

    /// Rehash-on-login signal: `Ok(true)` exactly when the password
    /// **verifies** against this hash but the hash was *not* made with the
    /// current pepper (a previous pepper's hash, or a legacy unpeppered
    /// hash under [`Hasher::accept_unpeppered`]).
    ///
    /// `Ok(false)` means either the login itself fails, or the hash is
    /// already in the strongest configured form. Typical use — see the
    /// [module docs](self#rotation-and-migration) for the full recipe:
    ///
    /// ```no_run
    /// # use salting::{Hasher, Pepper};
    /// # fn main() -> Result<(), salting::PasswordError> {
    /// # let hasher = Hasher::new().with_pepper(Pepper::new(b"kms")?);
    /// # let stored = hasher.hash("correct horse battery staple")?;
    /// # let password = "correct horse battery staple";
    /// if hasher.verify(password, &stored)? && hasher.needs_rehash(password, &stored)? {
    ///     let _upgraded = hasher.hash(password)?; // write back to the DB
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Cost: at most one extra Argon2 run beyond [`Hasher::verify`] —
    /// only meaningful right after a successful login.
    ///
    /// # Errors
    ///
    /// Same as [`Hasher::verify`].
    ///
    /// # Requirements
    /// REQ-SLT-303, REQ-SLT-304
    pub fn needs_rehash(&self, password: &str, hash: &str) -> Result<bool, PasswordError> {
        if !self.verify(password, hash)? {
            return Ok(false);
        }
        let Some(current) = &self.pepper else {
            return Ok(false);
        };
        let parsed = parse_and_validate(hash)?;
        Ok(!verify_with(
            &parsed,
            password.as_bytes(),
            Some(current.as_bytes()),
        )?)
    }
}

/// Parse a PHC string and run the documented cost-parameter bounds check
/// before any Argon2 allocation (shared with the unpeppered verify path).
fn parse_and_validate(hash: &str) -> Result<PasswordHash, PasswordError> {
    let parsed = PasswordHash::new(hash).map_err(|_| PasswordError::InvalidHashFormat)?;
    crate::validate_phc_params(&parsed.params)?;
    Ok(parsed)
}

/// Build the OWASP-default-parameter Argon2 instance with `secret` as the
/// Argon2 `K` input (the pepper). `Argon2::new_with_secret` cannot fail for
/// a non-empty secret within [`MAX_PEPPER_LEN`] (`argon2`'s own
/// `MAX_SECRET_LEN` is 2³²−1), but errors map to [`PasswordError::HashFailed`]
/// to fail closed (REQ-SLT-302).
fn argon2_with_secret<'a>(
    params: &Argon2Params,
    secret: &'a [u8],
) -> Result<Argon2<'a>, PasswordError> {
    let inner = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(params.output_len),
    )
    .map_err(|_| PasswordError::HashFailed)?;
    Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, inner)
        .map_err(|_| PasswordError::HashFailed)
}

/// One verification attempt: re-derive with (or without) the pepper `secret`
/// using the hash's own embedded parameters, constant-time tag compare
/// inside the `argon2` crate (REQ-SLT-101).
fn verify_with(
    parsed: &PasswordHash,
    password: &[u8],
    secret: Option<&[u8]>,
) -> Result<bool, PasswordError> {
    let outcome = match secret {
        Some(bytes) => {
            // Parameters are re-read from the PHC string by the verifier;
            // what matters here is that `secret` rides along as `K`.
            let argon2 = Argon2::new_with_secret(
                bytes,
                Algorithm::Argon2id,
                Version::V0x13,
                Params::default(),
            )
            .map_err(|_| PasswordError::HashFailed)?;
            argon2.verify_password(password, parsed)
        }
        None => Argon2::default().verify_password(password, parsed),
    };
    Ok(outcome.is_ok())
}

/// Hash a password with OWASP-default parameters and a pepper.
///
/// Convenience wrapper for `Hasher::new().with_pepper(...).hash(...)`; use
/// [`Hasher`] directly when you need custom [`Argon2Params`], rotation, or
/// migration support.
///
/// # Errors
///
/// Same as [`Hasher::hash`]; plus [`PasswordError::PepperEmpty`] /
/// [`PasswordError::PepperTooLong`] surface at [`Pepper::new`].
///
/// # Requirements
/// REQ-SLT-001, REQ-SLT-100, REQ-SLT-301
pub fn hash_password_with_pepper(password: &str, pepper: &Pepper) -> Result<String, PasswordError> {
    Hasher::new().with_pepper(pepper.clone()).hash(password)
}

/// Verify a password against a PHC hash string made with `pepper`.
///
/// Convenience wrapper for `Hasher::new().with_pepper(...).verify(...)`.
/// A wrong password *or* a wrong pepper is `Ok(false)`; hashes made
/// without a pepper never verify here (REQ-SLT-302).
///
/// # Errors
///
/// Same as [`Hasher::verify`].
///
/// # Requirements
/// REQ-SLT-101, REQ-SLT-102, REQ-SLT-301
pub fn verify_password_with_pepper(
    password: &str,
    hash: &str,
    pepper: &Pepper,
) -> Result<bool, PasswordError> {
    Hasher::new()
        .with_pepper(pepper.clone())
        .verify(password, hash)
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

    /// Small, fast parameters for roundtrip tests; verification honors the
    /// PHC-embedded parameters, so these never slow the verify path.
    fn test_params() -> Argon2Params {
        Argon2Params {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        }
    }

    /// REQ-SLT-300: empty peppers are rejected — they would silently
    /// behave as "no pepper".
    #[test]
    fn pepper_rejects_empty() {
        assert!(matches!(Pepper::new(""), Err(PasswordError::PepperEmpty)));
        assert!(matches!(
            Pepper::new(Vec::<u8>::new()),
            Err(PasswordError::PepperEmpty)
        ));
        assert!(matches!(
            Pepper::generate(0),
            Err(PasswordError::PepperEmpty)
        ));
    }

    /// REQ-SLT-300: oversized peppers are rejected with the bound reported.
    #[test]
    fn pepper_rejects_too_long() {
        let too_big = vec![0x41u8; MAX_PEPPER_LEN + 1];
        assert!(matches!(
            Pepper::new(too_big),
            Err(PasswordError::PepperTooLong { max, got })
                if max == MAX_PEPPER_LEN && got == MAX_PEPPER_LEN + 1
        ));
        assert!(matches!(
            Pepper::generate(MAX_PEPPER_LEN + 1),
            Err(PasswordError::PepperTooLong { max, got })
                if max == MAX_PEPPER_LEN && got == MAX_PEPPER_LEN + 1
        ));

        // Boundary: exactly the max is accepted.
        let at_max =
            Pepper::new(vec![0u8; MAX_PEPPER_LEN]).expect("pepper at the bound must be accepted");
        assert_eq!(at_max.as_bytes().len(), MAX_PEPPER_LEN);
    }

    /// REQ-SLT-301: the pepper roundtrips — right pepper verifies, wrong
    /// pepper fails cleanly as `Ok(false)` (never panics, never `Ok(true)`).
    #[test]
    fn pepper_roundtrip_and_wrong_pepper_fails() {
        let hasher = Hasher::new()
            .with_params(test_params())
            .with_pepper(Pepper::new(b"right pepper").unwrap());
        let hash = hasher.hash("correct horse battery staple").unwrap();

        assert!(
            hasher
                .verify("correct horse battery staple", &hash)
                .unwrap()
        );

        let wrong = Hasher::new()
            .with_params(test_params())
            .with_pepper(Pepper::new(b"wrong pepper").unwrap());
        assert!(!wrong.verify("correct horse battery staple", &hash).unwrap());
        assert!(!wrong.verify("totally different password", &hash).unwrap());

        // Free-function wrappers agree with the Hasher path.
        let pepper = Pepper::new(b"right pepper").unwrap();
        assert!(
            verify_password_with_pepper("correct horse battery staple", &hash, &pepper).unwrap()
        );
        assert!(!hasher.verify("wrong password", &hash).unwrap());
    }

    /// REQ-SLT-302: peppered and unpeppered constructions are mutually
    /// incompatible, and the PHC string itself carries no pepper marker.
    #[test]
    fn peppered_and_unpeppered_hashes_are_incompatible() {
        let params = test_params();
        let peppered = Hasher::new()
            .with_params(params.clone())
            .with_pepper(Pepper::new(b"pepper").unwrap())
            .hash("correct horse battery staple")
            .unwrap();
        let unpeppered = Hasher::new()
            .with_params(params)
            .hash("correct horse battery staple")
            .unwrap();

        // The PHC metadata (algorithm, version, cost params) is identical —
        // no marker distinguishes peppered from unpeppered; only the app
        // knows which is which (see the module docs on pepper_id tracking).
        let metadata = "$argon2id$v=19$m=32,t=1,p=1$";
        assert!(
            peppered.starts_with(metadata) && unpeppered.starts_with(metadata),
            "peppered/unpeppered PHC metadata must not differ: {peppered} vs {unpeppered}"
        );

        let plain = Hasher::new().with_params(test_params());
        assert!(
            !plain
                .verify("correct horse battery staple", &peppered)
                .unwrap()
        );
        assert!(
            !plain
                .needs_rehash("correct horse battery staple", &peppered)
                .unwrap()
        );

        let with = Hasher::new()
            .with_params(test_params())
            .with_pepper(Pepper::new(b"pepper").unwrap());
        assert!(
            !with
                .verify("correct horse battery staple", &unpeppered)
                .unwrap()
        );
    }

    /// REQ-SLT-303: rotation — hashes from the previous pepper still
    /// verify, `needs_rehash` flags exactly them, and fresh hashes from the
    /// current pepper do not need a rehash.
    #[test]
    fn pepper_rotation_current_and_previous() {
        let old = Pepper::new(b"pepper v1").unwrap();
        let new = Pepper::new(b"pepper v2").unwrap();
        let params = test_params();

        let old_hasher = Hasher::new()
            .with_params(params.clone())
            .with_pepper(old.clone());
        let old_hash = old_hasher.hash("correct horse battery staple").unwrap();

        let rotated = Hasher::new()
            .with_params(params)
            .with_pepper(new)
            .with_previous_pepper(old);

        assert!(
            rotated
                .verify("correct horse battery staple", &old_hash)
                .unwrap()
        );
        assert!(
            rotated
                .needs_rehash("correct horse battery staple", &old_hash)
                .unwrap()
        );

        let new_hash = rotated.hash("correct horse battery staple").unwrap();
        assert!(
            rotated
                .verify("correct horse battery staple", &new_hash)
                .unwrap()
        );
        assert!(
            !rotated
                .needs_rehash("correct horse battery staple", &new_hash)
                .unwrap()
        );
        assert!(!rotated.verify("wrong password", &old_hash).unwrap());
    }

    /// REQ-SLT-304: migration — legacy unpeppered hashes verify only with
    /// `accept_unpeppered(true)`, and are flagged by `needs_rehash`.
    #[test]
    fn migration_from_unpeppered_hashes() {
        let params = test_params();
        let legacy_hash = Hasher::new()
            .with_params(params.clone())
            .hash("correct horse battery staple")
            .unwrap();

        let migrating = Hasher::new()
            .with_params(params.clone())
            .with_pepper(Pepper::new(b"new pepper").unwrap())
            .accept_unpeppered(true);

        assert!(
            migrating
                .verify("correct horse battery staple", &legacy_hash)
                .unwrap()
        );
        assert!(
            migrating
                .needs_rehash("correct horse battery staple", &legacy_hash)
                .unwrap()
        );

        // Without the opt-in, the legacy hash does not verify — the secure
        // default for peppered deployments.
        let strict = Hasher::new()
            .with_params(params)
            .with_pepper(Pepper::new(b"new pepper").unwrap());
        assert!(
            !strict
                .verify("correct horse battery staple", &legacy_hash)
                .unwrap()
        );
    }

    /// REQ-SLT-303 edge: with no current pepper configured, nothing is
    /// ever flagged for rehash — there is nothing to upgrade toward.
    #[test]
    fn needs_rehash_is_false_without_a_current_pepper() {
        let params = test_params();
        let legacy = Hasher::new()
            .with_params(params.clone())
            .hash("correct horse battery staple")
            .unwrap();

        let hasher = Hasher::new().with_params(params).accept_unpeppered(true);
        assert!(
            hasher
                .verify("correct horse battery staple", &legacy)
                .unwrap()
        );
        assert!(
            !hasher
                .needs_rehash("correct horse battery staple", &legacy)
                .unwrap()
        );
    }

    /// REQ-SLT-301: a failed login never sets the rehash flag.
    #[test]
    fn needs_rehash_false_when_login_fails() {
        let hasher = Hasher::new()
            .with_params(test_params())
            .with_pepper(Pepper::new(b"pepper").unwrap());
        let hash = hasher.hash("correct horse battery staple").unwrap();

        assert!(!hasher.verify("wrong password", &hash).unwrap());
        assert!(!hasher.needs_rehash("wrong password", &hash).unwrap());
    }

    /// REQ-SLT-305: `Debug` output is redacted — the secret must never
    /// surface in logs, panic messages, or error strings.
    #[test]
    fn pepper_debug_is_redacted() {
        let secret = b"super-secret-pepper-material";
        let pepper = Pepper::new(secret).unwrap();
        let rendered = format!("{pepper:?}");
        assert_eq!(rendered, "Pepper(<redacted>)");
        assert!(
            !rendered
                .as_bytes()
                .windows(secret.len())
                .any(|w| w == secret)
        );

        let hasher = Hasher::new().with_pepper(pepper.clone());
        let rendered = format!("{hasher:?}");
        assert!(
            !rendered
                .as_bytes()
                .windows(secret.len())
                .any(|w| w == secret)
        );

        // Error display stays static for the new variants, too.
        assert_eq!(
            PasswordError::PepperEmpty.to_string(),
            "pepper must not be empty"
        );
        let msg = PasswordError::PepperTooLong { max: 1, got: 2 }.to_string();
        assert!(!msg.contains("secret"));
    }

    /// REQ-SLT-305: the pepper's storage is `Zeroizing<Vec<u8>>`, whose
    /// `Drop` impl overwrites the key material (zeroize crate's audited
    /// contract) — pinned as a type-level witness so a refactor cannot
    /// silently swap it for a plain `Vec`.
    #[test]
    fn pepper_storage_is_zeroizing() {
        let pepper = Pepper::new(b"wipe-on-drop").unwrap();
        // Compile-time witness: the field is `Zeroizing<Vec<u8>>`.
        let _: &Zeroizing<Vec<u8>> = &pepper.inner;

        // `Pepper` crosses threads freely (server runtimes share peppers).
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Pepper>();
        assert_send_sync::<Hasher>();
    }

    /// REQ-SLT-300/301: `Pepper::generate` produces CSPRNG material of the
    /// requested length that roundtrips through hash/verify.
    #[test]
    fn generate_roundtrip_and_bounds() {
        let pepper = Pepper::generate(RECOMMENDED_PEPPER_LEN).unwrap();
        assert_eq!(pepper.as_bytes().len(), RECOMMENDED_PEPPER_LEN);
        assert!(pepper.as_bytes().iter().any(|&b| b != 0));

        let hasher = Hasher::new()
            .with_params(test_params())
            .with_pepper(pepper.clone());
        let hash = hasher.hash("correct horse battery staple").unwrap();
        assert!(
            hasher
                .verify("correct horse battery staple", &hash)
                .unwrap()
        );
    }

    /// REQ-SLT-301 (property): arbitrary Unicode passwords roundtrip under
    /// a pepper, and fresh salts still make every hash unique.
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn pepper_roundtrip_property(password in "\\PC{1,128}") {
            let hasher = Hasher::new().with_params(test_params()).with_pepper(
                Pepper::new(b"proptest pepper").unwrap(),
            );
            let h1 = hasher.hash(&password).unwrap();
            let h2 = hasher.hash(&password).unwrap();
            prop_assert_ne!(&h1, &h2, "fresh salt must change the hash");
            prop_assert!(hasher.verify(&password, &h1).unwrap());
            prop_assert!(hasher.verify(&password, &h2).unwrap());
        }
    }
}
