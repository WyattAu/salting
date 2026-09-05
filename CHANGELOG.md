# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

## [1.0.0] - 2026-09-05

### Added

- API declared stable; semver contract enforced via cargo-semver-checks CI gate.
- Argon2id password hashing with OWASP-recommended defaults, configurable
  tuning knobs, and a low-memory preset.
- PHC string format output and strict verification
  (`verify_password_strict`).
- Optional zxcvbn-based strength checking (`strength` feature) and
  cargo-fuzz targets.
- Memory-DoS hardening: PHC cost-parameter clamping at verify with public
  `MAX_PHC_*` bounds (0.2.1).

## [0.2.1] - 2026-09-05

### Security

- **Memory-DoS hardening (REQ-SLT-107):** `verify_password` and
  `verify_password_strict` now validate the PHC-embedded cost parameters
  before any Argon2 allocation. Hashes with `m > 65536` KiB (64 MiB),
  `t > 16`, or `p > 8` are rejected with a new
  `Err(PasswordError::ParamsExceeded { param, max, got })` — fail closed,
  since a hash above the bounds was not produced by this crate. Bounds are
  public constants (`MAX_PHC_MEMORY_KIB`, `MAX_PHC_ITERATIONS`,
  `MAX_PHC_PARALLELISM`); defaults this crate produces sit at/inside them.
- **Malformed param rejection (REQ-SLT-108):** zero-valued (`m/t/p = 0`)
  and malformed (negative, leading zeroes, beyond `u32`, empty) cost
  parameter encodings are rejected with `Err(PasswordError::InvalidHashFormat)`
  before reaching Argon2.
- Behavior change: such hashes previously returned `Ok(false)` from
  `verify_password` (or `Err(VerificationFailed)` from the strict variant)
  *after* allocating per attacker-chosen params; they now fail fast with a
  distinct error. Patch bump is acceptable pre-1.0: inputs that used to
  hang or allocate gigabytes now return `Err`, and no previously-`Ok` input
  changes classification.
- THREAT-MODEL: OPEN-1 closed (see CLOSED-1); residual risk documented
  (attacker-replaced hashes cause account lockout, not memory exhaustion).

### Added

- Tests: bounds boundary, over-bound/zero/malformed param rejection
  (incl. a 250 ms no-allocation timing bound), plus two fuzz-style
  proptests over arbitrary and param-edited PHC strings (REQ-SLT-107/108).

## [0.2.0] - 2026-09-03

### Added

- Optional zxcvbn-based password strength checking (feature-gated).
- cargo-fuzz targets (`fuzz_parse`, `fuzz_policy`).

### Security

- Hardening sweep: `#![forbid(unsafe_code)]`, `deny(missing_docs)`,
  expanded test and proptest coverage.

## [0.1.0] - 2026-08-31

### Added

- Argon2id password hashing with OWASP-recommended defaults
  (64 MiB memory, 3 iterations, 4 parallelism threads).
- Configurable Argon2 tuning knobs and a low-memory preset
  (64 MiB, 2 iterations, 1 thread) for constrained environments.
- PHC string format output — hashes are self-describing and portable.
- Strict verification: `verify_password_strict()` returns `Err` on
  mismatch instead of `false`.
- `#![forbid(unsafe_code)]`; criterion benches and proptest suites.
