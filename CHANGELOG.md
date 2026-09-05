# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

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
