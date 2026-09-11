# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

## [1.2.0] - 2026-09-11

### Added

- **Pepper support (REQ-SLT-300..305):** server-side secret mixed into
  hashing as the **Argon2 secret key input** (`K`, RFC 9106) via
  `argon2::Argon2::new_with_secret` — the algorithm's native pepper
  mechanism; no pre-hashing, no new crypto dependencies. Peppered hashes
  verify only with the same pepper; the PHC string carries no pepper
  marker (pepper versioning is application-side, recipes in the module
  docs).
  - `Pepper`: zeroizing secret wrapper (`zeroize` dep), redacted `Debug`,
    empty/oversized secrets rejected (`MAX_PEPPER_LEN` = 1 KiB),
    `Pepper::generate` mints CSPRNG peppers.
  - `Hasher` builder: OWASP-default or custom `Argon2Params`, current
    pepper (`with_pepper`), previous peppers (`with_previous_pepper`) for
    **rotation**, `accept_unpeppered` for **migration** from pre-pepper
    databases, and `needs_rehash` for **rehash-on-login**.
  - Free functions `hash_password_with_pepper` /
    `verify_password_with_pepper` (thin `Hasher` wrappers).
  - Verify path inherits the PHC cost-parameter bounds check
    (REQ-SLT-107/108) before any Argon2 allocation.
- `docs/PEPPER-MANAGEMENT.md`: storage guidance (env var vs. KMS/HSM),
  AWS KMS / GCP KMS / HashiCorp Vault retrieval examples (app-side code,
  no new crate deps), and a zero-downtime rotation runbook.
- `benches/hash_bench.rs`: salting vs. raw `argon2` at equivalent params
  (wrapper overhead ≈ 0), plus bcrypt (cost 10) and scrypt (N=2¹⁷, r=8,
  p=1) at OWASP-recommended costs. Bench-only deps are dev-dependencies.
- README: pepper section (threat model + rotation example) and benchmark
  table.

### Security

- Pepper threat model documented (crate docs, README, THREAT-MODEL):
  protects against DB-only exfiltration, NOT full-server compromise.

### Tests

- 12 pepper unit tests + 1 proptest (`src/pepper.rs`) and 4 public-API
  integration tests (`tests/pepper.rs`): roundtrip, wrong-pepper fails
  closed, peppered/unpeppered incompatibility, rotation (current +
  previous), migration (legacy unpeppered verify + rehash flag),
  zeroize type-level witness, redacted `Debug`, hostile-hash hardening
  through the peppered verify path.


## [1.1.0] - 2026-09-09

### Changed
- **Breaking:** argon2 0.6 / password-hash 0.6 / phc 0.6 (digest 0.11
  ecosystem).
- Vendored dependency surface refreshed (cargo-vet registry audits).

### Tests
- Cover the PHC unknown-parameter ignore arm (Tier A coverage).
- Pin all zxcvbn score-bucket boundaries in strength tests.


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
