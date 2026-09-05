# Requirements — salting

Numbered, testable requirements. Every requirement maps to at least one named
test; every security-relevant test cites at least one requirement. Doc
comments on the implementing public item carry `REQ-SLT-NNN` tags.

Scope: Argon2id password hashing/verification (lib) + optional `strength`
feature (Policy, zxcvbn estimation).

## Functional

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-SLT-001 | `hash_password` returns a PHC-format Argon2id hash; `verify_password` returns `Ok(true)` for the correct password and `Ok(false)` for a wrong one | MUST |
| REQ-SLT-002 | `hash_password_with_params` with `Argon2Params::low_memory()` produces a verifiable hash | MUST |
| REQ-SLT-003 | `verify_password_strict` returns `Ok(())` on match and `Err(VerificationFailed)` on mismatch | MUST |
| REQ-SLT-004 | `Policy::default` enforces ≥12 chars with uppercase, lowercase, digit, special; checks run in fixed order (length → upper → lower → digit → special) and are deterministic | MUST |
| REQ-SLT-005 | The `Policy` builder relaxes/tightens each rule independently (`min_length`, `require_*`, `special_chars`) | SHOULD |
| REQ-SLT-006 | `strength` scores a common password 0 with non-empty feedback, a strong passphrase ≥ 3, and penalizes `user_inputs` matches | MUST |
| REQ-SLT-007 | `check_password` runs policy first (fail fast) and returns the `Strength` only when policy passes | MUST |

## Security

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-SLT-100 | Every hash uses a fresh random salt: hashing the same password twice yields different PHC strings | MUST |
| REQ-SLT-101 | Password comparison is constant-time: verification goes through the `argon2` crate's `PasswordVerifier` (subtle-backed tag compare); no `==` on secret material | MUST |
| REQ-SLT-102 | A wrong password never panics and never returns `Ok(true)`: `verify_password` → `Ok(false)`, `verify_password_strict` → `Err` (fails closed) | MUST |
| REQ-SLT-103 | A malformed or corrupt PHC hash string returns `Err(InvalidHashFormat)`, never panics | MUST |
| REQ-SLT-104 | Invalid `Argon2Params` (e.g. `output_len` below the 4-byte Argon2 minimum) return `Err(HashFailed)`, never panic | MUST |
| REQ-SLT-105 | Error `Display` output contains no password material (static messages only) | MUST |
| REQ-SLT-106 | `strength` never fails: an unanalyzable password yields score 0 with feedback (treated as weak) | SHOULD |
| REQ-SLT-107 | `verify_password`/`verify_password_strict` reject PHC strings whose embedded cost params exceed the documented bounds (`m` ≤ 65536 KiB = `MAX_PHC_MEMORY_KIB`, `t` ≤ 16 = `MAX_PHC_ITERATIONS`, `p` ≤ 8 = `MAX_PHC_PARALLELISM`) with `Err(ParamsExceeded)` **before any Argon2 allocation** — bounds sit at/above everything this crate hashes with, far below memory-DoS territory | MUST |
| REQ-SLT-108 | `verify_password`/`verify_password_strict` reject malformed cost-param encodings (non-decimal, negative, leading zeroes, beyond `u32`, empty) and zero-valued `m`/`t`/`p` with `Err(InvalidHashFormat)` before Argon2 sees them — never panic | MUST |

## Robustness

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-SLT-200 | Unicode passwords of 1–256 chars round-trip through hash/verify | MUST |
| REQ-SLT-201 | `Policy` length checks count Unicode characters, not bytes | SHOULD |

## Constant-Time Audit

- AUDIT: password verification via `Argon2::verify_password`
  (`src/lib.rs`) — the `argon2` crate compares the derived key in constant
  time (subtle-backed). ✓
- AUDIT: salt generation via `SaltString::generate(&mut OsRng)` — OS CSPRNG. ✓
- AUDIT: grep for `==` on secrets — none outside test code; the only
  comparisons of password-derived material are inside the argon2 crate.
- Note: `verify_password` parses the stored PHC string (public) before any
  secret-dependent work; parsing failures return before hashing.

## Traceability Matrix

| Requirement | Test (fn, file) | Property class |
|-------------|-----------------|----------------|
| REQ-SLT-001 | `hash_and_verify` (`src/lib.rs`) | unit |
| REQ-SLT-002 | `low_memory_params` (`src/lib.rs`) | unit |
| REQ-SLT-003 | `strict_verify_fails_on_mismatch` (`src/lib.rs`) | unit |
| REQ-SLT-004 | `policy_checks_are_deterministic_and_ordered`, `each_policy_error_variant` (`src/strength.rs`) | unit |
| REQ-SLT-005 | `policy_builder_customizes_rules` (`src/strength.rs`) | unit |
| REQ-SLT-006 | `common_password_scores_zero_with_feedback`, `strong_passphrase_scores_higher_than_weak`, `user_inputs_reduce_score` (`src/strength.rs`) | unit |
| REQ-SLT-007 | `check_password_fails_fast_on_policy`, `check_password_returns_strength_when_policy_passes` (`src/strength.rs`) | unit |
| REQ-SLT-100 | `hash_differs_each_time` (`src/lib.rs`) | property |
| REQ-SLT-101 | AUDIT above; `hash_verify_roundtrip` (`src/lib.rs`) | audit/property |
| REQ-SLT-102 | `verify_wrong_password_fails` (`src/lib.rs`) | property |
| REQ-SLT-103 | `malformed_hash_rejected` (`src/lib.rs`) — **gap test added** | unit |
| REQ-SLT-104 | `invalid_params_fail_closed` (`src/lib.rs`) — **gap test added** | unit |
| REQ-SLT-105 | `error_display_contains_no_password_material` (`src/lib.rs`) — **gap test added** | unit |
| REQ-SLT-106 | `empty_password_scores_zero` (`src/strength.rs`) | unit |
| REQ-SLT-107 | `default_hash_params_within_bounds` (boundary: defaults accepted), `phc_params_exceeding_bounds_rejected` (incl. 250 ms no-allocation bound), `fuzz_edited_params_are_classified` (`src/lib.rs`) — **gap tests added** | unit/property |
| REQ-SLT-108 | `phc_zero_params_rejected`, `phc_malformed_params_rejected`, `fuzz_arbitrary_phc_never_panics_or_lingers` (`src/lib.rs`) — **gap tests added** | unit/property |
| REQ-SLT-200 | `hash_verify_roundtrip` (`src/lib.rs`) | property |
| REQ-SLT-201 | `policy_length_counts_chars_not_bytes` (`src/strength.rs`) — **gap test added** | unit |

## Test Count Delta

- Before: 19 tests (6 lib incl. 3 proptests + 9 strength, 4 gap tests from prior sweep).
- Added: 6 (`default_hash_params_within_bounds`, `phc_params_exceeding_bounds_rejected`, `phc_zero_params_rejected`, `phc_malformed_params_rejected`, proptests `fuzz_arbitrary_phc_never_panics_or_lingers`, `fuzz_edited_params_are_classified`).
- After: 25.
