# Requirements: salting
| REQ-SLT-107 | `verify_password`/`verify_password_strict` reject PHC strings whose embedded cost params exceed the documented bounds (`m` ≤ 65536 KiB = `MAX_PHC_MEMORY_KIB`, `t` ≤ 16 = `MAX_PHC_ITERATIONS`, `p` ≤ 8 = `MAX_PHC_PARALLELISM`) with `Err(ParamsExceeded)` **before any Argon2 allocation**; bounds sit at/above everything this crate hashes with, far below memory-DoS territory | MUST |
| REQ-SLT-108 | `verify_password`/`verify_password_strict` reject malformed cost-param encodings (non-decimal, negative, leading zeroes, beyond `u32`, empty) and zero-valued `m`/`t`/`p` with `Err(InvalidHashFormat)` before Argon2 sees them; never panic | MUST |
| REQ-SLT-301 | A peppered hash verifies with the same pepper; a wrong pepper (or wrong password) yields `Ok(false)`; never `Ok(true)`, never a panic; free-function wrappers agree with `Hasher` | MUST |
  (`src/lib.rs`); the `argon2` crate compares the derived key in constant
- AUDIT: salt generation via `SaltString::generate(&mut OsRng)`; OS CSPRNG. ✓
- AUDIT: grep for `==` on secrets; none outside test code; the only
| REQ-SLT-103 | `malformed_hash_rejected` (`src/lib.rs`); **gap test added** | unit |
| REQ-SLT-104 | `invalid_params_fail_closed` (`src/lib.rs`); **gap test added** | unit |
| REQ-SLT-105 | `error_display_contains_no_password_material` (`src/lib.rs`); **gap test added** | unit |
| REQ-SLT-107 | `default_hash_params_within_bounds` (boundary: defaults accepted), `phc_params_exceeding_bounds_rejected` (incl. 250 ms no-allocation bound), `fuzz_edited_params_are_classified` (`src/lib.rs`); **gap tests added** | unit/property |
| REQ-SLT-108 | `phc_zero_params_rejected`, `phc_malformed_params_rejected`, `fuzz_arbitrary_phc_never_panics_or_lingers` (`src/lib.rs`); **gap tests added** | unit/property |
| REQ-SLT-201 | `policy_length_counts_chars_not_bytes` (`src/strength.rs`); **gap test added** | unit |