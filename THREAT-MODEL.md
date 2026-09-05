# Threat Model — salting

Status: **v1.0** · Method: STRIDE over the public API surface
(`hash_password`, `hash_password_with_params`, `verify_password`,
`verify_password_strict`, `check_password`/`Policy`/`strength` behind the
`strength` feature).

Trust boundaries: (1) the password string (attacker-influenced at login),
(2) the stored PHC hash string (trusted DB contents — but see OPEN-1),
(3) the `argon2`/`zxcvbn` dependency tree.

## Assets

| ID | Asset | Example |
|----|-------|---------|
| A1 | Password verifiability | Offline-crackable or collision-prone hashes |
| A2 | Hash uniqueness | Salt reuse across users |
| A3 | Verification decisions | Corrupt hash silently treated as "wrong password" |
| A4 | Caller availability | Memory/CPU exhaustion via hashing parameters |

## STRIDE Analysis

| # | Threat | Category | Surface | Mitigation | Verifying test |
|---|--------|----------|---------|------------|----------------|
| T1 | Weak / predictable salt | Spoofing | `hash_password_with_params` | Salt from `OsRng` via `SaltString::generate` (16-byte, PHC-encoded) | `src/lib.rs` proptest `hash_differs_each_time` (same password → different hashes) |
| T2 | Weak default parameters (offline cracking) | Elevation | `Argon2Params::default` | OWASP-recommended Argon2id: 64 MiB / t=3 / p=4, 32-byte output; `low_memory()` preset stays ≥ OWASP minimums; algorithm pinned to `Argon2id`, version `0x13` | `src/lib.rs::low_memory_params`, `hash_and_verify`; defaults asserted in `Argon2Params::default` docs |
| T3 | Password/PHC parser panic on hostile bytes | DoS | `verify_password` | Parsing delegated to `argon2::PasswordHash::new`; malformed → `InvalidHashFormat`, never panic; `#![forbid(unsafe_code)]` | `fuzz/fuzz_targets/fuzz_parse.rs`; proptest `hash_verify_roundtrip`, `verify_wrong_password_fails` |
| T4 | Policy bypass (weak password accepted) | Elevation | `Policy::check`, `check_password` | Deterministic composition rules run first (fail-fast), then zxcvbn guessability; user inputs reduce score | `src/strength.rs::policy_checks_are_deterministic_and_ordered`, `each_policy_error_variant`, `check_password_fails_fast_on_policy`, `common_password_scores_zero_with_feedback`, `user_inputs_reduce_score`, `empty_password_scores_zero`; `fuzz/fuzz_targets/fuzz_policy.rs` |
| T5 | Mismatch reported ambiguously | Repudiation | `verify_password` | All verify failures map to `Ok(false)` (no oracle about hash state); `verify_password_strict` distinguishes `VerificationFailed` for callers that care | `src/lib.rs::strict_verify_fails_on_mismatch` |

## OPEN RISKS (missing mitigations — not fabricated)

- **OPEN-1 — verify path honors PHC-embedded parameters without an upper
  bound.** `verify_password` parses `m`, `t`, `p` from the stored string and
  allocates accordingly. If hash strings are ever attacker-writable (import
  features, SQL injection elsewhere), a `m=4 GiB` hash becomes a memory-DoS
  primitive. No clamp, no test.
- **OPEN-2 — no rehash-on-login / parameter upgrade helper.** Hashes made
  under old `Argon2Params` are never transparently re-imported at a stronger
  cost; migration is entirely caller-side.
- **OPEN-3 — `verify_password` collapses corrupt-hash and wrong-password.**
  Operationally convenient, but a silently corrupted hash column is
  indistinguishable from user typos (A3); strict variant exists but is
  opt-in.
- **OPEN-4 — no minimum-password-length floor in `Policy` defaults beyond
  the configured `min_length`.** Callers who leave `min_length` at the
  default get the struct's default, but the crate never refuses to build a
  `Policy` with `min_length = 0`. No test pins the default value.

## Out of Scope

- Side-channel attacks on the Argon2 implementation (delegated to the
  `argon2` crate).
- Username enumeration via timing (hashing cost is constant per params).
- Caller-side storage of the PHC string (DB hardening).

## Residual Risks

- `strength` scores are probabilistic (zxcvbn); a policy-passing password is
  not guaranteed strong, only not-guessably-terrible.
- `Argon2Params` is caller-controlled: a caller may configure `memory_kib =
  8`, silently producing weak hashes; only the *defaults* are OWASP-anchored.
