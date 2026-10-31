- **OWASP-compliant defaults**; 64 MiB memory, 3 iterations, 4 parallelism threads
- **Pepper support**; server-side secret (env var or KMS) mixed into every hash; protects passwords when only the DB leaks, with rotation + rehash-on-login built in
- **Configurable parameters**; override any Argon2 tuning knob
- **Low-memory preset**; for constrained environments (64 MiB, 2 iterations, 1 thread)
- **PHC string format**; hashes are self-describing and portable
- **Strict verification**; `verify_password_strict()` returns `Err` on mismatch instead of `false`
- **`#![forbid(unsafe_code)]`**; no unsafe code anywhere
| `strength` |; | Password strength estimation (zxcvbn) and `Policy` checks via `check_password`. |
(env var, AWS/GCP KMS, HashiCorp Vault). If only the database leaks; the
most common breach shape; peppered hashes are useless for offline
RFC 9106) via the `argon2` crate's native support; no pre-hashing, no
crate; the wrapper adds no meaningful overhead. Measured with criterion
i5-9400F, 6 cores, **under steady load**; see honesty note):
| **salting** low-memory preset | m=64 MiB, t=2, p=1 | 524 |; |
above the *raw crate* verified slower than the wrapper; platform noise
are orientation on a contended box, not a lab result; run
measures wrapper vs raw `argon2` on identical inputs; the wrapper's
- New test added during this baseline: `generate_boundary_max_len_is_accepted`; exactly `MAX_PEPPER_LEN` must be accepted, one byte more rejected.