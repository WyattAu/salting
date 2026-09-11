# salting

[![docs.rs](https://docs.rs/salting/badge.svg)](https://docs.rs/salting)
[![crates.io](https://img.shields.io/crates/v/salting.svg)](https://crates.io/crates/salting)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Opinionated Argon2id password hashing for Rust with OWASP-recommended defaults.

## Why?

The [`argon2`](https://crates.io/crates/argon2) crate gives you raw access to the algorithm but leaves you choosing parameters, managing salts, and formatting output. `salting` wraps all of that into a simple API with secure defaults that follow the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

## Features

- **OWASP-compliant defaults** — 64 MiB memory, 3 iterations, 4 parallelism threads
- **Pepper support** — server-side secret (env var or KMS) mixed into every hash; protects passwords when only the DB leaks, with rotation + rehash-on-login built in
- **Configurable parameters** — override any Argon2 tuning knob
- **Low-memory preset** — for constrained environments (64 MiB, 2 iterations, 1 thread)
- **PHC string format** — hashes are self-describing and portable
- **Strict verification** — `verify_password_strict()` returns `Err` on mismatch instead of `false`
- **`#![forbid(unsafe_code)]`** — no unsafe code anywhere

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `argon2id` | ✅ | Argon2id hashing with OWASP-recommended defaults. |
| `strength` | — | Password strength estimation (zxcvbn) and `Policy` checks via `check_password`. |

## Quick Start

```rust
use salting::{hash_password, verify_password};

fn main() {
    let hash = hash_password("my secret password").unwrap();
    assert!(verify_password("my secret password", &hash).unwrap());
}
```

## Custom Parameters

```rust
use salting::{hash_password_with_params, Argon2Params};

let params = Argon2Params {
    memory_kib: 131072, // 128 MiB
    iterations: 4,
    parallelism: 2,
    output_len: 32,
};

let hash = hash_password_with_params("password", &params).unwrap();
```

## Pepper (Server-Side Secret)

A pepper is an application-wide secret stored **away from the database**
(env var, AWS/GCP KMS, HashiCorp Vault). If only the database leaks — the
most common breach shape — peppered hashes are useless for offline
cracking: every guess needs a full Argon2 run *plus* a secret the attacker
does not have.

The pepper enters hashing as the **Argon2 secret key** (`K` input,
RFC 9106) via the `argon2` crate's native support — no pre-hashing, no
extra dependencies. Peppered hashes verify only with the same pepper.

```rust
use salting::{Hasher, Pepper};

let pepper = Pepper::new(std::env::var("SALTING_PEPPER").unwrap()).unwrap();

let hasher = Hasher::new().with_pepper(pepper);
let hash = hasher.hash("correct horse battery staple").unwrap();
assert!(hasher.verify("correct horse battery staple", &hash).unwrap());
```

**Threat model:** protects against DB-only exfiltration; does **not**
protect against full-server compromise (attacker reads the env/KMS too).
Storage guidance, KMS/HSM retrieval examples (AWS, GCP, Vault), and a
zero-downtime rotation runbook: [docs/PEPPER-MANAGEMENT.md](docs/PEPPER-MANAGEMENT.md).

Rotation and migration are first-class: `with_previous_pepper` keeps old-cohort
logins working while `needs_rehash` drives rehash-on-login onto the current
pepper; `accept_unpeppered(true)` adopts peppers on existing unpeppered
databases the same way.

```rust
# use salting::{Hasher, Pepper};
# fn demo() -> Result<(), salting::PasswordError> {
let current = Pepper::new("v2-from-kms")?;
let previous = Pepper::new("v1-from-kms")?;
let hasher = Hasher::new()
    .with_pepper(current)          // hashes + verified first
    .with_previous_pepper(previous) // old-cohort logins still verify
    .accept_unpeppered(true);       // pre-pepper legacy hashes too

if hasher.verify("correct horse battery staple", &stored_hash)?
    && hasher.needs_rehash("correct horse battery staple", &stored_hash)?
{
    let _upgraded = hasher.hash("correct horse battery staple")?; // write back
}
# Ok(())
# }
```

## Benchmarks

`salting` is a DX wrapper around the [`argon2`](https://crates.io/crates/argon2)
crate — the wrapper adds no meaningful overhead. Measured with criterion
(`cargo bench --bench hash_bench`, single run, medians; Linux x86_64
i5-9400F, 6 cores, **under steady load** — see honesty note):

| Algorithm | Parameters | Hash (ms) | Verify (ms) |
|---|---|---|---|
| **salting** (Argon2id) | m=64 MiB, t=3, p=4 | 832 | 570 |
| **salting + pepper** | m=64 MiB, t=3, p=4 | 802 | 500 |
| raw `argon2` crate | m=64 MiB, t=3, p=4 | 691 | 745 |
| **salting** low-memory preset | m=64 MiB, t=2, p=1 | 524 | — |
| bcrypt | cost 10 (OWASP) | 269 | 359 |
| scrypt | N=2¹⁷, r=8, p=1 (OWASP) | 1545 | 1595 |

Honest framing: same algorithm, same parameters → same cost. All three
Argon2id variants' criterion intervals overlap in every run; in the run
above the *raw crate* verified slower than the wrapper — platform noise
dwarfs any wrapper cost, which is the point: **wrapper overhead ≈ 0**
(the pepper is one extra `K` input to Argon2, also ≈ 0). These numbers
are orientation on a contended box, not a lab result — run
`cargo bench --bench hash_bench` on your hardware for real figures.
bcrypt/scrypt at OWASP costs offer weaker memory-hardness per millisecond
than Argon2id at these parameters; the comparison is for orientation, not
a like-for-like security claim. Bench-only dependencies (`bcrypt`,
`scrypt`, `criterion`) are dev-dependencies and never ship with your
build.

## Comparison with Raw `argon2`

| Feature | `salting` | `argon2` |
|---|---|---|
| OWASP defaults | ✅ | ❌ (manual) |
| Salt generation | ✅ | Manual |
| PHC output | ✅ | Manual |
| Parameter presets | ✅ | ❌ |
| Pepper (secret key) plumbing + rotation | ✅ | Manual (`new_with_secret`) |
| Strict verify | ✅ | ❌ |
| `forbid(unsafe_code)` | ✅ | ❌ |

## License

MIT OR Apache-2.0

## Security

Threat model: [THREAT-MODEL.md](THREAT-MODEL.md).
