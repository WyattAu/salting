# salting

Opinionated Argon2id password hashing for Rust with OWASP-recommended defaults.

## Why?

The [`argon2`](https://crates.io/crates/argon2) crate gives you raw access to the algorithm but leaves you choosing parameters, managing salts, and formatting output. `salting` wraps all of that into a simple API with secure defaults that follow the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

## Features

- **OWASP-compliant defaults** — 64 MiB memory, 3 iterations, 4 parallelism threads
- **Configurable parameters** — override any Argon2 tuning knob
- **Low-memory preset** — for constrained environments (64 MiB, 2 iterations, 1 thread)
- **PHC string format** — hashes are self-describing and portable
- **Strict verification** — `verify_password_strict()` returns `Err` on mismatch instead of `false`
- **`#![forbid(unsafe_code)]`** — no unsafe code anywhere

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

## Comparison with Raw `argon2`

| Feature | `salting` | `argon2` |
|---|---|---|
| OWASP defaults | ✅ | ❌ (manual) |
| Salt generation | ✅ | Manual |
| PHC output | ✅ | Manual |
| Parameter presets | ✅ | ❌ |
| Strict verify | ✅ | ❌ |
| `forbid(unsafe_code)` | ✅ | ❌ |

## License

MIT OR Apache-2.0

## Security

Threat model: [THREAT-MODEL.md](THREAT-MODEL.md).
