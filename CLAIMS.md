# Performance claims inventory — salting

Every performance claim in [README.md](README.md), mapped to its proof
artifact. Created 2026-09-12 (salting 1.2.1).

Machine context for wall-clock records: Linux x86_64, i5-9400F (6 cores),
**under steady load** — the README says so explicitly; treat the table as
orientation, not a lab result. Proof kinds: **criterion** (wall-clock
record), **iai** (instruction gate, `cargo bench --bench iai_hot_path`),
**code**, **compiler**.

## Benchmark table (criterion, `benches/hash_bench.rs` — measured-on records)

| # | Claim (production params unless noted) | Artifact | Status |
|---|---|---|---|
| 1 | salting Argon2id: hash 832 ms / verify 570 ms | `hash_bench::argon2id_m65536_t3_p4` | backed (measured on, contended box) |
| 2 | salting + pepper: hash 802 ms / verify 500 ms | same, `salting_peppered` arms | backed (measured on) |
| 3 | raw `argon2` crate: hash 691 ms / verify 745 ms | same, `raw_argon2` arms | backed (measured on) |
| 4 | low-memory preset: hash 524 ms | same, `low_memory` arm | backed (measured on) |
| 5 | bcrypt cost 10: 269/359 ms | same, `bcrypt` arms | backed (measured on) |
| 6 | scrypt N=2¹⁷: 1545/1595 ms | same, `scrypt` arms | backed (measured on) |

## The core claim: wrapper overhead ≈ 0

| # | Claim | Artifact | Status |
|---|---|---|---|
| 7 | **"the wrapper adds no meaningful overhead"** / criterion intervals overlap | **proven at instruction level**: `benches/iai_hot_path.rs` (2026-09-12, valgrind 3.25.1, 64 KiB/t=1/p=1 small params, identical inputs incl. salt generation + PHC formatting on both sides): wrapper hash = 424 605 instructions vs raw 423 766 → **+839 (+0.20 %)**; wrapper verify = 428 917 vs raw 426 931 → **+1 986 (+0.47 %)**. At production parameters (64 MiB, t=3) the memory-hard loop dominates (~10⁹ instructions), so the fixed wrapper cost is ~10⁻⁴ % of a hash — ≈ 0 in the strictest measurable sense | **proven** (iai) |
| 8 | "the pepper is one extra `K` input to Argon2, also ≈ 0" | code: `Pepper` rides as the Argon2 secret/K parameter (`src/pepper.rs`, `argon2::Argon2::new_with_secret` path); inside the loop, not wrapper code | backed (code) |

## Presets / guarantees

| # | Claim | Artifact | Status |
|---|---|---|---|
| 9 | OWASP defaults: m=64 MiB, t=3, p=4, 32-byte output | `Argon2Params::default()` (`src/lib.rs`) | **proven** (code, exact values) |
| 10 | Low-memory preset: m=64 MiB, t=2, p=1 | `Argon2Params::low_memory()` | **proven** (code, exact values) |
| 11 | `#![forbid(unsafe_code)]` | attribute in `src/lib.rs` | **proven** (compiler) |
| 12 | Comparison table: OWASP defaults / salt gen / PHC / presets / pepper+rotation / strict verify vs raw argon2 | code — each row maps to a public API (`hash_password`, `verify_password_strict`, `Pepper`, `needs_rehash`) with unit tests | backed (code + tests) |
| 13 | bcrypt/scrypt benches "never ship with your build" | `Cargo.toml`: `bcrypt`/`scrypt`/`criterion` under `[dev-dependencies]` only | **proven** (manifest) |
| 14 | `verify_password_strict` returns Err on mismatch (vs `false`) | unit tests (`tests/pepper.rs`, `src/lib.rs`) | **proven** (test) |

## Totals

- **Proven by hard artifact (iai/code/compiler/manifest/test):** 7
  (claims 7, 9, 10, 11, 13, 14)
- **Backed (measured-on criterion records, code reading):** 7
- **Deleted/reworded:** 0

## Reproducing

```sh
cargo bench --bench hash_bench        # wall-clock table (production params)
cargo bench --bench iai_hot_path      # wrapper-vs-raw instruction gate (valgrind)
cargo test                            # correctness + strict-verify tests
```
