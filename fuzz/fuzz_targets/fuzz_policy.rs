#![no_main]

use libfuzzer_sys::fuzz_target;
use salting::strength::{Policy, check_password, strength};

fuzz_target!(|data: &[u8]| {
    let password = String::from_utf8_lossy(data);

    // Default policy plus a couple of builder-derived variants driven by the
    // input, so both permissive and strict configurations are exercised.
    let default_policy = Policy::default();
    let relaxed = Policy::default()
        .min_length(data.first().map_or(0, |b| (*b % 8) as usize))
        .require_uppercase(false)
        .require_special(false);
    let strict = Policy::default()
        .min_length(usize::MAX);

    for policy in [&default_policy, &relaxed, &strict] {
        let _ = policy.check(&password);
    }

    // `strength` is documented never-fail; the score is documented 0..=4.
    // Violating either invariant is a bug the harness must surface.
    let s = strength(&password, &[]);
    assert!(s.score <= 4, "strength score out of documented range: {}", s.score);

    let s2 = strength(&password, &[&password]);
    assert!(s2.score <= 4);

    // Policy first, then strength — both layers with arbitrary input.
    let _ = check_password(&password, &default_policy, &[&password]);
});
