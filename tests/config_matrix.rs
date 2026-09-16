//! Config-knob behavior matrix for salting.
//!
//! Every public config knob must OBSERVABLY change behavior: the table
//! below pairs a default with an alternate value and asserts the observable
//! output differs. A knob that cannot change behavior is a bug (see
//! breaker's sliding_window_size incident).
//!
//! The observable channel for the Argon2 cost knobs is the PHC string
//! itself (`$argon2id$v=19$m=..,t=..,p=..$salt$hash`) — the params are
//! read back out of the stored hash, exactly what a verifier consumes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

// --- Argon2Params knobs (feature `argon2id`) ------------------------------

#[cfg(feature = "argon2id")]
mod argon2_knobs {
    use salting::Argon2Params;

    /// Cheap params for tests (verification bounds: m ≥ 8·p KiB).
    fn fast(memory_kib: u32, iterations: u32, parallelism: u32, output_len: usize) -> Argon2Params {
        Argon2Params {
            memory_kib,
            iterations,
            parallelism,
            output_len,
        }
    }

    /// Extract the `m=..,t=..,p=..` cost segment from a PHC string.
    ///
    /// `$argon2id$v=19$m=..,t=..,p=..$salt$hash` splits on `$` as
    /// `["", "argon2id", "v=19", <cost>, <salt>, <hash>]`.
    fn cost_segment(phc: &str) -> &str {
        let v19 = phc.split('$').nth(2).expect("PHC version segment");
        assert_eq!(phc.split('$').nth(1), Some("argon2id"));
        assert_eq!(v19, "v=19");
        phc.split('$').nth(3).expect("PHC cost segment")
    }

    /// The base64 hash segment (length is monotonic in `output_len`).
    fn hash_segment(phc: &str) -> &str {
        phc.split('$').nth(5).expect("PHC hash segment")
    }

    #[test]
    fn knob_memory_kib_is_encoded_in_the_phc_string() {
        let low = salting::hash_password_with_params("pw", &fast(256, 1, 1, 32)).unwrap();
        let high = salting::hash_password_with_params("pw", &fast(512, 1, 1, 32)).unwrap();
        assert_eq!(cost_segment(&low), "m=256,t=1,p=1");
        assert_eq!(cost_segment(&high), "m=512,t=1,p=1");
        assert_ne!(low, high);
    }
    #[test]
    fn knob_iterations_is_encoded_in_the_phc_string() {
        let low = salting::hash_password_with_params("pw", &fast(256, 1, 1, 32)).unwrap();
        let high = salting::hash_password_with_params("pw", &fast(256, 2, 1, 32)).unwrap();
        assert_eq!(cost_segment(&low), "m=256,t=1,p=1");
        assert_eq!(cost_segment(&high), "m=256,t=2,p=1");
    }

    #[test]
    fn knob_parallelism_is_encoded_in_the_phc_string() {
        let low = salting::hash_password_with_params("pw", &fast(256, 1, 1, 32)).unwrap();
        let high = salting::hash_password_with_params("pw", &fast(256, 1, 2, 32)).unwrap();
        assert_eq!(cost_segment(&low), "m=256,t=1,p=1");
        assert_eq!(cost_segment(&high), "m=256,t=1,p=2");
    }

    #[test]
    fn knob_output_len_changes_hash_length_and_verifies() {
        let short = salting::hash_password_with_params("pw", &fast(256, 1, 1, 16)).unwrap();
        let long = salting::hash_password_with_params("pw", &fast(256, 1, 1, 32)).unwrap();
        assert_ne!(short, long);
        assert_ne!(
            hash_segment(&short).len(),
            hash_segment(&long).len(),
            "output_len must change the emitted hash size"
        );
        // Both remain verifiable — the params travel in the PHC string.
        assert!(salting::verify_password("pw", &short).unwrap());
        assert!(salting::verify_password("pw", &long).unwrap());
        assert!(!salting::verify_password("nope", &short).unwrap());
    }

    #[test]
    fn knob_defaults_differ_from_low_memory_preset() {
        let default_hash = salting::hash_password("pw").unwrap();
        let preset_hash =
            salting::hash_password_with_params("pw", &Argon2Params::low_memory()).unwrap();
        let default = cost_segment(&default_hash);
        let preset = cost_segment(&preset_hash);
        assert_ne!(
            default, preset,
            "low_memory() preset must differ from OWASP defaults"
        );
    }

    #[test]
    fn hasher_with_params_flows_into_the_hash() {
        let custom = salting::Hasher::new().with_params(fast(256, 2, 1, 32));
        let hash = custom.hash("pw").unwrap();
        assert_eq!(cost_segment(&hash), "m=256,t=2,p=1");
        assert!(custom.verify("pw", &hash).unwrap());
    }
}

// --- Hasher pepper knobs (no feature gate): with_pepper /
//--- with_previous_pepper / accept_unpeppered must each observably change
//--- verify; needs_rehash flags exactly the non-current-pepper hashes.
//--- Fast test params keep this deterministic and quick (verification
//--- honors PHC-embedded params).

mod hasher_pepper_knobs {
    use salting::{Argon2Params, Hasher, Pepper};

    fn fast() -> Argon2Params {
        Argon2Params {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        }
    }

    fn pepper(tag: &[u8]) -> Pepper {
        Pepper::new(tag).unwrap()
    }

    fn hasher_with(pepper: Pepper) -> Hasher {
        Hasher::new().with_params(fast()).with_pepper(pepper)
    }

    #[test]
    fn knob_with_pepper_changes_what_verifies() {
        let a = pepper(b"pepper-a");
        let b = pepper(b"pepper-b");
        let hash = hasher_with(a.clone()).hash("pw").unwrap();

        // Same pepper verifies; a different pepper is a clean Ok(false).
        assert!(hasher_with(a).verify("pw", &hash).unwrap());
        assert!(!hasher_with(b).verify("pw", &hash).unwrap());
        // A peppered hash never verifies through the unpeppered construction.
        assert!(
            !Hasher::new()
                .with_params(fast())
                .verify("pw", &hash)
                .unwrap()
        );
        assert!(!salting::verify_password("pw", &hash).unwrap());
    }

    #[test]
    fn knob_with_previous_pepper_accepts_rotated_hashes() {
        let old = pepper(b"retired-pepper");
        let current = pepper(b"current-pepper");
        let legacy_hash = hasher_with(old.clone()).hash("pw").unwrap();

        // Rotation hasher accepts the old-pepper hash; current-only does not.
        let rotated = Hasher::new()
            .with_params(fast())
            .with_pepper(current.clone())
            .with_previous_pepper(old);
        assert!(rotated.verify("pw", &legacy_hash).unwrap());

        let current_only = hasher_with(current);
        assert!(!current_only.verify("pw", &legacy_hash).unwrap());
    }

    #[test]
    fn knob_accept_unpeppered_gates_legacy_hashes() {
        // Legacy hash: fast params, no pepper at all.
        let legacy = Hasher::new().with_params(fast()).hash("pw").unwrap();
        let gate = hasher_with(pepper(b"new-pepper"));

        assert!(
            !gate.verify("pw", &legacy).unwrap(),
            "default must reject legacy unpeppered hashes"
        );
        let migrating = Hasher::new()
            .with_params(fast())
            .with_pepper(pepper(b"new-pepper"))
            .accept_unpeppered(true);
        assert!(migrating.verify("pw", &legacy).unwrap());
        // ...but the gate still rejects wrong passwords even when open.
        assert!(!migrating.verify("nope", &legacy).unwrap());
    }

    #[test]
    fn needs_rehash_flags_exactly_the_non_current_hashes() {
        let current = pepper(b"current-pepper");
        let old = pepper(b"retired-pepper");
        let hasher = Hasher::new()
            .with_params(fast())
            .with_pepper(current.clone())
            .with_previous_pepper(old.clone())
            .accept_unpeppered(true);

        let fresh = hasher_with(current).hash("pw").unwrap();
        let stale = hasher_with(old).hash("pw").unwrap();
        let legacy = Hasher::new().with_params(fast()).hash("pw").unwrap();

        assert!(!hasher.needs_rehash("pw", &fresh).unwrap());
        assert!(hasher.needs_rehash("pw", &stale).unwrap());
        assert!(hasher.needs_rehash("pw", &legacy).unwrap());
        // Failed logins never signal rehash.
        assert!(!hasher.needs_rehash("nope", &stale).unwrap());
        assert!(!hasher.needs_rehash("nope", &fresh).unwrap());
    }

    #[test]
    fn cost_bounds_are_observable_through_the_hasher() {
        let hasher = hasher_with(pepper(b"bound-pepper"));
        let base = hasher.hash("pw").unwrap();
        assert!(hasher.verify("pw", &base).unwrap());

        // Over-bound m=999999 must fail closed before any Argon2 allocation.
        let forged = base.replacen("m=32,", "m=999999,", 1);
        assert_ne!(forged, base);
        assert!(matches!(
            hasher.verify("pw", &forged),
            Err(salting::PasswordError::ParamsExceeded { param: "m", .. })
        ));
    }

    #[test]
    fn pepper_length_knobs_are_observable() {
        let generated = Pepper::generate(salting::RECOMMENDED_PEPPER_LEN).unwrap();
        assert_eq!(generated.as_bytes().len(), salting::RECOMMENDED_PEPPER_LEN);
        // One byte over the bound is rejected with the bound reported.
        let too_big = vec![0x41u8; salting::MAX_PEPPER_LEN + 1];
        assert!(matches!(
            Pepper::new(too_big),
            Err(salting::PasswordError::PepperTooLong { .. })
        ));
        assert!(matches!(
            Pepper::generate(salting::MAX_PEPPER_LEN + 1),
            Err(salting::PasswordError::PepperTooLong { .. })
        ));
    }
}

// --- Policy knobs (feature `strength`) ------------------------------------

#[cfg(feature = "strength")]
mod policy_knobs {
    use salting::strength::Policy;

    /// `Bcdefghij123!` — 12 chars, upper+lower+digit, with `!` special.
    const OK_DEFAULT: &str = "Bcdefghij123!";

    #[test]
    fn knob_min_length_default_vs_configured() {
        let default = Policy::default();
        let tightened = Policy::default().min_length(24);

        assert!(default.check(OK_DEFAULT).is_ok());
        assert!(
            tightened.check(OK_DEFAULT).is_err(),
            "min_length 24 must reject a 12-char password that the default accepts"
        );
    }

    #[test]
    fn knob_special_chars_default_vs_configured() {
        let default = Policy::default();
        let restricted = Policy::default().special_chars("?");

        assert!(default.check(OK_DEFAULT).is_ok());
        assert_eq!(
            restricted.check(OK_DEFAULT),
            Err(salting::strength::PolicyError::MissingSpecialChar),
            "`!` is special under the default set but not under `?`"
        );
        assert!(restricted.check("Bcdefghij123?").is_ok());
    }

    #[test]
    fn knob_require_uppercase_default_vs_configured() {
        let default = Policy::default();
        let relaxed = Policy::default().require_uppercase(false);

        assert!(default.check("bcdefghij123!").is_err());
        assert!(relaxed.check("bcdefghij123!").is_ok());
    }

    #[test]
    fn knob_require_lowercase_default_vs_configured() {
        let default = Policy::default();
        let relaxed = Policy::default().require_lowercase(false);

        assert!(default.check("BCDEFGHIJ123!").is_err());
        assert!(relaxed.check("BCDEFGHIJ123!").is_ok());
    }

    #[test]
    fn knob_require_digit_default_vs_configured() {
        let default = Policy::default();
        let relaxed = Policy::default().require_digit(false);

        assert!(default.check("Bcdefghijabc!").is_err());
        assert!(relaxed.check("Bcdefghijabc!").is_ok());
    }

    #[test]
    fn knob_require_special_default_vs_configured() {
        let default = Policy::default();
        let relaxed = Policy::default().require_special(false);

        assert!(default.check("Bcdefghij123").is_err());
        assert!(relaxed.check("Bcdefghij123").is_ok());
    }
}
