#![no_main]

use libfuzzer_sys::fuzz_target;

/// True when the PHC string embeds Argon2 cost parameters too large to run
/// in-process (m up to 4 GiB blocks, t up to 2^32 iterations). Those inputs
/// would abort on allocation failure or hang instead of returning `Err`, so
/// the harness skips them; everything else — including every malformed PHC
/// string — still goes through `verify_password`'s parser.
fn excessive_cost(hash: &str) -> bool {
    for seg in hash.split('$') {
        for kv in seg.split(',') {
            if let Some(v) = kv.strip_prefix("m=") {
                if v.parse::<u64>().map(|m| m > 65536).unwrap_or(false) {
                    return true;
                }
            }
            if let Some(v) = kv.strip_prefix("t=") {
                if v.parse::<u64>().map(|t| t > 64).unwrap_or(false) {
                    return true;
                }
            }
            if let Some(v) = kv.strip_prefix("p=") {
                if v.parse::<u64>().map(|p| p > 16).unwrap_or(false) {
                    return true;
                }
            }
        }
    }
    false
}

fuzz_target!(|data: &[u8]| {
    // Bound input so PHC parsing stays fast.
    let data = &data[..data.len().min(1024)];
    let mid = data.len() / 2;
    let hash = String::from_utf8_lossy(&data[..mid]);
    let password = String::from_utf8_lossy(&data[mid..]);

    if excessive_cost(&hash) {
        return;
    }

    // Malformed or adversarial hash strings must return Err, never panic.
    let _ = salting::verify_password(&password, &hash);
    let _ = salting::verify_password_strict(&password, &hash);
});
