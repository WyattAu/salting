> **only the database leaks**; the single most common breach shape. Peppered
| HSM / KMS key directly | DB-only exfiltration; plaintext pepper never leaves hardware | Latency per hash unless you wrap at boot; HSM does not hold Argon2 state; use it to decrypt/wrap the pepper, not to compute | Regulated environments |
or in-process (persist it to your secret store **before** first use; a
  permission; the pepper never sits in plaintext storage.
   `Hasher`. Never cache it in config, telemetry, or structured logs -
verifies (B, then A); schedule the rollout at your normal traffic
   app's runtime role access to B (and keep A readable; you still need