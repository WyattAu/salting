# Pepper Management Guide

Operational guidance for the [`Pepper`](../src/pepper.rs) type in `salting`
≥ 1.2: generating a server-side pepper, storing it (env var vs. KMS/HSM),
retrieving it at boot from AWS KMS, GCP KMS, or HashiCorp Vault, and
rotating it without locking users out.

> **Threat boundary (read this first).** A pepper protects passwords when
> **only the database leaks** — the single most common breach shape. Peppered
> hashes are worthless for offline cracking without the pepper, because every
> guess needs a full Argon2 run keyed by a secret the exfiltrated DB does not
> contain. A pepper does **not** protect against full-server compromise: an
> attacker who can read the process environment, the host filesystem, or the
> KMS credentials of the app role gets the pepper too. Keep the pepper's
> blast radius smaller than the database's: least-privilege KMS policy,
> no pepper in config files next to DB credentials, no pepper in source.

## Storage options

| Option | Protects against | Trade-offs | Use when |
|---|---|---|---|
| Env var (plain) | DB-only exfiltration | Simple; visible to host users with proc/env access, container inspection, crash dumps | Most deployments; server is otherwise hardened |
| Secrets manager (Secrets Manager, Secret Manager, Vault KV) | DB-only exfiltration + accidental config/env leaks | Extra service dependency; audit log of reads; easy rotation metadata | Compliance requirements; multi-tenant hosts |
| KMS-wrapped data key (envelope) | DB-only exfiltration; pepper never in plaintext at rest | One extra API call at boot (cache the result in memory only) | Strongest audit + rotation story |
| HSM / KMS key directly | DB-only exfiltration; plaintext pepper never leaves hardware | Latency per hash unless you wrap at boot; HSM does not hold Argon2 state — use it to decrypt/wrap the pepper, not to compute | Regulated environments |

Rule of thumb: the pepper must be *at least as hard to get* as a dump of
your database, and *easier to rotate* than every user's password.

## Generating a pepper

32 random bytes ([`RECOMMENDED_PEPPER_LEN`]):

```bash
openssl rand -base64 32
```

or in-process (persist it to your secret store **before** first use — a
pepper that only exists in one process's memory cannot verify tomorrow's
logins):

```rust
use salting::{Pepper, RECOMMENDED_PEPPER_LEN};

let pepper = Pepper::generate(RECOMMENDED_PEPPER_LEN)?;
// -> persist pepper.as_bytes() to your secret store, then drop it
```

## AWS KMS

Pattern: a KMS-managed data key wraps the pepper ("envelope encryption").
The pepper plaintext exists only in process memory at boot.

```rust
// cfg-gate this OUT of your crate deps if you prefer; this is app-side
// code (aws-sdk-kms = "1", tokio). salting itself has no cloud deps.
use aws_sdk_kms::Client as Kms;

async fn load_pepper_aws(kms: &Kms, bucket: &str, key: &str, encrypted: &[u8]) -> anyhow::Result<salting::Pepper> {
    // 1. Fetch the KMS-wrapped pepper blob (S3 / Secrets Manager / DB meta).
    //    Here: assume `encrypted` bytes came from Secrets Manager.
    // 2. Decrypt via KMS. IAM policy: kms:Decrypt limited to the CMK ARN.
    let out = kms.decrypt().ciphertext_blob(encrypted.to_vec()).send().await?;
    let plaintext = out.plaintext().unwrap_or_default();

    // 3. Wrap immediately; zeroized on drop by salting.
    Ok(salting::Pepper::new(plaintext.to_vec())?)
}
```

Alternatives:

- **AWS Secrets Manager** holds the pepper directly:

  ```rust
  let secret = asm.get_secret_value().secret_id("salting/pepper").send().await?;
  let pepper = salting::Pepper::new(secret.secret_string().unwrap_or_default().as_bytes().to_vec())?;
  ```

- **SSM Parameter Store** with `SecureString` works the same way for
  smaller setups.

IAM sketch (least privilege):

```json
{
  "Effect": "Allow",
  "Action": ["kms:Decrypt"],
  "Resource": "arn:aws:kms:us-east-1:123456789012:key/<cmk-id>"
}
```

## GCP KMS

```rust
// app-side deps: google-cloud-kms = "0.x" (or REST via reqwest + OAuth)
async fn load_pepper_gcp(client: &KmsClient, name: String, ciphertext: Vec<u8>) -> Result<salting::Pepper> {
    // Decrypt the wrapped pepper. Service account needs
    // roles/cloudkms.cryptoKeyDecrypter on this key only.
    let resp = client.decrypt(DecryptRequest { name, ciphertext, .. }).await?;
    Ok(salting::Pepper::new(resp.plaintext)?)
}
```

Alternatives:

- **Secret Manager** (`projects/*/secrets/salting-pepper/versions/latest`)
  with the Secret Manager Secret Accessor role on the app's service
  account.
- Pepper stored **wrapped by GCS CMEK**: object encrypted with a
  customer-managed key; reading the bucket requires the KMS decrypt
  permission — the pepper never sits in plaintext storage.

## HashiCorp Vault

```rust
// app-side dep: vaultrs = "0.x"
async fn load_pepper_vault(client: &VaultClient, mount: &str, path: &str) -> Result<salting::Pepper> {
    // KV-v2 secret written with: vault kv put secret/salting pepper=$(openssl rand -base64 32)
    let secret = vaultrs::kv2::read(client, mount, path).await?;
    let value: String = secret.get("pepper").cloned().unwrap_or_default();
    Ok(salting::Pepper::new(value.into_bytes())?)
}
```

Hardening: short TTL on the AppRole/agent token, response-wrapped secret
delivery if the host is not fully trusted, and audit device enabled (every
pepper read is logged).

## Boot flow (all providers)

1. Fetch/decrypt the pepper **once at startup**; hold it only as
   `salting::Pepper` (zeroized on drop) inside your long-lived
   `Hasher`. Never cache it in config, telemetry, or structured logs —
   `Pepper`'s `Debug` impl is redacted to keep this survivable.
2. Build the app state: `Hasher::new().with_pepper(pepper)`.
3. Optionally add `.with_previous_pepper(old)` during a rotation, and
   `.accept_unpeppered(true)` when adopting peppers for the first time.
4. On login success, consult `Hasher::needs_rehash` and rehash-on-login
   to move accounts onto the current pepper.

## Rotation runbook

Goal: replace pepper *A* with pepper *B* with zero user-visible impact.
Cost model: until each account rehashes, its login does two Argon2
verifies (B, then A) — schedule the rollout at your normal traffic
low-tide.

1. **Mint B** (32 random bytes) in the same secret store as A; grant the
   app's runtime role access to B (and keep A readable — you still need
   it to verify old-cohort logins).
2. **Deploy** the app with:

   ```rust
   let hasher = Hasher::new()
       .with_pepper(b)               // new hashes + tried first
       .with_previous_pepper(a);     // old-cohort logins keep working
   ```

3. **Rehash-on-login** (no mass migration outage):

   ```rust
   if hasher.verify(password, &stored)? && hasher.needs_rehash(password, &stored)? {
       let upgraded = hasher.hash(password)?; // write back to the DB
   }
   ```

4. **Monitor** the legacy cohort: count logins where `needs_rehash` is
   true. When it stops firing for real traffic (dormant accounts: force a
   rehash on next login or expire per your policy), continue.
5. **Retire A**: remove `.with_previous_pepper(a)` from the config,
   revoke the app role's read on A, then destroy the secret per your
   store's policy. Every stored hash now verifies only under B.

Migration from a pre-pepper deployment (salting ≤ 1.1 hashes) is the same
runbook with `.accept_unpeppered(true)` in step 2 and dropped in step 5.

## Incident note: pepper suspected compromised

A leaked pepper degrades you to unpeppered-Argon2 security (still far
better than unsalted/fast hashes). Do the rotation runbook **and** treat
the DB as crackable-with-effort: raise `Argon2Params` for the new hashes
and consider forced password resets for high-value accounts. A leaked
pepper alone is not grounds for panic; a leaked pepper *plus* a DB dump
is.
