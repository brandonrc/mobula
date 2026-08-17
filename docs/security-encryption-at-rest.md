# Encryption at rest

Deployment guidance for regulated environments (issue #60): what Mobula
persists, where, and how to get encryption at rest for each store — plus
which gaps are Mobula's own and which belong to the platform.

Scope note: at-rest encryption protects against *offline* attacks (stolen
disks, snapshots, dumps, backups, decommissioned media). It does nothing
against a live compromised control plane, which must be able to decrypt to
serve. The compensating controls — hash-not-encrypt for credentials, RBAC,
short-lived tokens, the audit trail — are covered in [ARCHITECTURE.md](ARCHITECTURE.md)
and [adr/0011](adr/0011-local-auth-opaque-tokens.md). The research backing
for this page is [research/compliance-isolation-gap-assessment.md §6](research/compliance-isolation-gap-assessment.md).

## Data inventory

Verified against the store schemas (`crates/mobula-controller/src/store_postgres.rs`,
`store_sqlite.rs` — identical tables), the local-auth routes
(`crates/mobula-api/src/local_auth.rs`), and the audit emitter
(`crates/mobula-api/src/audit.rs`).

| Store | What it holds | Sensitive fields | At-rest mechanism |
|---|---|---|---|
| Postgres control-plane DB (`--db postgres://…`, ADR-0004) | `clusters`, `pools`, `allocations` (specs as JSON text), `intents` (idempotency outbox), `jobs`, `usage_samples`, `control` (policy JSON), `role_assignments`, `audit_events`, `local_users`, `api_tokens` | `local_users.password_hash` and `api_tokens.token_hash` — **bcrypt hashes, never plaintext** (ADR-0011); user emails; audit subjects/paths; per-project usage. `ClusterSpec`/`PoolSpec` hold names, projects, images, resource quantities — no credentials (verified) | Volume/disk encryption or KMS-backed storage class; optional pgcrypto column-level; `sslmode=require` on the connection URL (in-transit) |
| SQLite local mode (`--db <path>`) | Same schema as Postgres, one file | Same as above | SQLCipher build, or full-disk encryption only. **Dev/demo grade** — do not run regulated workloads on it |
| Audit JSONL (`--audit-log <path>`) | Append-only JSONL export of every `mobula::audit` event (per-request gateway rows, authn/authz decisions) | Subjects, paths, deny reasons | Filesystem/volume encryption; ship off-box (see below) |
| K8s Secrets (deployment-side) | Ray cluster static tokens (injected via env per the registry's `auth_token_env` indirection, #57), OIDC client secrets (`MOBULA_CLIENT_SECRET`), the Postgres URL/password, `MOBULA_LOCAL_ADMIN_PASSWORD` | All of the above — these are the only plaintext credentials in the system | `EncryptionConfiguration` with a KMS provider (etcd-level); see below |
| Keycloak DB | Realm config, users, credentials, sessions | User credential hashes, client secrets | The demo stack (`deploy/docker-compose.auth.yml`) runs Keycloak `start-dev` with embedded H2 — **dev only**. A production Keycloak on Postgres takes the same guidance as the control-plane DB |
| Object-store job logs (future, #50) | Durable job/service logs captured cluster-side (REQUIREMENTS §3.7; not yet implemented) | Job output may contain tenant data | SSE-S3 / SSE-KMS (AWS), CMEK (GCS) bucket defaults when the feature lands |

## Per-store guidance

### Postgres (control plane and Keycloak)

Community Postgres has no built-in TDE, so layer it:

- **Baseline: volume/disk encryption.** LUKS on self-managed hosts, or the
  cloud default (EBS encryption, PD encryption) on managed instances. On
  managed Postgres (RDS, Cloud SQL, Azure Database) enable the KMS-backed
  storage encryption option with a customer-managed key so rotation and
  key-use audit land in your KMS, not the provider's.
- **Column-level for the most sensitive fields.** Mobula's own credential
  columns are already bcrypt hashes, so there is little left worth
  column-encrypting today; if you add replayable secrets later, use
  pgcrypto or application-level envelope encryption (see the gap list).
- **In-transit (note, not at-rest):** pass `sslmode=require` (or
  `verify-full` with a CA) in the `--db` URL. Mobula passes the URL
  through to sqlx unchanged; nothing forces TLS for you.
- **Backups inherit everything above.** Encrypt dumps/snapshots with a
  KMS-wrapped key and restrict restore permissions; backups are the
  classic theft vector.

### SQLite (local mode)

SQLite itself reads and writes plaintext pages. Options are an SQLCipher
build (not what Mobula links against — adopting it is a build change) or
full-disk encryption on the host. Treat local mode as dev/demo grade: the
demo compose stacks (`deploy/docker-compose*.yml`) exist to exercise the
API, not to hold regulated data.

### Audit JSONL files

`--audit-log` appends each audit event as a JSON line to a local file.
Two facts to plan around:

- The hash chain (#59) lives in the **store rows** (`audit_events.chain_hash`,
  verified by `GET /api/v1/audit/verify`); the JSONL export is a plain
  trace of the same events and is not itself chained.
- Even the chained store cannot detect deletion of the *newest* rows
  locally (api-v1.md §5.9). The answer is off-box export (#63): ship the
  JSONL (or store rows) to a remote, append-only destination — a SIEM, or
  object storage with object-lock/WORM retention — so tampering with the
  local trail is detectable by comparison.

Encrypt the volume the file sits on, but treat off-box export as the
integrity control, not encryption.

### Kubernetes Secrets

Mobula does not create Secret objects itself (verified: nothing in
`mobula-provision` writes Secrets); the secrets exist because your
deployment injects credentials as env vars — from Secret objects in any
real manifest. K8s Secrets are base64, not encryption, until you configure
the API server:

- Enable an `EncryptionConfiguration` for the `secrets` resource with the
  **`kms` v2 provider** (envelope encryption against AWS KMS, GCP KMS,
  Azure Key Vault, or Vault) — stable since K8s 1.29. Managed offerings
  (EKS, GKE, AKS) expose this as a cluster option backed by their KMS.
  Avoid `aescbc` (padding-oracle-prone, per the Kubernetes docs);
  `aesgcm`/`secretbox` are acceptable self-managed fallbacks.
- Rotate the KMS KEK on a documented schedule (the Kubernetes docs suggest
  at least every 90 days).
- Defense in depth: the Secrets Store CSI driver or External Secrets
  Operator keep plaintext out of etcd entirely for the highest-value
  secrets.

### Object-store job logs (when #50 lands)

Durable log capture is designed cluster-side into object storage
(PLAN.md S6). When provisioning the bucket/container: require SSE-KMS
with a customer-managed key on S3 (SSE-S3 is default-on since 2023 but
gives you no key control or key-use audit), or CMEK on GCS. Deny unencrypted
uploads via bucket policy so the control is enforced by the store, not by
the uploader.

## What Mobula itself must still do (the gap list)

Platform encryption covers the media; these items are Mobula's own
responsibility. Framed as recommendations tied to open issues:

1. **Column-level protection for any future replayable secret (#60).**
   Today every credential Mobula stores is verification-only and already
   bcrypt-hashed (`password_hash`, `token_hash`, ADR-0011) — the
   hash-not-encrypt posture is correct and should be kept. If a future
   feature must store a secret Mobula has to *replay* (e.g. tenant cloud
   credentials), it needs envelope encryption (AES-256-GCM DEK wrapped by
   a KMS/Vault KEK), not a plaintext column.
2. **Retire plaintext tokens in config (#57 follow-on).** The registry
   still accepts a literal `auth_token` next to the preferred
   `auth_token_env` indirection. Recommend deprecating the literal field in
   favor of env/secret-store references so no Ray token ever sits in a
   file.
3. **Keep secrets out of audit payloads.** Audit events currently carry
   subject, action, path, status, and roles — no credential material
   (verified in `crates/mobula-api/src/audit.rs`). There is no automated
   guard; recommend a redaction test/lint so future audit sites can't
   regress this.
4. **Document key-rotation runbooks (#60).** KMS KEK rotation for etcd and
   buckets, Postgres volume-key rotation, and the bootstrap-admin password
   written 0600 next to the DB on first boot (ADR-0011) all need
   operator-facing rotation/compromise procedures.
5. **Off-box audit export (#63).** Until the export ships to a WORM
   destination, newest-row deletion is undetectable; closing #63 is the
   integrity half of the at-rest story.

## Compliance mapping

High-level only; the full treatment is
[research/compliance-isolation-gap-assessment.md](research/compliance-isolation-gap-assessment.md)
and [research/RESEARCH-2026-08-gov-defense-compliance.md](research/RESEARCH-2026-08-gov-defense-compliance.md).

- **NIST SP 800-53 SC-28 (Protection of Information at Rest).** The
  per-store mechanisms above are the SC-28 story: encrypted storage for
  the control-plane DB and audit trail, KMS-backed etcd encryption for
  Secrets, bucket-level SSE for logs. Mobula's hash-not-encrypt credential
  columns reduce what SC-28 has to cover.
- **SOC 2 CC6 (Logical and Physical Access).** At-rest encryption is CC6.1
  evidence (protecting stored data commensurate with risk); the
  availability/auditability side is served by the hash-chained trail and
  `audit_read` rows (#59). The organizational remainder — key custody,
  rotation schedules, restore testing — belongs to the operator.
- **FIPS 140-3.** Where a validated cryptographic module is required, the
  at-rest mechanisms must run on validated modules (cloud KMS/HSM-backed
  storage encryption qualifies by inheritance; verify your provider's
  certificate scope). Note Mobula's own crypto posture is **not** FIPS:
  bcrypt is not a FIPS-approved algorithm, and the `ring` TLS/JWT backend
  is not validated — prefer OIDC-only auth in FIPS-scoped deployments
  (see the gov/defense research doc for details).
