# Credential delivery to workers, and the shared-vs-object storage split

Date: 2026-08-21. Answers the questions posed in #73, with a recommendation per question, for the follow-up architecture meeting. Context: the Ray architecture discussion (18 Aug 2026) identified three transfer problems — environments, credentials, data — of which this doc covers the second and third. Environments are covered in `environments-and-reproducibility.md` and the recipe ADR (#79).

## Part I — Credentials

### The principle (one sentence)

Mobula never sees, stores, or transports a credential value; it grants **named references** to credentials that the platform delivers directly into pods.

A `ClusterSpec` is persisted in the store, echoed by the API, and hashed into the audit chain — so a value in a spec is a value leaked to three places. The mechanism that makes references safe already exists: the pod-shaping catalog (#66 / PR #75), where the platform declares what exists, the caller picks by name, and the resolved grant is frozen at admission. Credentials are **additional catalog volume-source types**, not a new subsystem.

### Q1: Workload identity vs mounted secrets — and the fallback story

**Recommendation: three tiers, all expressed as catalog entry types, chosen per deployment.**

| Tier | Mechanism | When |
|---|---|---|
| 1 (preferred) | **Cloud workload identity** — pod's projected ServiceAccount token federated to IRSA / GKE WIF / Azure MI. Catalog entry names a `service_account`; the cloud IAM binding is infra-owned. No secret material exists anywhere. | Cloud deployments. REQUIREMENTS §3.8's stated preference. |
| 2 | **CSI secret injection** — catalog volume-source of type `csi` (SecretProviderClass: Vault, AWS/GCP/Azure secret stores). Values go tmpfs-file into the pod; rotation is the provider's job. | On-prem with a secret manager; the JATIC/Mystic "credential manager" discussion lands here when it lands. |
| 3 (floor) | **Kubernetes Secret mount** — catalog volume-source of type `secret` naming an existing K8s Secret in the cluster namespace. | Standalone / air-gapped / dev-stack. Acceptable because K8s Secrets + etcd encryption at rest (docs/security-encryption-at-rest.md) is the platform baseline; unacceptable to *block* standalone on tiers 1–2. |

Fallback is a deployment posture, not a runtime cascade: an admin configures which tiers the catalog may contain; Mobula does not silently degrade from tier 1 to tier 3.

**Env-var credentials are refused.** `RESERVED_ENV` already blocks caller-set sensitive vars; we extend the rule: catalog entries never materialize secrets as env vars (they leak via `ray.util.state`, logs, and crash dumps). Ray code reads files or uses the SDK default-credential chain, which honors both tier 1 and mounted files.

### Q2: Where do secret references live in `ClusterSpec`?

**Nowhere new.** `pod.mounts = ["s3-team-a"]` (a catalog name) and `pod_resolved` (the frozen grant) are the entire wire surface — identical to how PVC mounts work post-#75. No `secret_ref` field. The spec stays value-free by construction, and the smuggling test from PR #75 extends to credential-typed entries.

### Q3: Who grants which project access to which credential?

The same policy surface as everything else: catalog entries carry a `projects` allowlist, edited via `PUT /api/v1/settings/policy` (Admin), audited (`update_policy`), never retroactive (grants freeze at admission; edits apply on re-submit). When scoped RBAC (#49) lands, "may reference entry X" becomes a binding under the ADR-0009 model with `target = credential-entry`, and the PR #75 "Admin can grant any PVC" caveat gets the same `mountable_claims`-style boot-time bound if the first real deployment needs it.

### Q4: The standalone answer

Tier 3 **is** the standalone answer, and `SecretStore` (named in REQUIREMENTS §2/§4, currently unimplemented) gets exactly one v0 implementation: a validator that a referenced K8s Secret / ServiceAccount exists at admission — fail at create, not at pod start. `SecretStore` is *not* a value store; recommend renaming the trait `CredentialCatalog` when implemented to kill the ambiguity.

### Q5: One mechanism or two, vs the Ray-token indirection?

**Two mechanisms, one principle.** Northbound Ray cluster tokens (what Mobula brokers per ADR-0003) are Mobula-owned secrets with their own indirection (`auth_token_env`). Southbound workload credentials (what *user code* uses to reach S3/databases) are platform-delivered and Mobula-invisible. Unifying them would make Mobula a secret store — the thing this design exists to avoid. Non-goal confirmed: no rotation machinery in v0; tiers 1–2 make rotation the provider's job, which is the design not precluding it.

## Part II — Storage

### The split (naming from the meeting)

Two storage classes with different physics, configured separately and never conflated:

- **Shared (volume) storage** — RWX filesystem mounts (home + project dirs). For experimentation, config files, small file I/O, POSIX-only formats (SQLite, GDB). The decided interim path: home dirs mounted on workers via the pod-shaping catalog. Ships in M1.
- **Object storage** — S3-compatible. For distributed datasets, checkpoints, and durable job logs (#50). The correct path at scale; not yet implemented anywhere in Mobula.

### Q6: Per-project object-store defaults

Add an `[object_store]` policy section per project: `endpoint`, `bucket`, `prefix`, `credential` (a catalog entry name from Part I), `region`, `force_path_style`. At admission Mobula injects the *non-secret* parts as standard env (`AWS_ENDPOINT_URL`, `AWS_DEFAULT_REGION`…) and the credential arrives via its catalog tier. "Use object storage" becomes a selection, not a wiring exercise, and #50's durable job logs consume the same section — one config, resolved once. This is the storage analog of the price sheet: policy-store data, live-editable, audited.

### Q7: The shared-FS guardrail — a number, not a verbal caveat

The failure mode on record: ~100–400 users each launching ~10-worker clusters against one NFS/EFS share collapsed aggregate IOPS, twice, including on provisioned-IOPS EFS. The risk is **aggregate mounts across the deployment**, not one cluster's size, so the guardrail has two knobs in `[storage]` policy:

- `shared_fs_warn_workers = 8` — create succeeds; response and UI carry a warning that shared-FS is not a distributed-data path.
- `shared_fs_max_workers = 32` — create refused (409, same admission surface as quota) when the cluster mounts shared storage and exceeds this; Admin-overridable per project.
- Defaults are deliberately conservative and deployment-tunable; the *number* matters less than the refusal existing. Document Dharhas's incident as the rationale string in the policy file comment.

### Q8: Warn, throttle, or refuse?

**Warn at the soft line, refuse at the hard line, never throttle.** Throttling filesystem I/O from a control plane that is deliberately out of the data path (REQUIREMENTS §"control/data split") is a lie we can't enforce; admission is the only honest lever Mobula owns.

## What this unblocks, in order

1. **Now (Mobula-only):** credential catalog entry types `secret` + `service_account` validation (tier 3 floor), `[object_store]` + `[storage]` policy sections, guardrail admission checks, env injection of non-secret object-store config.
2. **Needs decisions:** tier 1/2 availability per deployment (infra), the guardrail default numbers (this meeting), credential-manager product if any (explicitly *not* this doc's call — the shape is decided, the product is not).
3. **Needs NIC:** RWX StorageClass for home/project dirs across namespaces (Longhorn research), cloud IAM bindings for tier 1, Vault/CSI driver install for tier 2.

## Acceptance mapping (#73)

- Design doc with a recommendation per question — this document.
- ADR for the credential mechanism once the group agrees — draft after the meeting; the decision to ratify is Part I's principle + the three tiers.
- Follow-up implementation issues — file against M3/M5 per the "what this unblocks" list once accepted.
