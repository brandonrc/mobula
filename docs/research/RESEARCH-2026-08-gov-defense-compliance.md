<!-- Research sweep 2026-08-16. Companion: compliance-isolation-gap-assessment.md (SOC 2 / PCI / ISO 27001 / tenancy patterns). -->

# Mobula — Government/Defense Compliance Gap Assessment (2026-08)

## 1. NIST SP 800-53 Rev 5

**Applies to Mobula: indirectly but binding in practice.** 800-53 is mandatory for federal systems under FISMA/RMF (SP 800-37); Mobula is software, not a federal system, but any government buyer will assess it as a component inside their authorization boundary. A defense deployment lands at Moderate (287 controls) or High (370). Current status: Rev 5 remains current; NIST issued Release 5.2.0 (Aug 2025) adding SA-15(13), SA-24, SI-2(7) — no baseline changes. ([SP 800-53 Rev 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), [SP 800-53B](https://csrc.nist.gov/pubs/sp/800/53/b/final), [5.2.0 news](https://csrc.nist.gov/News/2025/nist-releases-revision-to-sp-800-53-controls))

Controls that bite, with engineering implications:

**AC — Access Control**
- **AC-3 Access Enforcement** — enforcement in the mechanism for every access, not policy-by-convention. → Mobula's RBAC must be enforced server-side on every path, including proxy/controller channels — not UI hiding.
- **AC-6 Least Privilege** (+ enhancements 1/2/5/9/10). → Per-cluster K8s ServiceAccounts get minimal RoleBindings (no cluster-admin); privileged API ops need distinct privileged tokens; privileged-function use must be audit-logged.
- **AC-4 Information Flow Enforcement** — tenant A's jobs/data never cross into tenant B. → Namespaces alone are weak evidence; AC-4(4) points at NetworkPolicy per tenant.

**AU — Audit and Accountability**
- **AU-2 Event Logging** — defined auditable event taxonomy. → Document the event set (login, role grant, cluster create/delete, policy change) with rationale.
- **AU-6 Review & Analysis** (+ AU-6(1) automated). → Logging alone fails AU-6; Mobula needs SIEM export / anomaly alerting hooks.
- **AU-9 Protection of Audit Information** (+ AU-9(4) auditor-only access). → audit_events must be tamper-evident (hash chaining/WORM export) and readable only by an auditor role distinct from cluster admins. Plus AU-3 (record content), AU-12 (generation across all components incl. proxy).

**SC — Communications Protection**
- **SC-8 / SC-8(1) Transmission protection.** → "Partial TLS" is a finding: every hop — API↔proxy↔controller↔K8s API — needs TLS; High effectively forces mTLS.
- **SC-13 Cryptographic Protection** — FIPS-validated crypto. → Stock rustls/ring is not FIPS-validated; hard DoD gap (see §5).
- **SC-28 At-Rest Protection.** → Postgres (audit/policies/credentials) and K8s Secrets need at-rest encryption; secret material should move to KMS/external secrets.

**IA — Identification & Authentication**
- **IA-2(1)/(2) MFA** — in the Moderate baseline. → Keycloak OIDC satisfies if MFA enforced per realm; Mobula's local auth bypasses it — must be MFA-capable or documented break-glass-only.
- **IA-5 Authenticator Management.** → API tokens need issuance, rotation, expiry, revocation, strong hashing — never plaintext.
- **IA-8 Non-Organizational Users** — applies directly to tenant users. → Federate tenant identities (OIDC/SAML; CAC-PKI for DoD); shared local accounts are non-compliant.

**CM — Configuration Management**
- **CM-2/CM-6/CM-7** (baselines, STIG/CIS settings, least functionality). → Ship hardened default manifests, minimal exposed listeners, STIG-hardened base images; CM-8/CM-3 tie changes to the audit trail.

**SI — System Integrity**
- **SI-7 / SI-7(1) Integrity checks.** → Signed images + admission-time signature verification (cosign/Kyverno); integrity monitoring on the audit store. SI-2 flaw remediation → patch SLAs; SI-4 monitoring feeds.

**SA / SR — Acquisition & Supply Chain**
- **SA-11** (static analysis, threat/vuln testing) → SAST + fuzz/property tests on policy enforcement in CI, evidence retained. **SA-15** documented secure SDLC; **SA-17** security architecture spec (ARCHITECTURE.md/ADRs must be accreditation-grade).
- **SR family (new in Rev 5)**: SR-3/4/5/6/11 — mostly organization-level, but Mobula must supply artifacts: **SBOM for crates + images, signed releases, dependency provenance** (cargo-deny exists — extend to SBOM generation).

## 2. NIST SP 800-171 / CMMC

**Applies: indirectly.** Binds the deploying contractor's nonfederal system, not Mobula as a product — but if Mobula manages clusters touching CUI, it's in scope as a protection-providing component, audited control-by-control in the customer's SSP/SPRS score.

- **800-171 Rev 3 is final** (May 2024; 97 requirements/17 families), **but CMMC still enforces Rev 2's 110 requirements** per the DFARS 252.204-7012 class deviation — build against Rev 2 numbering today. ([800-171r3](https://csrc.nist.gov/pubs/sp/800/171/r3/final))
- **CMMC status (July 2026)**: Phase 2 (C3PAO certification) suspended; only Level 1/2 self-assessment designations active; 32 CFR Part 170 and DFARS -7021 remain in force; reform task force reports ~Sep 2026. ([DoD CIO CMMC](https://dodcio.defense.gov/CMMC/About/), [suspension analysis](https://www.governmentcontractslaw.com/2026/07/dod-suspends-cmmc-phase-2-what-happened-what-it-means-and-what-nobody-is-telling-you/))
- **Delta vs 800-53**: 800-171 is the Moderate-baseline subset for CUI confidentiality on nonfederal systems — drops availability (CP), PII (PT), federal program-management controls. Mobula's deliverable is evidence the customer cites.
- Concrete bites: **3.5.3 MFA** (local-auth fallback must not bypass — POA&M-blocking), **3.3.x audit** (synced timestamps, retention, separation of duties on audit access), **3.1.5–3.1.7 least privilege** (privileged calls RBAC-gated *and* logged), **3.1.10/11 device lock/session termination** (token expiry, idle logout — no evidence this exists on the local-auth path), **3.13.11 FIPS-validated crypto** (mandatory under Rev 2; biggest gap), **3.13.8** (partial TLS fails outright), **3.1.3 flow control** (NetworkPolicies per tenant namespace are required, not optional). MFA, FIPS, and audit protection are 5-point SPRS items — the expensive ones to lose.

## 3. FedRAMP

**Applies: no — not to self-hosted Mobula; indirectly otherwise.** FedRAMP covers only cloud services handling federal info *on behalf of* an agency; systems "only used for a single agency's operations, hosted on cloud infrastructure… and not offered as a shared service" are explicitly out of scope. ([M-24-15 scope](https://www.fedramp.gov/2026/authority/m-24-15/scope/))

- **Self-hosted Mobula** → the agency authorizes under RMF and issues its own ATO; Mobula is a component. Its job is to be *authorizable*, not authorized.
- **Mobula as a hosted multi-tenant service** → in scope, would need FedRAMP authorization.
- **What IS relevant**: running on FedRAMP-authorized IaaS/PaaS lets the agency inherit infrastructure controls; baselines are Rev 5-derived (Low 156 / Moderate 323 / High 410 controls) but sized for whole services, not components.
- **FedRAMP 20x** (active as of 2026): "Certification" replaces "Authorization", classes A/B/C/D replace tiers, machine-readable **Key Security Indicators** replace narrative SSPs, Rev 5 intake ends June 2027. ([fedramp.gov/20x](https://www.fedramp.gov/20x/)) → Engineering takeaway: expose posture as machine-readable evidence (OSCAL-friendly artifacts, automated scan/audit exports) — aligns with Mobula's existing API/CSV audit export.
- DoD workloads layer DISA CC SRG impact levels (IL2/IL4/IL5) on top of FedRAMP Moderate/High. ([DoD CC SRG](https://www.wbdg.org/files/pdfs/dod_cloudcomputing.pdf))

## 4. DISA STIGs

**Applies: yes (indirectly but binding).** STIGs are DISA configuration baselines mandatory on DoD networks, assessed rule-by-rule as CAT I/II/III findings. Mobula is assessed under the Application Security & Development STIG; because it *provisions clusters*, the **Kubernetes STIG (V2R6, 2026-04)** becomes a requirement on every cluster Mobula stands up.

What the Kubernetes STIG concretely requires ([STIG library](https://public.cyber.mil/stigs/), [V-ID cross-reference](https://documentation.ubuntu.com/canonical-kubernetes/latest/snap/reference/disa-stig-audit/)):
- TLS ≥1.2 on API server/scheduler/controller-manager/etcd (V-242376–380); `--authorization-mode=Node,RBAC` (V-242382); anonymous auth disabled on API server + kubelet (**CAT I**); basic/token auth disabled (OIDC/cert only).
- **V-242383 (CAT I)**: nothing user-managed in `default`/`kube-public` namespaces → Mobula's namespace-per-cluster model satisfies this; enforce it.
- **PodSecurity admission controller enabled** with explicit config (V-242437, CAT II) → Mobula must label tenant namespaces for Pod Security Standards enforce=baseline/restricted; Kueue admission is quota, not security admission.
- **etcd encryption-provider-config** (CNTR-K8-001162) → secrets encrypted at rest in every managed cluster.
- **V-242415 (CAT I)**: secrets never as env vars → audit how Mobula injects OIDC secrets/DB passwords; use mounted Secrets.
- API-server audit policy at RequestResponse with retention config (V-242402/403) → K8s-level auditing *in addition to* Mobula's own audit log.
- **CNTR-K8-002720 (CAT I)**: current IAVM patches → Mobula needs a cluster upgrade/patch pipeline, not just suspend/resume.

**ubi-micro → ubi9-stig** ([catalog entry](https://catalog.redhat.com/software/containers/ubi9/ubi-stig/68e7aca8a3801e04bcb7873b), [announcement](https://www.redhat.com/en/blog/introducing-red-hats-stig-hardened-ubi-nvidia-gpus-red-hat-openshift)): buys pre-remediated in-image RHEL 9 STIG controls (umask, file perms, crypto-policy defaults, removed setuid binaries) with OpenSCAP scan evidence — closing container-applicable RHEL 9 STIG findings before Mobula's layer is added = faster ATO. Does **not** buy: FIPS mode (a host-kernel + crypto-policy property), host-level rules (auditd/sshd/kernel params are N/A in containers), or anything for application-layer STIG findings. Tradeoff: ubi-stig is a full-ish base vs. micro — bigger attack surface; consider it only if DoD STIG-scan evidence outweighs minimalism.

## 5. FIPS 140-3

**Applies: indirectly but decisively.** FIPS 140-3 validates *modules*, not applications — Mobula can never be "FIPS certified," but SC-13/3.13.11 route the requirement through it: all cryptography must run inside a CMVP-validated module, and CMVP treats non-validated crypto as **"no protection… considered unprotected plaintext."** ([CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program), [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final))

- **Module vs platform**: the module is validated *on listed operational environments*. "Just linking OpenSSL on a FIPS host" is insufficient — only the OpenSSL FIPS Provider is the validated module (3.1.2 = 140-3 cert [#4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985)); 140-2 certs go Historical **2026-09-21**.
- **Rust path**: rustls 0.23 `fips` feature → `aws-lc-rs` fips → AWS-LC-FIPS module (certs #4816/#5429/#5298/#5314); `rustls::crypto::default_fips_provider().install_default()`. Caveats: **pin aws-lc-rs <1.18.0** (latest binds AWS-LC-FIPS 4.x, still "in Review"), static FIPS builds are Linux-only, build needs CMake+Go. Self-tests/integrity checks come free with the module; Mobula's job is wiring + fail-closed startup assertions (`ServerConfig::fips()`). ([rustls FIPS](https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html), [aws-lc-rs](https://github.com/aws/aws-lc-rs/blob/main/aws-lc-rs/README.md), [AWS-LC FIPS.md](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md))
- **Concrete Mobula gaps**: `ring` backend (never validated) on all TLS paths (axum ingress, reqwest/kube egress); `jsonwebtoken` via rust_crypto/ring (Ed25519 is **not** FIPS-approved — RS256/ES384 are); `bcrypt` for local auth is not an approved algorithm (prefer OIDC-only in FIPS deployments, or PBKDF2 via the validated module).

## 6. Multi-tenancy / tenant isolation

**Applies: indirectly — and the core finding holds: no NIST framework mandates a specific isolation mechanism.**

- **SP 800-144** discusses multi-tenancy risks (hypervisor compromise, side channels, residual data) but explicitly prescribes no mechanism — risk-based, org-defined. ([800-144](https://csrc.nist.gov/pubs/sp/800/144/final))
- **SP 800-125/125A** address the hypervisor layer, not applications. ([800-125](https://csrc.nist.gov/pubs/sp/800/125/final), [125A](https://csrc.nist.gov/pubs/sp/800/125/a/r1/final))
- **SP 800-190 (container security)** is what actually bites, since Mobula *is* orchestration-layer software: §4.3.1 least-privilege orchestrator admin access; **§4.3.4 — "only group containers with the same purpose, sensitivity, and threat posture on a single host OS kernel"** — the single most direct statement against namespace-only tenancy; §4.3.3 NetworkPolicy isolation between differing-sensitivity workloads; §4.1 image scanning/provenance; §4.2 registry TLS+auth. ([800-190](https://csrc.nist.gov/pubs/sp/800/190/final))
- Isolation requirements derive from **SC-39 process isolation** (containers/namespaces suffice per-process — no VM-per-tenant mandate), **AC-4/SC-7** flow control and boundary protection between tenant security domains (mechanism org-defined). ([SC-39](https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-39/))
- The only mechanism-picking source is the **DoD CC SRG**: IL2/IL4 accept logical separation; **IL5 requires physical separation** from non-federal tenants — an infrastructure requirement on hosting, not Mobula's code.
- "Soft/hard tenancy" is Kubernetes-community terminology (SIG Multi-tenancy), not NIST's. **Kueue quotas are admission/fairness controls — no framework counts them as isolation**, and assessors won't either.
- Hard(er) tenancy per this guidance: per-tenant namespaces + default-deny NetworkPolicy + per-namespace RBAC (minimum); **dedicated node pools (taints/labels) or separate clusters per sensitivity level** for anything above Low — so tenants of different sensitivity never share a kernel.

---

## Prioritized Top-10 Control Gaps

Given what Mobula already has (OIDC+local auth, scoped RBAC, append-only audit + export, partial TLS, Kueue quotas, namespace-per-cluster):

1. **SC-13 / 3.13.11 — non-FIPS crypto stack.** ring/rustls, jsonwebtoken, bcrypt are all non-validated. Add a `fips` Cargo feature (rustls-fips → aws-lc-rs, pinned to a certified module version) with fail-closed startup assertion. *Highest blocker for DoD; 5-point SPRS item.*
2. **SC-8 / 3.13.8 — partial TLS.** Every hop (API↔proxy↔controller↔K8s API, inter-cluster, registry pulls) encrypted; mTLS for internal control-plane channels at Moderate+.
3. **AU-9 / 3.3.x — audit tamper evidence & access separation.** Append-only persistence isn't enough: add hash chaining or WORM/immutable export, and restrict audit read/export to an auditor role distinct from cluster admins (separation of duties, 3.1.4).
4. **IA-2(1)/(2) / 3.5.3 — MFA gap on local auth.** Local accounts bypass IdP-enforced MFA. Either add MFA to local auth or gate it as documented break-glass, disabled by default in federal profiles. *POA&M-blocking under CMMC.*
5. **AC-4 / SC-7 / 800-190 §4.3.3 — no tenant network isolation.** Provision default-deny NetworkPolicy per tenant namespace; document tenant boundaries as the AC-4 mechanism. Kueue quotas don't count.
6. **SI-7 / 800-190 §4.1 — no image integrity enforcement.** Signed images (cosign) verified at admission; provenance gating on an approved registry for Ray images Mobula deploys.
7. **Kubernetes STIG posture on provisioned clusters.** Pod Security Standards labels on tenant namespaces (V-242437), etcd encryption-provider-config (CNTR-K8-001162), anonymous/basic/token auth disabled, API-server audit policy with retention — emit STIG-compliant clusters by default and add admission checks for the flags.
8. **SC-28 / 3.13.16 — at-rest protection.** Encrypt Postgres (audit/policy/credentials) and K8s Secrets; stop injecting secrets as env vars (**V-242415, CAT I** — mounted Secrets or external secrets store).
9. **AU-6 / AU-11 — audit review & retention.** SIEM export/alerting hooks, NTP-synced timestamps (03.03.07), configurable retention. Logging without review tooling fails AU-6 outright.
10. **SR family / SA-11 — supply-chain artifacts.** SBOM (CycloneDX) for crates + images, signed releases, SAST in CI with retained evidence — extend the existing cargo-deny setup. Needed for any ATO package and FedRAMP 20x's machine-readable evidence direction.

*Not on the list*: FedRAMP authorization itself (not applicable unless Mobula is sold as a hosted service) and STIG-hardened base images (nice-to-have; ubi9-stig trades attack surface for scan evidence).
