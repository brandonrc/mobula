# Compliance & Isolation Gap Assessment — Mobula

Date: 2026-08. Scope: commercial readiness of Mobula (open-source Rust control plane managing multi-tenant Ray clusters on Kubernetes) against SOC 2, PCI DSS 4.0.1 (as benchmark), ISO 27001:2022, plus multi-tenant isolation, Keycloak hardening, and encryption-at-rest patterns.

**Assumed current state** (per brief): OIDC + local auth with opaque revocable tokens; project-scoped RBAC; append-only audit log with export; Kueue quota-based admission; cluster-per-tenant compute isolation; demo-mode (unhardened) Keycloak; tokens in TOML config (documented); no at-rest encryption story; no NetworkPolicy enforcement story.

---

## 1. SOC 2 (Trust Services Criteria)

The governing document is AICPA TSP Section 100, "2017 Trust Services Criteria (With Revised Points of Focus — 2022)" ([AICPA download page](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022); readable [mirror](https://gccertification.com/wp-content/uploads/2024/06/AICPA-TSP-Section-100-Trust-Services-Criteria-2022.pdf)). Three structural facts frame everything:

- The TSC are **principles-based, not a control catalog** — each entity designs its own controls; points of focus are aids, not checklist items (TSP 100 ¶.03, ¶.07). Security (CC1–CC9) is the only mandatory TSC category ([Linford & Co](https://linfordco.com/blog/soc-2-security-criteria-principle/)).
- The 2022 revision changed **no criterion text**, only points of focus ([AICPA red-line](https://www.aicpa-cima.com/resources/download/trust-services-criteria-see-what-has-changed)).
- A SOC 2 report covers the **service organization operating the system**, not the codebase. For an open-source vendor, the system description will include the Mobula codebase, build pipeline, and deployed infrastructure.

### 1.1 What the criteria demand

**CC3 (risk assessment)** — documented, cross-functional risk register with likelihood×impact scoring, owners, mitigations, refreshed on change ([Linford & Co](https://linfordco.com/blog/soc-2-risk-assessment-criteria/)). ~95% organizational. *Mobula's role: emit the telemetry that feeds it; its own multi-tenant risk surface is what the register must cover.*

**CC5 (control activities)** — CC5.2 "general controls over technology" is where a software vendor's SDLC, infrastructure access, and the product's own security capabilities land; CC5.3 demands the written policy portfolio (infosec, access control, change management, incident response, vendor management) ([Bitlion](https://bitlionai.com/framework/soc-type-2-system-and-organization-controls-type-2/cc5-control-activities)).

**CC6 (logical & physical access)** — per official wording ([Hicomply](https://www.hicomply.com/hub/soc-2-controls-cc6-logical-and-physical-access-controls), [soc2auditors.org](https://soc2auditors.org/insights/soc-2-security-controls/)):
- CC6.1: logical access security software/architecture — authN appropriate to risk, credential lifecycle, boundary protection.
- CC6.2: register/authorize users **before** issuing credentials; revoke when no longer authorized.
- CC6.3: role-based access, **least privilege, segregation of duties**.
- CC6.4/6.5: physical access + media decommissioning — inherited from the cloud provider's SOC 2 report for hosted SaaS.
- CC6.6: boundary defense — firewalls, segmentation, IDS/WAF, zero-trust remote access.
- CC6.7: transmission protection — TLS everywhere, no unencrypted export paths.
- CC6.8: malware prevention/detection — EDR, patch SLAs, image scanning.

**CC7 (system operations)** — CC7.1 detect configuration changes that introduce vulnerabilities + newly discovered vulnerabilities; CC7.2 monitor for anomalies; CC7.3 evaluate events → incidents; CC7.4 incident response program; CC7.5 recovery ([soc2auditors.org](https://soc2auditors.org/insights/soc-2-security-controls/)).

**CC8.1 (change management)** — verbatim: "authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures" ([soc2auditors.org](https://soc2auditors.org/insights/soc-2-change-management-controls/)). Requires segregation of duties (author ≠ approver/deployer) and a documented emergency/break-glass path with retroactive documentation.

### 1.2 Software vs organizational — the split

| Criterion | Software must support | Organizational process |
|---|---|---|
| CC3 | Telemetry emission | Risk register, assessments |
| CC5.2 | AuthN/Z, audit logging, encryption as product features | SDLC policy, infra access policy |
| CC6.1–6.3 | OIDC/SSO, MFA **enforced at IdP**, least-privilege RBAC, per-user attributable credentials (incl. service accounts), revocation within SLA | Access request/approval workflow, **quarterly access reviews** with dated artifacts, joiner/mover/leaver |
| CC6.6/6.7 | Network boundary controls, TLS everywhere, segmentation | Firewall rule reviews, remote-access policy |
| CC7.1/7.2 | Security event logs, config-change detection hooks, vuln scanning of shipped artifacts | SIEM operation, alert triage, on-call |
| CC7.3–7.5 | — | Severity matrix, IRP, tabletop exercises, post-incident reviews |
| CC8.1 | Attributable config/policy changes in the product (Mobula's store-backed policy API + audit trail qualifies) | PR review enforcement, CI gates, emergency-change docs |

Note for 2026-era audits: auditors now test **non-human/service/AI-agent identities** under CC6 (distinct attributable identities, scoped short-lived credentials) — directly relevant since a K8s control plane is dense with service accounts ([soc2auditors.org](https://soc2auditors.org/insights/soc-2-security-controls/), [accorppartners](https://accorppartners.com/blogs/risk-assurance/soc-2/soc-2-for-ai-companies-in-2026-what-auditors-test-that-didn-t-exist-two-years-ago)).

### 1.3 Evidence artifacts an auditor expects

- **Audit logs** answering "who did what, when, from where, did it succeed" — tamper-resistant, centralized, retained across the full Type 2 observation window (6–12 months); auditors sample the alert→ticket→resolution chain ([ssojet](https://ssojet.com/blog/soc-2-enterprise-sso-what-auditors-check), [processfinder](https://processfinder.ai/learn/soc-2-logging-requirements)).
- **Access reviews**: quarterly exports naming reviewer, population, decisions, remediations; sampled joiner/mover/leaver tickets showing approval-before-provisioning and timely revocation ([dsalta](https://www.dsalta.com/resources/soc-2/soc-2-audit-evidence-artifacts-collection-checklist)).
- **Change records**: PRs with reviewer approvals, CI logs proving tests passed pre-deploy, deployment logs with deployer identity; Type 2 sampling of 25–50 changes with **zero exceptions tolerated**; screenshots increasingly rejected in favor of exported configs/CI logs ([soc2auditors.org](https://soc2auditors.org/insights/soc-2-change-management-controls/)).
- Vulnerability scan reports + remediation tickets against SLAs; pentest report (not named in TSC but expected in practice, ≥1 per Type 2 window, with retest evidence) ([CodeAnt AI](https://codeant.ai/blogs/compliance-automation-vs-penetration-testing-soc-2)).
- IdP config exports showing MFA enforcement; cloud provider SOC 2 report (CC6.4 inheritance); EDR/MDM coverage reports.

**Concrete engineering implication for Mobula:** the product's SOC 2 contribution concentrates in CC6.1/6.6/6.7 (authN/Z, boundary, encryption), CC7.1/7.2 (telemetry + tamper-evident audit), and CC8-adjacent change attribution. The audit log must be verifiably immutable, retention-configurable to ≥12 months, and exportable in a form auditors can sample. Everything else — access reviews, IRP, pentests, vendor management of Keycloak/Kueue/cloud dependencies — is the operator's process; Mobula's docs should state this boundary explicitly.

---

## 2. PCI DSS 4.0.1 (as engineering benchmark)

**Version status:** v4.0 retired 2024-12-31; v4.0.1 (June 2024, clarifications only) is the sole active version; all future-dated items became mandatory after **2025-03-31** ([PCI SSC Summary of Changes](https://www.pcisecuritystandards.org/documents/PCI-DSS-v3-2-1-to-v4-0-Summary-of-Changes-r1.pdf), [Delinea](https://delinea.com/blog/pci-dss-4.0.1-and-identity-security-compliance-requirements)).

### 2.1 Scope boundary — confirmed

PCI DSS is a **contractual standard** enforced by card brands, applying to any entity that stores, processes, or transmits cardholder data. The CDE includes systems that don't touch CHD but have **unrestricted connectivity** to, or **could impact the security of**, systems that do ([PCI DSS v4.0.1 text, hosted copy](https://www.middlebury.edu/sites/default/files/2025-01/PCI-DSS-v4_0_1.pdf?fv=AKHVQBp6)).

**For Mobula:** not applicable unless a Mobula-managed cluster or the control plane itself touches cardholder data — **but** if Mobula manages a tenant's CDE workloads, the control plane falls into scope under the "could impact the security of" clause. Worth one sentence in customer-facing docs.

### 2.2 Requirement 7 (least privilege) as engineering requirements

- Access control model covering **all** system components, deny-all default (7.2.x); access per job function (7.2.1); approved before grant (7.2.3).
- **7.2.4** (now mandatory): periodic review of all user accounts and privileges.
- **7.2.5 / 7.2.5.1** (now mandatory): application/system accounts assigned, managed, and periodically reviewed.
([Genesys v4.0.1 requirement matrix](https://help.mypurecloud.com/wp-content/uploads/2025/02/pci-dss-requirements-v4.0.1.pdf))

**Implication for Mobula:** deny-by-default authorization server-side on every request; a first-class **access-review export** (who has what role in which project, when granted, by whom) — this doubles as SOC 2 CC6.3 evidence. Service-account inventory and review is a named requirement, not a nicety.

### 2.3 Requirement 8 (identity & MFA) as engineering requirements

- **8.2.1** unique ID per user before any access; **8.2.2** shared accounts exception-only, time-limited, every action attributable to an individual.
- **8.3.6** passwords ≥12 chars (8 only if unsupported), numeric + alphabetic ([SAQ A v4.0.1](https://developer.swedbankpay.com/assets/documents/PCI-DSS-v4-0-1-SAQ-A.pdf)).
- **8.3.9** (now mandatory): if password is the only factor, 90-day rotation **or** dynamic security-posture analysis.
- **8.4.2** (now mandatory): **MFA for ALL access into the CDE** — not just remote/admin. v4.0.1 exempts phishing-resistant-only accounts ([Delinea](https://delinea.com/blog/pci-dss-4.0.1-and-identity-security-compliance-requirements)).
- **8.5.1** MFA must resist replay; all factors must succeed.
- **8.6.2** (now mandatory): **no hardcoded passwords in scripts, configs, or source**; 8.6.3: strength/rotation for service accounts ([Schellman](https://www.schellman.com/blog/pci-compliance/pci-dss-service-account-requirements)).

**Implication for Mobula:** MFA enforcement belongs at the Keycloak realm (mobula cannot enforce it downstream of bearer tokens); unique attributable identity must propagate into every audit record including CLI/API-token use; **the TOML-embedded tokens are a direct 8.6.2-class violation** of the benchmark.

### 2.4 Requirement 10 (logging & monitoring) as engineering requirements

Log all of: individual user access to data (10.2.1.1), all admin actions incl. interactive use of system accounts (10.2.1.2), **access to the audit logs themselves** (10.2.1.3), invalid access attempts (10.2.1.4), credential/account/privilege changes (10.2.1.5), starting/stopping/pausing of audit logs (10.2.1.6), creation/deletion of system-level objects (10.2.1.7). Each entry: user ID, event type, date/time, success/failure, origin, affected resource (10.2.2). Protection from modification (10.3); daily review with **automated mechanisms** (10.4.1.1, now mandatory); retention **≥12 months, 3 months immediately available** (10.5.1); NTP time sync from accepted sources (10.6) ([Genesys matrix](https://help.mypurecloud.com/wp-content/uploads/2025/02/pci-dss-requirements-v4.0.1.pdf), [Qualys](https://blog.qualys.com/product-tech/2023/10/04/pci-dss-4-0-fim-requirements-simplified-with-qualys-file-integrity-monitoring)).

**Implication for Mobula:** this is the most precise free checklist for what an audit subsystem must do. Checklist gaps to verify: does Mobula log *reads of the audit log*, *audit-log pause/stop events*, *failed auth attempts*, and *privilege changes*? Is there a retention knob meeting 12mo/3mo-hot? Are timestamps NTP-synchronized UTC?

### 2.5 Requirements 2 & 6 (one-liners)

- Req 2: no vendor default passwords/security parameters; hardening standards before deployment ([HeroDevs](https://www.herodevs.com/blog-posts/pci-dss-4-0-requirement-2-how-to-apply-secure-configurations-to-all-system-components)). → Mobula ships demo-mode Keycloak and TOML tokens: fine for a dev profile, but the production path must not inherit them.
- Req 6: secure SDLC, code review, critical patches within one month (6.3.3), no live sensitive data in test envs ([Dionach](https://dionach.com/project/pci-dss-4-ecommerce-changes-for-saq-a-explained/)).

---

## 3. ISO/IEC 27001:2022 / 27002:2022

Annex A: 93 controls in 4 themes (Organizational 37, People 8, Physical 14, Technological 34) ([GAICC full list](https://gaicc.org/blog/iso-27001-annex-a-controls-list/)). Normative texts paywalled at [iso.org](https://www.iso.org/standard/27001.html); control interpretations below from reputable secondary sources.

**Certifies the ISMS, not the product.** ISO 27001 is risk-driven: the operator produces a Statement of Applicability (SoA) justifying each control's inclusion/exclusion, and certification covers the management system, not Mobula-as-code ([GAICC](https://gaicc.org/blog/iso-27001-annex-a-controls-list/)). "Mobula is ISO 27001 certified" is a category error; the goal is making the Technological controls **provable by the product** so an operator can point to them in a Stage 2 audit.

### 3.1 Controls that map to software features — one line each

Access control cluster ([ISMS.online A.8.2](https://www.isms.online/iso-27001/annex-a-2022/8-2-use-of-privileged-access-rights-2022/), [A.8.3](https://www.isms.online/iso-27001/annex-a-2022/8-3-information-access-restriction-2022/)):
- **A.8.2 Privileged access rights** → separate admin bindings from project roles; log every privileged action; consider time-boxed elevation.
- **A.8.3 Information access restriction** → deny-by-default authorization enforced server-side at every API layer (Mobula: already project-scoped RBAC — verify no UI-only checks).
- **A.8.5 Secure authentication** → OIDC SSO, MFA at IdP, token expiry/rotation.
- **A.8.6 Capacity management** → quota pools + capacity dashboards/alerts map directly.

Logging/monitoring cluster ([Clarysec](https://blog.clarysec.com/posts/iso-27001-logging-evidence-nis2-dora-gdpr/), [TCSA 8.16](https://www.tcsa.in/frameworks/iso-27001/controls/8-16-monitoring-activities)):
- **A.8.12 Data leakage prevention** (new 2022) → restrict tenant workload egress; audit export/copy operations.
- **A.8.13 Information backup** → tested backup/restore of the Postgres control-plane store; backups protected like production.
- **A.8.14 Redundancy** → HA deployment of API/controller, leader election.
- **A.8.15 Logging** → the audit log is the core evidence: append-only, tamper-protected (including from the admins being logged), retention policy.
- **A.8.16 Monitoring activities** (new 2022) → logging is passive; Mobula also needs **alerting/anomaly detection on audit events** (failed-auth spikes, quota abuse) — a real gap if export-only.
- **A.8.17 Clock synchronization** → NTP everywhere; consistent UTC timestamps in audit records.
- **A.8.18 Privileged utility programs** → restrict and log break-glass tooling (direct DB access, controller overrides).

Network cluster ([Atos SoA](https://www.atosgroup.com/sites/default/files/uploads/2026-04-30/atos-global-statement-of-applicability.pdf)):
- **A.8.20 Networks security** → TLS everywhere; secured east-west traffic.
- **A.8.22 Segregation of networks** → per-tenant namespace + NetworkPolicy isolation; separate management vs production networks. *Direct hit on the missing NetworkPolicy story.*

Crypto & secure development:
- **A.8.24 Use of cryptography** → TLS 1.2+, encryption at rest for secrets/Postgres, managed keys.
- **A.8.28 Secure coding** (new 2022) → Rust memory safety + `cargo-deny` (already present via `deny.toml`), OWASP-aware review.
- **A.8.31 Separation of dev/test/prod** → separate clusters/realms; no prod credentials in dev (relevant to the demo-mode Keycloak).
- **A.8.32 Change management** → versioned, reviewed, audited policy/config changes — Mobula's store-backed policy API + audit trail maps well.
- **A.8.9 Configuration management** (new 2022) → baseline config as code (`policy.toml`, deploy manifests) + drift detection.
- **A.8.10 Information deletion / A.8.11 Data masking** → retention/deletion jobs for audit logs and tenant data.

Organizational-theme controls with product implications ([Hicomply 5.18](https://www.hicomply.com/hub/iso-27001-annex-a-5-18-access-rights), [IronVault](https://ironvaultkeys.com/blog/iso-27001-2022-access-control.html)):
- **A.5.15 Access control** → policy expressible and enforceable as code.
- **A.5.16 Identity management** → unique identity propagation into audit records; service-account governance.
- **A.5.17 Authentication information** → token issuance/rotation/revocation; no hardcoded secrets.
- **A.5.18 Access rights** → joiner/mover/leaver workflows, **periodic access-review exports**, audit trail of every grant/revoke.

### 3.2 Clearly organizational-only (out of software scope)

A.5.1–5.13 (policies, asset management), A.5.19–5.23 (supplier/cloud governance), A.5.24–5.30 (incident management, continuity), A.5.31–5.37 (legal/privacy/review), all of A.6 (People) and A.7 (Physical) ([GAICC](https://gaicc.org/blog/iso-27001-annex-a-controls-list/)). Mobula features at most supply supporting evidence.

**Concrete engineering implication for Mobula:** publish a shared-responsibility statement mapping each Technological control (plus A.5.14–5.18) to the Mobula feature/evidence-export that satisfies it, and mark the rest as operator responsibility.

---

## 4. Multi-tenant SaaS isolation patterns

### 4.1 Tenancy models

AWS SaaS Lens canonical taxonomy: **silo** (dedicated infra per tenant), **pool** (fully shared), **bridge** (hybrid). Regulatory profile and noisy-neighbor attributes steer toward silo; cost and agility toward pool; mixing per tier is standard practice ([AWS SaaS Lens — Silo, Pool, Bridge](https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/silo-pool-and-bridge-models.html)). Key framing from AWS: *"authentication and authorization ≠ isolation"* — isolation must be enforced by identity (JWT tenant claims) + infrastructure policy, independent of application code ([SaaS Tenant Isolation Strategies](https://d1.awsstatic.com/whitepapers/saas-tenant-isolation-strategies.pdf)).

**Mobula mapping:** cluster-per-tenant Ray compute + pooled control plane is already a **bridge architecture** — the consensus shape for AI-compute SaaS.

### 4.2 Kubernetes tenancy models

kubernetes.io distinguishes "multiple teams" (soft) from "multiple customers" (strong isolation is the vendor's burden) ([Multi-tenancy — kubernetes.io](https://kubernetes.io/docs/concepts/security/multi-tenancy/)). The landscape:

- **Namespace-per-tenant (soft):** namespaces are the attachment point for RBAC/NetworkPolicy/ResourceQuota but are **logical separation, not a security boundary** — API server, etcd, kubelet, and node kernel are shared; "a skilled attacker could use the permissions assigned to the kubelet to move laterally." Cluster-scoped resources (CRDs, StorageClasses, webhooks) escape namespace isolation entirely ([kubernetes.io](https://kubernetes.io/docs/concepts/security/multi-tenancy/)).
- **Cluster-per-tenant (hard):** strongest; cost/ops overhead; Mobula's current compute model.
- **Virtual control plane (vCluster, Loft Labs):** per-tenant API server/controller/etcd over shared workers; solves control-plane noisy neighbor and CRD collisions, but explicitly *"per-tenant control planes do not solve isolation problems in the data plane"* ([kubernetes.io](https://kubernetes.io/docs/concepts/security/multi-tenancy/), [vCluster docs](https://www.vcluster.com/docs/platform/next/understand/what-are-virtual-clusters)).
- **Capsule (Clastix):** policy-level multi-tenancy grouping namespaces into Tenant abstractions — quotas, network policies, pod security without a second control plane ([capsule.clastix.io](https://capsule.clastix.io/docs/general/tutorial)).
- **HNC:** archived/retired ([kubernetes-retired/hierarchical-namespaces](https://github.com/kubernetes-retired/hierarchical-namespaces)) — do not adopt.

### 4.3 Network isolation

Pattern: **default-deny NetworkPolicy (ingress + egress) per tenant namespace**, then allow rules — notably egress to cluster DNS, which default-deny breaks ([kubernetes.io NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/), [multi-tenancy](https://kubernetes.io/docs/concepts/security/multi-tenancy/)). Hard limits, all from kubernetes.io:

- **CNI-dependent**: "Creating a NetworkPolicy resource without a controller that implements it will have no effect."
- **L3/L4 only**; no explicit-deny rules, no L7, no logging of blocked connections.
- **Node traffic always allowed**; `hostNetwork` pods bypass policy in common implementations.
- Pods created before the CNI processes policy "may be started unprotected."

Second layer: service mesh mTLS "protecting your data even in the presence of a compromised node" ([kubernetes.io multi-tenancy](https://kubernetes.io/docs/concepts/security/multi-tenancy/)).

**Mobula gap:** no NetworkPolicy story means the Kubernetes default applies — *all pods in all namespaces can communicate with each other, unencrypted*. This is the single highest-impact isolation fix, and it's A.8.22/CC6.6 evidence.

### 4.4 Data isolation

DB-per-tenant (silo) / schema-per-tenant (bridge) / shared-schema + discriminator (pool) ([AWS SaaS Storage Strategies](https://d1.awsstatic.com/whitepapers/Multi_Tenant_SaaS_Storage_Strategies.pdf), [AWS Prescriptive Guidance for PostgreSQL SaaS](https://docs.aws.amazon.com/prescriptive-guidance/latest/saas-multitenant-managed-postgresql/partitioning-models.html)). For the pooled model, **Postgres Row-Level Security** is the consensus second layer — but superusers/`BYPASSRLS`/table owners bypass it, and referential-integrity checks create covert-channel leaks; RLS is defense-in-depth, not a sole boundary ([postgresql.org RLS docs](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)). DB-per-tenant wins on per-tenant backup/restore, per-tenant keys, and GDPR deletion granularity.

**Implication for Mobula:** the control-plane Postgres holds cross-tenant desired state and tokens — decide and document the partitioning model (shared + app-level scoping is defensible for a control plane, unlike tenant data planes); add RLS as a second layer if pooled; per-tenant restore granularity argues for at least schema-per-tenant if offering a regulated tier.

### 4.5 Noisy-neighbor controls

ResourceQuota/LimitRange per namespace; **Kueue** ClusterQueues + ResourceFlavors + cohorts with borrowing/lending limits and fair-sharing preemption ([Kueue overview](https://kueue.sigs.k8s.io/docs/overview/), [ClusterQueue](https://kueue.sigs.k8s.io/docs/concepts/cluster_queue/)); priority classes for tiered QoS ([kubernetes.io multi-tenancy](https://kubernetes.io/docs/concepts/security/multi-tenancy/)).

**Key limit:** quotas and Kueue govern **admission and scheduling, not runtime IO** — nothing stops a running tenant from saturating disk I/O, network bandwidth, or GPU SMs. Runtime isolation needs node pools, storage QoS, bandwidth plugins, or hardware partitioning.

### 4.6 GPU multi-tenancy risk

- **MIG (A100/H100, ≤7 instances):** hardware-partitioned, "each with dedicated compute and memory resources," error/fault containment hardware-enforced — **the only NVIDIA sharing mode that is a genuine tenant boundary** ([MIG User Guide](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/index.html)).
- **CUDA time-slicing:** NVIDIA's own device-plugin docs: *"nothing special is done to isolate workloads... each workload has access to the GPU memory and runs in the same fault-domain as all the others."* A tenant can read another tenant's GPU memory remnants. **Not a security boundary; same-trust-domain packing only** ([NVIDIA k8s-device-plugin README](https://github.com/NVIDIA/k8s-device-plugin)).
- **MPS:** software-enforced memory/compute limits per client; better than time-slicing, experimental, unsupported on MIG devices (same README).
- **Footgun:** "If you do not request GPUs when you use the device plugin, the plugin exposes all the GPUs on the machine inside your container" — admission enforcement of GPU requests is mandatory ([README](https://github.com/NVIDIA/k8s-device-plugin)).
- **Driver/toolkit CVEs as a class:** CVE-2024-0132 (CVSS 9.0) NVIDIA Container Toolkit container escape; incomplete patch bypassed as CVE-2025-23359 ([Wiz](https://www.wiz.io/blog/nvidia-ai-vulnerability-deep-dive-cve-2024-0132), [oss-sec](https://www.openwall.com/lists/oss-security/2025/02/14/4)). Any tenant controlling an image could escape — pin and patch toolkit/driver versions.
- **Confidential computing:** H100 CC mode — AES-encrypted HBM, hardware firewall, SPDM attestation — the premium-tier answer for regulated tenants sharing GPU infra ([NVIDIA Technical Blog](https://developer.nvidia.com/blog/confidential-computing-on-h100-gpus-for-secure-and-trustworthy-ai/)).

**Bottom line for Mobula:** whole-GPU-per-tenant or MIG slices only; cross-tenant time-slicing is an explicit non-starter per NVIDIA's own docs. This needs to be an **admission-enforced policy**, not documentation.

### 4.7 Consensus defense-in-depth stack

From [kubernetes.io multi-tenancy](https://kubernetes.io/docs/concepts/security/multi-tenancy/) and [NSA/CISA Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003076362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE-1.2.PDF):

1. Strong API authN/Z — "the most important type of isolation for the control plane is authorization."
2. Admission control (OPA/Gatekeeper or Kyverno) enforcing per-tenant guardrails at create time.
3. Namespace isolation + default-deny NetworkPolicy with DNS carve-out.
4. Pod Security Standards "restricted" via Pod Security Admission.
5. Runtime sandboxing (gVisor/Kata) for untrusted code — containers share the host kernel.
6. Encrypted etcd (separate CA, API-server-only access).
7. Node pools per tenant tier via taints/tolerations.
8. Egress controls beyond NetworkPolicy + audit logging/threat detection.

**Reference stack for a multi-tenant AI-compute platform (2026):** bridge tenancy tiering; API authZ + admission policy as the load-bearing control; per-tenant default-deny NetworkPolicy on a conformant CNI (Cilium/eBPF); ResourceQuota + Kueue for scheduling; whole-GPU/MIG-only GPU tenancy with admission-enforced requests; Postgres RLS as second-layer data isolation; Pod Security restricted + gVisor/Kata for tenant-supplied code; encrypted etcd; egress gateway controls; audit logging.

---

## 5. Keycloak production hardening

All items verified against official Keycloak 26.x docs. Demo-mode red flags to eliminate: `start-dev`, missing `KC_HOSTNAME`, HTTP enabled, wildcard redirect URIs, no brute-force detection, weak master-realm admin password.

| # | Item | What to set | Why | Source |
|---|---|---|---|---|
| 1 | Production mode | `start`, never `start-dev` | start-dev enables HTTP, disables strict hostname checks | [server/configuration](https://www.keycloak.org/server/configuration) |
| 2 | Hostname v2 | `KC_HOSTNAME=https://id.example.com` (full URL) | Prevents forged issuer/redirect URLs from request headers; v1 options removed in 26 | [server/hostname](https://www.keycloak.org/server/hostname) |
| 3 | Admin hostname | `KC_HOSTNAME_ADMIN` on a separate host | Admin UI/REST not exposed on the public login hostname (REST API still needs proxy-level blocking) | [server/hostname](https://www.keycloak.org/server/hostname) |
| 4 | Proxy headers | `--proxy-headers forwarded` **or** `xforwarded`; `--proxy-trusted-addresses=<CIDRs>` | Legacy `--proxy` removed; untrusted forwarded headers poison IP-based audit logs | [server/reverseproxy](https://www.keycloak.org/server/reverseproxy) |
| 5 | TLS | Real certs; realm **Require SSL: All requests** | All traffic carries credentials/tokens | [server/enabletls](https://www.keycloak.org/server/enabletls) |
| 6 | Brute force | Enable — **Lockout temporarily**, e.g. 5 failures, escalating wait | **Disabled by default**; without it unlimited password guessing. Per-account not per-IP — add WAF/rate-limit at proxy | [Server Admin Guide](https://www.keycloak.org/docs/latest/server_admin/index.html) |
| 7 | Password policy | length(12+), digits, upper/lower, notUsername, passwordHistory(5+); hashing default is pbkdf2-sha512 @ 210k iterations (don't downgrade; argon2 available) | Baseline guessing resistance; 24/25 raised PBKDF2 defaults per OWASP | [Server Admin Guide](https://www.keycloak.org/docs/latest/server_admin/index.html), [25.0 release notes](https://www.keycloak.org/2024/06/keycloak-2500-released) |
| 8 | Token lifespans | Access token ≤5 min default; refresh-token **rotation** on; SSO idle/max tuned per risk | Self-contained JWTs aren't per-call revocable — lifespan *is* the exposure window | [Server Admin Guide — timeouts](https://www.keycloak.org/docs/latest/server_admin/index.html) |
| 9 | Client hardening | Confidential clients for server apps; **exact redirect URIs** (no wildcards); PKCE S256 enforced; implicit flow + direct-access-grants off unless needed | Wildcards enable code interception (CVE-2024-2419 class); each enabled grant is attack surface | [Server Admin Guide](https://www.keycloak.org/docs/latest/server_admin/index.html) |
| 10 | Admin lockdown | master realm for realm management only, never app users; dedicated admin users with WebAuthn/OTP; fine-grained admin permissions v2 (supported since 26.2) | Console compromise = full IdP compromise | [Server Admin Guide](https://www.keycloak.org/docs/latest/server_admin/index.html), [RHBK 26.2 notes](https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/26.2/pdf/release_notes/index) |
| 11 | Event logging | Enable **user events** AND **admin events** (+ Include Representation); set expiration; forward to SIEM via listener SPI | Your auth audit trail (user, IP, event type); DB retention ≠ SIEM | [RHBK 26 — auditing](https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/26.0/html/server_administration_guide/configuring_auditing_to_track_events) |
| 12 | Database | `KC_DB=postgres` external DB — never embedded H2; creds via secrets, not committed compose files | H2 is dev-only; plaintext DB passwords in compose are a demo-mode smell | [server/db](https://www.keycloak.org/server/db), [server/containers](https://www.keycloak.org/server/containers) |
| 13 | HA | 2+ nodes, Infinispan distributed caches; note 26.x persists user sessions to DB by default | Survives node loss; changes DB sizing | [configuration-production](https://www.keycloak.org/server/configuration-production), [26.0 release notes](https://www.keycloak.org/2024/10/keycloak-2600-released) |

Version-watch items: hostname v1 options gone in 26; `--proxy` removed (24); PBKDF2 defaults raised (24/25); persistent sessions default-on (26); admin-fine-grained-authz v2 supported (26.2). No native breached-password checking — community SPIs only (e.g. [keycloak-hibp-password-policy](https://github.com/CACI-IIG/keycloak-hibp-password-policy)).

**Concrete engineering implication for Mobula:** ship a hardened `docker-compose.auth.yml` / Helm profile (prod values for items 1–5, 12) plus a documented realm-setup checklist (6–11) — or better, realm configuration as code (keycloak-config-cli / Terraform) so hardening is reviewable and reproducible. This is also the MFA enforcement point the PCI Req 8 / SOC 2 CC6.1 benchmark demands.

---

## 6. Encryption at rest

### 6.1 Threat model (state this plainly)

At-rest encryption protects against **offline** attacks: disk/snapshot/dump/backup theft, decommissioned media. It does **not** protect against a live compromised app server — the app must be able to decrypt to serve requests ([OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)). Kubernetes docs make the same point: a locally managed etcd key "protects against an etcd compromise, but fails to protect against a host compromise"; with a remote KMS, "an attacker... would need to compromise etcd **and** the third-party KMS provider" ([kubernetes.io encrypt-data](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)). Compensating controls for live compromise: hash-not-encrypt, RBAC, short-lived credentials, audit.

### 6.2 Per layer

**PostgreSQL (desired state, tokens, audit records).** Community Postgres has **no built-in TDE** — options are pgcrypto (column-level), full-disk encryption, or commercial TDE forks ([EDB](https://www.enterprisedb.com/blog/everything-need-know-postgres-data-encryption), [pgcrypto docs](https://www.postgresql.org/docs/current/pgcrypto.html)). Standard pattern: volume/disk encryption as baseline + **application-level envelope encryption of high-value columns** (per-row/per-tenant DEK wrapped by a KEK in KMS/Vault; ciphertext + wrapped DEK stored together) ([AWS KMS concepts](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html), [GCP envelope encryption](https://cloud.google.com/kms/docs/envelope-encryption)). **Better where possible: hash, don't encrypt** — a bearer token only needs verification, so a keyed hash/SHA-256 of a high-entropy token suffices; encrypt only secrets Mobula must *replay* (tenant cloud credentials) ([OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)).

→ *Mobula: small envelope module in mobula-core (Rust `aes-gcm` + KMS/Vault client); migrate token columns to hash-or-envelope; disk encryption is infra baseline, not a substitute.*

**Kubernetes Secrets / etcd.** Default is plaintext (base64 ≠ encryption). EncryptionConfiguration providers per the [official table](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/): `identity` (none), `aescbc` (**"not recommended due to CBC's vulnerability to padding oracle attacks"**), `aesgcm` (rotate every 200k writes), `secretbox` (strong), **`kms` v2** — envelope encryption, stable since 1.29, "a good choice if using a third party tool for key management"; KEK rotation ≥ every 90 days ([kms-provider docs](https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/)). Complements: **Sealed Secrets** (encrypt into a `SealedSecret` safe to commit to Git — [bitnami-labs/sealed-secrets](https://github.com/bitnami-labs/sealed-secrets)), **External Secrets Operator** (sync from Vault/AWS SM — [external-secrets.io](https://external-secrets.io)), **Secrets Store CSI driver** (mount without creating etcd Secret objects at all).

→ *Mobula: verify KMS v2 encryption on provisioned clusters as a mobula-policy check; prefer CSI/ESO for tenant-facing secrets so plaintext never lands in etcd.*

**Object store (logs, job outputs).** SSE-S3 is default-on for all new objects since 2023-01-05; use **SSE-KMS** for key control, rotation, and CloudTrail audit of key use ([S3 default encryption docs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html)). Client-side-encrypt genuinely sensitive artifacts before upload.

→ *Mobula: bucket default SSE-KMS with customer-managed key in provisioning templates.*

**Config files holding static tokens.** OWASP baseline: no hard-coded keys in source/VCS, restrictive permissions, dedicated secrets-management systems "provide an additional layer of security... as well as making the management of secrets significantly easier" ([OWASP Key Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)).

→ *Mobula: tokens in TOML become references to a secrets manager (Vault KV / AWS SM) resolved at startup, or mounted K8s Secrets; where a token must remain static, store it hashed server-side. This closes the PCI 8.6.2-class "no hardcoded passwords in configs" violation.*

**Backups.** Backups inherit all of the above and are the classic theft vector; encrypt archives with a KMS-wrapped key, restrict restore permissions, retain retired KEKs long enough to restore old backups ([OWASP Key Lifetimes](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)). Note: AWS is disabling SSE-C by default on new buckets from April 2026 — affects Velero-style tooling with customer-provided keys ([velero#9762](https://github.com/velero-io/velero/issues/9762)).

### 6.3 Key-management practices

Envelope structure everywhere (DEK encrypts data; KEK in KMS wraps DEK); key/data separation; central key store as audit choke point (every KMS use logged); rotation on cryptoperiod/compromise with a tested runbook; CSPRNG-only generation (Rust `rand`); never in git; separation of duties (app role can wrap/unwrap, not manage/export); AES-256-GCM as default cipher, don't roll your own ([OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), [kubernetes.io](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)).

**Concrete engineering implication for Mobula:** the minimal credible at-rest story is three moves: (1) hash all verification-only tokens, envelope-encrypt replayable secrets via KMS/Vault; (2) KMS v2 etcd encryption as a provisioning-time policy check; (3) SSE-KMS bucket defaults + encrypted backups. Disk encryption underneath all of it as infra baseline.

---

## 7. Prioritized gap list

Priority = (compliance evidence value × isolation risk reduction) / effort. P0 = do before any enterprise/compliance conversation; P1 = before a SOC 2 Type 1 window opens; P2 = maturity items.

### P0 — isolation and credential hygiene (weeks, not months)

1. **Default-deny NetworkPolicy per tenant namespace** (ingress + egress, DNS carve-out, explicit allow to Ray head/services), shipped as part of cluster provisioning, with a documented CNI-enforcement requirement. Highest single impact: closes A.8.22/CC6.6 evidence, eliminates cross-tenant pod reachability. *(§4.3)*
2. **Eliminate plaintext tokens in TOML**: secrets-manager references or mounted secrets at startup; hash verification-only tokens server-side. Closes PCI 8.6.2-class violation, A.5.17, and the worst of the at-rest gap. *(§2.3, §6.2)*
3. **Keycloak production profile**: `start` mode, hostname v2, TLS/Require-SSL, brute-force detection, password policy, event logging, exact redirect URIs + PKCE, admin lockdown — as code (Terraform/keycloak-config-cli), with the demo compose clearly labeled dev-only. This is the MFA enforcement point for SOC 2 CC6.1 / PCI 8.4.2 benchmarks. *(§5)*
4. **GPU tenancy policy as admission control**: whole-GPU or MIG slices per tenant only; block cross-tenant time-slicing; enforce GPU requests (a pod with no GPU request sees all GPUs); pin/patch NVIDIA Container Toolkit (CVE-2024-0132 class). *(§4.6)*

### P1 — evidence-grade operations (before SOC 2 Type 1 / enterprise procurement)

5. **At-rest encryption story**: envelope encryption for replayable secrets in Postgres (KMS/Vault), KMS v2 etcd encryption as a provisioning policy check, SSE-KMS bucket defaults, encrypted backups with key-retention doc. *(§6)*
6. **Audit log hardening to PCI Req 10 / SOC 2 CC7 spec**: verify coverage of audit-log *reads*, log-pause/stop events, failed auth attempts, and privilege changes; retention knob ≥12 months / 3 months hot; documented immutability mechanism; NTP/UTC consistency. *(§2.4, §1.3)*
7. **Active monitoring path** (A.8.16 / CC7.2): alerting on audit-event anomalies (failed-auth spikes, quota abuse) — export-only logging is passive recording, not monitoring. *(§3.1)*
8. **Access-review export**: who has what role in which project, granted when, by whom — covering human *and* service accounts. Serves SOC 2 CC6.3, PCI 7.2.4/7.2.5, ISO A.5.18 simultaneously. *(§1.3, §2.2, §3.1)*
9. **Pod Security Standards "restricted"** enforced per tenant namespace + admission policy (Kyverno/OPA) for guardrails. *(§4.7)*

### P2 — maturity / tiered offerings

10. **Runtime noisy-neighbor story** beyond scheduling quotas: per-tier node pools via taints, storage/network IO controls; document that Kueue is admission-time, not runtime. *(§4.5)*
11. **Runtime sandboxing** (gVisor/Kata) for tenant-supplied code on pooled tiers; runtime egress gateway controls beyond NetworkPolicy (A.8.12 DLP). *(§4.7, §3.1)*
12. **HA + tested backup/restore** of the control-plane store (A.8.13/8.14), capacity dashboards (A.8.6). *(§3.1)*
13. **Data-partitioning decision documented** for the control-plane Postgres (shared + scoping vs schema-per-tenant for a regulated tier; RLS as second layer). *(§4.4)*
14. **Shared-responsibility / compliance-mapping doc**: SOC 2 CC6–CC8 and ISO Annex A control → Mobula feature/evidence-export mapping, with the organizational remainder explicitly assigned to the operator. This is the artifact that turns the above engineering into sales-ready compliance posture. *(§1.2, §3)*
15. **Process items for the operator/vendor** (not product): quarterly access reviews, IRP + tabletop, annual pentest scoped to the system description, vendor management for Keycloak/Kueue/cloud dependencies. *(§1.2, §1.3)*

### What is NOT a gap

OIDC + opaque revocable tokens, project-scoped RBAC, append-only audit with export, Kueue admission quotas, and cluster-per-tenant compute are the right foundations — they map cleanly onto CC6.1, A.8.3, A.8.15, A.8.6, and the silo/bridge model respectively. The gaps are concentrated in **network isolation, credential storage, Keycloak operational hardening, GPU sharing policy, and at-rest encryption** — all closable without architectural change.
