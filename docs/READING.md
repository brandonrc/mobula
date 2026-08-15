# Reading list

The distributed-systems literature Mobula's design is audited against
(2026-08-15 audit; findings dispositioned in ../PLAN.md, Review 4).
One-line takeaways are Mobula-specific.

| Paper / doc | Takeaway for Mobula | Link |
|---|---|---|
| Borg (EuroSys '15) | Quota is admission control, not scheduling; priority-banded, oversold, capacity-planned | https://research.google/pubs/large-scale-cluster-management-at-google-with-borg/ |
| Borg, Omega, Kubernetes (ACM Queue '16) | Reconcile from observation, not a state diagram | https://queue.acm.org/detail.cfm?id=2898444 |
| Omega (EuroSys '13) | Incremental transactions by default; all-or-nothing only for gangs | https://research.google/pubs/omega-flexible-scalable-schedulers-for-large-compute-clusters/ |
| Mesos (NSDI '11) | Two-level offers take a pessimistic lock; picky/gang frameworks starve | https://www.usenix.org/legacy/event/nsdi11/tech/full_papers/Hindman_new.pdf |
| YARN (SoCC '13) | Central allocator stays ignorant of allocation semantics; late binding | https://dl.acm.org/doi/10.1145/2523616.2523633 |
| DRF (NSDI '11) | Weighted DRF over weighted fair share; sharing incentive + strategy-proofness | https://www.usenix.org/conference/nsdi11/dominant-resource-fairness |
| H-DRF (SoCC '13) | Hierarchies that sum child usage raw starve siblings | https://people.eecs.berkeley.edu/~alig/papers/h-drf.pdf |
| Themis (NSDI '20) | DRF degrades for long gang GPU jobs; finish-time fairness | https://www.usenix.org/conference/nsdi20/presentation/mahajan |
| Autopilot (EuroSys '20) | Asymmetric cost: under-provision hurts more than waste; fast-up/slow-down with churn penalty | https://dl.acm.org/doi/10.1145/3342195.3387524 |
| Kueue concepts | Cohorts/borrowing/preemption; autoscaling escapes quota without elastic Workload Slices | https://kueue.sigs.k8s.io/docs/concepts/ |
| Karpenter disruption docs | Consolidation budgets, do-not-disrupt, >=15-instance-type rule for spot | https://karpenter.sh/docs/concepts/disruption/ |
| Cluster Autoscaler FAQ | Never run a second autoscaler over the same capacity | https://github.com/kubernetes/autoscaler/blob/master/cluster-autoscaler/FAQ.md |
| Ray (OSDI '18) | Bottom-up scheduling; control state in GCS | https://www.usenix.org/conference/osdi18/presentation/moritz |
| Ownership (NSDI '21) | Owner death is unrecoverable (`OwnerDiedError`) - spot preemption is data loss, not rescheduling | https://www.usenix.org/system/files/nsdi21-wang.pdf |
| Ray autoscaling + ArgoCD | Ray's sidecar owns `replicas`; external writers cause stuck instances | https://docs.ray.io/en/latest/cluster/kubernetes/examples/argocd.html |
| K8s design principles | Edge-triggered behavior must be only an optimization; no observation-free state machines | https://github.com/kubernetes/design-proposals-archive/blob/main/architecture/principles.md |
| K8s API conventions | spec/status split, `observedGeneration`, Conditions; `phase` is deprecated | https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md |
| Writing Controllers (sig-api-machinery) | Level-driven; leader election is imperfect; percolate errors into requeue backoff | https://github.com/kubernetes/community/blob/master/contributors/devel/sig-api-machinery/controllers.md |
| Kleppmann, distributed locking | Leases without fencing tokens double-provision | https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html |
| Transactional outbox | The pattern that kills the Postgres+CR dual-write | https://microservices.io/patterns/data/transactional-outbox.html |

Gaps the audit noted: Ray autoscaler v2 has no REP (docs page + tracking
issues ray#35595/#42840 only); no Jepsen analysis exists for control-plane
dual-write - Kleppmann carries that argument alone.
