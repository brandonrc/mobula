use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Opaque identifier for a managed Ray cluster.
///
/// Also the routing key for the job gateway: each cluster is exposed at its
/// own base URL because the stock `ray job submit` client has no cluster-id
/// slot in its paths (PLAN.md, review finding S3).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClusterId(pub String);

impl std::fmt::Display for ClusterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The compute engine a cluster is provisioned on (multi-engine spike). The
/// control plane is engine-neutral above the provisioner seam; this
/// discriminator is what the reconciler and the provisioner router dispatch
/// on. `Ray` is the default so specs persisted before multi-engine — and any
/// client that omits the field — still deserialize as Ray clusters, exactly
/// as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    /// KubeRay `RayCluster` — full control + interactive + batch (Ray Jobs) +
    /// serving (Ray Serve).
    #[default]
    Ray,
    /// dask-kubernetes-operator `DaskCluster` — control + interactive only.
    /// Batch (no Ray-Jobs-REST equivalent) and serving (no Ray Serve
    /// equivalent) are deliberately out of scope for Dask.
    Dask,
}

impl std::fmt::Display for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Engine::Ray => "ray",
            Engine::Dask => "dask",
        })
    }
}

/// Declarative spec for a managed cluster.
///
/// Historically Ray-only (fields mirror a RayCluster CR so the KubeRay
/// provisioner stays a thin translation). Multi-engine adds [`Self::engine`];
/// the head/scheduler + worker-group shape is generic to both engines. For
/// `engine = dask`, `ray_version` is unused (Dask's version is carried by
/// [`Self::image`]); it stays a required field only for back-compat with
/// stored Ray specs and existing clients.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClusterSpec {
    pub name: String,
    pub project: String,
    /// Which compute engine backs this cluster. `#[serde(default)]` = Ray, so
    /// every pre-multi-engine spec and every Ray client keeps working
    /// untouched.
    #[serde(default)]
    pub engine: Engine,
    pub ray_version: String,
    pub image: String,
    pub head_cpu: String,
    pub head_memory: String,
    pub worker_groups: Vec<WorkerGroup>,
    /// **Absolute max-age cap** in seconds: the cluster is reaped this long
    /// after creation regardless of activity. `None` disables the max-age
    /// reaper. (Despite the historical name, this is a wall-clock age cap, not
    /// an inactivity window — see [`Self::idle_timeout_secs`] for that.)
    pub ttl_seconds: Option<u64>,
    /// **Inactivity reap window** in seconds (#100): the cluster is reaped once
    /// it has been *idle* — no job activity — for this long, so a busy cluster
    /// survives past it while a genuinely unused one is released. Distinct from
    /// [`Self::ttl_seconds`], which still caps absolute age independently:
    /// whichever fires first reaps the cluster.
    ///
    /// Activity is derived from the persisted job history (a running/recent
    /// gateway job keeps the cluster alive). **Limitation:** interactive Ray
    /// Client / Dask sessions submit no gateway jobs, so their activity is
    /// invisible to this signal — an interactive-only cluster looks idle from
    /// creation. For such sessions rely on [`Self::ttl_seconds`] or leave this
    /// unset. See `reconcile.rs` module docs.
    ///
    /// `#[serde(default)]` so specs persisted before this field — and any
    /// client that omits it — keep the prior max-age-only behavior.
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    /// The authenticated owner of this cluster (tier-2 owned session
    /// clusters): the human identity that requested it — a
    /// `preferred_username` when the OIDC token carries one, else the `sub`.
    /// Set control-plane-side from the request identity (never trusted from
    /// the client body); `None` for clusters created without an owner (e.g.
    /// admin/service paths). When set it is stamped as the
    /// `mobula.dev/owner` label on the RayCluster and its pods, and drives
    /// the per-owner Ray-client (`:10001`) ingress NetworkPolicy so only the
    /// owner's notebook pod can reach the cluster. `#[serde(default)]` keeps
    /// specs persisted before this field deserializable (they parse as
    /// `None`).
    #[serde(default)]
    pub owner: Option<String>,
}

/// A homogeneous group of Ray worker nodes.
///
/// Autoscaling in v0 is actuated exclusively through these replica bounds,
/// which translate to KubeRay worker-group fields — never by reading demand
/// from GCS (ADR-0002).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkerGroup {
    pub name: String,
    pub cpu: String,
    pub memory: String,
    pub gpu: Option<String>,
    pub min_replicas: u32,
    pub max_replicas: u32,
    pub replicas: u32,
}

/// Lifecycle states of a managed cluster (PLAN.md §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClusterState {
    Pending,
    Provisioning,
    Running,
    Degraded,
    Updating,
    Suspending,
    Suspended,
    Terminating,
    Terminated,
}

/// A drift/health condition the reconcile engine raises, distinct from the
/// observed [`ClusterState`]: it records *why* a cluster diverges from
/// desired so the control plane alarms instead of silently converging
/// (ADR-0004: drift raises alarms, never a silent stomp).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DriftCondition {
    /// The observed spec diverges from desired at the same generation — an
    /// out-of-band edit of a Mobula-owned field.
    SpecDrift,
    /// Observed `Degraded` while desired `Running`: the cluster is unhealthy
    /// for runtime reasons, so re-applying the unchanged spec cannot repair
    /// it — surfaced as an alarm rather than a re-apply hot loop.
    Degraded,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid cluster state transition: {from:?} -> {to:?}")]
pub struct TransitionError {
    pub from: ClusterState,
    pub to: ClusterState,
}

impl ClusterState {
    /// Whether `self -> to` is a legal transition for a **user-issued
    /// lifecycle command** against desired state (e.g. you cannot ask a
    /// Terminated cluster to Suspend).
    ///
    /// Never apply this to observed state: observed reality is not
    /// validated, it is recorded (ADR-0006). Reconcilers reconstruct
    /// status from observation; drift is a Condition, not an error.
    pub fn can_transition(self, to: ClusterState) -> bool {
        use ClusterState::*;
        matches!(
            (self, to),
            (Pending, Provisioning)
                | (Pending, Terminating)
                | (Provisioning, Running)
                | (Provisioning, Degraded)
                | (Provisioning, Terminating)
                | (Running, Degraded)
                | (Running, Updating)
                | (Running, Suspending)
                | (Running, Terminating)
                | (Degraded, Running)
                | (Degraded, Terminating)
                | (Updating, Running)
                | (Updating, Degraded)
                | (Suspending, Suspended)
                | (Suspended, Provisioning)
                | (Suspended, Terminating)
                | (Terminating, Terminated)
        )
    }

    pub fn transition(self, to: ClusterState) -> Result<ClusterState, TransitionError> {
        if self.can_transition(to) {
            Ok(to)
        } else {
            Err(TransitionError { from: self, to })
        }
    }

    /// Terminal states never leave via reconciliation.
    pub fn is_terminal(self) -> bool {
        self == ClusterState::Terminated
    }
}

#[cfg(test)]
mod tests {
    use super::ClusterState::*;
    use super::*;

    #[test]
    fn happy_path_lifecycle() {
        let mut s = Pending;
        for next in [
            Provisioning,
            Running,
            Suspending,
            Suspended,
            Provisioning,
            Running,
            Terminating,
            Terminated,
        ] {
            s = s.transition(next).expect("legal transition");
        }
        assert!(s.is_terminal());
    }

    #[test]
    fn terminated_is_terminal() {
        for target in [
            Pending,
            Provisioning,
            Running,
            Degraded,
            Updating,
            Suspending,
            Suspended,
            Terminating,
        ] {
            assert_eq!(
                Terminated.transition(target),
                Err(TransitionError {
                    from: Terminated,
                    to: target
                })
            );
        }
    }

    #[test]
    fn no_resume_without_reprovision() {
        // Suspended clusters released their compute; they must re-enter
        // Provisioning rather than jumping straight to Running.
        assert!(!Suspended.can_transition(Running));
        assert!(Suspended.can_transition(Provisioning));
    }
}
