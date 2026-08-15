use serde::{Deserialize, Serialize};

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

/// Declarative spec for a managed Ray cluster.
///
/// v0 targets the KubeRay backend only; fields deliberately mirror what maps
/// onto a RayCluster CR so the provisioner stays a thin translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSpec {
    pub name: String,
    pub project: String,
    pub ray_version: String,
    pub image: String,
    pub head_cpu: String,
    pub head_memory: String,
    pub worker_groups: Vec<WorkerGroup>,
    /// Idle TTL in seconds; `None` disables reaping.
    pub ttl_seconds: Option<u64>,
}

/// A homogeneous group of Ray worker nodes.
///
/// Autoscaling in v0 is actuated exclusively through these replica bounds,
/// which translate to KubeRay worker-group fields — never by reading demand
/// from GCS (ADR-0002).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
