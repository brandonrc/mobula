//! Pod shaping: how a cluster's containers reach environments, data, and
//! identity (#66).
//!
//! Ray workers are useless without a way to say "mount my home directory",
//! "set this env var", "run as this service account", "land on the GPU
//! pool". Kubernetes expresses all of that in the pod spec — but a control
//! plane whose selling point is *self-service without Kubernetes admin
//! privileges* cannot accept a pod spec from a caller. A free-form pod
//! template is a privilege-escalation path: mount any PVC in the namespace,
//! `hostPath` the node filesystem, assume any service account, schedule
//! onto any tainted node.
//!
//! So this module splits the concept in two:
//!
//! - [`PodOverrides`] is what a **caller** may ask for: literal environment
//!   variables, plus *names* selected from a platform-declared catalog.
//!   Names are inert — an unknown one is rejected, never passed through.
//! - [`ResolvedPodShape`] is what the platform **grants**: concrete claim
//!   names, mount paths, service accounts, selectors and tolerations. It is
//!   computed server-side (`mobula_policy::podshape::resolve`) and is never
//!   accepted from the wire.
//!
//! Both are persisted on [`crate::ClusterSpec`]: the selections because
//! they are the user's intent, the resolution because it is the privilege
//! decision made at admission time. Keeping the resolution on the spec is
//! what lets the KubeRay translation stay a pure function of the spec (no
//! catalog lookup at reconcile time), and means a later catalog edit cannot
//! silently re-shape a cluster that is already running.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

/// A literal environment variable set on every Ray container in the cluster.
///
/// Values are literals only. Secret *references* are deliberately absent:
/// where credentials live in a spec is an open design question (see the
/// credential-delivery design doc issue), and guessing at it here would
/// prejudge it. A spec is persisted in the store and echoed by the API, so
/// a literal must never be used to carry a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

/// Environment variables the platform manages itself. A caller-supplied
/// value for one of these would fight KubeRay's own injection and break
/// worker registration in ways that surface as an unschedulable or
/// silently-idle cluster, so they are rejected at admission.
pub const RESERVED_ENV: &[&str] = &[
    "RAY_ADDRESS",
    "RAY_CLUSTER_NAME",
    "RAY_IP",
    "RAY_NODE_TYPE_NAME",
    "RAY_PORT",
    "RAY_USAGE_STATS_EXTRA_TAGS",
    "REDIS_PASSWORD",
];

/// What a caller may ask for. Every field is either a literal they own
/// (`env`) or a *name* the platform must recognize.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PodOverrides {
    /// Literal environment variables, applied to head and every worker.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    /// Mount names from the platform catalog. The catalog's default mounts
    /// are applied whether or not they appear here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<String>,
    /// Service-account name, which must appear in the catalog's allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
    /// Named placement (node selector + tolerations) from the catalog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<String>,
}

impl PodOverrides {
    /// True when the caller asked for nothing. An empty override set still
    /// resolves (the catalog's default mounts may apply).
    pub fn is_empty(&self) -> bool {
        self.env.is_empty()
            && self.mounts.is_empty()
            && self.service_account.is_none()
            && self.placement.is_none()
    }
}

/// A resolved volume: the platform's claim, mounted where the platform
/// says, with the sub-path already expanded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct VolumeMount {
    /// Catalog name, reused as the pod-spec volume name.
    pub name: String,
    /// The PersistentVolumeClaim backing it.
    pub claim_name: String,
    pub mount_path: String,
    pub read_only: bool,
    /// Expanded sub-path within the claim, if the catalog entry scoped one.
    /// This is the field that keeps a shared home volume from exposing every
    /// user's directory to every cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_path: Option<String>,
}

/// A pod toleration, in the Kubernetes shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Toleration {
    pub key: String,
    /// `Equal` or `Exists`.
    pub operator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// `NoSchedule`, `PreferNoSchedule` or `NoExecute`.
    pub effect: String,
}

/// The platform's answer to a [`PodOverrides`] request: concrete, already
/// authorized, safe to render into a pod template verbatim.
///
/// Server-computed only. It appears in the serialized spec because the
/// store round-trips the spec, but the API overwrites it unconditionally on
/// every create and update — a value arriving from a client is discarded,
/// not trusted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ResolvedPodShape {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<VolumeMount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub node_selector: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tolerations: Vec<Toleration>,
}

impl ResolvedPodShape {
    /// True when the resolution adds nothing to the pod template, so the
    /// translation can emit a manifest byte-identical to the pre-#66 form.
    pub fn is_empty(&self) -> bool {
        self.env.is_empty()
            && self.volumes.is_empty()
            && self.service_account.is_none()
            && self.node_selector.is_empty()
            && self.tolerations.is_empty()
    }
}

/// Whether `name` is usable as a single path segment: no separators, no
/// traversal, no leading dot, and drawn from a conservative character set.
///
/// Used to gate any value interpolated into a mount sub-path. A project
/// named `../../etc` interpolated into a shared claim would escape its own
/// directory, so this is a security check, not tidiness.
pub fn is_safe_path_segment(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Whether `name` is a legal environment-variable name. Kubernetes accepts
/// a broader set, but C-identifier rules are what every shell and Python
/// runtime can actually read back.
pub fn is_valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_overrides_and_shape() {
        assert!(PodOverrides::default().is_empty());
        assert!(ResolvedPodShape::default().is_empty());
        let with_env = PodOverrides {
            env: vec![EnvVar {
                name: "A".into(),
                value: "1".into(),
            }],
            ..Default::default()
        };
        assert!(!with_env.is_empty());
    }

    #[test]
    fn shape_is_empty_covers_every_field() {
        let base = ResolvedPodShape::default();
        assert!(base.is_empty());
        assert!(!ResolvedPodShape {
            env: vec![EnvVar {
                name: "A".into(),
                value: "1".into()
            }],
            ..base.clone()
        }
        .is_empty());
        assert!(!ResolvedPodShape {
            volumes: vec![VolumeMount {
                name: "home".into(),
                claim_name: "c".into(),
                mount_path: "/home".into(),
                read_only: false,
                sub_path: None,
            }],
            ..base.clone()
        }
        .is_empty());
        assert!(!ResolvedPodShape {
            service_account: Some("sa".into()),
            ..base.clone()
        }
        .is_empty());
        assert!(!ResolvedPodShape {
            node_selector: BTreeMap::from([("k".to_string(), "v".to_string())]),
            ..base.clone()
        }
        .is_empty());
        assert!(!ResolvedPodShape {
            tolerations: vec![Toleration {
                key: "gpu".into(),
                operator: "Exists".into(),
                value: None,
                effect: "NoSchedule".into(),
            }],
            ..base
        }
        .is_empty());
    }

    #[test]
    fn path_segment_rejects_traversal_and_separators() {
        assert!(is_safe_path_segment("ml-team"));
        assert!(is_safe_path_segment("user_1.2"));
        assert!(!is_safe_path_segment(""));
        assert!(!is_safe_path_segment(".."));
        assert!(!is_safe_path_segment(".hidden"));
        assert!(!is_safe_path_segment("a/b"));
        assert!(!is_safe_path_segment("../etc"));
        assert!(!is_safe_path_segment("a b"));
        assert!(!is_safe_path_segment("naïve"));
        assert!(!is_safe_path_segment(&"x".repeat(64)));
        assert!(is_safe_path_segment(&"x".repeat(63)));
    }

    #[test]
    fn env_name_follows_c_identifier_rules() {
        assert!(is_valid_env_name("MY_VAR"));
        assert!(is_valid_env_name("_x9"));
        assert!(!is_valid_env_name(""));
        assert!(!is_valid_env_name("9LIVES"));
        assert!(!is_valid_env_name("MY-VAR"));
        assert!(!is_valid_env_name("MY VAR"));
    }

    #[test]
    fn overrides_round_trip_and_omit_empties() {
        let o = PodOverrides {
            mounts: vec!["home".into()],
            ..Default::default()
        };
        let j = serde_json::to_value(&o).unwrap();
        assert_eq!(j, serde_json::json!({ "mounts": ["home"] }));
        let back: PodOverrides = serde_json::from_value(j).unwrap();
        assert_eq!(back, o);
        // An absent object is the same as no selections.
        let none: PodOverrides = serde_json::from_str("{}").unwrap();
        assert!(none.is_empty());
    }
}
