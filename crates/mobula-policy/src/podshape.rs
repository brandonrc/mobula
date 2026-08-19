//! Pod-shape admission (#66): turn a caller's [`PodOverrides`] into a
//! [`ResolvedPodShape`], or refuse.
//!
//! This is the enforcement point for the rule that makes self-service safe:
//! **the platform declares what exists, the caller picks by name.**
//!
//! The catalog is store-backed and Admin-editable through
//! `PUT /api/v1/settings/policy`, like prices and quotas — adding a mount
//! must not require a restart, and the same reasoning already made pools
//! API-managed (ADR-0010). The `--policy` file's `[pod_shaping]` section is
//! the boot seed. Two consequences worth being explicit about:
//!
//! - **An edit is never retroactive.** A cluster's grant is frozen onto its
//!   spec as `pod_resolved` at admission, and the KubeRay translation reads
//!   only the spec. A cluster moves onto a new catalog when, and only when,
//!   it is re-submitted — the re-resolution bumps the generation and rolls
//!   the pods. Migration is deliberate, never ambient.
//! - **A live catalog widens what the Admin role means:** an Admin can grant
//!   any PVC in the namespace to any project's pods, where before that took
//!   deployment access. Every edit is audited; a deployment that wants the
//!   tighter posture should bound the mountable claims at the file level.
//!
//! Resolution runs at admission, alongside quota. It is pure: same catalog,
//! same request, same answer. [`PodShapeCatalog::validate`] separately checks
//! the catalog is coherent on its own terms, so a bad edit fails where the
//! mistake was made rather than as a 403 on every subsequent create.

use mobula_core::podspec::{
    is_safe_path_segment, is_valid_env_name, EnvVar, PodOverrides, ResolvedPodShape, Toleration,
    VolumeMount, RESERVED_ENV,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

/// A mount the platform offers. `sub_path` may contain the single
/// placeholder `{project}`, which expands to the cluster's project.
///
/// The placeholder is what makes one shared home volume safe to offer to
/// every project: without it, `claim: nebari-home` mounted at `/home` hands
/// every cluster every user's directory. With it, a project sees only its
/// own subtree. Per-*user* home directories fall out of the same mechanism
/// once each user has a default project (tracked separately, in the
/// self-service work).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct MountEntry {
    pub name: String,
    pub claim_name: String,
    pub mount_path: String,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub sub_path: Option<String>,
}

/// A named placement: where pods land, and what taints they tolerate.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct PlacementEntry {
    pub name: String,
    #[serde(default)]
    pub node_selector: BTreeMap<String, String>,
    #[serde(default)]
    pub tolerations: Vec<TolerationEntry>,
}

/// Toleration as written in config. Mirrors the Kubernetes shape; `operator`
/// defaults to `Equal` and `effect` to `NoSchedule`, which is what a taint
/// on a GPU pool almost always is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct TolerationEntry {
    pub key: String,
    #[serde(default = "default_operator")]
    pub operator: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default = "default_effect")]
    pub effect: String,
}

fn default_operator() -> String {
    "Equal".to_string()
}

fn default_effect() -> String {
    "NoSchedule".to_string()
}

impl From<&TolerationEntry> for Toleration {
    fn from(t: &TolerationEntry) -> Toleration {
        Toleration {
            key: t.key.clone(),
            operator: t.operator.clone(),
            value: t.value.clone(),
            effect: t.effect.clone(),
        }
    }
}

/// Everything a caller is allowed to select from. An empty catalog means
/// pod shaping is switched off: any request for it is refused, and clusters
/// render exactly as they did before #66.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct PodShapeCatalog {
    #[serde(default)]
    pub mounts: Vec<MountEntry>,
    #[serde(default)]
    pub placements: Vec<PlacementEntry>,
    /// Service accounts a caller may run clusters as.
    #[serde(default)]
    pub service_accounts: Vec<String>,
    /// Mounts applied to every cluster whether or not requested — this is
    /// how "workers always see home" is configured.
    #[serde(default)]
    pub default_mounts: Vec<String>,
    /// Placement applied when a caller names none.
    #[serde(default)]
    pub default_placement: Option<String>,
    /// Service account used when a caller names none.
    #[serde(default)]
    pub default_service_account: Option<String>,
}

impl PodShapeCatalog {
    /// True when the platform offers nothing.
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty() && self.placements.is_empty() && self.service_accounts.is_empty()
    }

    /// Check the catalog is internally coherent, so a bad edit is rejected
    /// where the mistake was made rather than surfacing later as a 403 on
    /// every cluster create.
    ///
    /// The motivating case: `default_mounts = ["home"]` with no `home` entry
    /// makes EVERY create fail, because the defaults are resolved whether or
    /// not the caller asked for anything. That is a catalog bug, and the
    /// place to catch it is the edit.
    ///
    /// Deliberately not checked: whether the named claims, service accounts
    /// or node labels exist in Kubernetes. That is a live-cluster question,
    /// it can stop being true after the edit, and a catalog that names a
    /// claim created moments later is legitimate. Kubernetes reports those
    /// as unschedulable pods, which the reconciler already surfaces.
    pub fn validate(&self) -> Result<(), CatalogError> {
        fn dup(names: impl Iterator<Item = String>) -> Option<String> {
            let mut seen: Vec<String> = Vec::new();
            for n in names {
                if seen.contains(&n) {
                    return Some(n);
                }
                seen.push(n);
            }
            None
        }

        for m in &self.mounts {
            if m.name.is_empty() {
                return Err(CatalogError::EmptyName("mount"));
            }
            if m.claim_name.is_empty() {
                return Err(CatalogError::MissingField {
                    entry: m.name.clone(),
                    field: "claim_name",
                });
            }
            if !m.mount_path.starts_with('/') {
                return Err(CatalogError::RelativeMountPath {
                    mount: m.name.clone(),
                    path: m.mount_path.clone(),
                });
            }
            // Reject a traversing or absolute sub_path here, not only at
            // admission: `{project}` is still unexpanded, so this catches the
            // authoring mistake independent of any project name.
            if let Some(sp) = &m.sub_path {
                if sp.starts_with('/') || sp.split('/').any(|seg| seg == "..") {
                    return Err(CatalogError::BadSubPath {
                        mount: m.name.clone(),
                        sub_path: sp.clone(),
                    });
                }
            }
        }
        if let Some(n) = dup(self.mounts.iter().map(|m| m.name.clone())) {
            return Err(CatalogError::DuplicateName {
                kind: "mount",
                name: n,
            });
        }

        for pl in &self.placements {
            if pl.name.is_empty() {
                return Err(CatalogError::EmptyName("placement"));
            }
            for t in &pl.tolerations {
                if !matches!(t.operator.as_str(), "Equal" | "Exists") {
                    return Err(CatalogError::BadToleration {
                        placement: pl.name.clone(),
                        reason: format!(
                            "operator {:?} must be \"Equal\" or \"Exists\"",
                            t.operator
                        ),
                    });
                }
                if !matches!(
                    t.effect.as_str(),
                    "NoSchedule" | "PreferNoSchedule" | "NoExecute"
                ) {
                    return Err(CatalogError::BadToleration {
                        placement: pl.name.clone(),
                        reason: format!(
                            "effect {:?} must be \"NoSchedule\", \"PreferNoSchedule\" or \"NoExecute\"",
                            t.effect
                        ),
                    });
                }
                // `Exists` ignores any value; carrying one means the author
                // expected matching semantics they are not getting.
                if t.operator == "Exists" && t.value.is_some() {
                    return Err(CatalogError::BadToleration {
                        placement: pl.name.clone(),
                        reason: format!(
                            "toleration {:?} uses operator Exists, which ignores `value`",
                            t.key
                        ),
                    });
                }
            }
        }
        if let Some(n) = dup(self.placements.iter().map(|p| p.name.clone())) {
            return Err(CatalogError::DuplicateName {
                kind: "placement",
                name: n,
            });
        }

        // The defaults must resolve, or every create fails.
        for d in &self.default_mounts {
            if !self.mounts.iter().any(|m| &m.name == d) {
                return Err(CatalogError::DanglingDefault {
                    kind: "mount",
                    name: d.clone(),
                });
            }
        }
        if let Some(d) = &self.default_placement {
            if !self.placements.iter().any(|p| &p.name == d) {
                return Err(CatalogError::DanglingDefault {
                    kind: "placement",
                    name: d.clone(),
                });
            }
        }
        if let Some(d) = &self.default_service_account {
            if !self.service_accounts.contains(d) {
                return Err(CatalogError::DanglingDefault {
                    kind: "service account",
                    name: d.clone(),
                });
            }
        }
        Ok(())
    }
}

/// A catalog that is malformed on its own terms, independent of any request.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CatalogError {
    #[error("a {0} entry has an empty name")]
    EmptyName(&'static str),
    #[error("{kind} {name:?} is defined more than once")]
    DuplicateName { kind: &'static str, name: String },
    #[error("mount {entry:?} is missing {field}")]
    MissingField { entry: String, field: &'static str },
    #[error("mount {mount:?}: mount_path {path:?} must be absolute")]
    RelativeMountPath { mount: String, path: String },
    #[error(
        "mount {mount:?}: sub_path {sub_path:?} must be relative and must not traverse upward"
    )]
    BadSubPath { mount: String, sub_path: String },
    #[error("placement {placement:?}: {reason}")]
    BadToleration { placement: String, reason: String },
    #[error(
        "default {kind} {name:?} is not defined in the catalog — every cluster create would fail"
    )]
    DanglingDefault { kind: &'static str, name: String },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PodShapeError {
    #[error("unknown mount {0:?}: not offered by this deployment")]
    UnknownMount(String),
    #[error("unknown placement {0:?}: not offered by this deployment")]
    UnknownPlacement(String),
    #[error("service account {0:?} is not allowed for cluster workloads")]
    UnknownServiceAccount(String),
    #[error("invalid environment variable name {0:?}: must match [A-Za-z_][A-Za-z0-9_]*")]
    InvalidEnvName(String),
    #[error("environment variable {0:?} set more than once")]
    DuplicateEnv(String),
    #[error("environment variable {0:?} is managed by the platform and cannot be overridden")]
    ReservedEnv(String),
    #[error("project {0:?} cannot be used in a mount path: not a safe path segment")]
    UnsafeProject(String),
    #[error("mount {mount:?} is misconfigured: {reason}")]
    BadCatalogEntry { mount: String, reason: String },
}

/// The default mounts plus whatever the caller named, de-duplicated,
/// catalog order first so a deployment controls layering.
fn selected_mounts<'a>(
    catalog: &'a PodShapeCatalog,
    requested: &[String],
) -> Result<Vec<&'a MountEntry>, PodShapeError> {
    let mut names: Vec<&str> = catalog.default_mounts.iter().map(String::as_str).collect();
    for r in requested {
        if !names.contains(&r.as_str()) {
            names.push(r);
        }
    }
    names
        .into_iter()
        .map(|n| {
            catalog
                .mounts
                .iter()
                .find(|m| m.name == n)
                .ok_or_else(|| PodShapeError::UnknownMount(n.to_string()))
        })
        .collect()
}

/// Expand a catalog sub-path against the cluster's project.
fn expand_sub_path(entry: &MountEntry, project: &str) -> Result<Option<String>, PodShapeError> {
    let Some(raw) = entry.sub_path.as_deref() else {
        return Ok(None);
    };
    if raw.contains("{project}") && !is_safe_path_segment(project) {
        return Err(PodShapeError::UnsafeProject(project.to_string()));
    }
    let expanded = raw.replace("{project}", project);
    // A sub-path is joined onto the volume root by the kubelet; anything
    // that climbs out of it is a catalog authoring bug, and it must not
    // reach the cluster regardless of how it got there.
    if expanded.starts_with('/') || expanded.split('/').any(|seg| seg == "..") {
        return Err(PodShapeError::BadCatalogEntry {
            mount: entry.name.clone(),
            reason: format!("sub_path {expanded:?} must be relative and must not traverse upward"),
        });
    }
    Ok(Some(expanded))
}

fn validate_env(env: &[EnvVar]) -> Result<Vec<EnvVar>, PodShapeError> {
    let mut seen: Vec<&str> = Vec::with_capacity(env.len());
    for e in env {
        if !is_valid_env_name(&e.name) {
            return Err(PodShapeError::InvalidEnvName(e.name.clone()));
        }
        if RESERVED_ENV.contains(&e.name.as_str()) {
            return Err(PodShapeError::ReservedEnv(e.name.clone()));
        }
        if seen.contains(&e.name.as_str()) {
            return Err(PodShapeError::DuplicateEnv(e.name.clone()));
        }
        seen.push(&e.name);
    }
    Ok(env.to_vec())
}

/// Resolve `overrides` against `catalog` for a cluster in `project`.
///
/// Returns `None` when the result would add nothing to the pod template, so
/// a deployment that configures no pod shaping produces manifests
/// byte-identical to the pre-#66 form.
///
/// Every failure is a refusal to grant something: callers should surface it
/// as 403, not 400 — the request is well-formed, the caller just may not
/// have it.
pub fn resolve(
    catalog: &PodShapeCatalog,
    overrides: Option<&PodOverrides>,
    project: &str,
) -> Result<Option<ResolvedPodShape>, PodShapeError> {
    let requested = overrides.cloned().unwrap_or_default();

    let mounts = selected_mounts(catalog, &requested.mounts)?;
    let mut volumes = Vec::with_capacity(mounts.len());
    for m in mounts {
        volumes.push(VolumeMount {
            name: m.name.clone(),
            claim_name: m.claim_name.clone(),
            mount_path: m.mount_path.clone(),
            read_only: m.read_only,
            sub_path: expand_sub_path(m, project)?,
        });
    }

    let placement_name = requested
        .placement
        .as_deref()
        .or(catalog.default_placement.as_deref());
    let placement = match placement_name {
        None => None,
        Some(n) => Some(
            catalog
                .placements
                .iter()
                .find(|p| p.name == n)
                .ok_or_else(|| PodShapeError::UnknownPlacement(n.to_string()))?,
        ),
    };

    let service_account = match requested
        .service_account
        .as_deref()
        .or(catalog.default_service_account.as_deref())
    {
        None => None,
        Some(sa) if catalog.service_accounts.iter().any(|a| a == sa) => Some(sa.to_string()),
        Some(sa) => return Err(PodShapeError::UnknownServiceAccount(sa.to_string())),
    };

    let shape = ResolvedPodShape {
        env: validate_env(&requested.env)?,
        volumes,
        service_account,
        node_selector: placement
            .map(|p| p.node_selector.clone())
            .unwrap_or_default(),
        tolerations: placement
            .map(|p| p.tolerations.iter().map(Toleration::from).collect())
            .unwrap_or_default(),
    };
    Ok((!shape.is_empty()).then_some(shape))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> MountEntry {
        MountEntry {
            name: "home".into(),
            claim_name: "nebari-home".into(),
            mount_path: "/home/ray".into(),
            read_only: false,
            sub_path: Some("home/{project}".into()),
        }
    }

    fn shared() -> MountEntry {
        MountEntry {
            name: "shared".into(),
            claim_name: "nebari-shared".into(),
            mount_path: "/shared".into(),
            read_only: true,
            sub_path: None,
        }
    }

    fn catalog() -> PodShapeCatalog {
        PodShapeCatalog {
            mounts: vec![home(), shared()],
            placements: vec![PlacementEntry {
                name: "gpu".into(),
                node_selector: BTreeMap::from([("accelerator".to_string(), "a100".to_string())]),
                tolerations: vec![TolerationEntry {
                    key: "nvidia.com/gpu".into(),
                    operator: "Exists".into(),
                    value: None,
                    effect: "NoSchedule".into(),
                }],
            }],
            service_accounts: vec!["ray-workload".into()],
            default_mounts: vec!["home".into()],
            default_placement: None,
            default_service_account: None,
        }
    }

    #[test]
    fn empty_catalog_and_no_request_resolves_to_nothing() {
        let c = PodShapeCatalog::default();
        assert!(c.is_empty());
        assert_eq!(resolve(&c, None, "p").unwrap(), None);
        assert_eq!(
            resolve(&c, Some(&PodOverrides::default()), "p").unwrap(),
            None
        );
    }

    #[test]
    fn default_mounts_apply_without_being_requested() {
        // The meeting's decision — workers always see home — is a config
        // choice, not something every caller has to remember to ask for.
        let shape = resolve(&catalog(), None, "ml-team").unwrap().unwrap();
        assert_eq!(shape.volumes.len(), 1);
        assert_eq!(shape.volumes[0].name, "home");
        assert_eq!(shape.volumes[0].claim_name, "nebari-home");
        assert_eq!(shape.volumes[0].sub_path.as_deref(), Some("home/ml-team"));
        assert!(!shape.volumes[0].read_only);
    }

    #[test]
    fn requested_mount_adds_to_defaults_without_duplicating() {
        let o = PodOverrides {
            mounts: vec!["home".into(), "shared".into()],
            ..Default::default()
        };
        let shape = resolve(&catalog(), Some(&o), "p").unwrap().unwrap();
        let names: Vec<_> = shape.volumes.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, vec!["home", "shared"], "home not duplicated");
        assert!(shape.volumes[1].read_only);
        assert_eq!(shape.volumes[1].sub_path, None);
    }

    #[test]
    fn unknown_selections_are_refused() {
        let c = catalog();
        let bad_mount = PodOverrides {
            mounts: vec!["etc".into()],
            ..Default::default()
        };
        assert_eq!(
            resolve(&c, Some(&bad_mount), "p"),
            Err(PodShapeError::UnknownMount("etc".into()))
        );
        let bad_placement = PodOverrides {
            placement: Some("control-plane".into()),
            ..Default::default()
        };
        assert_eq!(
            resolve(&c, Some(&bad_placement), "p"),
            Err(PodShapeError::UnknownPlacement("control-plane".into()))
        );
        let bad_sa = PodOverrides {
            service_account: Some("default".into()),
            ..Default::default()
        };
        assert_eq!(
            resolve(&c, Some(&bad_sa), "p"),
            Err(PodShapeError::UnknownServiceAccount("default".into()))
        );
    }

    #[test]
    fn placement_resolves_selector_and_tolerations() {
        let o = PodOverrides {
            placement: Some("gpu".into()),
            ..Default::default()
        };
        let shape = resolve(&catalog(), Some(&o), "p").unwrap().unwrap();
        assert_eq!(shape.node_selector.get("accelerator").unwrap(), "a100");
        assert_eq!(shape.tolerations.len(), 1);
        assert_eq!(shape.tolerations[0].key, "nvidia.com/gpu");
        assert_eq!(shape.tolerations[0].operator, "Exists");
        assert_eq!(shape.tolerations[0].effect, "NoSchedule");
    }

    #[test]
    fn defaults_for_placement_and_service_account_apply() {
        let mut c = catalog();
        c.default_placement = Some("gpu".into());
        c.default_service_account = Some("ray-workload".into());
        let shape = resolve(&c, None, "p").unwrap().unwrap();
        assert_eq!(shape.service_account.as_deref(), Some("ray-workload"));
        assert!(shape.node_selector.contains_key("accelerator"));
    }

    #[test]
    fn project_must_be_a_safe_path_segment() {
        // The whole point of sub_path scoping is that one project cannot
        // read another's directory; a traversing project name would undo it.
        for evil in ["../../etc", "a/b", "..", ""] {
            assert_eq!(
                resolve(&catalog(), None, evil),
                Err(PodShapeError::UnsafeProject(evil.to_string())),
                "project {evil:?} must be refused"
            );
        }
    }

    #[test]
    fn unsafe_project_only_matters_when_interpolated() {
        // A mount with no `{project}` placeholder is unaffected by the
        // project name, so it must not be refused for one.
        let c = PodShapeCatalog {
            mounts: vec![shared()],
            default_mounts: vec!["shared".into()],
            ..Default::default()
        };
        let shape = resolve(&c, None, "../evil").unwrap().unwrap();
        assert_eq!(shape.volumes[0].sub_path, None);
    }

    #[test]
    fn traversing_catalog_sub_path_is_rejected() {
        let c = PodShapeCatalog {
            mounts: vec![MountEntry {
                sub_path: Some("home/../../root".into()),
                ..home()
            }],
            default_mounts: vec!["home".into()],
            ..Default::default()
        };
        assert!(matches!(
            resolve(&c, None, "p"),
            Err(PodShapeError::BadCatalogEntry { .. })
        ));
        let absolute = PodShapeCatalog {
            mounts: vec![MountEntry {
                sub_path: Some("/etc".into()),
                ..home()
            }],
            default_mounts: vec!["home".into()],
            ..Default::default()
        };
        assert!(matches!(
            resolve(&absolute, None, "p"),
            Err(PodShapeError::BadCatalogEntry { .. })
        ));
    }

    #[test]
    fn env_is_validated() {
        let c = catalog();
        let env = |n: &str| PodOverrides {
            env: vec![EnvVar {
                name: n.into(),
                value: "v".into(),
            }],
            ..Default::default()
        };
        assert_eq!(
            resolve(&c, Some(&env("9BAD")), "p"),
            Err(PodShapeError::InvalidEnvName("9BAD".into()))
        );
        assert_eq!(
            resolve(&c, Some(&env("RAY_ADDRESS")), "p"),
            Err(PodShapeError::ReservedEnv("RAY_ADDRESS".into()))
        );
        let dup = PodOverrides {
            env: vec![
                EnvVar {
                    name: "A".into(),
                    value: "1".into(),
                },
                EnvVar {
                    name: "A".into(),
                    value: "2".into(),
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            resolve(&c, Some(&dup), "p"),
            Err(PodShapeError::DuplicateEnv("A".into()))
        );
        let ok = resolve(&c, Some(&env("AWS_ENDPOINT_URL")), "p")
            .unwrap()
            .unwrap();
        assert_eq!(ok.env.len(), 1);
    }

    #[test]
    fn resolution_is_deterministic() {
        let c = catalog();
        let o = PodOverrides {
            mounts: vec!["shared".into()],
            placement: Some("gpu".into()),
            service_account: Some("ray-workload".into()),
            env: vec![EnvVar {
                name: "A".into(),
                value: "1".into(),
            }],
        };
        assert_eq!(
            resolve(&c, Some(&o), "p").unwrap(),
            resolve(&c, Some(&o), "p").unwrap()
        );
    }

    // -----------------------------------------------------------------
    // Catalog validation (live-editable catalog, #66 follow-up)
    // -----------------------------------------------------------------

    #[test]
    fn a_good_catalog_validates() {
        catalog().validate().unwrap();
        PodShapeCatalog::default().validate().unwrap();
    }

    #[test]
    fn dangling_defaults_are_rejected() {
        // The motivating bug: this catalog 403s EVERY cluster create,
        // because defaults resolve whether or not the caller asked.
        let c = PodShapeCatalog {
            default_mounts: vec!["home".into()],
            ..Default::default()
        };
        assert_eq!(
            c.validate(),
            Err(CatalogError::DanglingDefault {
                kind: "mount",
                name: "home".into()
            })
        );
        // And it really would fail every create — the check earns its keep.
        assert!(resolve(&c, None, "p").is_err());

        let c = PodShapeCatalog {
            default_placement: Some("gpu".into()),
            ..Default::default()
        };
        assert!(matches!(
            c.validate(),
            Err(CatalogError::DanglingDefault {
                kind: "placement",
                ..
            })
        ));
        let c = PodShapeCatalog {
            default_service_account: Some("ray-workload".into()),
            ..Default::default()
        };
        assert!(matches!(
            c.validate(),
            Err(CatalogError::DanglingDefault {
                kind: "service account",
                ..
            })
        ));
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let c = PodShapeCatalog {
            mounts: vec![home(), home()],
            ..Default::default()
        };
        assert_eq!(
            c.validate(),
            Err(CatalogError::DuplicateName {
                kind: "mount",
                name: "home".into()
            })
        );
    }

    #[test]
    fn malformed_mounts_are_rejected() {
        let bad = |m: MountEntry| {
            PodShapeCatalog {
                mounts: vec![m],
                ..Default::default()
            }
            .validate()
        };
        assert!(matches!(
            bad(MountEntry {
                name: "".into(),
                ..home()
            }),
            Err(CatalogError::EmptyName("mount"))
        ));
        assert!(matches!(
            bad(MountEntry {
                claim_name: "".into(),
                ..home()
            }),
            Err(CatalogError::MissingField { .. })
        ));
        assert!(matches!(
            bad(MountEntry {
                mount_path: "home/ray".into(),
                ..home()
            }),
            Err(CatalogError::RelativeMountPath { .. })
        ));
        // Caught with `{project}` still unexpanded, so the authoring mistake
        // is reported independent of any project name.
        assert!(matches!(
            bad(MountEntry {
                sub_path: Some("home/{project}/../../root".into()),
                ..home()
            }),
            Err(CatalogError::BadSubPath { .. })
        ));
        assert!(matches!(
            bad(MountEntry {
                sub_path: Some("/etc".into()),
                ..home()
            }),
            Err(CatalogError::BadSubPath { .. })
        ));
    }

    #[test]
    fn malformed_tolerations_are_rejected() {
        let bad = |t: TolerationEntry| {
            PodShapeCatalog {
                placements: vec![PlacementEntry {
                    name: "p".into(),
                    tolerations: vec![t],
                    ..Default::default()
                }],
                ..Default::default()
            }
            .validate()
        };
        let base = TolerationEntry {
            key: "nvidia.com/gpu".into(),
            operator: "Equal".into(),
            value: Some("true".into()),
            effect: "NoSchedule".into(),
        };
        assert!(bad(base.clone()).is_ok());
        assert!(matches!(
            bad(TolerationEntry {
                operator: "In".into(),
                ..base.clone()
            }),
            Err(CatalogError::BadToleration { .. })
        ));
        assert!(matches!(
            bad(TolerationEntry {
                effect: "Evict".into(),
                ..base.clone()
            }),
            Err(CatalogError::BadToleration { .. })
        ));
        // `Exists` ignores `value`; carrying one means the author expected
        // matching semantics Kubernetes will not give them.
        assert!(matches!(
            bad(TolerationEntry {
                operator: "Exists".into(),
                ..base
            }),
            Err(CatalogError::BadToleration { .. })
        ));
    }

    #[test]
    fn the_catalog_round_trips_through_json() {
        // It lives in the policy store row now, so it must survive serde
        // both ways.
        let c = catalog();
        let j = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<PodShapeCatalog>(&j).unwrap(), c);
        // Rows written before the catalog existed stay readable.
        let legacy: PodShapeCatalog = serde_json::from_str("{}").unwrap();
        assert!(legacy.is_empty());
    }

    #[test]
    fn catalog_parses_from_toml_with_defaults() {
        let c: PodShapeCatalog = toml::from_str(
            r#"
            default_mounts = ["home"]
            service_accounts = ["ray-workload"]

            [[mounts]]
            name = "home"
            claim_name = "nebari-home"
            mount_path = "/home/ray"
            sub_path = "home/{project}"

            [[placements]]
            name = "gpu"
            node_selector = { accelerator = "a100" }
            tolerations = [{ key = "nvidia.com/gpu", operator = "Exists" }]
            "#,
        )
        .unwrap();
        assert_eq!(c.mounts.len(), 1);
        assert!(!c.mounts[0].read_only, "read_only defaults to false");
        // Toleration effect defaults to the one a GPU taint actually uses.
        assert_eq!(c.placements[0].tolerations[0].effect, "NoSchedule");
        assert!(!c.is_empty());
    }
}
