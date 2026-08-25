use std::io::Write as _;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use mobula_auth::{flows, AuthConfig, Validator};
use mobula_core::{ClusterRegistry, TokenSourceNote};

#[derive(Parser)]
#[command(
    name = "mobula",
    version,
    about = "FOSS control plane for Ray clusters"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the control-plane API server.
    Serve {
        /// Address to bind.
        #[arg(long, default_value = "127.0.0.1:8484")]
        bind: std::net::SocketAddr,
        /// TOML cluster registry for the job gateway (Phase 1 static
        /// registry; the lifecycle controller replaces this in Phase 3).
        /// Prefer `auth_token_env` (name of an env var read at startup)
        /// over a plaintext `auth_token` (#57). When the file contains
        /// plaintext auth_tokens, a warning is logged if its permissions
        /// are more permissive than 0600 (#4).
        #[arg(long)]
        registry: Option<std::path::PathBuf>,
        /// TOML auth config (OIDC issuer, audience, role mappings).
        /// When set, every request needs a valid Bearer JWT and
        /// non-loopback binds are permitted (Phase 2, ADR-0003).
        #[arg(long)]
        auth_config: Option<std::path::PathBuf>,
        /// Append-only JSONL audit log file. `mobula::audit` events
        /// (every proxied request + every authz denial) are written here
        /// in addition to normal stdout logging.
        #[arg(long)]
        audit_log: Option<std::path::PathBuf>,
        /// DANGER: serve without authentication on a non-loopback
        /// address. Anyone who can reach the port can run code on every
        /// registered cluster. Refused by default (security issue #1).
        #[arg(long)]
        dev_allow_unauthenticated: bool,
        /// DANGER: permit auth tokens over cleartext http:// southbound
        /// (local dev only; security issue #2).
        #[arg(long)]
        allow_insecure_transport: bool,
        /// Enable the cluster lifecycle controller: reconcile RayClusters
        /// in this Kubernetes namespace via KubeRay. Requires cluster
        /// access; mounts the /api/v1/clusters routes and runs the resync
        /// loop (Phase 3, ADR-0006).
        #[arg(long)]
        kuberay_namespace: Option<String>,
        /// Database for desired cluster state (used with
        /// --kuberay-namespace, --demo, --local-auth): either a SQLite
        /// file path (created if missing) or a postgres:// /
        /// postgresql:// URL (schema auto-created on connect). Defaults
        /// to in-memory (state lost on restart) if unset.
        #[arg(long)]
        db: Option<String>,
        /// Reconcile resync interval, seconds (with --kuberay-namespace).
        #[arg(long, default_value = "30")]
        reconcile_interval_secs: u64,
        /// Usage metering interval, seconds (Slice 4). The metering loop
        /// samples Kueue ledger usage (or observed-spec estimates when
        /// Kueue is absent) into the store for /api/v1/usage and
        /// /api/v1/metrics. Off when no store is configured.
        #[arg(long, default_value = "60")]
        metering_interval_secs: u64,
        /// Enable local (IdP-free) auth (ADR-0011): username/password
        /// login issuing opaque bearer tokens from the store. Counts as
        /// configured authentication for the fail-closed non-loopback
        /// rule. Requires a store: uses --db when set, otherwise an
        /// in-memory store (users lost on restart). On first boot with an
        /// empty users table, an `admin` user is created with a random
        /// password (written 0600 next to the DB and printed once to the
        /// log); MOBULA_LOCAL_ADMIN_PASSWORD overrides it (demos only).
        #[arg(long)]
        local_auth: bool,
        /// TOML governance file (Phase 4): `[prices]` as resource→$/hour
        /// (e.g. cpu = 0.04, "nvidia.com/gpu" = 2.50) for cost estimates,
        /// and `[quotas] project = { cpu = 100, ... }` for admission
        /// control. Without it there are no cost estimates and no quotas.
        /// This is the boot-time DEFAULT: it seeds the store's policy row,
        /// which is then editable via `PUT /api/v1/settings/policy` — the
        /// store wins once edited (api-v1.md §5.16).
        #[arg(long)]
        policy: Option<std::path::PathBuf>,
        /// DEMO: mount the full cluster/service API backed by an in-memory
        /// mock provisioner instead of KubeRay — no Kubernetes required.
        /// For local testing / docker compose / dashboard development only;
        /// nothing is actually provisioned. Ignored if --kuberay-namespace
        /// is set.
        #[arg(long)]
        demo: bool,
    },
    /// Sign in and store the token: OIDC device-code flow by default, or
    /// local username/password auth with --local (ADR-0011).
    Login {
        /// OIDC issuer URL (e.g. https://keycloak.example/realms/nebari).
        #[arg(long, required_unless_present = "local", conflicts_with = "local")]
        issuer: Option<String>,
        /// Public OAuth client id registered for the Mobula CLI.
        #[arg(long, default_value = "mobula-cli")]
        client_id: String,
        /// Requested scopes.
        #[arg(long, default_value = "openid profile email")]
        scope: String,
        /// Local auth: username/password login against the control plane.
        #[arg(long)]
        local: bool,
        /// Local auth username.
        #[arg(long, required_if_eq("local", "true"))]
        username: Option<String>,
        /// Local auth: read the password from stdin (one line). There is
        /// no interactive hidden prompt — pipe it: `pass show mobula |
        /// mobula login --local --username admin --password-stdin`.
        #[arg(long, requires = "local")]
        password_stdin: bool,
        /// Control-plane URL for local login.
        #[arg(long, env = "MOBULA_SERVER", default_value = "http://127.0.0.1:8484")]
        server: String,
    },
    /// Log out: revoke the stored token server-side when it is a local
    /// PAT (OIDC JWTs are stateless — nothing to revoke), then delete the
    /// stored credentials.
    Logout,
    /// Print a bearer token: the stored login token by default, or a
    /// fresh service-account token with --issuer/--client-id/--client-secret.
    Token {
        /// Service account: OIDC issuer URL.
        #[arg(long, requires = "client_id", requires = "client_secret")]
        issuer: Option<String>,
        /// Service account: confidential client id.
        #[arg(long)]
        client_id: Option<String>,
        /// Service account: client secret (or set MOBULA_CLIENT_SECRET
        /// to keep it out of shell history).
        #[arg(long, env = "MOBULA_CLIENT_SECRET", hide_env_values = true)]
        client_secret: Option<String>,
        /// Optional scope for the client-credentials grant.
        #[arg(long)]
        scope: Option<String>,
    },
    /// Exchange a user's token for a Mobula-audience token that carries the
    /// USER as subject (RFC 8693, #102). A trusted service uses this to submit
    /// jobs on a human's behalf so the run attributes to the human, not the
    /// service account. Prints the exchanged access token.
    Exchange {
        /// OIDC issuer URL (its token endpoint performs the exchange).
        #[arg(long)]
        issuer: String,
        /// The trusted service's confidential client id (e.g. checkmaite-svc).
        #[arg(long)]
        client_id: String,
        /// The service's client secret (or set MOBULA_CLIENT_SECRET to keep
        /// it out of shell history).
        #[arg(long, env = "MOBULA_CLIENT_SECRET", hide_env_values = true)]
        client_secret: String,
        /// The user's token to exchange (their gateway-verified access/id
        /// token). Read from stdin with --subject-token-stdin instead to keep
        /// it out of the process table.
        #[arg(long, conflicts_with = "subject_token_stdin")]
        subject_token: Option<String>,
        /// Read the user's subject token from stdin (one line).
        #[arg(long)]
        subject_token_stdin: bool,
        /// Treat the subject token as an OIDC id token rather than an access
        /// token (RFC 8693 subject_token_type).
        #[arg(long)]
        id_token: bool,
        /// Requested audience for the exchanged token (defaults to "mobula").
        #[arg(long, default_value = "mobula")]
        audience: String,
        /// Optional requested scope.
        #[arg(long)]
        scope: Option<String>,
    },
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let audit_log = match &cli.command {
        Command::Serve { audit_log, .. } => audit_log.clone(),
        _ => None,
    };
    init_tracing(audit_log.as_deref())?;

    // FIPS 140-3 (#61, ADR-0012): a `fips` build must run all TLS on the
    // aws-lc-rs FIPS-validated provider; abort startup (panic) unless it is
    // confirmed active. Not compiled in non-fips builds — nothing to enforce.
    #[cfg(feature = "fips")]
    {
        mobula_core::crypto::enforce_fips_startup();
        tracing::info!("FIPS 140-3 mode: rustls on the aws-lc-rs FIPS-validated crypto provider");
    }

    match cli.command {
        Command::Serve {
            bind,
            registry,
            auth_config,
            audit_log: _,
            dev_allow_unauthenticated,
            allow_insecure_transport,
            kuberay_namespace,
            db,
            reconcile_interval_secs,
            metering_interval_secs,
            local_auth,
            policy,
            demo,
        } => {
            // Governance config (Phase 4): prices + per-project quotas from
            // a TOML file. Parse fail-fast like the auth config.
            let policy_config: mobula_api::clusters::PolicyConfig = match policy {
                Some(path) => {
                    let raw = std::fs::read_to_string(&path)?;
                    let cfg = parse_policy(&raw).map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("invalid policy file {}: {e}", path.display()),
                        )
                    })?;
                    tracing::info!(
                        prices = cfg.prices.as_ref().map(|p| p.0.len()).unwrap_or(0),
                        quotas = cfg.quotas.len(),
                        "governance policy loaded"
                    );
                    cfg
                }
                None => Default::default(),
            };
            let validator = match auth_config {
                Some(path) => {
                    let raw = std::fs::read_to_string(&path)?;
                    let cfg: AuthConfig = toml::from_str(&raw).map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("invalid auth config {}: {e}", path.display()),
                        )
                    })?;
                    tracing::info!(issuer = %cfg.issuer, audience = %cfg.audience, "OIDC discovery");
                    let v = Validator::discover(
                        cfg,
                        mobula_auth::idp_client(),
                        allow_insecure_transport,
                    )
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                    Some(Arc::new(v))
                }
                None => None,
            };
            let registry = match registry {
                Some(path) => load_registry(&path)?,
                None => ClusterRegistry::default(),
            };
            for c in &registry.clusters {
                tracing::info!(id = %c.id, hostname = %c.hostname, "cluster registered");
            }
            tracing::info!(clusters = registry.clusters.len(), "registry loaded");

            // Lifecycle controller: when a KubeRay namespace is configured,
            // stand up the desired-state store + KubeRay provisioner, spawn
            // the resync loop, and mount the cluster routes on that store
            // (Phase 3, ADR-0006). Without it, serve is gateway-only.
            let mut service_provisioner: Option<
                std::sync::Arc<dyn mobula_provision::ServiceProvisioner>,
            > = None;
            let mut cluster_provisioner: Option<std::sync::Arc<dyn mobula_provision::Provisioner>> =
                None;
            let store: Option<std::sync::Arc<dyn mobula_controller::Store>> =
                match &kuberay_namespace {
                    Some(ns) => {
                        // --db selects the backend (SQLite path or
                        // postgres:// URL); start_lifecycle is generic over
                        // the concrete store type the reconciler requires.
                        let handle = connect_store(
                            db.as_deref(),
                            "no --db: cluster state is in-memory and lost on restart",
                        )
                        .await?;
                        let (store, svc_prov, cluster_prov) = match handle {
                            StoreHandle::Sqlite(s) => {
                                start_lifecycle(
                                    s,
                                    ns,
                                    reconcile_interval_secs,
                                    metering_interval_secs,
                                )
                                .await?
                            }
                            StoreHandle::Postgres(s) => {
                                start_lifecycle(
                                    s,
                                    ns,
                                    reconcile_interval_secs,
                                    metering_interval_secs,
                                )
                                .await?
                            }
                        };
                        // The same provisioner backs both the reconcile loop
                        // (clusters) and the Serve-service routes.
                        service_provisioner = Some(svc_prov);
                        cluster_provisioner = Some(cluster_prov);
                        Some(store)
                    }
                    // DEMO: full cluster/service API on a mock provisioner —
                    // no Kubernetes (local testing / compose). Uses --db when
                    // set so demo state (incl. local-auth users/tokens and
                    // usage history) survives restarts; in-memory otherwise.
                    None if demo => {
                        let handle = connect_store(
                            db.as_deref(),
                            "no --db: demo state is in-memory and lost on restart",
                        )
                        .await?;
                        let (store, svc_prov, cluster_prov) = match handle {
                            StoreHandle::Sqlite(s) => start_demo(s, metering_interval_secs).await?,
                            StoreHandle::Postgres(s) => {
                                start_demo(s, metering_interval_secs).await?
                            }
                        };
                        service_provisioner = Some(svc_prov);
                        cluster_provisioner = Some(cluster_prov);
                        Some(store)
                    }
                    None => None,
                };

            // Local auth (ADR-0011) needs a store for users/tokens. Reuse
            // the lifecycle/demo store when one is already up; otherwise
            // open --db (or an in-memory store, with a loud warning).
            let mut store = store;
            if local_auth && store.is_none() {
                let concrete: std::sync::Arc<dyn mobula_controller::Store> = connect_store(
                    db.as_deref(),
                    "--local-auth without --db: users and tokens are in-memory \
                     and lost on restart",
                )
                .await?
                .into_dyn();
                store = Some(concrete);
            }
            let local_authenticator = if local_auth {
                let store = store
                    .as_ref()
                    .expect("local auth store ensured above")
                    .clone();
                // The bootstrap password file is written next to the DB —
                // only meaningful when --db is a filesystem path.
                let db_path = db.as_deref().and_then(|d| match db_target(Some(d)) {
                    DbTarget::Sqlite(_) => Some(std::path::Path::new(d)),
                    _ => None,
                });
                bootstrap_local_admin(&store, db_path).await?;
                tracing::info!("local auth enabled (ADR-0011): /api/v1/auth/login");
                Some(std::sync::Arc::new(
                    mobula_auth::local::LocalAuthenticator::new(store, 86_400, 90),
                ))
            } else {
                None
            };

            // Fail-closed invariants (non-loopback needs auth, registry
            // validation) are enforced inside serve() so they can't be
            // bypassed by library embedders (#36). The non-loopback refusal
            // is also enforced at the router level (#45), so a direct
            // axum::serve of a validator-less router still fails closed.
            mobula_api::serve(
                bind,
                mobula_api::ServeOptions {
                    registry,
                    validator,
                    local_auth: local_authenticator,
                    allow_unauthenticated: dev_allow_unauthenticated,
                    allow_insecure_transport,
                    store,
                    policy: policy_config,
                    services: service_provisioner,
                    provisioner: cluster_provisioner,
                },
            )
            .await
        }
        Command::Login {
            issuer,
            client_id,
            scope,
            local,
            username,
            password_stdin,
            server,
        } => {
            if local {
                let username = username.expect("clap enforces --username with --local");
                login_local(&server, &username, password_stdin).await
            } else {
                let issuer = issuer.expect("clap enforces --issuer without --local");
                login(&issuer, &client_id, &scope).await
            }
        }
        Command::Logout => logout().await,
        Command::Token {
            issuer,
            client_id,
            client_secret,
            scope,
        } => match (issuer, client_id, client_secret) {
            (Some(issuer), Some(id), Some(secret)) => {
                service_token(&issuer, &id, &secret, scope.as_deref()).await
            }
            _ => {
                let creds = load_credentials()?;
                match stored_token_action(&creds, unix_now()) {
                    StoredTokenAction::Valid => {
                        println!("{}", creds.access_token);
                        Ok(())
                    }
                    StoredTokenAction::ExpiredNoRefresh => {
                        Err(std::io::Error::other("token expired, run mobula login"))
                    }
                    StoredTokenAction::Refresh => refresh_stored_token(&creds).await,
                }
            }
        },
        Command::Exchange {
            issuer,
            client_id,
            client_secret,
            subject_token,
            subject_token_stdin,
            id_token,
            audience,
            scope,
        } => {
            let subject_token = if subject_token_stdin {
                read_line_from_stdin()?
            } else {
                subject_token.ok_or_else(|| {
                    std::io::Error::other("provide --subject-token or --subject-token-stdin")
                })?
            };
            exchange_user_token(
                &issuer,
                &client_id,
                &client_secret,
                &subject_token,
                id_token,
                &audience,
                scope.as_deref(),
            )
            .await
        }
    }
}

/// Which store backend `--db` selects (pure; no connections). A
/// `postgres://` / `postgresql://` URL picks Postgres; anything else is a
/// SQLite file path (the pre-Postgres behavior, `mode=rwc`). `None` means
/// the in-memory store.
#[derive(Debug, PartialEq, Eq)]
enum DbTarget {
    InMemory,
    /// Full `sqlite://…?mode=rwc` connection URL.
    Sqlite(String),
    /// The `postgres://` / `postgresql://` URL as given.
    Postgres(String),
}

fn db_target(db: Option<&str>) -> DbTarget {
    match db {
        None => DbTarget::InMemory,
        Some(url) if url.starts_with("postgres://") || url.starts_with("postgresql://") => {
            DbTarget::Postgres(url.to_string())
        }
        Some(path) => DbTarget::Sqlite(format!("sqlite://{path}?mode=rwc")),
    }
}

/// The connected store, keeping the concrete type so the reconciler /
/// metering generics (which require `S: Store`) stay monomorphized.
enum StoreHandle {
    Sqlite(std::sync::Arc<mobula_controller::SqliteStore>),
    Postgres(std::sync::Arc<mobula_controller::PostgresStore>),
}

impl StoreHandle {
    fn into_dyn(self) -> std::sync::Arc<dyn mobula_controller::Store> {
        match self {
            StoreHandle::Sqlite(s) => s,
            StoreHandle::Postgres(s) => s,
        }
    }
}

/// Shared `--db` wiring for the kuberay, demo, and local-auth call sites:
/// connect the backend selected by [`db_target`], or an in-memory SQLite
/// store (with a warning) when `--db` is unset.
async fn connect_store(db: Option<&str>, in_memory_warning: &str) -> std::io::Result<StoreHandle> {
    match db_target(db) {
        DbTarget::InMemory => {
            tracing::warn!("{in_memory_warning}");
            Ok(StoreHandle::Sqlite(std::sync::Arc::new(
                mobula_controller::SqliteStore::in_memory()
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?,
            )))
        }
        DbTarget::Sqlite(url) => Ok(StoreHandle::Sqlite(std::sync::Arc::new(
            mobula_controller::SqliteStore::connect(&url)
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?,
        ))),
        DbTarget::Postgres(url) => Ok(StoreHandle::Postgres(std::sync::Arc::new(
            mobula_controller::PostgresStore::connect(&url)
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?,
        ))),
    }
}

/// Phase 3 lifecycle bring-up (ADR-0006), generic over the store backend so
/// `--db` can pick SQLite or Postgres: KubeRay provisioner, reconcile loop,
/// pool reconcile loop, and usage metering. Returns the store (erased to
/// `dyn Store` for the API routes), the service provisioner, and the cluster
/// provisioner (the metrics passthrough's endpoint source, #52).
async fn start_lifecycle<S: mobula_controller::Store + 'static>(
    concrete: std::sync::Arc<S>,
    ns: &str,
    reconcile_interval_secs: u64,
    metering_interval_secs: u64,
) -> std::io::Result<(
    std::sync::Arc<dyn mobula_controller::Store>,
    std::sync::Arc<dyn mobula_provision::ServiceProvisioner>,
    std::sync::Arc<dyn mobula_provision::Provisioner>,
)> {
    // Multi-engine: one KubeRay backend and one Dask backend, fronted by the
    // EngineRouter which dispatches each cluster to the right one by
    // `spec.engine`. The router backs the reconcile loop (clusters) and the
    // cluster obs/metrics/nodes passthrough (so those dispatch per engine);
    // the Serve-service routes stay Ray-only (Dask has no serving surface).
    let ray = std::sync::Arc::new(
        mobula_provision::KubeRayProvisioner::connect(ns.to_string(), false)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    let dask = std::sync::Arc::new(
        mobula_provision::DaskProvisioner::connect(ns.to_string())
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    let router = std::sync::Arc::new(mobula_provision::EngineRouter::from_parts(
        ray.clone(),
        dask,
    ));
    let service_provisioner: std::sync::Arc<dyn mobula_provision::ServiceProvisioner> = ray.clone();
    let cluster_provisioner: std::sync::Arc<dyn mobula_provision::Provisioner> = router.clone();
    // Global actuation rate limit (#43): cap provider apply calls so a burst
    // of failing clusters can't hammer the Kubernetes API. Generous enough
    // for normal ops (per-cluster exponential backoff is the primary
    // throttle); this is defense-in-depth.
    let reconciler = mobula_controller::Reconciler::with_limits(
        concrete.clone(),
        router,
        mobula_controller::RateLimits {
            capacity: 20.0,
            refill_per_sec: 5.0,
        },
    );
    // ADR-0007 restore quarantine (#41): before actuating, check whether the
    // store was restored behind reality (a backing cluster newer than the
    // DB). If so, the reconciler quarantines itself and only observes until
    // an operator clears it.
    match reconciler.detect_stale_restore().await {
        Ok(true) => tracing::error!(
            "started QUARANTINED after detecting a stale DB restore; not actuating until cleared"
        ),
        Ok(false) => {}
        Err(e) => tracing::warn!(error = %e, "stale-restore boot check failed"),
    }
    let interval = std::time::Duration::from_secs(reconcile_interval_secs);
    tokio::spawn(async move {
        reconciler
            .run(interval, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await;
    });
    // ADR-0010: pool reconcile loop — converges each pool's Kueue objects
    // (Cohort/ResourceFlavor/ClusterQueue/LocalQueue) and records
    // ClusterQueue status observations. Inert when the Kueue CRDs are absent
    // (pools stay in-process quota only).
    let kueue = std::sync::Arc::new(
        mobula_provision::KueueClient::connect()
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    let pool_reconciler = mobula_controller::PoolReconciler::new(concrete.clone(), kueue.clone());
    tokio::spawn(async move {
        pool_reconciler
            .run(interval, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await;
    });
    // Slice 4: usage metering — samples the Kueue reservation ledger
    // (ClusterQueue + LocalQueue flavorsUsage) into the store for
    // /api/v1/usage and /api/v1/metrics.
    let metering = mobula_controller::Metering::new(
        concrete.clone(),
        Some(kueue),
        std::time::Duration::from_secs(metering_interval_secs),
    );
    tokio::spawn(async move {
        metering
            .run(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await;
    });
    tracing::info!(namespace = %ns, "cluster lifecycle controller + services enabled");
    Ok((concrete, service_provisioner, cluster_provisioner))
}

/// DEMO bring-up, generic over the store backend: seed the dashboard's job
/// history, then run the mock provisioner, reconcile loop, and metering on
/// a snappy tick.
async fn start_demo<S: mobula_controller::Store + 'static>(
    concrete: std::sync::Arc<S>,
    metering_interval_secs: u64,
) -> std::io::Result<(
    std::sync::Arc<dyn mobula_controller::Store>,
    std::sync::Arc<dyn mobula_provision::ServiceProvisioner>,
    std::sync::Arc<dyn mobula_provision::Provisioner>,
)> {
    // Seed cross-cluster job history so the dashboard's Jobs screen has data
    // (incl. a record whose cluster no longer exists, showing history
    // outlives clusters). Skip when the store already has jobs (a persisted
    // --db survives restarts; seeding again would duplicate).
    if concrete
        .list_jobs()
        .await
        .map(|j| j.is_empty())
        .unwrap_or(true)
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        for (id, cluster, submitter, status, duration_secs, ago) in [
            (
                "raysubmit_a1b2",
                "demo-alpha",
                "alice@example.com",
                "SUCCEEDED",
                Some(742u64),
                3600u64,
            ),
            (
                "raysubmit_c3d4",
                "demo-alpha",
                "bob@example.com",
                "RUNNING",
                None,
                120,
            ),
            (
                "raysubmit_e5f6",
                "retired-beta",
                "alice@example.com",
                "FAILED",
                Some(51),
                7200,
            ),
            (
                "raysubmit_g7h8",
                "demo-gamma",
                "carol@example.com",
                "STOPPED",
                Some(310),
                1800,
            ),
        ] {
            let _ = concrete
                .record_job(mobula_core::JobRecord {
                    id: id.into(),
                    cluster: cluster.into(),
                    submitter: submitter.into(),
                    status: status.into(),
                    duration_secs,
                    submitted_at: now.saturating_sub(ago),
                })
                .await;
        }
    }
    let provisioner = std::sync::Arc::new(mobula_provision::DemoProvisioner::new());
    let service_provisioner: std::sync::Arc<dyn mobula_provision::ServiceProvisioner> =
        provisioner.clone();
    let cluster_provisioner: std::sync::Arc<dyn mobula_provision::Provisioner> =
        provisioner.clone();
    let reconciler = mobula_controller::Reconciler::new(concrete.clone(), provisioner);
    // Snappy tick so created clusters show Running quickly.
    let interval = std::time::Duration::from_secs(2);
    tokio::spawn(async move {
        reconciler
            .run(interval, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await;
    });
    // Slice 4: usage metering without Kubernetes — the Kueue-absent path
    // meters the min-demand baseline of desired cluster specs, so the demo's
    // usage endpoints have data.
    let metering = mobula_controller::Metering::new(
        concrete.clone(),
        None,
        std::time::Duration::from_secs(metering_interval_secs),
    );
    tokio::spawn(async move {
        metering
            .run(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await;
    });
    tracing::warn!("DEMO mode: in-memory mock provisioner — nothing is actually provisioned");
    Ok((concrete, service_provisioner, cluster_provisioner))
}

/// Parse the `--policy` TOML: `[prices]` resource→$/hour,
/// `[quotas] project = { resource = amount }` (Phase 4 governance), and
/// `[gpu] default_sharing = "whole-gpu" | "mig" | "time-slice"` (#58 — the
/// platform fallback for pool specs that leave `gpu_sharing` unset;
/// boot-time only, never seeded into the store).
fn parse_policy(raw: &str) -> Result<mobula_api::clusters::PolicyConfig, toml::de::Error> {
    #[derive(serde::Deserialize)]
    struct GpuSection {
        #[serde(default)]
        default_sharing: mobula_core::GpuSharing,
    }
    #[derive(serde::Deserialize)]
    struct PolicyFile {
        prices: Option<mobula_policy::PriceSheet>,
        quotas: Option<std::collections::HashMap<String, mobula_policy::ResourceMap>>,
        gpu: Option<GpuSection>,
    }
    let parsed: PolicyFile = toml::from_str(raw)?;
    Ok(mobula_api::clusters::PolicyConfig {
        prices: parsed.prices,
        quotas: parsed.quotas.unwrap_or_default(),
        gpu_default_sharing: parsed.gpu.map(|g| g.default_sharing).unwrap_or_default(),
    })
}

/// Bootstrap the first local admin when the users table is empty
/// (ADR-0011, artifact-keeper pattern): a random 20-char password written
/// 0600 next to the database AND printed once to the log, unless
/// MOBULA_LOCAL_ADMIN_PASSWORD is set (demos only — then the env value is
/// used and nothing is printed).
async fn bootstrap_local_admin(
    store: &std::sync::Arc<dyn mobula_controller::Store>,
    db: Option<&std::path::Path>,
) -> std::io::Result<()> {
    if !store
        .list_local_users()
        .await
        .map_err(std::io::Error::other)?
        .is_empty()
    {
        return Ok(());
    }
    let (password, from_env) = match std::env::var("MOBULA_LOCAL_ADMIN_PASSWORD") {
        Ok(p) if !p.is_empty() => (p, true),
        _ => (mobula_auth::local::random_password(20), false),
    };
    let hash = mobula_auth::local::hash_password(&password)
        .await
        .map_err(std::io::Error::other)?;
    store
        .create_local_user("admin", None, &hash, mobula_core::LocalRole::Admin)
        .await
        .map_err(std::io::Error::other)?;
    if from_env {
        tracing::warn!(
            "bootstrapped local 'admin' from MOBULA_LOCAL_ADMIN_PASSWORD — demo use only; \
             change the password and unset the variable"
        );
        return Ok(());
    }
    if let Some(db) = db {
        let dir = db.parent().unwrap_or(std::path::Path::new("."));
        let pw_path = dir.join("local-admin-password");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&pw_path)?;
        file.write_all(password.as_bytes())?;
        file.write_all(b"\n")?;
        tracing::warn!(path = %pw_path.display(), "local 'admin' password written (0600)");
    }
    tracing::warn!("local auth bootstrap — admin password (shown once): {password}");
    Ok(())
}

/// Local-auth login (ADR-0011): POST /api/v1/auth/login against the
/// control plane, store the opaque token like a device-flow token (0600).
async fn login_local(server: &str, username: &str, password_stdin: bool) -> std::io::Result<()> {
    if !password_stdin {
        return Err(std::io::Error::other(
            "no interactive password prompt is available; pipe the password with \
             --password-stdin",
        ));
    }
    let mut password = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut password)?;
    let password = password.trim_end_matches(['\n', '\r']).to_string();
    if password.is_empty() {
        return Err(std::io::Error::other("empty password on stdin"));
    }

    let url = format!("{}/api/v1/auth/login", server.trim_end_matches('/'));
    let res = mobula_auth::idp_client()
        .post(&url)
        .json(&serde_json::json!({"username": username, "password": password}))
        .send()
        .await
        .map_err(|e| std::io::Error::other(e.without_url().to_string()))?;
    if res.status() != reqwest::StatusCode::OK {
        return Err(std::io::Error::other(format!(
            "login failed: {}",
            res.status()
        )));
    }
    let body: serde_json::Value = res
        .json()
        .await
        .map_err(|e| std::io::Error::other(e.without_url().to_string()))?;
    let token = body["token"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("login response missing token"))?;
    save_credentials(&Credentials {
        access_token: token.to_string(),
        refresh_token: None,
        // For local logins this field carries the control-plane URL.
        issuer: server.to_string(),
        client_id: None,
    })?;
    let subject = body["identity"]["subject"].as_str().unwrap_or(username);
    let roles = body["identity"]["roles"]
        .as_array()
        .map(|r| {
            r.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    println!("Logged in as {subject} (roles: {roles}).");
    Ok(())
}

/// Revoke the stored token server-side when it is a local PAT, then delete
/// the credentials file. OIDC JWTs are stateless — local delete only.
async fn logout() -> std::io::Result<()> {
    let creds = load_credentials()?;
    if creds.access_token.starts_with("mob_") {
        let url = format!("{}/api/v1/auth/logout", creds.issuer.trim_end_matches('/'));
        // Best-effort: the local delete happens regardless.
        let _ = mobula_auth::idp_client()
            .post(&url)
            .bearer_auth(&creds.access_token)
            .send()
            .await;
    }
    let path = credentials_path()?;
    std::fs::remove_file(&path)?;
    println!("Logged out; removed {}", path.display());
    Ok(())
}

async fn login(issuer: &str, client_id: &str, scope: &str) -> std::io::Result<()> {
    let client = mobula_auth::idp_client();
    let meta = mobula_auth::discover_metadata(&client, issuer)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let device_ep = meta.device_authorization_endpoint.ok_or_else(|| {
        std::io::Error::other("issuer does not advertise a device_authorization_endpoint")
    })?;
    let token_ep = meta
        .token_endpoint
        .ok_or_else(|| std::io::Error::other("issuer does not advertise a token_endpoint"))?;

    let auth = flows::device_authorize(&client, &device_ep, client_id, scope)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let url = auth
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&auth.verification_uri);
    println!(
        "To sign in, open:\n\n    {url}\n\nand enter code: {}\n",
        auth.user_code
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(auth.expires_in);
    let mut interval = auth.interval.max(1);
    let token = loop {
        if std::time::Instant::now() > deadline {
            return Err(std::io::Error::other("device code expired before approval"));
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        match flows::poll_device_token(&client, &token_ep, client_id, &auth.device_code)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?
        {
            flows::DevicePoll::Pending { slow_down } => {
                if slow_down {
                    interval += 5; // RFC 8628 §3.5
                }
            }
            flows::DevicePoll::Ready(t) => break t,
        }
    };

    save_credentials(&Credentials {
        access_token: token.access_token.clone(),
        refresh_token: token.refresh_token.clone(),
        issuer: issuer.to_string(),
        client_id: Some(client_id.to_string()),
    })?;
    match token.expires_in {
        Some(secs) => println!("Logged in. Token expires in {secs}s."),
        None => println!("Logged in."),
    }
    println!("Attach it to Ray jobs with:");
    println!(
        "  export RAY_JOB_HEADERS=\"{{\\\"Authorization\\\": \\\"Bearer $(mobula token)\\\"}}\""
    );
    Ok(())
}

async fn service_token(
    issuer: &str,
    client_id: &str,
    client_secret: &str,
    scope: Option<&str>,
) -> std::io::Result<()> {
    let client = mobula_auth::idp_client();
    let meta = mobula_auth::discover_metadata(&client, issuer)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let token_ep = meta
        .token_endpoint
        .ok_or_else(|| std::io::Error::other("issuer does not advertise a token_endpoint"))?;
    let token = flows::client_credentials(&client, &token_ep, client_id, client_secret, scope)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    // Print only the token so it composes: $(mobula token --issuer ...)
    println!("{}", token.access_token);
    Ok(())
}

/// Read one trimmed, non-empty line from stdin (for piped secrets).
fn read_line_from_stdin() -> std::io::Result<String> {
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;
    let line = line.trim_end_matches(['\n', '\r']).to_string();
    if line.is_empty() {
        return Err(std::io::Error::other("empty input on stdin"));
    }
    Ok(line)
}

/// RFC 8693 token exchange (#102): swap the user's `subject_token` for a
/// Mobula-audience token whose subject is the USER, so a service submitting on
/// their behalf attributes runs to the human. Prints only the exchanged token.
async fn exchange_user_token(
    issuer: &str,
    client_id: &str,
    client_secret: &str,
    subject_token: &str,
    id_token: bool,
    audience: &str,
    scope: Option<&str>,
) -> std::io::Result<()> {
    let client = mobula_auth::idp_client();
    let meta = mobula_auth::discover_metadata(&client, issuer)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let token_ep = meta
        .token_endpoint
        .ok_or_else(|| std::io::Error::other("issuer does not advertise a token_endpoint"))?;
    let mut params = flows::TokenExchange::new(client_id, client_secret, subject_token);
    if id_token {
        params.subject_token_type = flows::TOKEN_TYPE_ID_TOKEN;
    }
    params.audience = Some(audience);
    params.scope = scope;
    let token = flows::exchange_token(&client, &token_ep, &params)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    println!("{}", token.access_token);
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What `mobula token` should do with the stored access token (#18).
#[derive(Debug, PartialEq, Eq)]
enum StoredTokenAction {
    /// Print it as-is.
    Valid,
    /// Expired JWT with a refresh token — attempt a refresh grant.
    Refresh,
    /// Expired JWT and no way to refresh — the user must re-login.
    ExpiredNoRefresh,
}

/// Client-side expiry decision for the stored token. Opaque local-auth
/// tokens (`mob_…`) carry no exp — the server enforces their lifetime, so
/// they pass through, as do undecodable tokens (the server validates for
/// real; this is display-only hygiene).
fn stored_token_action(creds: &Credentials, now: u64) -> StoredTokenAction {
    let Some(exp) = jwt_exp(&creds.access_token) else {
        return StoredTokenAction::Valid;
    };
    if exp > now {
        return StoredTokenAction::Valid;
    }
    if creds.refresh_token.is_some() {
        StoredTokenAction::Refresh
    } else {
        StoredTokenAction::ExpiredNoRefresh
    }
}

/// Decode the `exp` claim from a JWT payload WITHOUT verifying the
/// signature — client-side display only; the server is the validator.
/// `None` for opaque tokens, non-JWT strings, and payloads without `exp`.
fn jwt_exp(token: &str) -> Option<u64> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64url_decode(payload)?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("exp")?.as_u64()
}

/// Minimal base64url (RFC 4648 §5) decoder — avoids a base64 dependency
/// for this one JWT payload decode.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Refresh grant against the stored issuer (RFC 6749 §6), persisting the
/// new tokens (0600) and printing the fresh access token. Any failure —
/// discovery, transport, grant rejected — means re-login (#18).
async fn refresh_stored_token(creds: &Credentials) -> std::io::Result<()> {
    let re_login = || std::io::Error::other("token expired, run mobula login");
    let Some(refresh) = creds.refresh_token.as_deref() else {
        return Err(re_login());
    };
    let client = mobula_auth::idp_client();
    let meta = mobula_auth::discover_metadata(&client, &creds.issuer)
        .await
        .map_err(|_| re_login())?;
    let token_ep = meta.token_endpoint.ok_or_else(re_login)?;
    // Logins predating #18 did not persist the client id; fall back to the
    // default public client.
    let client_id = creds.client_id.as_deref().unwrap_or("mobula-cli");
    let res = client
        .post(&token_ep)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", client_id),
        ])
        .send()
        .await
        .map_err(|_| re_login())?;
    if !res.status().is_success() {
        return Err(re_login());
    }
    let token: flows::TokenResponse = res.json().await.map_err(|_| re_login())?;
    save_credentials(&Credentials {
        access_token: token.access_token.clone(),
        // Providers may rotate refresh tokens; keep the old one when the
        // response omits a replacement.
        refresh_token: token.refresh_token.or_else(|| creds.refresh_token.clone()),
        issuer: creds.issuer.clone(),
        client_id: creds.client_id.clone(),
    })?;
    println!("{}", token.access_token);
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Credentials {
    access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    issuer: String,
    /// OAuth client id used at login — needed for the refresh_token grant
    /// (#18). Absent for local logins and pre-#18 credential files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
}

fn credentials_path() -> std::io::Result<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("MOBULA_CONFIG_DIR") {
        return Ok(std::path::PathBuf::from(dir).join("credentials.json"));
    }
    let home = std::env::var("HOME")
        .map_err(|_| std::io::Error::other("HOME is not set; set MOBULA_CONFIG_DIR"))?;
    Ok(std::path::PathBuf::from(home)
        .join(".config")
        .join("mobula")
        .join("credentials.json"))
}

fn save_credentials(creds: &Credentials) -> std::io::Result<()> {
    let path = credentials_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(creds)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&json)?;
    Ok(())
}

fn load_credentials() -> std::io::Result<Credentials> {
    let path = credentials_path()?;
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "no stored credentials at {} — run `mobula login`",
                path.display()
            ),
        )
    })?;
    serde_json::from_str(&raw)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

fn load_registry(path: &std::path::Path) -> std::io::Result<ClusterRegistry> {
    let raw = std::fs::read_to_string(path)?;
    let mut registry: ClusterRegistry = toml::from_str(&raw).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid registry {}: {e}", path.display()),
        )
    })?;
    // Token-source bookkeeping (#57): warn on plaintext tokens, acknowledge
    // env-sourced ones — names only, never values.
    for note in registry.token_source_notes() {
        match note {
            TokenSourceNote::Plaintext { id } => tracing::warn!(
                cluster = %id,
                "plaintext token in registry file; prefer auth_token_env — issue #57"
            ),
            TokenSourceNote::Env { id, var } => {
                tracing::info!(cluster = %id, env_var = %var, "token source: env")
            }
        }
    }
    if let Some(warning) = registry_permission_warning(path, &registry) {
        tracing::warn!("{warning}");
    }
    // Fail fast before serving: an unresolved env indirection means a
    // missing cluster credential.
    registry.resolve_auth_tokens().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid registry {}: {e}", path.display()),
        )
    })?;
    Ok(registry)
}

/// A registry file carrying plaintext `auth_token`s holds bearer-equivalent
/// secrets, like credentials.json — warn (never fail) when group/other can
/// read it (#4). Entries using `auth_token_env` hold no secret in the file
/// (#57) and don't need the warning. `None` when no plaintext tokens are
/// present or the mode is 0600 or tighter.
fn registry_permission_warning(
    path: &std::path::Path,
    registry: &ClusterRegistry,
) -> Option<String> {
    if !registry
        .clusters
        .iter()
        .any(|c| c.auth_token.is_some() && c.auth_token_env.is_none())
    {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).ok()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some(format!(
                "registry {} contains auth_tokens but is mode {:04o} — group/other can \
                 read cluster bearer tokens; run: chmod 600 {}",
                path.display(),
                mode,
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    None
}

/// Stdout logging always; when `audit_log` is set, `mobula::audit`
/// events are additionally appended as JSON lines to that file
/// (append-only, exportable — REQUIREMENTS §3.7).
fn init_tracing(audit_log: Option<&std::path::Path>) -> std::io::Result<()> {
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::prelude::*;

    let stdout = tracing_subscriber::fmt::layer().with_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
    );
    match audit_log {
        Some(path) => {
            let mut opts = std::fs::OpenOptions::new();
            opts.create(true).append(true);
            // Audit records carry subjects, paths, and cluster ids — not
            // world/group readable (#33).
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let file = opts.open(path)?;
            let audit = tracing_subscriber::fmt::layer()
                .json()
                .with_writer(Arc::new(file))
                .with_filter(
                    Targets::new()
                        .with_target("mobula::audit", tracing::level_filters::LevelFilter::INFO),
                );
            tracing_subscriber::registry()
                .with(stdout)
                .with(audit)
                .init();
        }
        None => tracing_subscriber::registry().with(stdout).init(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bootstrap_local_admin_creates_admin_once() {
        let store: std::sync::Arc<dyn mobula_controller::Store> =
            std::sync::Arc::new(mobula_controller::InMemoryStore::new());
        std::env::set_var("MOBULA_LOCAL_ADMIN_PASSWORD", "bootstrap-test-pw");
        bootstrap_local_admin(&store, None).await.unwrap();
        // Second call is a no-op (users table no longer empty).
        bootstrap_local_admin(&store, None).await.unwrap();
        std::env::remove_var("MOBULA_LOCAL_ADMIN_PASSWORD");

        let users = mobula_controller::Store::list_local_users(&*store)
            .await
            .unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin");
        assert_eq!(users[0].role, mobula_core::LocalRole::Admin);
        // The env password actually verifies (via the auth module).
        let auth = mobula_auth::local::LocalAuthenticator::new(store, 3600, 90);
        assert!(auth.login("admin", "bootstrap-test-pw").await.is_ok());
    }

    #[test]
    fn db_target_selects_backend_without_connecting() {
        // No --db → in-memory.
        assert_eq!(db_target(None), DbTarget::InMemory);
        // Plain paths (relative and absolute) → SQLite, mode=rwc preserved.
        assert_eq!(
            db_target(Some("state.db")),
            DbTarget::Sqlite("sqlite://state.db?mode=rwc".into())
        );
        assert_eq!(
            db_target(Some("/var/lib/mobula/state.db")),
            DbTarget::Sqlite("sqlite:///var/lib/mobula/state.db?mode=rwc".into())
        );
        // postgres:// and postgresql:// URLs → Postgres, URL passed through.
        assert_eq!(
            db_target(Some("postgres://mobula:mobula@localhost:5432/mobula")),
            DbTarget::Postgres("postgres://mobula:mobula@localhost:5432/mobula".into())
        );
        assert_eq!(
            db_target(Some("postgresql://mobula@db.internal/mobula")),
            DbTarget::Postgres("postgresql://mobula@db.internal/mobula".into())
        );
    }

    #[test]
    fn load_registry_missing_file_errors() {
        assert!(load_registry(std::path::Path::new("/nonexistent/clusters.toml")).is_err());
    }

    #[test]
    fn parse_policy_reads_prices_and_quotas() {
        let cfg = parse_policy(
            r#"
[prices]
cpu = 0.04
memory = 0.005
"nvidia.com/gpu" = 2.50

[quotas]
dev = { cpu = 200, memory = 400, "nvidia.com/gpu" = 8 }
"#,
        )
        .unwrap();
        let prices = cfg.prices.expect("prices parsed");
        assert_eq!(prices.0["nvidia.com/gpu"], 2.50);
        assert_eq!(cfg.quotas["dev"].0["cpu"], 200.0);
        // No [gpu] section → the safe platform default.
        assert_eq!(cfg.gpu_default_sharing, mobula_core::GpuSharing::WholeGpu);
        assert!(parse_policy("prices = 'nope'").is_err());
        assert!(parse_policy("").is_ok(), "empty file = no governance");
    }

    #[test]
    fn parse_policy_reads_gpu_default_sharing() {
        let cfg = parse_policy("[gpu]\ndefault_sharing = \"mig\"\n").unwrap();
        assert_eq!(cfg.gpu_default_sharing, mobula_core::GpuSharing::Mig);
        // An empty [gpu] section still defaults to whole-gpu.
        let cfg = parse_policy("[gpu]\n").unwrap();
        assert_eq!(cfg.gpu_default_sharing, mobula_core::GpuSharing::WholeGpu);
        // Unknown modes fail at boot, never silently coerce.
        assert!(parse_policy("[gpu]\ndefault_sharing = \"shared\"\n").is_err());
    }

    #[test]
    fn load_registry_rejects_invalid_toml() {
        let dir = std::env::temp_dir().join(format!("mobula-cli-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        std::fs::write(&path, "clusters = 'not a table'").unwrap();
        let err = load_registry(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_registry_reads_valid_file() {
        let dir = std::env::temp_dir().join(format!("mobula-cli-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ok.toml");
        std::fs::write(
            &path,
            "[[clusters]]\nid = \"a\"\nhostname = \"a.test\"\napi_base_url = \"http://a:8265\"\n",
        )
        .unwrap();
        let reg = load_registry(&path).unwrap();
        assert_eq!(reg.clusters.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_registry_resolves_auth_token_env() {
        let dir = std::env::temp_dir().join(format!("mobula-cli-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("env.toml");
        std::fs::write(
            &path,
            "[[clusters]]\nid = \"a\"\nhostname = \"a.test\"\n\
             api_base_url = \"http://a:8265\"\n\
             auth_token_env = \"MOBULA_CLI_TEST_REGISTRY_TOKEN\"\n",
        )
        .unwrap();

        // Missing var → fail fast, naming the entry and the var.
        std::env::remove_var("MOBULA_CLI_TEST_REGISTRY_TOKEN");
        let err = load_registry(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains('a') && msg.contains("MOBULA_CLI_TEST_REGISTRY_TOKEN"),
            "{msg}"
        );

        // Set var → token resolved into auth_token at load time (#57).
        std::env::set_var("MOBULA_CLI_TEST_REGISTRY_TOKEN", "cli-env-secret");
        let reg = load_registry(&path).unwrap();
        std::env::remove_var("MOBULA_CLI_TEST_REGISTRY_TOKEN");
        assert_eq!(
            reg.clusters[0].auth_token.as_deref(),
            Some("cli-env-secret")
        );
        assert_eq!(
            reg.clusters[0].auth_token_env.as_deref(),
            Some("MOBULA_CLI_TEST_REGISTRY_TOKEN")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_registry_rejects_conflicting_token_sources() {
        let dir = std::env::temp_dir().join(format!("mobula-cli-both-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("both.toml");
        std::fs::write(
            &path,
            "[[clusters]]\nid = \"a\"\nhostname = \"a.test\"\n\
             api_base_url = \"http://a:8265\"\n\
             auth_token = \"secret\"\nauth_token_env = \"SOME_VAR\"\n",
        )
        .unwrap();
        let err = load_registry(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exactly one"), "{}", err);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn registry_toml_round_trip() {
        let toml = r#"
            [[clusters]]
            id = "demo"
            hostname = "demo.ray.example.com"
            api_base_url = "http://demo-head-svc:8265"
            auth_token = "secret"

            [[clusters]]
            id = "batch"
            hostname = "batch.ray.example.com"
            api_base_url = "http://batch-head-svc:8265"
        "#;
        let reg: ClusterRegistry = ::toml::from_str(toml).unwrap();
        assert_eq!(reg.clusters.len(), 2);
        assert_eq!(reg.clusters[0].auth_token.as_deref(), Some("secret"));
        assert!(reg.clusters[1].auth_token.is_none());
    }

    #[test]
    fn credentials_round_trip_with_0600_permissions() {
        let dir = std::env::temp_dir().join(format!("mobula-creds-{}", std::process::id()));
        // Serialize access to the env var within this test binary.
        std::env::set_var("MOBULA_CONFIG_DIR", &dir);
        save_credentials(&Credentials {
            access_token: "tok".into(),
            refresh_token: Some("ref".into()),
            issuer: "https://idp.example".into(),
            client_id: Some("mobula-cli".into()),
        })
        .unwrap();
        let loaded = load_credentials().unwrap();
        assert_eq!(loaded.access_token, "tok");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("credentials.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "credentials must not be group/world readable"
            );
        }
        std::env::remove_var("MOBULA_CONFIG_DIR");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// base64url-encode without padding — for fabricating unsigned JWTs in
    /// tests (no real signatures needed; jwt_exp never verifies).
    fn b64url(bytes: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut s = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = u32::from(chunk[0]);
            let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
            let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
            let n = (b0 << 16) | (b1 << 8) | b2;
            s.push(T[((n >> 18) & 63) as usize] as char);
            s.push(T[((n >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                s.push(T[((n >> 6) & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                s.push(T[(n & 63) as usize] as char);
            }
        }
        s
    }

    fn jwt_with_exp(exp: u64) -> String {
        format!(
            "{}.{}.sig",
            b64url(br#"{"alg":"RS256"}"#),
            b64url(format!(r#"{{"exp":{exp}}}"#).as_bytes())
        )
    }

    #[test]
    fn jwt_exp_decodes_payload_without_verifying_signature() {
        assert_eq!(jwt_exp(&jwt_with_exp(2_000_000_000)), Some(2_000_000_000));
        // Payload without exp, non-JSON payload, opaque token, garbage.
        let no_exp = format!("h.{}.s", b64url(br#"{"sub":"x"}"#));
        assert_eq!(jwt_exp(&no_exp), None);
        let bad_payload = format!("h.{}.s", b64url(b"not json"));
        assert_eq!(jwt_exp(&bad_payload), None);
        assert_eq!(
            jwt_exp("mob_abcd1234_0123456789abcdef0123456789abcdef"),
            None
        );
        assert_eq!(jwt_exp("not-a-jwt"), None);
    }

    #[test]
    fn stored_token_action_matrix() {
        let now = 1_700_000_000;
        let creds = |access: String, refresh: Option<&str>| Credentials {
            access_token: access,
            refresh_token: refresh.map(str::to_string),
            issuer: "https://idp.example".into(),
            client_id: Some("mobula-cli".into()),
        };
        // Valid JWT → print as-is.
        assert_eq!(
            stored_token_action(&creds(jwt_with_exp(now + 3600), None), now),
            StoredTokenAction::Valid
        );
        // Expired + refresh token → attempt refresh.
        assert_eq!(
            stored_token_action(&creds(jwt_with_exp(now - 1), Some("ref")), now),
            StoredTokenAction::Refresh
        );
        // Expired, no refresh → re-login.
        assert_eq!(
            stored_token_action(&creds(jwt_with_exp(now - 1), None), now),
            StoredTokenAction::ExpiredNoRefresh
        );
        // Opaque local-auth token (no exp) → pass through; the server
        // enforces its lifetime.
        assert_eq!(
            stored_token_action(
                &creds("mob_abcd1234_0123456789abcdef0123456789abcdef".into(), None),
                now
            ),
            StoredTokenAction::Valid
        );
    }

    #[cfg(unix)]
    #[test]
    fn registry_with_tokens_warns_on_permissive_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mobula-cli-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("clusters.toml");
        let with_token = "[[clusters]]\nid = \"a\"\nhostname = \"a.test\"\n\
             api_base_url = \"http://a:8265\"\nauth_token = \"secret\"\n";
        std::fs::write(&path, with_token).unwrap();
        let registry: ClusterRegistry = ::toml::from_str(with_token).unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let warning = registry_permission_warning(&path, &registry).expect("0644 + token warns");
        assert!(warning.contains("chmod 600"), "{warning}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(registry_permission_warning(&path, &registry).is_none());

        // No tokens → no warning, even at 0644.
        let bare: ClusterRegistry = ::toml::from_str(
            "[[clusters]]\nid = \"a\"\nhostname = \"a.test\"\napi_base_url = \"http://a:8265\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(registry_permission_warning(&path, &bare).is_none());

        // Env-referenced entries hold no secret in the file (#57) — no
        // warning even once the token is resolved in memory.
        let env_sourced: ClusterRegistry = ::toml::from_str(
            "[[clusters]]\nid = \"a\"\nhostname = \"a.test\"\n\
             api_base_url = \"http://a:8265\"\nauth_token_env = \"A_RAY_TOKEN\"\n",
        )
        .unwrap();
        assert!(registry_permission_warning(&path, &env_sourced).is_none());
        let mut resolved = env_sourced.clone();
        resolved.clusters[0].auth_token = Some("resolved".into());
        assert!(registry_permission_warning(&path, &resolved).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
