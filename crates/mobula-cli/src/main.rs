use std::io::Write as _;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use mobula_auth::{flows, AuthConfig, Validator};
use mobula_core::ClusterRegistry;

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
        /// SQLite database for desired cluster state (used with
        /// --kuberay-namespace). Defaults to in-memory (state lost on
        /// restart) if unset.
        #[arg(long)]
        db: Option<std::path::PathBuf>,
        /// Reconcile resync interval, seconds (with --kuberay-namespace).
        #[arg(long, default_value = "30")]
        reconcile_interval_secs: u64,
    },
    /// Sign in via the OIDC device-code flow and store the token.
    Login {
        /// OIDC issuer URL (e.g. https://keycloak.example/realms/nebari).
        #[arg(long)]
        issuer: String,
        /// Public OAuth client id registered for the Mobula CLI.
        #[arg(long, default_value = "mobula-cli")]
        client_id: String,
        /// Requested scopes.
        #[arg(long, default_value = "openid profile email")]
        scope: String,
    },
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
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let audit_log = match &cli.command {
        Command::Serve { audit_log, .. } => audit_log.clone(),
        _ => None,
    };
    init_tracing(audit_log.as_deref())?;

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
        } => {
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
            let store: Option<std::sync::Arc<dyn mobula_controller::Store>> =
                match &kuberay_namespace {
                    Some(ns) => {
                        // Concrete Arc for the reconciler (it is generic over
                        // the store type); a clone coerces to Arc<dyn Store>
                        // for the API routes.
                        let concrete = std::sync::Arc::new(match &db {
                            Some(path) => mobula_controller::SqliteStore::connect(&format!(
                                "sqlite://{}?mode=rwc",
                                path.display()
                            ))
                            .await
                            .map_err(|e| std::io::Error::other(e.to_string()))?,
                            None => {
                                tracing::warn!(
                                    "no --db: cluster state is in-memory and lost on restart"
                                );
                                mobula_controller::SqliteStore::in_memory()
                                    .await
                                    .map_err(|e| std::io::Error::other(e.to_string()))?
                            }
                        });
                        let provisioner = std::sync::Arc::new(
                            mobula_provision::KubeRayProvisioner::connect(ns.clone(), false)
                                .await
                                .map_err(|e| std::io::Error::other(e.to_string()))?,
                        );
                        let reconciler =
                            mobula_controller::Reconciler::new(concrete.clone(), provisioner);
                        let interval = std::time::Duration::from_secs(reconcile_interval_secs);
                        tokio::spawn(async move {
                            reconciler
                                .run(interval, async {
                                    let _ = tokio::signal::ctrl_c().await;
                                })
                                .await;
                        });
                        tracing::info!(namespace = %ns, "cluster lifecycle controller enabled");
                        Some(concrete)
                    }
                    None => None,
                };

            // Fail-closed invariants (non-loopback needs auth, registry
            // validation) are enforced inside serve() so they can't be
            // bypassed by library embedders (#36).
            mobula_api::serve(
                bind,
                mobula_api::ServeOptions {
                    registry,
                    validator,
                    allow_unauthenticated: dev_allow_unauthenticated,
                    allow_insecure_transport,
                    store,
                    policy: Default::default(),
                },
            )
            .await
        }
        Command::Login {
            issuer,
            client_id,
            scope,
        } => login(&issuer, &client_id, &scope).await,
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
                println!("{}", creds.access_token);
                Ok(())
            }
        },
    }
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

#[derive(serde::Serialize, serde::Deserialize)]
struct Credentials {
    access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    issuer: String,
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
    toml::from_str(&raw).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid registry {}: {e}", path.display()),
        )
    })
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

    #[test]
    fn load_registry_missing_file_errors() {
        assert!(load_registry(std::path::Path::new("/nonexistent/clusters.toml")).is_err());
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
}
