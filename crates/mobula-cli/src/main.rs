use clap::{Parser, Subcommand};
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
        /// DANGER: serve without authentication on a non-loopback
        /// address. Until Phase 2 identity lands, anyone who can reach
        /// the port can run code on every registered cluster. Refused by
        /// default (security issue #1).
        #[arg(long)]
        dev_allow_unauthenticated: bool,
        /// DANGER: permit auth tokens over cleartext http:// southbound
        /// (local dev only; security issue #2).
        #[arg(long)]
        allow_insecure_transport: bool,
    },
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    match Cli::parse().command {
        Command::Serve {
            bind,
            registry,
            dev_allow_unauthenticated,
            allow_insecure_transport,
        } => {
            if !bind.ip().is_loopback() && !dev_allow_unauthenticated {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing to bind {bind}: no authentication is implemented yet \
                         (Phase 2), so a non-loopback bind exposes every registered \
                         cluster to unauthenticated code execution. Pass \
                         --dev-allow-unauthenticated only on trusted networks."
                    ),
                ));
            }
            let registry = match registry {
                Some(path) => load_registry(&path)?,
                None => ClusterRegistry::default(),
            };
            registry
                .validate(allow_insecure_transport)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            for c in &registry.clusters {
                tracing::info!(id = %c.id, hostname = %c.hostname, "cluster registered");
            }
            tracing::info!(clusters = registry.clusters.len(), "registry loaded");
            mobula_api::serve(bind, registry).await
        }
    }
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
}
