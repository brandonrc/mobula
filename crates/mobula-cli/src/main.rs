use clap::{Parser, Subcommand};

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
        Command::Serve { bind } => mobula_api::serve(bind).await,
    }
}
