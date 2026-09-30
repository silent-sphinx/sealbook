const USAGE: &str = "\
sealbook-server

USAGE:
    sealbook-server              Run the server
    sealbook-server --health-check
                                 Probe the local server and exit 0 if healthy
    sealbook-server --help       Show this message
";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bind = std::env::var("SEALBOOK_BIND").unwrap_or_else(|_| "0.0.0.0:8443".into());

    // Handled before logging is set up: the health check is run by the container
    // runtime many times an hour and should say nothing unless it fails.
    match std::env::args().nth(1).as_deref() {
        Some("--health-check") => {
            if let Err(error) = sealbook_server::healthcheck::run(&bind) {
                eprintln!("health check failed: {error:#}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some("--help" | "-h") => {
            print!("{USAGE}");
            return Ok(());
        }
        Some(other) => {
            eprintln!("unknown argument {other:?}\n\n{USAGE}");
            std::process::exit(2);
        }
        None => {}
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sealbook_server=info".into()),
        )
        .init();

    let data_dir = std::env::var_os("SEALBOOK_DATA_DIR").map(std::path::PathBuf::from);
    let db_path = std::env::var_os("SEALBOOK_DB")
        .map(std::path::PathBuf::from)
        .or_else(|| data_dir.as_ref().map(|dir| dir.join("sealbook.db")))
        .unwrap_or_else(|| "sealbook.db".into());
    let tls_dir = std::env::var_os("SEALBOOK_TLS_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| data_dir.as_ref().map(|dir| dir.join("tls")))
        .unwrap_or_else(|| "tls".into());
    std::env::set_var("SEALBOOK_TLS_DIR", tls_dir);
    let db_path = db_path.to_string_lossy();
    sealbook_server::serve(&db_path, &bind).await
}
