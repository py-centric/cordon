//! Cordon CLI binary entrypoint.

use clap::Parser;
use cordon::cli::{CordonCli, execute_cli, log_stderr_diagnostic};

#[tokio::main]
async fn main() {
    let cli = CordonCli::parse();
    match execute_cli(cli).await {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            log_stderr_diagnostic("ERROR", "cli.error", &err.to_string());
            std::process::exit(1);
        }
    }
}
