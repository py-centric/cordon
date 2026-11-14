//! Cordon CLI binary entrypoint.

use clap::Parser;
use cordon::cli::{CordonCli, execute_cli, log_stderr_diagnostic};
use cordon::error::CordonError;

#[tokio::main]
async fn main() {
    let cli = CordonCli::parse();
    match execute_cli(cli).await {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            log_stderr_diagnostic("ERROR", "cli.error", &err.to_string());
            // EX_UNAVAILABLE (69): a Gate 3.5 MicroVM prerequisite is missing on this host.
            let unavailable = matches!(
                err.downcast_ref::<CordonError>(),
                Some(CordonError::MicroVmUnavailable(_))
            );
            std::process::exit(if unavailable { 69 } else { 1 });
        }
    }
}
