// SPDX-License-Identifier: Apache-2.0

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use filebelt_private_egress_gateway::{GatewayConfig, serve};
use filebelt_runtime::install_crypto_provider;
use tracing::error;

const ROLE: &str = "filebelt-private-egress-gateway";

#[derive(Debug, Parser)]
#[command(name = "filebelt-private-egress-gateway", disable_version_flag = true)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "/etc/filebelt/private-egress-gateway.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some("--version" | "--build-info=json")
    ) {
        return filebelt_deployment_diagnostics::run_probe(ROLE);
    }
    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    if install_crypto_provider().is_err() {
        error!(code = "private_egress_crypto_provider_failed");
        return ExitCode::FAILURE;
    }
    let Arguments {
        command: Command::Serve { config },
    } = Arguments::parse();
    let Ok(config) = GatewayConfig::load(&config) else {
        error!(code = "private_egress_config_invalid");
        return ExitCode::FAILURE;
    };
    match serve(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            error!(code = "private_egress_gateway_stopped");
            ExitCode::FAILURE
        }
    }
}
