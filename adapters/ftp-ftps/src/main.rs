// SPDX-License-Identifier: GPL-3.0-or-later

//! `libunftp` integration entrypoint.
//!
//! The listener is opt-in and read-only. It resolves every FTP path afresh
//! through VFS list results, so no host path or stale UUID cache is accepted.
//! The process exits fail-closed unless all explicit-FTPS, VFS mTLS, and fixed
//! virtual-root inputs are present.

use filebelt_ftp_ftps_gateway::read_only::{ReadOnlyGatewayConfig, serve};
use filebelt_ftp_ftps_gateway::vfs_contract::GatewayIdentity;
use std::path::PathBuf;
use std::process::ExitCode;
use uuid::Uuid;

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::var("FILEBELT_FTPS_ENABLE_READ_ONLY")
        .ok()
        .as_deref()
        != Some("true")
    {
        eprintln!(
            "filebelt-ftp-ftps-gateway is disabled; set FILEBELT_FTPS_ENABLE_READ_ONLY=true after operator review"
        );
        return ExitCode::from(78);
    }
    match config() {
        Ok(config) => match serve(config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("filebelt-ftp-ftps-gateway stopped: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("filebelt-ftp-ftps-gateway configuration rejected: {error}");
            ExitCode::from(78)
        }
    }
}

fn config() -> Result<ReadOnlyGatewayConfig, String> {
    let required = |name: &str| std::env::var(name).map_err(|_| format!("{name} is required"));
    let tenant_id = required("FILEBELT_FTPS_TENANT_ID")?
        .parse::<Uuid>()
        .map_err(|_| "FILEBELT_FTPS_TENANT_ID is invalid")?;
    let drive_id = required("FILEBELT_FTPS_DRIVE_ID")?
        .parse::<Uuid>()
        .map_err(|_| "FILEBELT_FTPS_DRIVE_ID is invalid")?;
    let root_node_id = required("FILEBELT_FTPS_ROOT_NODE_ID")?
        .parse::<Uuid>()
        .map_err(|_| "FILEBELT_FTPS_ROOT_NODE_ID is invalid")?;
    let start = required("FILEBELT_FTPS_PASSIVE_PORT_START")?
        .parse::<u16>()
        .map_err(|_| "FILEBELT_FTPS_PASSIVE_PORT_START is invalid")?;
    let end = required("FILEBELT_FTPS_PASSIVE_PORT_END")?
        .parse::<u16>()
        .map_err(|_| "FILEBELT_FTPS_PASSIVE_PORT_END is invalid")?;
    if start == 0 || end < start {
        return Err("FILEBELT_FTPS_PASSIVE_PORT range is invalid".into());
    }
    let read =
        |name: &str| std::fs::read(required(name)?).map_err(|_| format!("{name} cannot be read"));
    Ok(ReadOnlyGatewayConfig {
        identity: GatewayIdentity {
            tenant_id,
            gateway_id: required("FILEBELT_FTPS_GATEWAY_ID")?,
            gateway_epoch: 0,
        },
        shard_key: required("FILEBELT_FTPS_SHARD_KEY")?,
        vfs_url: required("FILEBELT_VFS_URL")?,
        vfs_ca_pem: read("FILEBELT_VFS_CA_PEM_FILE")?,
        vfs_client_cert_pem: read("FILEBELT_VFS_CLIENT_CERT_PEM_FILE")?,
        vfs_client_key_pem: read("FILEBELT_VFS_CLIENT_KEY_PEM_FILE")?,
        drive_id,
        root_node_id,
        ftps_cert_path: PathBuf::from(required("FILEBELT_FTPS_CERT_FILE")?),
        ftps_key_path: PathBuf::from(required("FILEBELT_FTPS_KEY_FILE")?),
        bind_address: required("FILEBELT_FTPS_BIND_ADDRESS")?,
        passive_host: required("FILEBELT_FTPS_PASSIVE_HOST")?,
        passive_ports: start..=end,
    })
}
