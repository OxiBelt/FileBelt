// SPDX-License-Identifier: LGPL-3.0-or-later

use filebelt_nfs_bridge::config::{BridgeConfig, DEFAULT_CONFIG_PATH};
use filebelt_nfs_bridge::control::GaneshaControlClient;
use filebelt_nfs_bridge::gateway::{Gateway, drain, healthy};
use filebelt_nfs_bridge::ipc::SeqPacketListener;
use filebelt_nfs_bridge::vfs::VfsClient;
use filebelt_vfs_protocol::VfsRequest;
use prost::Message;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

fn main() {
    if let Err(error) = run() {
        eprintln!("filebelt-nfs-bridge: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let (command, config_path) = arguments()?;
    let config = BridgeConfig::load(&config_path).map_err(|error| error.to_string())?;
    match command.as_str() {
        "check-config" => Ok(()),
        "health" => healthy(&config)
            .then_some(())
            .ok_or_else(|| "bridge is not admitted and ready".into()),
        "drain" => {
            BridgeConfig::reject_forbidden_authority_environment()
                .map_err(|error| error.to_string())?;
            let vfs = VfsClient::new(&config).map_err(|error| error.to_string())?;
            drain(&config, &vfs).map_err(|error| error.to_string())
        }
        "serve" => serve(config),
        _ => Err("expected serve, drain, health, or check-config".into()),
    }
}

fn serve(config: BridgeConfig) -> Result<(), String> {
    BridgeConfig::reject_forbidden_authority_environment().map_err(|error| error.to_string())?;
    let vfs = VfsClient::new(&config).map_err(|error| error.to_string())?;
    let control = GaneshaControlClient::new(&config.ganesha_control_socket);
    let mut gateway = Gateway::new(config.clone(), vfs, control);
    gateway.bootstrap().map_err(|error| error.to_string())?;
    let listener =
        SeqPacketListener::bind(&config.ipc_socket).map_err(|error| error.to_string())?;
    loop {
        let packet = match listener.accept() {
            Ok(packet) => packet,
            Err(_) => continue,
        };
        let mut encoded = match packet.receive() {
            Ok(encoded) => encoded,
            Err(_) => continue,
        };
        let request = VfsRequest::decode(encoded.as_slice());
        encoded.zeroize();
        let Ok(request) = request else {
            continue;
        };
        let response = gateway.handle(request).encode_to_vec();
        let _ = packet.send(&response);
    }
}

fn arguments() -> Result<(String, PathBuf), String> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| "missing bridge command".to_owned())?;
    let config_path = match arguments.next() {
        None => Path::new(DEFAULT_CONFIG_PATH).to_owned(),
        Some(flag) if flag == "--config" => arguments
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| "--config requires an absolute path".to_owned())?,
        Some(_) => return Err("unexpected bridge argument".into()),
    };
    if arguments.next().is_some() || !config_path.is_absolute() {
        return Err("unexpected bridge argument".into());
    }
    Ok((command, config_path))
}
