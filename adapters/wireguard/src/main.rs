// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fmt, fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

const INTERFACE: &str = "fbwg0";
const IP: &str = "/usr/local/bin/ip";
const WG: &str = "/usr/local/bin/wg";
const SECRET_ROOT: &str = "/run/secrets/wireguard";

#[derive(Debug, Eq, PartialEq)]
struct Config {
    private_key_file: PathBuf,
    preshared_key_file: Option<PathBuf>,
    peer_public_key: String,
    endpoint: SocketAddr,
    tunnel_address: String,
    target_cidrs: Vec<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wireguard initialization failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Error> {
    let config = parse(env::args_os().skip(1))?;
    configure(&config)
}

fn parse(arguments: impl Iterator<Item = OsString>) -> Result<Config, Error> {
    let values = arguments
        .map(|value| {
            value
                .into_string()
                .map_err(|_| Error("arguments must be valid UTF-8".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut private_key_file = None;
    let mut preshared_key_file = None;
    let mut peer_public_key = None;
    let mut endpoint = None;
    let mut tunnel_address = None;
    let mut target_cidrs = Vec::new();
    let mut index = 0;
    while index < values.len() {
        let flag = &values[index];
        index += 1;
        let value = values
            .get(index)
            .ok_or_else(|| Error(format!("{flag} requires a value")))?;
        index += 1;
        match flag.as_str() {
            "--interface" if value == INTERFACE => {}
            "--interface" => return Err(Error(format!("interface must be {INTERFACE}"))),
            "--private-key-file" if private_key_file.is_none() => {
                private_key_file = Some(secret_path(value, "private key")?);
            }
            "--preshared-key-file" if preshared_key_file.is_none() => {
                preshared_key_file = Some(secret_path(value, "preshared key")?);
            }
            "--peer-public-key" if peer_public_key.is_none() => {
                validate_key(value, "peer public key")?;
                peer_public_key = Some(value.clone());
            }
            "--endpoint" if endpoint.is_none() => {
                let address = value
                    .parse::<SocketAddr>()
                    .map_err(|_| Error("endpoint must be a numeric IP and port".into()))?;
                validate_peer_ip(address.ip())?;
                endpoint = Some(address);
            }
            "--tunnel-address" if tunnel_address.is_none() => {
                parse_tunnel_address(value)?;
                tunnel_address = Some(value.clone());
            }
            "--target-cidr" => {
                parse_target_cidr(value)?;
                target_cidrs.push(value.clone());
            }
            _ if !flag.starts_with("--") => {
                return Err(Error(format!("unexpected positional argument {flag}")));
            }
            _ => return Err(Error(format!("unknown or duplicated option {flag}"))),
        }
    }
    if target_cidrs.is_empty() || target_cidrs.len() > 16 {
        return Err(Error(
            "one through sixteen target host CIDRs are required".into(),
        ));
    }
    let unique = target_cidrs.iter().collect::<BTreeSet<_>>();
    if unique.len() != target_cidrs.len() {
        return Err(Error("target host CIDRs must be unique".into()));
    }
    Ok(Config {
        private_key_file: private_key_file
            .ok_or_else(|| Error("private key is required".into()))?,
        preshared_key_file,
        peer_public_key: peer_public_key
            .ok_or_else(|| Error("peer public key is required".into()))?,
        endpoint: endpoint.ok_or_else(|| Error("numeric peer endpoint is required".into()))?,
        tunnel_address: tunnel_address.ok_or_else(|| Error("tunnel address is required".into()))?,
        target_cidrs,
    })
}

fn secret_path(value: &str, description: &str) -> Result<PathBuf, Error> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || !path.starts_with(SECRET_ROOT)
        || path.components().any(|part| part.as_os_str() == "..")
    {
        return Err(Error(format!(
            "{description} path must be below {SECRET_ROOT}"
        )));
    }
    let metadata = fs::metadata(&path)
        .map_err(|error| Error(format!("cannot read {description} file metadata: {error}")))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 128 {
        return Err(Error(format!("{description} file has an invalid size")));
    }
    Ok(path)
}

fn validate_key(value: &str, description: &str) -> Result<(), Error> {
    if value.len() != 44
        || !value.ends_with('=')
        || !value[..43]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
    {
        return Err(Error(format!(
            "{description} must be a canonical base64 key"
        )));
    }
    Ok(())
}

fn parse_tunnel_address(value: &str) -> Result<(), Error> {
    let (address, prefix) = split_cidr(value, "tunnel address")?;
    let exact = if address.is_ipv4() { 32 } else { 128 };
    if prefix != exact || forbidden_ip(address) {
        return Err(Error(
            "tunnel address must be one safe IPv4 /32 or IPv6 /128".into(),
        ));
    }
    Ok(())
}

fn parse_target_cidr(value: &str) -> Result<IpAddr, Error> {
    let (address, prefix) = split_cidr(value, "target CIDR")?;
    let exact = if address.is_ipv4() { 32 } else { 128 };
    if prefix != exact || forbidden_ip(address) || is_metadata(address) {
        return Err(Error(
            "target CIDR must be one safe IPv4 /32 or IPv6 /128".into(),
        ));
    }
    Ok(address)
}

fn split_cidr(value: &str, description: &str) -> Result<(IpAddr, u8), Error> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| Error(format!("{description} must include a prefix")))?;
    if address.contains('%') {
        return Err(Error(format!(
            "{description} cannot contain an interface scope"
        )));
    }
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| Error(format!("{description} must contain a numeric IP")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| Error(format!("{description} prefix is invalid")))?;
    Ok((address, prefix))
}

fn validate_peer_ip(address: IpAddr) -> Result<(), Error> {
    if forbidden_ip(address) || is_metadata(address) {
        return Err(Error("WireGuard peer endpoint IP is unsafe".into()));
    }
    Ok(())
}

fn forbidden_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_unicast_link_local()
                || address.is_multicast()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| forbidden_ip(IpAddr::V4(mapped)))
        }
    }
}

fn is_metadata(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address == Ipv4Addr::new(169, 254, 169, 254),
        IpAddr::V6(address) => address == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254),
    }
}

fn configure(config: &Config) -> Result<(), Error> {
    let _ = command(IP, &["link", "delete", "dev", INTERFACE]);
    command(IP, &["link", "add", "dev", INTERFACE, "type", "wireguard"])?;
    let result = configure_created_interface(config);
    if result.is_err() {
        let _ = command(IP, &["link", "delete", "dev", INTERFACE]);
    }
    result
}

fn configure_created_interface(config: &Config) -> Result<(), Error> {
    let private_key = path_string(&config.private_key_file)?;
    let endpoint = config.endpoint.to_string();
    let allowed_ips = config.target_cidrs.join(",");
    let mut arguments = vec![
        "set",
        INTERFACE,
        "private-key",
        private_key,
        "peer",
        config.peer_public_key.as_str(),
        "endpoint",
        endpoint.as_str(),
        "allowed-ips",
        allowed_ips.as_str(),
    ];
    let preshared_key;
    if let Some(path) = &config.preshared_key_file {
        preshared_key = path_string(path)?;
        arguments.extend(["preshared-key", preshared_key]);
    }
    command(WG, &arguments)?;
    command(
        IP,
        &[
            "address",
            "add",
            config.tunnel_address.as_str(),
            "dev",
            INTERFACE,
        ],
    )?;
    command(IP, &["link", "set", "up", "dev", INTERFACE])?;
    for target in &config.target_cidrs {
        command(IP, &["route", "add", target, "dev", INTERFACE])?;
    }
    Ok(())
}

fn path_string(path: &Path) -> Result<&str, Error> {
    path.to_str()
        .ok_or_else(|| Error("secret path must be valid UTF-8".into()))
}

fn command(program: &str, arguments: &[&str]) -> Result<(), Error> {
    let status = Command::new(program)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| command_error(program, &error))?;
    if !status.success() {
        return Err(Error(format!("{program} returned a nonzero status")));
    }
    Ok(())
}

fn command_error(program: &str, error: &io::Error) -> Error {
    Error(format!("cannot execute {program}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_routes_are_exact_safe_hosts() {
        assert_eq!(
            parse_target_cidr("10.42.0.7/32"),
            Ok("10.42.0.7".parse().unwrap())
        );
        assert_eq!(
            parse_target_cidr("fd42::7/128"),
            Ok("fd42::7".parse().unwrap())
        );
        for rejected in [
            "0.0.0.0/0",
            "10.42.0.0/24",
            "127.0.0.1/32",
            "169.254.20.1/32",
            "169.254.169.254/32",
            "255.255.255.255/32",
            "::/0",
            "::1/128",
            "ff02::1/128",
        ] {
            assert!(parse_target_cidr(rejected).is_err(), "accepted {rejected}");
        }
    }

    #[test]
    fn peer_requires_a_numeric_safe_endpoint() {
        assert!("10.0.0.8:51820".parse::<SocketAddr>().is_ok());
        assert!("vpn.example.test:51820".parse::<SocketAddr>().is_err());
        assert!(validate_peer_ip("169.254.169.254".parse().unwrap()).is_err());
    }

    #[test]
    fn tunnel_address_cannot_install_a_connected_prefix_route() {
        assert!(parse_tunnel_address("10.0.0.1/32").is_ok());
        assert!(parse_tunnel_address("fd00::1/128").is_ok());
        assert!(parse_tunnel_address("10.0.0.1/8").is_err());
        assert!(parse_tunnel_address("fd00::1/64").is_err());
    }

    #[test]
    fn keys_are_canonical_base64() {
        assert!(validate_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "key").is_ok());
        assert!(validate_key("not-a-key", "key").is_err());
    }
}
