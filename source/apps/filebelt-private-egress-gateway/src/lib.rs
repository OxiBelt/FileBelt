// SPDX-License-Identifier: Apache-2.0

//! Fixed-protocol HTTPS egress through a destination-free authenticated relay.

#![deny(unsafe_code)]

mod config;
mod policy;
mod service;
mod tls;

pub use config::{GatewayConfig, GatewayMode, Limits, RelayConfig, TargetPolicy};
pub use policy::{McpRequestPolicy, OnlyofficeRequestPolicy, PolicyError};
pub use service::serve;

pub const RELAY_ALPN: &[u8] = b"filebelt-private-egress/1";
pub const MAX_RESPONSE_BYTES: usize = 100 * 1024 * 1024;
