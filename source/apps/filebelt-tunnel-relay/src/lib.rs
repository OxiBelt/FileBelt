// SPDX-License-Identifier: Apache-2.0

//! Authenticated raw-byte relay to one operator-configured numeric target set.

#![deny(unsafe_code)]

mod config;
mod service;

pub use config::{RelayConfig, RelayLimits};
pub use service::serve;

pub const RELAY_ALPN: &[u8] = b"filebelt-private-egress/1";
