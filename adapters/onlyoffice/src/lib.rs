// SPDX-License-Identifier: AGPL-3.0-only

//! AGPL-only policy and process boundary for the ONLYOFFICE adapter.
//!
//! The adapter intentionally has no payload mount, database driver, Core
//! implementation dependency, browser-session authority, or direct Internet
//! client.  A production transport must implement the narrow traits below over
//! the approved replaceable Core and egress-gateway interfaces.

#![deny(unsafe_code)]

pub mod config;
pub mod routes;
pub mod runtime;
pub mod tls;

pub use config::{AdapterConfig, JwtKeySet, Origin, Provider, ServerTlsConfig};
pub use routes::{
    AdapterService, CallbackEvent, CallbackStatus, CoreClient, EgressGateway, Request, Response,
    public_info_response,
};
pub use runtime::{Hs256JwtVerifier, HttpCoreClient, HttpEgressGateway, Sha256FingerprintDeriver};
