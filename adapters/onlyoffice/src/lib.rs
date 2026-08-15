// SPDX-License-Identifier: AGPL-3.0-only

//! AGPL-only policy and process boundary for the ONLYOFFICE adapter.
//!
//! The adapter intentionally has no payload mount, database driver, Core
//! implementation dependency, browser-session authority, or direct Internet
//! client. It directly links the Apache-2.0 document-protocol crate and its
//! generated types at compile time. At runtime, a production transport uses
//! that replaceable protocol over the separate Core and egress-gateway mTLS
//! process boundaries; Apache Core has no dependency on this AGPL package.

#![deny(unsafe_code)]

pub mod config;
pub mod release_metadata;
#[cfg(test)]
mod release_metadata_validation;
pub mod routes;
pub mod runtime;
pub mod tls;

pub use config::{AdapterConfig, JwtKeySet, Origin, Provider, ServerTlsConfig};
pub use release_metadata::{BuildKind, RELEASE_METADATA, ReleaseMetadata};
pub use routes::{
    AdapterService, CallbackEvent, CallbackStatus, CoreClient, EgressGateway, Request, Response,
    public_info_response,
};
pub use runtime::{Hs256JwtVerifier, HttpCoreClient, HttpEgressGateway, Sha256FingerprintDeriver};
