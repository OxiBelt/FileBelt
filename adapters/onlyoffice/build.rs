// SPDX-License-Identifier: AGPL-3.0-only

#[path = "src/release_metadata_validation.rs"]
mod release_metadata_validation;

use release_metadata_validation::{REQUIRED_RELEASE_ENVIRONMENT, validate_release_environment};
use std::collections::BTreeMap;
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/release_metadata_validation.rs");
    for name in REQUIRED_RELEASE_ENVIRONMENT {
        println!("cargo:rerun-if-env-changed={name}");
    }

    if env::var_os("CARGO_FEATURE_QUALIFIED_RELEASE").is_none() {
        return;
    }

    let values = REQUIRED_RELEASE_ENVIRONMENT
        .into_iter()
        .filter_map(|name| env::var(name).ok().map(|value| (name, value)))
        .collect::<BTreeMap<_, _>>();
    let package_version = env::var("CARGO_PKG_VERSION")
        .expect("Cargo must provide the ONLYOFFICE adapter package version");
    if let Err(error) = validate_release_environment(&values, &package_version) {
        panic!("qualified ONLYOFFICE release metadata is invalid: {error}");
    }
}
