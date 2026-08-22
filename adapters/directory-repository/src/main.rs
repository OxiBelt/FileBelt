// SPDX-License-Identifier: Apache-2.0

#![deny(unsafe_code)]

fn main() {
    match filebelt_directory_repository_adapter::serve_private_mtls_scaffold() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("filebelt-directory-repository-adapter: {error}");
            std::process::exit(78);
        }
    }
}
