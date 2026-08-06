// SPDX-License-Identifier: Apache-2.0

//! Smoke-only deployment probes for FileBelt role images.

#![deny(unsafe_code)]

use std::{env, fmt, io, io::Write as _, process::ExitCode};

use filebelt_build_identity::CURRENT;

/// Error returned when a placeholder role is asked to start a service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedInvocation;

impl fmt::Display for UnsupportedInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("only `--version` and `--build-info=json` are supported")
    }
}

impl std::error::Error for UnsupportedInvocation {}

/// Renders the output for one exact smoke-probe argument.
///
/// Rejecting all other invocations prevents a Phase 1 image from looking like
/// a running service when no service runtime exists yet.
pub fn render_probe(role: &str, arguments: &[&str]) -> Result<String, UnsupportedInvocation> {
    match arguments {
        ["--version"] => Ok(format!(
            "{role} {} ({})\n",
            CURRENT.version, CURRENT.revision
        )),
        ["--build-info=json"] => Ok(CURRENT.render_json_for_role(role)),
        _ => Err(UnsupportedInvocation),
    }
}

/// Runs a role's smoke-only command-line contract and returns its exit status.
#[must_use]
pub fn run_probe(role: &str) -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let argument_refs = arguments.iter().map(String::as_str).collect::<Vec<_>>();

    match render_probe(role, &argument_refs) {
        Ok(output) => match io::stdout().write_all(output.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let _ = writeln!(io::stderr(), "{role}: cannot write probe output: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            let _ = writeln!(io::stderr(), "{role}: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{UnsupportedInvocation, render_probe};

    #[test]
    fn version_probe_is_single_line_and_deterministic() {
        let output = render_probe("filebelt-api", &["--version"])
            .expect("the documented version probe must succeed");

        assert_eq!(output, "filebelt-api 0.1.0 (unknown)\n");
    }

    #[test]
    fn build_info_contains_role_and_compile_time_identity() {
        let output = render_probe("filebelt-worker-io", &["--build-info=json"])
            .expect("the documented JSON probe must succeed");

        assert_eq!(
            output,
            "{\"role\":\"filebelt-worker-io\",\"version\":\"0.1.0\",\"revision\":\"unknown\",\"source_ref\":\"unknown\",\"dirty\":true,\"kind\":\"local\"}\n"
        );
    }

    #[test]
    fn service_and_malformed_invocations_fail_closed() {
        for arguments in [
            Vec::<&str>::new(),
            vec!["serve"],
            vec!["--version", "extra"],
            vec!["--build-info"],
        ] {
            assert_eq!(
                render_probe("filebelt-api", &arguments),
                Err(UnsupportedInvocation)
            );
        }
    }
}
