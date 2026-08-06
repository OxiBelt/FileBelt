// SPDX-License-Identifier: Apache-2.0

//! Deterministic build identity embedded in FileBelt role binaries.

#![deny(unsafe_code)]

use std::fmt::Write as _;

/// The controlled context in which an artifact was built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildKind {
    /// An uncommitted developer build.
    Local,
    /// A continuous-integration build that is not a release candidate.
    Ci,
    /// A build made from a validated release ref.
    Release,
    /// An independent build used for reproducibility comparison.
    Rebuild,
}

impl BuildKind {
    /// Returns the stable lowercase representation used in evidence contracts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Ci => "ci",
            Self::Release => "release",
            Self::Rebuild => "rebuild",
        }
    }
}

/// Build metadata compiled into a FileBelt binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildIdentity {
    /// Package or release version.
    pub version: &'static str,
    /// Full source revision, or `unknown` for an uncommitted local build.
    pub revision: &'static str,
    /// Source ref used to create the build.
    pub source_ref: &'static str,
    /// Whether tracked source content differed from the named revision.
    pub dirty: bool,
    /// Controlled build context.
    pub kind: BuildKind,
}

const fn build_version() -> &'static str {
    match option_env!("FILEBELT_BUILD_VERSION") {
        Some(value) => value,
        None => env!("CARGO_PKG_VERSION"),
    }
}

const fn build_revision() -> &'static str {
    match option_env!("FILEBELT_BUILD_REVISION") {
        Some(value) => value,
        None => "unknown",
    }
}

const fn build_source_ref() -> &'static str {
    match option_env!("FILEBELT_BUILD_SOURCE_REF") {
        Some(value) => value,
        None => "unknown",
    }
}

const fn build_dirty() -> bool {
    parse_build_dirty(option_env!("FILEBELT_BUILD_DIRTY"))
}

const fn parse_build_dirty(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(value) => {
            if text_eq(value, "true") {
                true
            } else if text_eq(value, "false") {
                false
            } else {
                panic!("FILEBELT_BUILD_DIRTY must be `true` or `false`")
            }
        }
    }
}

const fn build_kind() -> BuildKind {
    parse_build_kind(option_env!("FILEBELT_BUILD_KIND"))
}

const fn parse_build_kind(value: Option<&str>) -> BuildKind {
    match value {
        None => BuildKind::Local,
        Some(value) => {
            if text_eq(value, "local") {
                BuildKind::Local
            } else if text_eq(value, "ci") {
                BuildKind::Ci
            } else if text_eq(value, "release") {
                BuildKind::Release
            } else if text_eq(value, "rebuild") {
                BuildKind::Rebuild
            } else {
                panic!("FILEBELT_BUILD_KIND must be `local`, `ci`, `release`, or `rebuild`")
            }
        }
    }
}

const fn text_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }

    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Identity compiled into the current crate graph.
pub const CURRENT: BuildIdentity = BuildIdentity {
    version: build_version(),
    revision: build_revision(),
    source_ref: build_source_ref(),
    dirty: build_dirty(),
    kind: build_kind(),
};

impl BuildIdentity {
    /// Renders the deterministic JSON object exposed by a role binary.
    ///
    /// The role is supplied by the binary rather than by build environment so
    /// one build cannot claim a different runtime role through metadata alone.
    #[must_use]
    pub fn render_json_for_role(self, role: &str) -> String {
        let mut output = String::with_capacity(192);
        output.push_str("{\"role\":");
        push_json_string(&mut output, role);
        output.push_str(",\"version\":");
        push_json_string(&mut output, self.version);
        output.push_str(",\"revision\":");
        push_json_string(&mut output, self.revision);
        output.push_str(",\"source_ref\":");
        push_json_string(&mut output, self.source_ref);
        output.push_str(",\"dirty\":");
        output.push_str(if self.dirty { "true" } else { "false" });
        output.push_str(",\"kind\":");
        push_json_string(&mut output, self.kind.as_str());
        output.push_str("}\n");
        output
    }
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{00}'..='\u{1f}' => {
                write!(output, "\\u{:04x}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            _ => output.push(character),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::{BuildIdentity, BuildKind, CURRENT, parse_build_dirty, parse_build_kind};

    fn current_identity() -> BuildIdentity {
        CURRENT
    }

    #[test]
    fn local_identity_has_safe_defaults() {
        let identity = current_identity();
        assert_eq!(identity.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(identity.revision, "unknown");
        assert_eq!(identity.source_ref, "unknown");
        assert!(identity.dirty);
        assert_eq!(identity.kind, BuildKind::Local);
    }

    #[test]
    fn json_is_deterministic_and_escapes_untrusted_build_text() {
        let identity = BuildIdentity {
            version: "1.2.3",
            revision: "abc\\\"def\n",
            source_ref: "refs/tags/1.2.3",
            dirty: false,
            kind: BuildKind::Release,
        };

        assert_eq!(
            identity.render_json_for_role("filebelt-api"),
            "{\"role\":\"filebelt-api\",\"version\":\"1.2.3\",\"revision\":\"abc\\\\\\\"def\\n\",\"source_ref\":\"refs/tags/1.2.3\",\"dirty\":false,\"kind\":\"release\"}\n"
        );
    }

    #[test]
    fn build_kind_strings_are_stable() {
        assert_eq!(BuildKind::Local.as_str(), "local");
        assert_eq!(BuildKind::Ci.as_str(), "ci");
        assert_eq!(BuildKind::Release.as_str(), "release");
        assert_eq!(BuildKind::Rebuild.as_str(), "rebuild");
    }

    #[test]
    fn compile_time_values_accept_only_contract_literals() {
        let runtime = std::hint::black_box;
        assert!(parse_build_dirty(runtime(None)));
        assert!(parse_build_dirty(runtime(Some("true"))));
        assert!(!parse_build_dirty(runtime(Some("false"))));
        assert_eq!(parse_build_kind(runtime(None)), BuildKind::Local);
        assert_eq!(parse_build_kind(runtime(Some("local"))), BuildKind::Local);
        assert_eq!(parse_build_kind(runtime(Some("ci"))), BuildKind::Ci);
        assert_eq!(
            parse_build_kind(runtime(Some("release"))),
            BuildKind::Release
        );
        assert_eq!(
            parse_build_kind(runtime(Some("rebuild"))),
            BuildKind::Rebuild
        );
    }

    #[test]
    #[should_panic(expected = "FILEBELT_BUILD_DIRTY must be `true` or `false`")]
    fn invalid_dirty_literal_panics() {
        parse_build_dirty(std::hint::black_box(Some("1")));
    }

    #[test]
    #[should_panic(expected = "FILEBELT_BUILD_KIND must be")]
    fn invalid_build_kind_panics() {
        parse_build_kind(std::hint::black_box(Some("nightly")));
    }
}
