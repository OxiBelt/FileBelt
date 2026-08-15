// SPDX-License-Identifier: AGPL-3.0-only

pub const COMPONENT_NAME: &str = "FileBelt ONLYOFFICE Adapter";
pub const FIRST_PARTY_LICENSE: &str = "AGPL-3.0-only";
pub const PROVIDER_DESCRIPTION: &str = "operator-supplied ONLYOFFICE Docs Community 9.4.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildKind {
    Development,
    QualifiedRelease,
}

impl BuildKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development (not qualified for publication)",
            Self::QualifiedRelease => "qualified release",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseMetadata {
    pub component: &'static str,
    pub version: &'static str,
    pub license: &'static str,
    pub release_tag: &'static str,
    pub source_url: &'static str,
    pub source_ref: &'static str,
    pub source_revision: &'static str,
    pub corresponding_source_url: &'static str,
    pub corresponding_source_sha256: &'static str,
    pub chart_version: &'static str,
    pub provider: &'static str,
    pub provider_assets_included: bool,
    pub build_kind: BuildKind,
}

impl ReleaseMetadata {
    pub fn build_instructions_url(&self) -> String {
        immutable_repository_file_url(
            self.source_url,
            self.source_revision,
            "adapters/onlyoffice/BUILD.md",
        )
    }

    pub fn notices_url(&self) -> String {
        immutable_repository_file_url(
            self.source_url,
            self.source_revision,
            "adapters/onlyoffice/THIRD_PARTY_NOTICES.md",
        )
    }
}

fn immutable_repository_file_url(repository: &str, revision: &str, path: &str) -> String {
    if repository.starts_with("https://") && revision.len() == 40 {
        format!("{repository}/blob/{revision}/{path}")
    } else {
        "not-published-development-build".into()
    }
}

#[cfg(feature = "qualified-release")]
pub const RELEASE_METADATA: ReleaseMetadata = ReleaseMetadata {
    component: COMPONENT_NAME,
    version: env!("CARGO_PKG_VERSION"),
    license: FIRST_PARTY_LICENSE,
    release_tag: env!("CARGO_PKG_VERSION"),
    source_url: env!("FILEBELT_SOURCE_URL"),
    source_ref: env!("FILEBELT_SOURCE_REF"),
    source_revision: env!("FILEBELT_SOURCE_REVISION"),
    corresponding_source_url: env!("FILEBELT_CORRESPONDING_SOURCE_URL"),
    corresponding_source_sha256: env!("FILEBELT_CORRESPONDING_SOURCE_SHA256"),
    chart_version: env!("FILEBELT_CHART_VERSION"),
    provider: PROVIDER_DESCRIPTION,
    provider_assets_included: false,
    build_kind: BuildKind::QualifiedRelease,
};

#[cfg(not(feature = "qualified-release"))]
pub const RELEASE_METADATA: ReleaseMetadata = ReleaseMetadata {
    component: COMPONENT_NAME,
    version: env!("CARGO_PKG_VERSION"),
    license: FIRST_PARTY_LICENSE,
    release_tag: "development-unreleased",
    source_url: "not-published-development-build",
    source_ref: "development-worktree",
    source_revision: "development-worktree",
    corresponding_source_url: "not-published-development-build",
    corresponding_source_sha256: "not-published-development-build",
    chart_version: env!("CARGO_PKG_VERSION"),
    provider: PROVIDER_DESCRIPTION,
    provider_assets_included: false,
    build_kind: BuildKind::Development,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_metadata_is_explicitly_not_release_evidence() {
        if cfg!(not(feature = "qualified-release")) {
            assert_eq!(RELEASE_METADATA.build_kind, BuildKind::Development);
            assert!(RELEASE_METADATA.release_tag.contains("development"));
            assert_eq!(
                RELEASE_METADATA.build_instructions_url(),
                "not-published-development-build"
            );
        }
    }
}
