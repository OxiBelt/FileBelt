// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

pub const REQUIRED_RELEASE_ENVIRONMENT: [&str; 6] = [
    "FILEBELT_SOURCE_URL",
    "FILEBELT_SOURCE_REF",
    "FILEBELT_SOURCE_REVISION",
    "FILEBELT_CORRESPONDING_SOURCE_URL",
    "FILEBELT_CORRESPONDING_SOURCE_SHA256",
    "FILEBELT_CHART_VERSION",
];

pub fn validate_release_environment(
    values: &BTreeMap<&str, String>,
    package_version: &str,
) -> Result<(), &'static str> {
    for name in REQUIRED_RELEASE_ENVIRONMENT {
        if values.get(name).is_none_or(|value| value.is_empty()) {
            return Err("a required release metadata field is absent or empty");
        }
    }
    if !valid_semver(package_version) {
        return Err("the package version is not an exact SemVer version");
    }
    if values["FILEBELT_SOURCE_REF"] != format!("refs/tags/{package_version}") {
        return Err("the signed source ref does not match the package version");
    }
    if values["FILEBELT_CHART_VERSION"] != package_version {
        return Err("the chart and package versions disagree");
    }
    let revision = &values["FILEBELT_SOURCE_REVISION"];
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err("the source revision is not a lowercase 40-hex commit");
    }
    if !valid_https_url(&values["FILEBELT_SOURCE_URL"])
        || values["FILEBELT_SOURCE_URL"].ends_with('/')
    {
        return Err("the source repository URL is not an absolute HTTPS URL");
    }
    let bundle_url = &values["FILEBELT_CORRESPONDING_SOURCE_URL"];
    if !valid_https_url(bundle_url) || has_mutable_alias(bundle_url) {
        return Err("the corresponding-source URL is mutable or is not HTTPS");
    }
    let immutable_release_segment = format!("/{package_version}/");
    let immutable_revision_segment = format!("/{revision}/");
    if !bundle_url.contains(&immutable_release_segment)
        && !bundle_url.contains(&immutable_revision_segment)
    {
        return Err("the corresponding-source URL is not version- or revision-addressed");
    }
    let expected_asset = format!("/filebelt-onlyoffice-adapter-source-{package_version}.tar.gz");
    if !bundle_url.ends_with(&expected_asset) {
        return Err("the corresponding-source URL does not name the release source bundle");
    }
    let checksum = &values["FILEBELT_CORRESPONDING_SOURCE_SHA256"];
    if checksum.len() != 64
        || !checksum
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err("the corresponding-source checksum is not lowercase SHA-256");
    }
    Ok(())
}

fn valid_https_url(value: &str) -> bool {
    let Some(remainder) = value.strip_prefix("https://") else {
        return false;
    };
    let authority = remainder.split('/').next().unwrap_or_default();
    !authority.is_empty()
        && authority.contains('.')
        && !authority.starts_with('.')
        && !authority.ends_with('.')
        && authority
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && !value.contains(['\\', '?', '#', '%'])
        && !value.chars().any(char::is_whitespace)
}

fn has_mutable_alias(value: &str) -> bool {
    value
        .to_ascii_lowercase()
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|segment| {
            matches!(
                segment,
                "current"
                    | "dev"
                    | "develop"
                    | "development"
                    | "edge"
                    | "head"
                    | "latest"
                    | "main"
                    | "master"
                    | "nightly"
                    | "snapshot"
                    | "stable"
                    | "tip"
                    | "trunk"
            )
        })
}

fn valid_semver(value: &str) -> bool {
    let (core_and_pre, build) = value
        .split_once('+')
        .map_or((value, None), |(left, right)| (left, Some(right)));
    if build.is_some_and(|value| !valid_identifiers(value, false)) {
        return false;
    }
    let (core, prerelease) = core_and_pre
        .split_once('-')
        .map_or((core_and_pre, None), |(left, right)| (left, Some(right)));
    if prerelease.is_some_and(|value| !valid_identifiers(value, true)) {
        return false;
    }
    let parts = core.split('.').collect::<Vec<_>>();
    parts.len() == 3 && parts.into_iter().all(valid_numeric_identifier)
}

fn valid_numeric_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn valid_identifiers(value: &str, reject_numeric_leading_zero: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!reject_numeric_leading_zero
                    || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || valid_numeric_identifier(identifier))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release_values() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (
                "FILEBELT_SOURCE_URL",
                "https://github.com/OxiBelt/FileBelt".into(),
            ),
            ("FILEBELT_SOURCE_REF", "refs/tags/0.1.0".into()),
            (
                "FILEBELT_SOURCE_REVISION",
                "0123456789abcdef0123456789abcdef01234567".into(),
            ),
            (
                "FILEBELT_CORRESPONDING_SOURCE_URL",
                "https://github.com/OxiBelt/FileBelt/releases/download/0.1.0/filebelt-onlyoffice-adapter-source-0.1.0.tar.gz".into(),
            ),
            (
                "FILEBELT_CORRESPONDING_SOURCE_SHA256",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            ),
            ("FILEBELT_CHART_VERSION", "0.1.0".into()),
        ])
    }

    #[test]
    fn accepts_exact_immutable_release_metadata() {
        assert_eq!(
            validate_release_environment(&release_values(), "0.1.0"),
            Ok(())
        );
    }

    #[test]
    fn rejects_each_missing_release_field() {
        for field in REQUIRED_RELEASE_ENVIRONMENT {
            let mut values = release_values();
            values.remove(field);
            assert!(
                validate_release_environment(&values, "0.1.0").is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn rejects_mutable_malformed_and_inconsistent_release_metadata() {
        for (field, value) in [
            ("FILEBELT_SOURCE_REF", "refs/heads/main"),
            ("FILEBELT_SOURCE_REVISION", "ABCDEF"),
            (
                "FILEBELT_CORRESPONDING_SOURCE_URL",
                "http://example.test/0.1.0/source.tar.gz",
            ),
            (
                "FILEBELT_CORRESPONDING_SOURCE_URL",
                "https://example.test/releases/latest/source.tar.gz",
            ),
            (
                "FILEBELT_CORRESPONDING_SOURCE_URL",
                "https://example.test/releases/current/0.1.0/source.tar.gz",
            ),
            (
                "FILEBELT_CORRESPONDING_SOURCE_URL",
                "https://user@example.test/releases/0.1.0/source.tar.gz",
            ),
            (
                "FILEBELT_CORRESPONDING_SOURCE_URL",
                "https://example.test/releases/0.1.0/source.tar.gz?download=1",
            ),
            ("FILEBELT_CORRESPONDING_SOURCE_SHA256", "ABCDEF"),
            ("FILEBELT_CHART_VERSION", "0.1.1"),
        ] {
            let mut values = release_values();
            values.insert(field, value.into());
            assert!(
                validate_release_environment(&values, "0.1.0").is_err(),
                "{field}={value}"
            );
        }
    }
}
