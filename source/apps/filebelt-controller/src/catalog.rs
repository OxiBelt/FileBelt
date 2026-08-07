// SPDX-License-Identifier: Apache-2.0

//! Cryptographically verified, operator-owned runner catalog.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sigstore_verify::trust_root::{TrustedRoot, ValidityPeriod};
use sigstore_verify::types::{Bundle, Sha256Hash};
use sigstore_verify::{VerificationPolicy, Verifier};
use url::Url;

const MAX_CATALOG_BYTES: u64 = 1_048_576;
const MAX_TRUST_ROOT_BYTES: u64 = 2_097_152;
const MAX_BUNDLE_BYTES: u64 = 4_194_304;
const MAX_ENTRIES: usize = 128;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Catalog {
    pub schema_version: u8,
    pub entries: Vec<CatalogEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogEntry {
    pub name: String,
    /// OCI repository without a tag or digest.
    pub repository: String,
    pub image: String,
    /// Human-readable upstream source URL retained for provenance display.
    pub source: String,
    pub license: String,
    pub command: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    pub architectures: BTreeSet<String>,
    pub egress_profile: String,
    pub signature: CatalogSignature,
    pub resources: CatalogResources,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogSignature {
    pub bundle_file: String,
    pub identity: String,
    pub issuer: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogResources {
    pub cpu_request: String,
    pub cpu_limit: String,
    pub memory_request: String,
    pub memory_limit: String,
    pub ephemeral_storage_limit: String,
}

#[derive(Clone, Debug)]
pub struct VerifiedCatalog {
    entries: BTreeMap<String, CatalogEntry>,
}

impl VerifiedCatalog {
    pub fn load(
        catalog_path: &Path,
        trusted_root_path: &Path,
        bundle_directory: &Path,
    ) -> Result<Self, String> {
        let catalog_json = read_bounded(catalog_path, MAX_CATALOG_BYTES, "runner catalog")?;
        let catalog: Catalog = serde_json::from_slice(&catalog_json)
            .map_err(|error| format!("runner catalog is invalid JSON: {error}"))?;
        catalog.verify(trusted_root_path, bundle_directory)
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&CatalogEntry> {
        self.entries.get(name)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Catalog {
    pub fn verify(
        self,
        trusted_root_path: &Path,
        bundle_directory: &Path,
    ) -> Result<VerifiedCatalog, String> {
        if self.schema_version != 1 {
            return Err("runner catalog schemaVersion must be 1".into());
        }
        if self.entries.is_empty() || self.entries.len() > MAX_ENTRIES {
            return Err(format!(
                "runner catalog must contain between 1 and {MAX_ENTRIES} entries"
            ));
        }
        let trusted_root_json = read_bounded(
            trusted_root_path,
            MAX_TRUST_ROOT_BYTES,
            "Sigstore trusted root",
        )?;
        let trusted_root = TrustedRoot::from_json(
            std::str::from_utf8(&trusted_root_json)
                .map_err(|_| "Sigstore trusted root must be UTF-8 JSON")?,
        )
        .map_err(|error| format!("Sigstore trusted root is invalid: {error}"))?;
        validate_trusted_root_shape(&trusted_root)?;
        let verifier = Verifier::new(&trusted_root);
        let canonical_bundle_directory = bundle_directory
            .canonicalize()
            .map_err(|error| format!("cannot resolve Sigstore bundle directory: {error}"))?;
        let mut entries = BTreeMap::new();
        for entry in self.entries {
            validate_entry(&entry)?;
            let digest = entry.image.strip_prefix("sha256:").ok_or_else(|| {
                format!("catalog entry {} image must be a sha256 digest", entry.name)
            })?;
            let artifact_digest = Sha256Hash::from_hex(digest).map_err(|error| {
                format!("catalog entry {} digest is invalid: {error}", entry.name)
            })?;
            let bundle_path =
                resolve_bundle(&canonical_bundle_directory, &entry.signature.bundle_file)?;
            let bundle_json = read_bounded(&bundle_path, MAX_BUNDLE_BYTES, "Sigstore bundle")?;
            let bundle = Bundle::from_json(
                std::str::from_utf8(&bundle_json)
                    .map_err(|_| "Sigstore bundle must be UTF-8 JSON")?,
            )
            .map_err(|error| format!("catalog entry {} bundle is invalid: {error}", entry.name))?;
            let validation_time = validate_bundle_trust_window(&trusted_root, &bundle)
                .map_err(|error| format!("catalog entry {} {error}", entry.name))?;
            let policy = VerificationPolicy::default()
                .require_identity(&entry.signature.identity)
                .require_issuer(&entry.signature.issuer);
            let verified = verifier
                .verify(artifact_digest, &bundle, &policy)
                .map_err(|error| {
                    format!(
                        "catalog entry {} failed offline Sigstore verification: {error}",
                        entry.name
                    )
                })?;
            if verified.integrated_time != Some(validation_time.as_second())
                || !verified.warnings.is_empty()
            {
                return Err(format!(
                    "catalog entry {} returned ambiguous Sigstore verification evidence",
                    entry.name
                ));
            }
            let name = entry.name.clone();
            if entries.insert(name.clone(), entry).is_some() {
                return Err(format!("runner catalog contains duplicate entry {name}"));
            }
        }
        Ok(VerifiedCatalog { entries })
    }
}

fn validate_trusted_root_shape(root: &TrustedRoot) -> Result<(), String> {
    if root.certificate_authorities.len() != 1
        || root.tlogs.len() != 1
        || root.ctlogs.len() != 1
        || !root.timestamp_authorities.is_empty()
        || !(1..=8).contains(
            &root.certificate_authorities[0]
                .cert_chain
                .certificates
                .len(),
        )
    {
        return Err(
            "Sigstore trusted root must contain exactly one bounded Fulcio, Rekor, and CT authority and no TSA authority"
                .into(),
        );
    }
    Ok(())
}

fn validate_bundle_trust_window(root: &TrustedRoot, bundle: &Bundle) -> Result<Timestamp, String> {
    let entries = &bundle.verification_material.tlog_entries;
    if entries.len() != 1
        || entries[0].integrated_time <= 0
        || entries[0].kind_version.version != "0.0.1"
        || entries[0].inclusion_promise.is_none()
        || entries[0].inclusion_proof.is_none()
        || !bundle
            .verification_material
            .timestamp_verification_data
            .rfc3161_timestamps
            .is_empty()
        || entries[0].log_id.key_id != root.tlogs[0].log_id.key_id
    {
        return Err(
            "Sigstore bundle must carry one Rekor v1 entry with proof, promise, and no TSA timestamp"
                .into(),
        );
    }
    let time = Timestamp::from_second(entries[0].integrated_time)
        .map_err(|_| "Sigstore integrated time is invalid")?;
    require_exact_window(
        root.certificate_authorities[0].valid_for.as_ref(),
        time,
        "Fulcio authority",
    )?;
    require_exact_window(
        root.tlogs[0].public_key.valid_for.as_ref(),
        time,
        "Rekor key",
    )?;
    require_exact_window(root.ctlogs[0].public_key.valid_for.as_ref(), time, "CT key")?;
    Ok(time)
}

fn require_exact_window(
    period: Option<&ValidityPeriod>,
    time: Timestamp,
    authority: &str,
) -> Result<(), String> {
    let period = period.ok_or_else(|| format!("{authority} has no bounded validFor window"))?;
    if period.start.is_none()
        || period.end.is_none()
        || !period
            .contains(time)
            .map_err(|error| format!("{authority} validFor window is invalid: {error}"))?
    {
        return Err(format!(
            "Sigstore integrated time is outside the exact {authority} validFor window"
        ));
    }
    Ok(())
}

fn validate_entry(entry: &CatalogEntry) -> Result<(), String> {
    if !is_dns_label(&entry.name) {
        return Err(format!("catalog entry name is invalid: {}", entry.name));
    }
    if !entry.image.starts_with("sha256:") || entry.image.len() != 71 {
        return Err(format!(
            "catalog entry {} image is not digest-pinned",
            entry.name
        ));
    }
    if !valid_repository(&entry.repository)
        || !valid_source_url(&entry.source)
        || entry.license.is_empty()
        || entry.license.len() > 256
        || !entry.command.starts_with('/')
        || entry.command.len() > 1024
        || entry.arguments.len() > 32
        || entry.arguments.iter().any(|argument| argument.len() > 4096)
        || !is_dns_label(&entry.egress_profile)
        || entry.signature.identity.is_empty()
        || entry.signature.identity.len() > 2048
        || entry.signature.issuer.is_empty()
        || entry.signature.issuer.len() > 2048
    {
        return Err(format!(
            "catalog entry {} has invalid bounded fields",
            entry.name
        ));
    }
    let supported = BTreeSet::from(["amd64".to_owned(), "arm64".to_owned(), "riscv64".to_owned()]);
    if entry.architectures.is_empty() || !entry.architectures.is_subset(&supported) {
        return Err(format!(
            "catalog entry {} has unsupported architectures",
            entry.name
        ));
    }
    for quantity in [
        &entry.resources.cpu_request,
        &entry.resources.cpu_limit,
        &entry.resources.memory_request,
        &entry.resources.memory_limit,
        &entry.resources.ephemeral_storage_limit,
    ] {
        if !valid_quantity(quantity) {
            return Err(format!(
                "catalog entry {} has invalid resource quantity",
                entry.name
            ));
        }
    }
    Ok(())
}

fn valid_repository(value: &str) -> bool {
    (value.starts_with("ghcr.io/") || value.starts_with("docker.io/"))
        && value.len() <= 255
        && !value.contains('@')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"./_-".contains(&byte)
        })
        && value
            .rsplit_once('/')
            .is_some_and(|(_, name)| !name.is_empty() && !name.contains(':'))
}

fn valid_source_url(value: &str) -> bool {
    value.len() <= 2048
        && Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none()
        })
}

fn resolve_bundle(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let candidate = Path::new(relative);
    if candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err("Sigstore bundle path must stay below the bundle directory".into());
    }
    let resolved = root
        .join(candidate)
        .canonicalize()
        .map_err(|error| format!("cannot resolve Sigstore bundle: {error}"))?;
    if !resolved.starts_with(root) {
        return Err("Sigstore bundle resolves outside the bundle directory".into());
    }
    Ok(resolved)
}

fn read_bounded(path: &Path, maximum: u64, description: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("cannot inspect {description}: {error}"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(format!("{description} size is outside its allowed range"));
    }
    fs::read(path).map_err(|error| format!("cannot read {description}: {error}"))
}

fn is_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'-' => index > 0 && index + 1 < value.len(),
            _ => false,
        })
}

fn valid_quantity(value: &str) -> bool {
    let suffix = ["m", "Ki", "Mi", "Gi", "Ti"]
        .iter()
        .find(|suffix| value.ends_with(**suffix))
        .copied()
        .unwrap_or("");
    let digits = value.strip_suffix(suffix).unwrap_or(value);
    !digits.is_empty() && digits.len() <= 20 && digits.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{
        Catalog, CatalogEntry, CatalogResources, CatalogSignature, require_exact_window,
        validate_entry, validate_trusted_root_shape,
    };
    use jiff::Timestamp;
    use sigstore_verify::trust_root::{TrustedRoot, ValidityPeriod};
    use std::collections::BTreeSet;

    fn entry() -> CatalogEntry {
        CatalogEntry {
            name: "read-only-files".into(),
            repository: "ghcr.io/example/read-only-files".into(),
            image: format!("sha256:{}", "a".repeat(64)),
            source: "https://example.invalid/server".into(),
            license: "Apache-2.0".into(),
            command: "/usr/local/bin/server".into(),
            arguments: vec!["--stdio".into()],
            architectures: BTreeSet::from(["amd64".into(), "arm64".into()]),
            egress_profile: "public-web".into(),
            signature: CatalogSignature {
                bundle_file: "server.sigstore.json".into(),
                identity: "https://github.com/example/release.yml@refs/tags/v1".into(),
                issuer: "https://token.actions.githubusercontent.com".into(),
            },
            resources: CatalogResources {
                cpu_request: "50m".into(),
                cpu_limit: "500m".into(),
                memory_request: "64Mi".into(),
                memory_limit: "256Mi".into(),
                ephemeral_storage_limit: "64Mi".into(),
            },
        }
    }

    #[test]
    fn entry_requires_digest_fixed_command_and_supported_architecture() {
        validate_entry(&entry()).expect("valid entry");
        let mut mutable = entry();
        mutable.image = "latest".into();
        assert!(validate_entry(&mutable).is_err());
        let mut mutable = entry();
        mutable.command = "sh -c server".into();
        assert!(validate_entry(&mutable).is_err());
        let mut mutable = entry();
        mutable.architectures.insert("ppc64le".into());
        assert!(validate_entry(&mutable).is_err());
    }

    #[test]
    fn catalog_denies_unknown_fields() {
        let document = r#"{"schemaVersion":1,"entries":[],"network":"any"}"#;
        assert!(serde_json::from_str::<Catalog>(document).is_err());
    }

    #[test]
    fn trust_material_requires_one_exact_bounded_authority_window() {
        let empty = TrustedRoot::from_json(
            r#"{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1","tlogs":[],"certificateAuthorities":[],"ctlogs":[],"timestampAuthorities":[]}"#,
        )
        .expect("valid empty root shape");
        assert!(validate_trusted_root_shape(&empty).is_err());

        let time: Timestamp = "2026-08-07T00:00:00Z".parse().expect("timestamp");
        let exact = ValidityPeriod {
            start: Some("2026-08-01T00:00:00Z".into()),
            end: Some("2026-09-01T00:00:00Z".into()),
        };
        require_exact_window(Some(&exact), time, "test authority").expect("bounded window");
        let unbounded = ValidityPeriod {
            start: None,
            end: exact.end,
        };
        assert!(require_exact_window(Some(&unbounded), time, "test authority").is_err());
    }
}
