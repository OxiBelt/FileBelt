// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use filebelt_repository_tests::repository_root;
use toml::Value;

const POLICY_PATH: &str = "supply-chain/cargo-boundaries-v1.toml";
const PRODUCTION_DEPENDENCY_TABLES: &[&str] = &["dependencies", "build-dependencies"];
const ALL_DEPENDENCY_TABLES: &[&str] = &["dependencies", "build-dependencies", "dev-dependencies"];

#[derive(Debug)]
struct GraphProfile {
    package: String,
    manifest: PathBuf,
    allowed_first_party: BTreeSet<String>,
}

#[derive(Debug)]
struct CargoBoundaryPolicy {
    apache_manifest_roots: Vec<PathBuf>,
    adapter_root: PathBuf,
    registered_adapter_manifests: BTreeSet<PathBuf>,
    profiles: Vec<GraphProfile>,
}

#[derive(Debug, PartialEq, Eq)]
struct ResolvedDependency {
    package: String,
    manifest: Option<PathBuf>,
    local_only: bool,
}

fn read_toml(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    toml::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn table<'a>(value: &'a Value, key: &str) -> &'a toml::map::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_table)
        .unwrap_or_else(|| panic!("{key} must be a TOML table"))
}

fn string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a TOML string"))
        .to_owned()
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be a TOML array"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn load_policy(root: &Path) -> CargoBoundaryPolicy {
    let document = read_toml(&root.join(POLICY_PATH));
    assert_eq!(
        document.get("schema_version").and_then(Value::as_integer),
        Some(1),
        "unsupported Cargo-boundary policy schema"
    );

    let repository = table(&document, "repository");
    let apache_manifest_roots =
        string_array(&Value::Table(repository.clone()), "apache_manifest_roots")
            .into_iter()
            .map(PathBuf::from)
            .collect();
    let adapter_root = PathBuf::from(string(&Value::Table(repository.clone()), "adapter_root"));
    let registered_adapter_manifests = string_array(
        &Value::Table(repository.clone()),
        "registered_adapter_manifests",
    )
    .into_iter()
    .map(PathBuf::from)
    .collect();

    let profiles = document
        .get("graph_profiles")
        .and_then(Value::as_array)
        .expect("graph_profiles must be a TOML array")
        .iter()
        .map(|profile| {
            let allowed_first_party = table(profile, "first_party_features")
                .keys()
                .cloned()
                .collect();
            GraphProfile {
                package: string(profile, "package"),
                manifest: PathBuf::from(string(profile, "manifest")),
                allowed_first_party,
            }
        })
        .collect();

    CargoBoundaryPolicy {
        apache_manifest_roots,
        adapter_root,
        registered_adapter_manifests,
        profiles,
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                assert!(normalized.pop(), "path escapes its filesystem root");
            }
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Normal(segment) => normalized.push(segment),
        }
    }
    normalized
}

fn discover_manifests(path: &Path, manifests: &mut BTreeSet<PathBuf>) {
    if path.is_file() {
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("Cargo.toml"),
            "Apache manifest roots must be Cargo.toml files or directories"
        );
        manifests.insert(path.to_path_buf());
        return;
    }

    if !path.exists() {
        panic!(
            "configured manifest root does not exist: {}",
            path.display()
        );
    }

    let mut entries: Vec<_> = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .map(|entry| entry.expect("directory entry must be readable").path())
        .collect();
    entries.sort();

    for entry in entries {
        if entry.is_dir() {
            if entry.file_name().and_then(|name| name.to_str()) != Some("target") {
                discover_manifests(&entry, manifests);
            }
        } else if entry.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml") {
            manifests.insert(entry);
        }
    }
}

fn dependency_tables(manifest: &Value, include_dev: bool) -> Vec<&toml::map::Map<String, Value>> {
    let names = if include_dev {
        ALL_DEPENDENCY_TABLES
    } else {
        PRODUCTION_DEPENDENCY_TABLES
    };
    let mut tables = Vec::new();
    let manifest_table = manifest.as_table().expect("manifest root must be a table");

    for name in names {
        if let Some(dependencies) = manifest_table.get(*name) {
            tables.push(
                dependencies
                    .as_table()
                    .unwrap_or_else(|| panic!("{name} must be a TOML table")),
            );
        }
    }

    if let Some(targets) = manifest_table.get("target") {
        for target in targets
            .as_table()
            .expect("target must be a TOML table")
            .values()
        {
            let target = target.as_table().expect("target selector must be a table");
            for name in names {
                if let Some(dependencies) = target.get(*name) {
                    tables.push(
                        dependencies
                            .as_table()
                            .unwrap_or_else(|| panic!("target.{name} must be a TOML table")),
                    );
                }
            }
        }
    }

    tables
}

fn dependency_package_name(alias: &str, specification: &Value) -> String {
    specification
        .as_table()
        .and_then(|table| table.get("package"))
        .and_then(Value::as_str)
        .unwrap_or(alias)
        .to_owned()
}

fn dependency_path(specification: &Value) -> Option<&str> {
    specification
        .as_table()
        .and_then(|table| table.get("path"))
        .and_then(Value::as_str)
}

fn dependency_uses_workspace(specification: &Value) -> bool {
    specification
        .as_table()
        .and_then(|table| table.get("workspace"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn manifest_for_dependency_path(base_manifest: &Path, path: &str) -> Result<PathBuf, String> {
    let package_root = normalize(
        &base_manifest
            .parent()
            .ok_or_else(|| format!("manifest has no parent: {}", base_manifest.display()))?
            .join(path),
    );
    let manifest = if package_root.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml")
    {
        package_root
    } else {
        package_root.join("Cargo.toml")
    };
    fs::canonicalize(&manifest).map_err(|error| {
        format!(
            "failed to resolve local dependency {}: {error}",
            manifest.display()
        )
    })
}

fn resolve_dependency(
    alias: &str,
    specification: &Value,
    workspace_dependencies: &toml::map::Map<String, Value>,
    workspace_manifest: &Path,
    dependent_manifest: &Path,
) -> Result<ResolvedDependency, String> {
    let (resolved_specification, path_base) = if dependency_uses_workspace(specification) {
        let workspace_specification = workspace_dependencies.get(alias).ok_or_else(|| {
            format!("{alias} inherits from workspace dependencies but no root entry exists")
        })?;
        (workspace_specification, workspace_manifest)
    } else {
        (specification, dependent_manifest)
    };
    let package = dependency_package_name(alias, resolved_specification);
    let manifest = dependency_path(resolved_specification)
        .map(|path| manifest_for_dependency_path(path_base, path))
        .transpose()?;
    let local_only = resolved_specification.as_table().is_some_and(|table| {
        !table.contains_key("git")
            && !table.contains_key("registry")
            && !table.contains_key("registry-index")
    });

    Ok(ResolvedDependency {
        package,
        manifest,
        local_only,
    })
}

fn registered_manifest_identities(
    root: &Path,
    policy: &CargoBoundaryPolicy,
) -> BTreeMap<String, PathBuf> {
    let mut identities = BTreeMap::new();
    for profile in &policy.profiles {
        let manifest = fs::canonicalize(root.join(&profile.manifest)).unwrap_or_else(|error| {
            panic!(
                "failed to resolve registered manifest {}: {error}",
                profile.manifest.display()
            )
        });
        assert!(
            identities
                .insert(profile.package.clone(), manifest)
                .is_none(),
            "registered package {} appears in more than one profile",
            profile.package
        );
    }
    identities
}

fn validate_dependency_identity(
    alias: &str,
    specification: &Value,
    workspace_dependencies: &toml::map::Map<String, Value>,
    workspace_manifest: &Path,
    dependent_manifest: &Path,
    registered: &BTreeMap<String, PathBuf>,
) -> Result<ResolvedDependency, String> {
    let dependency = resolve_dependency(
        alias,
        specification,
        workspace_dependencies,
        workspace_manifest,
        dependent_manifest,
    )?;
    if let Some(manifest) = &dependency.manifest {
        let registered_package = registered
            .iter()
            .find_map(|(registered_package, registered_manifest)| {
                (registered_manifest == manifest).then_some(registered_package)
            })
            .ok_or_else(|| {
                format!(
                    "{alias} resolves to unregistered local manifest {}",
                    manifest.display()
                )
            })?;
        if registered_package != &dependency.package {
            return Err(format!(
                "{alias} declares package {} but local manifest {} is registered as {}",
                dependency.package,
                manifest.display(),
                registered_package
            ));
        }
    }

    if let Some(expected_manifest) = registered.get(&dependency.package) {
        let actual_manifest = dependency.manifest.as_ref().ok_or_else(|| {
            format!(
                "reserved first-party package {} must resolve to registered local manifest {}",
                dependency.package,
                expected_manifest.display()
            )
        })?;
        if !dependency.local_only || actual_manifest != expected_manifest {
            return Err(format!(
                "reserved first-party package {} must resolve only to registered manifest {}",
                dependency.package,
                expected_manifest.display()
            ));
        }
    }

    Ok(dependency)
}

fn root_workspace_manifest(root: &Path) -> (Value, PathBuf) {
    let manifest_path = root.join("Cargo.toml");
    let workspace = read_toml(&manifest_path);
    (workspace, manifest_path)
}

fn workspace_dependency_table(workspace: &Value) -> &toml::map::Map<String, Value> {
    table(workspace, "workspace")
        .get("dependencies")
        .and_then(Value::as_table)
        .expect("workspace.dependencies must be a TOML table")
}

#[test]
fn policy_registers_every_apache_production_manifest() {
    let root = repository_root();
    let policy = load_policy(&root);
    let mut discovered = BTreeSet::new();
    for configured_root in &policy.apache_manifest_roots {
        discover_manifests(&root.join(configured_root), &mut discovered);
    }
    let discovered: BTreeSet<_> = discovered
        .into_iter()
        .map(|path| {
            path.strip_prefix(&root)
                .expect("production manifest must be within repository")
                .to_path_buf()
        })
        .collect();
    let registered: BTreeSet<_> = policy
        .profiles
        .iter()
        .filter(|profile| !profile.manifest.starts_with(&policy.adapter_root))
        .map(|profile| profile.manifest.clone())
        .collect();

    assert_eq!(registered, discovered);
    for profile in &policy.profiles {
        let manifest = read_toml(&root.join(&profile.manifest));
        assert_eq!(
            manifest
                .get("package")
                .and_then(Value::as_table)
                .and_then(|package| package.get("name"))
                .and_then(Value::as_str),
            Some(profile.package.as_str()),
            "profile package does not match {}",
            profile.manifest.display()
        );
        assert!(
            profile.allowed_first_party.contains(&profile.package),
            "{} must include itself in its reviewed first-party closure",
            profile.package
        );
    }
}

#[test]
fn workspace_membership_and_adapter_registration_are_fail_closed() {
    let root = repository_root();
    let policy = load_policy(&root);
    let workspace = read_toml(&root.join("Cargo.toml"));
    let workspace_table = table(&workspace, "workspace");
    let members: BTreeSet<_> = workspace_table
        .get("members")
        .and_then(Value::as_array)
        .expect("workspace.members must be an array")
        .iter()
        .map(|member| {
            let member = member.as_str().expect("workspace member must be a string");
            assert!(
                !member.contains(['*', '?', '[']),
                "workspace member globs are not supported by this contract"
            );
            normalize(&root.join(member).join("Cargo.toml"))
        })
        .collect();
    let adapter_root = normalize(&root.join(&policy.adapter_root));

    for profile in &policy.profiles {
        let manifest = normalize(&root.join(&profile.manifest));
        if manifest.starts_with(&adapter_root) {
            assert!(
                !members.contains(&manifest),
                "adapter package {} must stay outside the root workspace",
                profile.package
            );
        } else {
            assert!(
                members.contains(&manifest),
                "production package {} is not a root workspace member",
                profile.package
            );
        }
    }
    assert!(
        members
            .iter()
            .all(|manifest| !manifest.starts_with(&adapter_root)),
        "root Apache workspace must not contain adapters"
    );

    let mut discovered_adapters = BTreeSet::new();
    discover_manifests(&adapter_root, &mut discovered_adapters);
    let discovered_adapters: BTreeSet<_> = discovered_adapters
        .into_iter()
        .map(|path| {
            path.strip_prefix(&root)
                .expect("adapter manifest must be within repository")
                .to_path_buf()
        })
        .collect();
    assert_eq!(
        discovered_adapters, policy.registered_adapter_manifests,
        "adapter manifests require explicit, license-reviewed registration"
    );
}

#[test]
fn production_first_party_manifest_edges_stay_in_the_reviewed_closure() {
    let root = repository_root();
    let policy = load_policy(&root);
    let registered = registered_manifest_identities(&root, &policy);
    let (workspace, workspace_manifest) = root_workspace_manifest(&root);
    let workspace_dependencies = workspace_dependency_table(&workspace);

    for profile in &policy.profiles {
        let manifest_path = root.join(&profile.manifest);
        let manifest = read_toml(&manifest_path);
        for dependencies in dependency_tables(&manifest, false) {
            for (alias, specification) in dependencies {
                let dependency = validate_dependency_identity(
                    alias,
                    specification,
                    workspace_dependencies,
                    &workspace_manifest,
                    &manifest_path,
                    &registered,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "{} dependency {alias} violates Cargo identity contract: {error}",
                        profile.manifest.display()
                    )
                });
                if registered.contains_key(&dependency.package) {
                    assert!(
                        profile.allowed_first_party.contains(&dependency.package),
                        "{} has unreviewed first-party dependency {}",
                        profile.package,
                        dependency.package
                    );
                }
            }
        }
    }
}

#[test]
fn apache_manifests_never_path_depend_on_adapters() {
    let root = repository_root();
    let policy = load_policy(&root);
    let adapter_root = normalize(&root.join(&policy.adapter_root));
    let (workspace, workspace_manifest) = root_workspace_manifest(&root);
    let workspace_dependencies = workspace_dependency_table(&workspace);
    let manifests = std::iter::once(PathBuf::from("Cargo.toml")).chain(
        policy
            .profiles
            .iter()
            .filter(|profile| !profile.manifest.starts_with(&policy.adapter_root))
            .map(|profile| profile.manifest.clone()),
    );

    for relative_manifest in manifests {
        let absolute_manifest = root.join(&relative_manifest);
        let manifest = read_toml(&absolute_manifest);
        for dependencies in dependency_tables(&manifest, true) {
            for (alias, specification) in dependencies {
                let dependency = resolve_dependency(
                    alias,
                    specification,
                    workspace_dependencies,
                    &workspace_manifest,
                    &absolute_manifest,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "{} dependency {alias} cannot be resolved: {error}",
                        relative_manifest.display()
                    )
                });
                if let Some(resolved) = dependency.manifest {
                    assert!(
                        !resolved.starts_with(&adapter_root),
                        "{} dependency {alias} crosses into adapters via {}",
                        relative_manifest.display(),
                        resolved.display()
                    );
                }
            }
        }
    }
}

#[test]
fn structured_dependency_parser_detects_an_adapter_path() {
    let root = repository_root();
    let manifest: Value = toml::from_str(
        r#"
[package]
name = "fixture"

[target.'cfg(unix)'.dev-dependencies]
adapter-alias = { package = "adapter-example", path = "../../../adapters/example" }
"#,
    )
    .expect("fixture manifest must parse");
    let manifest_path = root.join("source/crates/fixture/Cargo.toml");
    let adapter_root = normalize(&root.join("adapters"));

    let detected = dependency_tables(&manifest, true)
        .into_iter()
        .flat_map(|dependencies| dependencies.values())
        .filter_map(dependency_path)
        .map(|path| {
            normalize(
                &manifest_path
                    .parent()
                    .expect("fixture manifest must have a parent")
                    .join(path),
            )
        })
        .any(|path| path.starts_with(&adapter_root));

    assert!(detected);
}

#[test]
fn manifest_identity_contract_rejects_direct_reserved_name_substitution() {
    let root = repository_root();
    let policy = load_policy(&root);
    let registered = registered_manifest_identities(&root, &policy);
    let (workspace, workspace_manifest) = root_workspace_manifest(&root);
    let workspace_dependencies = workspace_dependency_table(&workspace);
    let dependent_manifest = root.join("source/apps/filebelt-api/Cargo.toml");

    let approved: Value =
        toml::from_str(r#"filebelt-domain = { path = "../../crates/filebelt-domain" }"#)
            .expect("approved dependency fixture must parse");
    assert!(
        validate_dependency_identity(
            "filebelt-domain",
            &approved["filebelt-domain"],
            workspace_dependencies,
            &workspace_manifest,
            &dependent_manifest,
            &registered,
        )
        .is_ok(),
        "registered first-party manifest path must remain permitted"
    );

    let path_spoof: Value =
        toml::from_str(r#"filebelt-domain = { path = "../../../adapters/smb" }"#)
            .expect("path spoof fixture must parse");
    let error = validate_dependency_identity(
        "filebelt-domain",
        &path_spoof["filebelt-domain"],
        workspace_dependencies,
        &workspace_manifest,
        &dependent_manifest,
        &registered,
    )
    .expect_err("reserved package name must not resolve through another registered manifest");
    assert!(error.contains("filebelt-domain"));

    let mismatched_alias: Value =
        toml::from_str(r#"unregistered-alias = { path = "../../crates/filebelt-domain" }"#)
            .expect("mismatched alias fixture must parse");
    let error = validate_dependency_identity(
        "unregistered-alias",
        &mismatched_alias["unregistered-alias"],
        workspace_dependencies,
        &workspace_manifest,
        &dependent_manifest,
        &registered,
    )
    .expect_err("registered manifest paths must not accept unregistered aliases");
    assert!(error.contains("registered as filebelt-domain"));

    for specification in [
        r#"filebelt-domain = "=0.1.0""#,
        r#"filebelt-domain = { git = "https://example.invalid/filebelt-domain" }"#,
    ] {
        let fixture: Value =
            toml::from_str(specification).expect("substitution fixture must parse");
        assert!(
            validate_dependency_identity(
                "filebelt-domain",
                &fixture["filebelt-domain"],
                workspace_dependencies,
                &workspace_manifest,
                &dependent_manifest,
                &registered,
            )
            .is_err(),
            "reserved package substitutions must fail closed"
        );
    }
}

#[test]
fn manifest_identity_contract_resolves_workspace_dependencies_and_aliases() {
    let root = repository_root();
    let policy = load_policy(&root);
    let registered = registered_manifest_identities(&root, &policy);
    let dependent_manifest = root.join("source/apps/filebelt-api/Cargo.toml");
    let workspace_manifest = root.join("Cargo.toml");
    let approved_workspace: Value = toml::from_str(
        r#"
[workspace.dependencies]
domain-alias = { package = "filebelt-domain", path = "source/crates/filebelt-domain" }
"#,
    )
    .expect("approved workspace fixture must parse");
    let approved_dependencies = workspace_dependency_table(&approved_workspace);
    let inherited: Value = toml::from_str(r#"domain-alias = { workspace = true }"#)
        .expect("inherited dependency fixture must parse");
    let dependency = validate_dependency_identity(
        "domain-alias",
        &inherited["domain-alias"],
        approved_dependencies,
        &workspace_manifest,
        &dependent_manifest,
        &registered,
    )
    .expect("workspace alias must resolve to its registered manifest");
    assert_eq!(dependency.package, "filebelt-domain");

    let spoofed_workspace: Value = toml::from_str(
        r#"
[workspace.dependencies]
domain-alias = { package = "filebelt-domain", path = "adapters/smb" }
"#,
    )
    .expect("spoofed workspace fixture must parse");
    let spoofed_dependencies = workspace_dependency_table(&spoofed_workspace);
    assert!(
        validate_dependency_identity(
            "domain-alias",
            &inherited["domain-alias"],
            spoofed_dependencies,
            &workspace_manifest,
            &dependent_manifest,
            &registered,
        )
        .is_err(),
        "workspace-inherited reserved package path spoof must fail closed"
    );
}

#[test]
fn manifest_identity_contract_checks_target_specific_production_dependencies() {
    let root = repository_root();
    let policy = load_policy(&root);
    let registered = registered_manifest_identities(&root, &policy);
    let (workspace, workspace_manifest) = root_workspace_manifest(&root);
    let workspace_dependencies = workspace_dependency_table(&workspace);
    let dependent_manifest = root.join("source/apps/filebelt-api/Cargo.toml");
    let manifest: Value = toml::from_str(
        r#"
[target.'cfg(unix)'.dependencies]
filebelt-domain = { path = "../../../adapters/smb" }
"#,
    )
    .expect("target-specific production fixture must parse");

    let results: Vec<_> = dependency_tables(&manifest, false)
        .into_iter()
        .flat_map(|dependencies| dependencies.iter())
        .map(|(alias, specification)| {
            validate_dependency_identity(
                alias,
                specification,
                workspace_dependencies,
                &workspace_manifest,
                &dependent_manifest,
                &registered,
            )
        })
        .collect();

    assert_eq!(
        results.len(),
        1,
        "target dependency table must be traversed"
    );
    assert!(
        results.into_iter().next().expect("one result").is_err(),
        "target-specific production spoof must reach identity validation"
    );
}

#[test]
fn manifest_identity_contract_allows_registered_adapter_protocol_path() {
    let root = repository_root();
    let policy = load_policy(&root);
    let registered = registered_manifest_identities(&root, &policy);
    let (workspace, workspace_manifest) = root_workspace_manifest(&root);
    let workspace_dependencies = workspace_dependency_table(&workspace);
    let adapter_manifest = root.join("adapters/smb/Cargo.toml");
    let dependency: Value = toml::from_str(
        r#"filebelt-vfs-protocol = { path = "../../source/crates/filebelt-vfs-protocol" }"#,
    )
    .expect("adapter protocol fixture must parse");
    let resolved = validate_dependency_identity(
        "filebelt-vfs-protocol",
        &dependency["filebelt-vfs-protocol"],
        workspace_dependencies,
        &workspace_manifest,
        &adapter_manifest,
        &registered,
    )
    .expect("registered adapter protocol dependency must remain permitted");
    let profile = policy
        .profiles
        .iter()
        .find(|profile| profile.package == "filebelt-smb-bridge")
        .expect("SMB adapter profile must exist");
    assert!(profile.allowed_first_party.contains(&resolved.package));
}

#[test]
fn root_node_workspace_excludes_adapters() {
    let root = repository_root();
    let workspace = fs::read_to_string(root.join("pnpm-workspace.yaml")).expect("pnpm workspace");
    assert!(!workspace.contains("adapters/"));
}
