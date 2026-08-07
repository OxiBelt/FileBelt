// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use filebelt_repository_tests::repository_root;
use syn::visit::{self, Visit};
use syn::{ExprPath, File, Item, ItemExternCrate, ItemUse, Macro, TypePath, UseTree, Visibility};
use toml::Value;

const POLICY_PATH: &str = "supply-chain/cargo-boundaries-v1.toml";

#[derive(Debug)]
struct PackageRoot {
    package: String,
    root: PathBuf,
}

#[derive(Debug)]
struct SourceBoundary {
    label: String,
    packages: BTreeSet<String>,
    forbidden_paths: Vec<String>,
}

#[derive(Debug)]
struct PublicSurface {
    package: String,
    crate_root: PathBuf,
    public_modules: BTreeSet<String>,
    wildcard_reexports: BTreeSet<String>,
}

#[derive(Debug)]
struct DecompositionPolicy {
    production_source_roots: Vec<PathBuf>,
    excluded_source_roots: Vec<PathBuf>,
    packages: Vec<PackageRoot>,
    boundaries: Vec<SourceBoundary>,
    public_surfaces: Vec<PublicSurface>,
}

fn read_policy(root: &Path) -> DecompositionPolicy {
    let text = fs::read_to_string(root.join(POLICY_PATH)).expect("Cargo boundary policy");
    let document: Value = toml::from_str(&text).expect("valid Cargo boundary policy");
    assert_eq!(
        document.get("schema_version").and_then(Value::as_integer),
        Some(1),
        "unsupported Cargo boundary policy schema"
    );

    let repository = table(&document, "repository");
    let production_source_roots = string_array_from_table(repository, "production_source_roots")
        .into_iter()
        .map(PathBuf::from)
        .collect();
    let excluded_source_roots = string_array_from_table(repository, "excluded_source_roots")
        .into_iter()
        .map(PathBuf::from)
        .collect();

    let packages = array(&document, "graph_profiles")
        .iter()
        .map(|profile| {
            let manifest = PathBuf::from(string(profile, "manifest"));
            PackageRoot {
                package: string(profile, "package"),
                root: manifest
                    .parent()
                    .expect("profile manifest must have a parent")
                    .to_path_buf(),
            }
        })
        .collect::<Vec<_>>();
    let package_names: BTreeSet<_> = packages
        .iter()
        .map(|package| package.package.as_str())
        .collect();

    let boundaries = array(&document, "source_boundaries")
        .iter()
        .map(|boundary| {
            let packages: BTreeSet<_> = string_array(boundary, "packages").into_iter().collect();
            assert!(
                packages
                    .iter()
                    .all(|package| package_names.contains(package.as_str())),
                "source boundary references an unknown production package"
            );
            SourceBoundary {
                label: string(boundary, "label"),
                packages,
                forbidden_paths: string_array(boundary, "forbidden_paths"),
            }
        })
        .collect();

    let public_surfaces = array(&document, "public_surfaces")
        .iter()
        .map(|surface| PublicSurface {
            package: string(surface, "package"),
            crate_root: PathBuf::from(string(surface, "crate_root")),
            public_modules: string_set(surface, "public_modules"),
            wildcard_reexports: string_set(surface, "wildcard_reexports"),
        })
        .collect::<Vec<_>>();
    let surface_packages: BTreeSet<_> = public_surfaces
        .iter()
        .map(|surface| surface.package.as_str())
        .collect();
    assert_eq!(
        surface_packages, package_names,
        "every production package must have a public-surface snapshot"
    );
    let surface_roots: BTreeSet<_> = public_surfaces
        .iter()
        .map(|surface| surface.crate_root.as_path())
        .collect();
    assert_eq!(
        surface_roots.len(),
        public_surfaces.len(),
        "public-surface crate roots must be unique"
    );

    DecompositionPolicy {
        production_source_roots,
        excluded_source_roots,
        packages,
        boundaries,
        public_surfaces,
    }
}

fn table<'a>(value: &'a Value, key: &str) -> &'a toml::map::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_table)
        .unwrap_or_else(|| panic!("{key} must be a TOML table"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be a TOML array"))
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

fn string_array_from_table(value: &toml::map::Map<String, Value>, key: &str) -> Vec<String> {
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

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    let values = string_array(value, key);
    let result: BTreeSet<_> = values.iter().cloned().collect();
    assert_eq!(
        result.len(),
        values.len(),
        "{key} must not contain duplicates"
    );
    result
}

fn discover_rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("failed to inspect {}: {error}", path.display()));
    assert!(
        !metadata.file_type().is_symlink(),
        "source-policy roots cannot be symlinks"
    );
    if metadata.is_file() {
        if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            files.push(path.to_path_buf());
        }
        return;
    }
    assert!(
        metadata.is_dir(),
        "source-policy path is not a file or directory"
    );

    let mut entries: Vec<_> = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .map(|entry| entry.expect("source entry must be readable").path())
        .collect();
    entries.sort();
    for entry in entries {
        let file_type = fs::symlink_metadata(&entry)
            .unwrap_or_else(|error| panic!("failed to inspect {}: {error}", entry.display()))
            .file_type();
        assert!(
            !file_type.is_symlink(),
            "production source cannot be a symlink: {}",
            entry.display()
        );
        if file_type.is_dir()
            || entry.extension().and_then(|extension| extension.to_str()) == Some("rs")
        {
            discover_rust_files(&entry, files);
        }
    }
}

fn parse_rust(path: &Path) -> File {
    let source = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    syn::parse_file(&source).unwrap_or_else(|error| {
        panic!(
            "failed to parse production Rust {}: {error}",
            path.display()
        )
    })
}

#[derive(Default)]
struct PathCollector {
    paths: BTreeSet<String>,
}

impl PathCollector {
    fn insert_path(&mut self, path: &syn::Path) {
        let joined = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        if !joined.is_empty() {
            self.paths.insert(joined);
        }
    }

    fn insert_use_tree(&mut self, prefix: &mut Vec<String>, tree: &UseTree) {
        match tree {
            UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.insert_use_tree(prefix, &path.tree);
                prefix.pop();
            }
            UseTree::Name(name) => {
                prefix.push(name.ident.to_string());
                self.paths.insert(prefix.join("::"));
                prefix.pop();
            }
            UseTree::Rename(rename) => {
                prefix.push(rename.ident.to_string());
                self.paths.insert(prefix.join("::"));
                prefix.pop();
            }
            UseTree::Glob(_) => {
                if !prefix.is_empty() {
                    self.paths.insert(prefix.join("::"));
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.insert_use_tree(prefix, item);
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for PathCollector {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.insert_path(path);
        visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.insert_use_tree(&mut Vec::new(), &item.tree);
        visit::visit_item_use(self, item);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        self.paths.insert(item.ident.to_string());
        visit::visit_item_extern_crate(self, item);
    }

    fn visit_expr_path(&mut self, expression: &'ast ExprPath) {
        self.insert_path(&expression.path);
        visit::visit_expr_path(self, expression);
    }

    fn visit_type_path(&mut self, type_path: &'ast TypePath) {
        self.insert_path(&type_path.path);
        visit::visit_type_path(self, type_path);
    }

    fn visit_macro(&mut self, macro_invocation: &'ast Macro) {
        self.insert_path(&macro_invocation.path);
        visit::visit_macro(self, macro_invocation);
    }
}

fn path_matches(actual: &str, forbidden: &str) -> bool {
    let actual: Vec<_> = actual.trim_start_matches("::").split("::").collect();
    let forbidden: Vec<_> = forbidden.trim_start_matches("::").split("::").collect();
    actual.starts_with(&forbidden)
}

fn owning_package<'a>(relative: &Path, packages: &'a [PackageRoot]) -> Option<&'a str> {
    packages
        .iter()
        .filter(|package| relative.starts_with(&package.root))
        .max_by_key(|package| package.root.components().count())
        .map(|package| package.package.as_str())
}

fn collect_wildcard_reexports(
    tree: &UseTree,
    prefix: &mut Vec<String>,
    output: &mut BTreeSet<String>,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_wildcard_reexports(&path.tree, prefix, output);
            prefix.pop();
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_wildcard_reexports(item, prefix, output);
            }
        }
        UseTree::Glob(_) => {
            output.insert(format!("{}::*", prefix.join("::")));
        }
        UseTree::Name(_) | UseTree::Rename(_) => {}
    }
}

fn actual_public_surface(file: &File) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut modules = BTreeSet::new();
    let mut wildcard_reexports = BTreeSet::new();
    for item in &file.items {
        match item {
            Item::Mod(module) if matches!(module.vis, Visibility::Public(_)) => {
                modules.insert(module.ident.to_string());
            }
            Item::Use(item_use) if matches!(item_use.vis, Visibility::Public(_)) => {
                collect_wildcard_reexports(
                    &item_use.tree,
                    &mut Vec::new(),
                    &mut wildcard_reexports,
                );
            }
            _ => {}
        }
    }
    (modules, wildcard_reexports)
}

#[test]
fn production_sources_follow_import_and_public_surface_policy() {
    let root = repository_root();
    let policy = read_policy(&root);
    let excluded: Vec<_> = policy
        .excluded_source_roots
        .iter()
        .map(|path| root.join(path))
        .collect();
    let mut files = Vec::new();
    for source_root in &policy.production_source_roots {
        discover_rust_files(&root.join(source_root), &mut files);
    }
    files.sort();
    files.dedup();
    assert!(
        !files.is_empty(),
        "production source policy found no Rust files"
    );

    let boundaries_by_package: BTreeMap<_, Vec<_>> = policy
        .packages
        .iter()
        .map(|package| {
            let boundaries = policy
                .boundaries
                .iter()
                .filter(|boundary| boundary.packages.contains(&package.package))
                .collect();
            (package.package.as_str(), boundaries)
        })
        .collect();
    let mut violations = Vec::new();
    for file_path in files {
        assert!(
            excluded
                .iter()
                .all(|excluded| !file_path.starts_with(excluded)),
            "excluded generated/test source entered production scan: {}",
            file_path.display()
        );
        let parsed = parse_rust(&file_path);
        let relative = file_path
            .strip_prefix(&root)
            .expect("source below repository");
        let Some(package) = owning_package(relative, &policy.packages) else {
            // Reserved adapters without manifests are still syntax-checked above.
            continue;
        };
        let mut collector = PathCollector::default();
        collector.visit_file(&parsed);
        for boundary in boundaries_by_package.get(package).into_iter().flatten() {
            for forbidden in &boundary.forbidden_paths {
                if let Some(actual) = collector
                    .paths
                    .iter()
                    .find(|actual| path_matches(actual, forbidden))
                {
                    violations.push(format!(
                        "{} ({package}) violates {} with {actual}",
                        relative.display(),
                        boundary.label
                    ));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "production source-boundary violations:\n  - {}",
        violations.join("\n  - ")
    );

    for surface in &policy.public_surfaces {
        let path = root.join(&surface.crate_root);
        let parsed = parse_rust(&path);
        let (modules, wildcard_reexports) = actual_public_surface(&parsed);
        assert_eq!(
            modules,
            surface.public_modules,
            "{} public root modules changed for {}",
            surface.package,
            surface.crate_root.display()
        );
        assert_eq!(
            wildcard_reexports,
            surface.wildcard_reexports,
            "{} wildcard re-exports changed for {}",
            surface.package,
            surface.crate_root.display()
        );
    }
}

#[test]
fn path_collection_handles_nested_aliases_and_fully_qualified_paths() {
    let file = syn::parse_file(
        r#"
use std::{fs as filesystem, net::*};
use sqlx::{self as database, postgres::PgPool};

fn example() {
    let _ = openidconnect::IssuerUrl::new(String::new());
}
"#,
    )
    .expect("fixture Rust");
    let mut collector = PathCollector::default();
    collector.visit_file(&file);
    for expected in [
        "std::fs",
        "std::net",
        "sqlx::self",
        "sqlx::postgres::PgPool",
        "openidconnect::IssuerUrl::new",
    ] {
        assert!(
            collector.paths.contains(expected),
            "missing path {expected}"
        );
    }
}

#[test]
fn boundary_matching_uses_path_segments_not_string_prefixes() {
    assert!(path_matches("filebelt_storage::Store", "filebelt_storage"));
    assert!(path_matches("std::fs::File", "std::fs"));
    assert!(!path_matches(
        "filebelt_storage_protocol::Capability",
        "filebelt_storage"
    ));
    assert!(!path_matches("http_body::Body", "http"));
}

#[test]
fn public_surface_snapshot_ignores_named_reexports_and_private_modules() {
    let file = syn::parse_file(
        r#"
pub mod public_api;
pub(crate) mod internal;
pub use api::*;
pub use api::Named;
"#,
    )
    .expect("fixture Rust");
    let (modules, wildcard_reexports) = actual_public_surface(&file);
    assert_eq!(modules, BTreeSet::from(["public_api".to_owned()]));
    assert_eq!(wildcard_reexports, BTreeSet::from(["api::*".to_owned()]));
}

#[test]
fn malformed_rust_is_rejected() {
    assert!(syn::parse_file("fn missing_name( {").is_err());
}
