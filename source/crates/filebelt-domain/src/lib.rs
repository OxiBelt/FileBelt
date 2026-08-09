// SPDX-License-Identifier: Apache-2.0

//! Pure domain identifiers and value objects shared by FileBelt services.
//!
//! This crate intentionally has no knowledge of persistence, transports,
//! filesystems, identity providers, event systems, or adapters.

#![deny(unsafe_code)]

use std::{fmt, str::FromStr};

use caseless::Caseless;
use unicode_normalization::UnicodeNormalization;
use uuid::{Uuid, Variant};

/// Maximum UTF-8 length of a normalized namespace component.
pub const MAX_NAME_BYTES: usize = 255;
/// Maximum UTF-8 length of an absolute logical path, including separators.
pub const MAX_PATH_BYTES: usize = 4_096;
/// Maximum number of components below a drive root.
pub const MAX_PATH_COMPONENTS: usize = 128;

/// Unicode data used by NFC normalization.
pub const NORMALIZATION_UNICODE_VERSION: (u8, u8, u8) = unicode_normalization::UNICODE_VERSION;
/// Unicode data used by full, non-Turkic default case folding.
pub const CASE_FOLD_UNICODE_VERSION: (u64, u64, u64) = caseless::UNICODE_VERSION;

/// A UUID did not satisfy the canonical FileBelt identifier contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdError {
    /// The input was not syntactically a UUID.
    InvalidSyntax,
    /// The input was not the lowercase, hyphenated canonical representation.
    NonCanonical,
    /// The UUID did not use the RFC 4122 variant.
    UnsupportedVariant,
    /// The UUID was not version 4.
    UnsupportedVersion,
}

impl IdError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidSyntax => "id.invalid_syntax",
            Self::NonCanonical => "id.non_canonical",
            Self::UnsupportedVariant => "id.unsupported_variant",
            Self::UnsupportedVersion => "id.unsupported_version",
        }
    }
}

impl fmt::Display for IdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for IdError {}

fn validate_uuid_v4(value: Uuid) -> Result<Uuid, IdError> {
    if value.get_variant() != Variant::RFC4122 {
        return Err(IdError::UnsupportedVariant);
    }
    if value.get_version_num() != 4 {
        return Err(IdError::UnsupportedVersion);
    }
    Ok(value)
}

fn parse_uuid_v4(value: &str) -> Result<Uuid, IdError> {
    let parsed = Uuid::parse_str(value).map_err(|_| IdError::InvalidSyntax)?;
    if parsed.hyphenated().to_string() != value {
        return Err(IdError::NonCanonical);
    }
    validate_uuid_v4(parsed)
}

macro_rules! define_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new random RFC 4122 UUIDv4 identifier.
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// Constructs the typed identifier after verifying UUIDv4 semantics.
            pub fn from_uuid(value: Uuid) -> Result<Self, IdError> {
                validate_uuid_v4(value).map(Self)
            }

            /// Returns the underlying UUID value.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }

            /// Returns the network-order UUID bytes.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; 16] {
                self.0.into_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0.hyphenated(), formatter)
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_uuid_v4(value).map(Self)
            }
        }

        impl TryFrom<Uuid> for $name {
            type Error = IdError;

            fn try_from(value: Uuid) -> Result<Self, Self::Error> {
                Self::from_uuid(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

define_id!(TenantId, "Identifies an isolated FileBelt tenant.");
define_id!(UserId, "Identifies a FileBelt user record.");
define_id!(PrincipalId, "Identifies an authorization principal.");
define_id!(GroupId, "Identifies a flat local group.");
define_id!(DriveId, "Identifies a logical drive.");
define_id!(NodeId, "Identifies a file or directory node.");
define_id!(FileVersionId, "Identifies an immutable file version.");
define_id!(BlobId, "Identifies a whole-file logical blob.");
define_id!(PayloadId, "Identifies a physical payload object.");
define_id!(ChunkId, "Identifies a logical payload chunk.");
define_id!(UploadSessionId, "Identifies a resumable upload session.");
define_id!(JobId, "Identifies a durable background job.");
define_id!(SessionId, "Identifies a local authenticated session.");
define_id!(ShareLinkId, "Identifies an anonymous share link.");
define_id!(AclEntryId, "Identifies a Virtual ACL entry.");

/// Stable Virtual ACL action vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Action {
    ReadMetadata,
    ListChildren,
    ReadContent,
    CreateChild,
    WriteContent,
    CreateVersion,
    Rename,
    Move,
    Delete,
    Restore,
    SetAttributes,
    Share,
    ManageAcl,
    ManageDrive,
    Transcode,
    UseExternalEditor,
    Comment,
    Review,
    UseMcp,
    Mount,
    Export,
}

impl Action {
    /// Every action, in stable policy ordering.
    pub const ALL: [Self; 21] = [
        Self::ReadMetadata,
        Self::ListChildren,
        Self::ReadContent,
        Self::CreateChild,
        Self::WriteContent,
        Self::CreateVersion,
        Self::Rename,
        Self::Move,
        Self::Delete,
        Self::Restore,
        Self::SetAttributes,
        Self::Share,
        Self::ManageAcl,
        Self::ManageDrive,
        Self::Transcode,
        Self::UseExternalEditor,
        Self::Comment,
        Self::Review,
        Self::UseMcp,
        Self::Mount,
        Self::Export,
    ];

    /// Stable uppercase name used by policy and audit contracts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadMetadata => "READ_METADATA",
            Self::ListChildren => "LIST_CHILDREN",
            Self::ReadContent => "READ_CONTENT",
            Self::CreateChild => "CREATE_CHILD",
            Self::WriteContent => "WRITE_CONTENT",
            Self::CreateVersion => "CREATE_VERSION",
            Self::Rename => "RENAME",
            Self::Move => "MOVE",
            Self::Delete => "DELETE",
            Self::Restore => "RESTORE",
            Self::SetAttributes => "SET_ATTRIBUTES",
            Self::Share => "SHARE",
            Self::ManageAcl => "MANAGE_ACL",
            Self::ManageDrive => "MANAGE_DRIVE",
            Self::Transcode => "TRANSCODE",
            Self::UseExternalEditor => "USE_EXTERNAL_EDITOR",
            Self::Comment => "COMMENT",
            Self::Review => "REVIEW",
            Self::UseMcp => "USE_MCP",
            Self::Mount => "MOUNT",
            Self::Export => "EXPORT",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Kinds of internal authorization principals.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PrincipalKind {
    User,
    Group,
    Organization,
    Service,
    ShareLink,
    MountSession,
    McpSession,
    DocumentSession,
}

impl PrincipalKind {
    /// Whether this kind may own a drive.
    #[must_use]
    pub const fn may_own_drive(self) -> bool {
        matches!(
            self,
            Self::User | Self::Group | Self::Organization | Self::Service
        )
    }
}

/// Kinds of resources on which policy decisions are made.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceKind {
    Tenant,
    Group,
    Drive,
    Directory,
    File,
    FileVersion,
    UploadSession,
    ShareLink,
}

/// Stable typed identity for a policy resource.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceId {
    Tenant(TenantId),
    Group(GroupId),
    Drive(DriveId),
    Node(NodeId),
    FileVersion(FileVersionId),
    UploadSession(UploadSessionId),
    ShareLink(ShareLinkId),
}

/// Drive ownership principals accepted by the domain model.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DriveOwner {
    User(PrincipalId),
    Group(GroupId),
    Organization(PrincipalId),
    Service(PrincipalId),
}

/// Role of a user in a flat local group.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GroupRole {
    Member,
    Manager,
}

/// FileBelt namespace node kind.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NodeKind {
    File,
    Directory,
}

/// A monotonically increasing generation used for compare-and-swap and leases.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Generation(u64);

impl Generation {
    /// Initial generation for a newly persisted aggregate.
    pub const INITIAL: Self = Self(0);

    /// Creates a generation from its persisted integer representation.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the persisted integer representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next generation, or `None` on overflow.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// The generations that fully qualify an authorization decision.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct GenerationSnapshot {
    pub resource_acl: Generation,
    pub membership: Generation,
    pub namespace: Generation,
}

/// A non-negative byte count.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ByteCount(u64);

impl ByteCount {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// A byte offset within an immutable payload.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ByteOffset(u64);

impl ByteOffset {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A server-computed BLAKE3 digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Blake3Digest([u8; 32]);

impl Blake3Digest {
    #[must_use]
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Stable normalized-name validation category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameError {
    Empty,
    DotComponent,
    ForbiddenCharacter,
    TrailingSpaceOrDot,
    ReservedDeviceName,
    TooLong,
}

impl NameError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Empty => "name.empty",
            Self::DotComponent => "name.dot_component",
            Self::ForbiddenCharacter => "name.forbidden_character",
            Self::TrailingSpaceOrDot => "name.trailing_space_or_dot",
            Self::ReservedDeviceName => "name.reserved_device",
            Self::TooLong => "name.too_long",
        }
    }
}

impl fmt::Display for NameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for NameError {}

/// A validated namespace component and its collision comparison key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NormalizedName {
    display: String,
    comparison_key: String,
}

impl NormalizedName {
    /// Normalizes an input component to NFC and validates the shared namespace policy.
    pub fn new(value: &str) -> Result<Self, NameError> {
        let display: String = value.nfc().collect();
        validate_display_name(&display)?;
        let comparison_key = display.chars().default_case_fold().collect();
        Ok(Self {
            display,
            comparison_key,
        })
    }

    /// NFC display form persisted and returned to clients.
    #[must_use]
    pub fn display(&self) -> &str {
        &self.display
    }

    /// Full Unicode default case-fold key used for sibling uniqueness.
    #[must_use]
    pub fn comparison_key(&self) -> &str {
        &self.comparison_key
    }
}

impl fmt::Display for NormalizedName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.display)
    }
}

impl FromStr for NormalizedName {
    type Err = NameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

fn validate_display_name(value: &str) -> Result<(), NameError> {
    if value.is_empty() {
        return Err(NameError::Empty);
    }
    if matches!(value, "." | "..") {
        return Err(NameError::DotComponent);
    }
    if value.ends_with([' ', '.']) {
        return Err(NameError::TrailingSpaceOrDot);
    }
    if value.chars().any(is_forbidden_name_character) {
        return Err(NameError::ForbiddenCharacter);
    }
    if value.len() > MAX_NAME_BYTES {
        return Err(NameError::TooLong);
    }
    if is_windows_device_name(value) {
        return Err(NameError::ReservedDeviceName);
    }
    Ok(())
}

fn is_forbidden_name_character(character: char) -> bool {
    character.is_ascii_control()
        || matches!(
            character,
            '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*'
        )
}

fn is_windows_device_name(value: &str) -> bool {
    let basename = value.split('.').next().unwrap_or(value);
    if ["CON", "PRN", "AUX", "NUL"]
        .iter()
        .any(|reserved| basename.eq_ignore_ascii_case(reserved))
    {
        return true;
    }

    let bytes = basename.as_bytes();
    bytes.len() == 4
        && matches!(bytes[0].to_ascii_uppercase(), b'C' | b'L')
        && match bytes[0].to_ascii_uppercase() {
            b'C' => bytes[1..3].eq_ignore_ascii_case(b"OM"),
            b'L' => bytes[1..3].eq_ignore_ascii_case(b"PT"),
            _ => false,
        }
        && matches!(bytes[3], b'1'..=b'9')
}

/// Stable logical-path validation category.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathError {
    NotAbsolute,
    EmptyComponent,
    TooManyComponents,
    TooLong,
    InvalidComponent { index: usize, source: NameError },
}

impl PathError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotAbsolute => "path.not_absolute",
            Self::EmptyComponent => "path.empty_component",
            Self::TooManyComponents => "path.too_many_components",
            Self::TooLong => "path.too_long",
            Self::InvalidComponent { .. } => "path.invalid_component",
        }
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidComponent { index, source } => {
                write!(formatter, "{} at component {index}: {source}", self.code())
            }
            _ => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for PathError {}

/// An absolute logical path below a drive root.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct LogicalPath {
    components: Vec<NormalizedName>,
}

impl LogicalPath {
    /// The drive root (`/`).
    #[must_use]
    pub const fn root() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    /// Builds a path from already validated components and enforces aggregate limits.
    pub fn from_components(components: Vec<NormalizedName>) -> Result<Self, PathError> {
        validate_path_limits(&components)?;
        Ok(Self { components })
    }

    /// Returns the path components below the drive root.
    #[must_use]
    pub fn components(&self) -> &[NormalizedName] {
        &self.components
    }

    /// Returns whether this path names the drive root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// Returns the final component, if this is not the root.
    #[must_use]
    pub fn file_name(&self) -> Option<&NormalizedName> {
        self.components.last()
    }

    /// Returns the parent path, or `None` for the drive root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let (_, parent) = self.components.split_last()?;
        Some(Self {
            components: parent.to_vec(),
        })
    }

    /// Appends a component while enforcing depth and byte limits.
    pub fn join(&self, component: NormalizedName) -> Result<Self, PathError> {
        let mut components = self.components.clone();
        components.push(component);
        Self::from_components(components)
    }

    /// UTF-8 byte length of the canonical absolute display form.
    #[must_use]
    pub fn display_len_bytes(&self) -> usize {
        absolute_path_len(&self.components)
    }
}

impl fmt::Display for LogicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("/")?;
        for (index, component) in self.components.iter().enumerate() {
            if index > 0 {
                formatter.write_str("/")?;
            }
            formatter.write_str(component.display())?;
        }
        Ok(())
    }
}

impl FromStr for LogicalPath {
    type Err = PathError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(remainder) = value.strip_prefix('/') else {
            return Err(PathError::NotAbsolute);
        };
        if remainder.is_empty() {
            return Ok(Self::root());
        }
        if remainder.split('/').any(str::is_empty) {
            return Err(PathError::EmptyComponent);
        }
        let components = remainder
            .split('/')
            .enumerate()
            .map(|(index, value)| {
                NormalizedName::new(value)
                    .map_err(|source| PathError::InvalidComponent { index, source })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_components(components)
    }
}

fn validate_path_limits(components: &[NormalizedName]) -> Result<(), PathError> {
    if components.len() > MAX_PATH_COMPONENTS {
        return Err(PathError::TooManyComponents);
    }
    if absolute_path_len(components) > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    Ok(())
}

fn absolute_path_len(components: &[NormalizedName]) -> usize {
    1 + components
        .iter()
        .map(|component| component.display().len())
        .sum::<usize>()
        + components.len().saturating_sub(1)
}

macro_rules! define_state {
    ($name:ident { $($variant:ident => [$($target:ident),* $(,)?]),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            /// Whether the authoritative state machine permits this transition.
            #[must_use]
            pub const fn can_transition_to(self, target: Self) -> bool {
                match self {
                    $(Self::$variant => false $(|| matches!(target, Self::$target))*),+
                }
            }
        }
    };
}

define_state!(NodeState {
    Active => [Trashed],
    Trashed => [Active, PurgePending],
    PurgePending => [Purged],
    Purged => []
});

define_state!(UploadState {
    Created => [Receiving, Aborted, Expired],
    Receiving => [Finalizing, Aborted, Expired],
    Finalizing => [Finalized, Aborted],
    Finalized => [Committed, Aborted],
    Committed => [],
    Aborted => [],
    Expired => []
});

define_state!(PayloadState {
    Staged => [Finalized, DeletionPending, Quarantined],
    Finalized => [Referenced, DeletionPending, Quarantined],
    Referenced => [DeletionPending, Quarantined],
    DeletionPending => [Deleted, Quarantined],
    Quarantined => [DeletionPending],
    Deleted => []
});

define_state!(FileVersionState {
    Staging => [Committed, Aborted],
    Committed => [],
    Aborted => []
});

define_state!(JobState {
    Pending => [Running],
    Running => [Succeeded, Retryable, OperatorBlocked],
    Retryable => [Running, OperatorBlocked],
    OperatorBlocked => [Pending],
    Succeeded => []
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_ids_generate_and_round_trip_canonically() {
        let id = NodeId::generate();
        let encoded = id.to_string();
        assert_eq!(encoded.len(), 36);
        assert_eq!(encoded, encoded.to_ascii_lowercase());
        assert_eq!(encoded.parse::<NodeId>(), Ok(id));
        assert_eq!(NodeId::from_uuid(id.as_uuid()), Ok(id));
        assert_eq!(id.into_bytes().len(), 16);
    }

    #[test]
    fn typed_ids_reject_non_v4_and_noncanonical_forms() {
        assert_eq!(
            "550e8400-e29b-11d4-a716-446655440000".parse::<NodeId>(),
            Err(IdError::UnsupportedVersion)
        );
        assert_eq!(
            "550E8400-E29B-41D4-A716-446655440000".parse::<NodeId>(),
            Err(IdError::NonCanonical)
        );
        assert_eq!(
            "550e8400e29b41d4a716446655440000".parse::<NodeId>(),
            Err(IdError::NonCanonical)
        );
        assert_eq!("not-an-id".parse::<NodeId>(), Err(IdError::InvalidSyntax));
    }

    #[test]
    fn name_normalization_is_nfc_and_full_case_folded() {
        assert_eq!(NORMALIZATION_UNICODE_VERSION, (17, 0, 0));
        assert_eq!(CASE_FOLD_UNICODE_VERSION, (16, 0, 0));
        let composed = NormalizedName::new("Cafe\u{301}").expect("valid name");
        let uppercase = NormalizedName::new("CAFÉ").expect("valid name");
        assert_eq!(composed.display(), "Café");
        assert_eq!(composed.comparison_key(), uppercase.comparison_key());

        let sharp_s = NormalizedName::new("Straße").expect("valid name");
        let expanded = NormalizedName::new("STRASSE").expect("valid name");
        assert_eq!(sharp_s.comparison_key(), expanded.comparison_key());
    }

    #[test]
    fn normalization_and_case_folding_are_idempotent_properties() {
        let samples = [
            "alpha",
            "Cafe\u{301}",
            "Straße",
            "İstanbul",
            "Σίσυφος",
            "西遊記",
            "emoji-🧰",
        ];
        for sample in samples {
            let once = NormalizedName::new(sample).expect("sample is valid");
            let twice = NormalizedName::new(once.display()).expect("normalized value is valid");
            assert_eq!(once, twice, "normalization must be idempotent for {sample}");
            assert_eq!(
                once.comparison_key(),
                once.comparison_key()
                    .chars()
                    .default_case_fold()
                    .collect::<String>(),
                "case folding must be idempotent for {sample}"
            );
        }
    }

    #[test]
    fn invalid_name_matrix_has_stable_categories() {
        let cases = [
            ("", NameError::Empty),
            (".", NameError::DotComponent),
            ("..", NameError::DotComponent),
            ("bad/name", NameError::ForbiddenCharacter),
            ("bad\\name", NameError::ForbiddenCharacter),
            ("bad\0name", NameError::ForbiddenCharacter),
            ("bad\u{7f}name", NameError::ForbiddenCharacter),
            ("bad:name", NameError::ForbiddenCharacter),
            ("trailing ", NameError::TrailingSpaceOrDot),
            ("trailing.", NameError::TrailingSpaceOrDot),
            ("CON", NameError::ReservedDeviceName),
            ("nul.txt", NameError::ReservedDeviceName),
            ("CoM9.log", NameError::ReservedDeviceName),
            ("lpt1", NameError::ReservedDeviceName),
        ];
        for (input, expected) in cases {
            assert_eq!(
                NormalizedName::new(input),
                Err(expected),
                "input: {input:?}"
            );
            assert!(!expected.code().is_empty());
        }
        assert!(NormalizedName::new("COM0").is_ok());
        assert!(NormalizedName::new("LPT10").is_ok());
    }

    #[test]
    fn name_length_is_measured_after_nfc_normalization() {
        assert!(NormalizedName::new(&"a".repeat(MAX_NAME_BYTES)).is_ok());
        assert_eq!(
            NormalizedName::new(&"a".repeat(MAX_NAME_BYTES + 1)),
            Err(NameError::TooLong)
        );
        let decomposed = "e\u{301}".repeat(127);
        let normalized = NormalizedName::new(&decomposed).expect("NFC form fits 255 bytes");
        assert_eq!(normalized.display().len(), 254);
    }

    #[test]
    fn logical_paths_round_trip_and_enforce_shape() {
        let path: LogicalPath = "/Projects/Cafe\u{301}/notes.txt"
            .parse()
            .expect("valid path");
        assert_eq!(path.to_string(), "/Projects/Café/notes.txt");
        assert_eq!(path.components().len(), 3);
        assert_eq!(
            path.file_name().map(NormalizedName::display),
            Some("notes.txt")
        );
        assert_eq!(path.parent().expect("parent").to_string(), "/Projects/Café");
        assert_eq!("/".parse::<LogicalPath>(), Ok(LogicalPath::root()));
        assert_eq!(
            "relative".parse::<LogicalPath>(),
            Err(PathError::NotAbsolute)
        );
        assert_eq!(
            "/a//b".parse::<LogicalPath>(),
            Err(PathError::EmptyComponent)
        );
        assert_eq!("/a/".parse::<LogicalPath>(), Err(PathError::EmptyComponent));
    }

    #[test]
    fn logical_path_depth_and_length_properties_are_bounded() {
        let component = NormalizedName::new("a").expect("valid name");
        let deepest = LogicalPath::from_components(vec![component.clone(); MAX_PATH_COMPONENTS])
            .expect("maximum depth is valid");
        assert_eq!(deepest.components().len(), MAX_PATH_COMPONENTS);
        assert_eq!(
            LogicalPath::from_components(vec![component; MAX_PATH_COMPONENTS + 1]),
            Err(PathError::TooManyComponents)
        );

        let wide = NormalizedName::new(&"a".repeat(MAX_NAME_BYTES)).expect("valid name");
        let too_long = vec![wide; 17];
        assert!(absolute_path_len(&too_long) > MAX_PATH_BYTES);
        assert_eq!(
            LogicalPath::from_components(too_long),
            Err(PathError::TooLong)
        );
    }

    #[test]
    fn generations_and_sizes_fail_safely_on_overflow() {
        assert_eq!(Generation::INITIAL.checked_next(), Some(Generation::new(1)));
        assert_eq!(Generation::new(u64::MAX).checked_next(), None);
        assert_eq!(
            ByteCount::new(u64::MAX).checked_add(ByteCount::new(1)),
            None
        );
    }

    #[test]
    fn principal_ownership_kinds_are_explicit() {
        for kind in [
            PrincipalKind::User,
            PrincipalKind::Group,
            PrincipalKind::Organization,
            PrincipalKind::Service,
        ] {
            assert!(kind.may_own_drive());
        }
        for kind in [
            PrincipalKind::ShareLink,
            PrincipalKind::MountSession,
            PrincipalKind::McpSession,
            PrincipalKind::DocumentSession,
        ] {
            assert!(!kind.may_own_drive());
        }
    }

    #[test]
    fn state_machines_reject_skipped_and_terminal_transitions() {
        assert!(UploadState::Created.can_transition_to(UploadState::Receiving));
        assert!(!UploadState::Created.can_transition_to(UploadState::Committed));
        assert!(!UploadState::Committed.can_transition_to(UploadState::Receiving));
        assert!(PayloadState::Finalized.can_transition_to(PayloadState::Referenced));
        assert!(!PayloadState::Deleted.can_transition_to(PayloadState::Staged));
        assert!(NodeState::Trashed.can_transition_to(NodeState::Active));
        assert!(!NodeState::Purged.can_transition_to(NodeState::Active));
    }

    #[test]
    fn action_names_are_unique_and_stable() {
        let names = Action::ALL.map(Action::as_str);
        for (index, name) in names.iter().enumerate() {
            assert!(
                name.bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
            );
            assert!(
                !names[..index].contains(name),
                "duplicate action name {name}"
            );
        }
    }

    #[test]
    fn document_actions_are_stably_serialized() {
        assert_eq!(Action::UseExternalEditor.as_str(), "USE_EXTERNAL_EDITOR");
        assert_eq!(Action::Comment.as_str(), "COMMENT");
        assert_eq!(Action::Review.as_str(), "REVIEW");
        assert_eq!(
            &Action::ALL[15..18],
            &[Action::UseExternalEditor, Action::Comment, Action::Review]
        );
    }
}
