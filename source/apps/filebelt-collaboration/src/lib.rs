// SPDX-License-Identifier: Apache-2.0

//! Durable, bounded Yjs-compatible Markdown document mechanics.

#![deny(unsafe_code)]

use std::fmt;

use blake3::Hash;
use filebelt_collaboration_protocol::normalized_markdown_source_digest;
use filebelt_control_protocol::CollaborationLimitConfig;
use yrs::Transact as _;
use yrs::updates::encoder::Encode as _;
use yrs::{
    ClientID, Doc, GetString as _, OffsetKind, Options, ReadTxn as _, StateVector, Text as _,
};

mod rate_limit;
mod source;
mod update_decoder;
mod wire;

#[cfg(test)]
mod containment_tests;

pub mod io_client;
pub mod server;
pub mod webtransport;

#[cfg(not(panic = "unwind"))]
compile_error!("filebelt-collaboration requires panic unwinding for decoder containment");

pub use rate_limit::{AdmissionKind, RateAdmission, RateLimiter};
pub use source::{LineEnding, MarkdownSource, MarkdownSourceError};
pub use wire::{FrameError, decode_frame, encode_frame, validate_awareness};

/// Installs the process-wide hook required to let decoder containment unwind
/// while preserving the existing hook for every unrelated panic.
///
/// The collaboration binary installs this before startup. No later component
/// may replace the process panic hook with an aborting hook.
pub fn install_decoder_panic_containment_hook() {
    update_decoder::install_containment_aware_panic_hook();
}

/// Side-effect-free exercises for repository-owned fuzz targets.
#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    use filebelt_collaboration_protocol::collaboration_frame::Frame;
    use filebelt_control_protocol::CollaborationLimitConfig;

    use crate::{RoomDocument, decode_frame, encode_frame, validate_awareness};

    /// Replaces libFuzzer's aborting panic hook with a containment-aware
    /// wrapper. Panics outside FileBelt's untrusted decoder boundary retain
    /// libFuzzer's original crash behavior.
    pub fn install_containment_aware_panic_hook() {
        crate::install_decoder_panic_containment_hook();
    }

    /// Exercises collaboration Protobuf, awareness, and bounded Yjs decoding.
    pub fn exercise_collaboration_wire(input: &[u8]) {
        if let Ok(decoded) = decode_frame(input) {
            let frame = decoded
                .frame
                .expect("the collaboration decoder rejects empty frames");
            let encoded = encode_frame(frame.clone())
                .expect("a decoded bounded collaboration frame re-encodes");
            assert_eq!(
                decode_frame(&encoded).ok().and_then(|value| value.frame),
                Some(frame.clone())
            );
            if let Frame::Awareness(awareness) = frame {
                let _ = validate_awareness(&awareness, 8_192);
            }
        }

        let limits = CollaborationLimitConfig {
            max_update_bytes: 256 * 1024,
            max_operation_group_bytes: 256 * 1024,
            max_state_bytes: 512 * 1024,
            ..CollaborationLimitConfig::default()
        };
        let staged = RoomDocument::from_source("", limits.clone());
        let _ = staged.stage_group(&[input.to_vec()]);
        if let Ok(restored) = RoomDocument::from_snapshot(input, 1, limits.clone()) {
            let snapshot = restored.snapshot();
            let round_trip = RoomDocument::from_snapshot(&snapshot, 1, limits)
                .expect("an accepted collaboration snapshot remains valid");
            assert_eq!(round_trip.snapshot(), snapshot);
        }
    }
}

pub const MARKDOWN_ROOT: &str = "source";
/// Initial Markdown collaboration source follows the shared per-user editor
/// ceiling. Encoded Yjs state and retained-room limits remain independently
/// bounded by `CollaborationLimitConfig`.
pub const MAX_MARKDOWN_SOURCE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoomFreezeReason {
    ExternalHead,
    Quota,
    StateLimit,
    RetainedPayloadLimit,
    CorruptState,
    AuthorizationUncertain,
    Expired,
}

impl fmt::Display for RoomFreezeReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExternalHead => "external_head",
            Self::Quota => "quota",
            Self::StateLimit => "state_limit",
            Self::RetainedPayloadLimit => "retained_payload_limit",
            Self::CorruptState => "corrupt_state",
            Self::AuthorizationUncertain => "authorization_uncertain",
            Self::Expired => "expired",
        })
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum RoomDocumentError {
    #[error("room is frozen: {0}")]
    Frozen(RoomFreezeReason),
    #[error("operation group is empty")]
    EmptyGroup,
    #[error("an update exceeds the configured byte limit")]
    UpdateTooLarge,
    #[error("an operation group exceeds the configured byte limit")]
    GroupTooLarge,
    #[error("a Yjs v1 update is malformed")]
    InvalidUpdate,
    #[error("the room sequence advanced before the staged update committed")]
    StaleSequence,
    #[error("the encoded CRDT state exceeds the configured limit")]
    StateTooLarge,
    #[error("the Markdown source exceeds the editor limit")]
    SourceTooLarge,
    #[error("the Markdown source contains a NUL code point")]
    SourceContainsNul,
    #[error("the persisted CRDT snapshot is malformed")]
    InvalidSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyReceipt {
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub state_vector: Vec<u8>,
    pub state_digest: [u8; 32],
    /// Digests of the normalized Markdown source immediately before and after
    /// this staged group. They are provenance bindings, never source storage.
    pub source_before_digest: [u8; 32],
    pub source_after_digest: [u8; 32],
}

/// A validated update that has not yet been acknowledged or made visible.
/// Callers must durably persist its manifest before committing it.
pub struct StagedUpdate {
    doc: Doc,
    receipt: ApplyReceipt,
}

impl StagedUpdate {
    #[must_use]
    pub fn receipt(&self) -> &ApplyReceipt {
        &self.receipt
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub source: Vec<u8>,
    pub source_digest: [u8; 32],
    pub state_vector: Vec<u8>,
    pub snapshot: Vec<u8>,
    pub snapshot_digest: [u8; 32],
    pub server_sequence: u64,
}

pub struct RoomDocument {
    doc: Doc,
    limits: CollaborationLimitConfig,
    server_sequence: u64,
    frozen: Option<RoomFreezeReason>,
}

struct ValidatedDocument {
    source: Vec<u8>,
    snapshot: Vec<u8>,
}

impl RoomDocument {
    #[must_use]
    pub fn from_source(source: &str, limits: CollaborationLimitConfig) -> Self {
        Self::from_source_document(source, limits, yjs_document())
    }

    #[must_use]
    pub fn from_source_with_client_id(
        source: &str,
        limits: CollaborationLimitConfig,
        client_id: u64,
    ) -> Self {
        let options = Options {
            offset_kind: OffsetKind::Utf16,
            ..Options::with_client_id(ClientID::new(client_id))
        };
        Self::from_source_document(source, limits, Doc::with_options(options))
    }

    fn from_source_document(source: &str, limits: CollaborationLimitConfig, doc: Doc) -> Self {
        let text = doc.get_or_insert_text(MARKDOWN_ROOT);
        text.push(&mut doc.transact_mut(), source);
        Self {
            doc,
            limits,
            server_sequence: 0,
            frozen: None,
        }
    }

    pub fn from_snapshot(
        snapshot: &[u8],
        server_sequence: u64,
        limits: CollaborationLimitConfig,
    ) -> Result<Self, RoomDocumentError> {
        if snapshot.len() > usize::try_from(limits.max_state_bytes).unwrap_or(usize::MAX) {
            return Err(RoomDocumentError::StateTooLarge);
        }
        let doc =
            update_decoder::contain_untrusted_panic(RoomDocumentError::InvalidSnapshot, || {
                let update = update_decoder::decode_update_v1(snapshot)
                    .map_err(|_| RoomDocumentError::InvalidSnapshot)?;
                let doc = yjs_document();
                doc.transact_mut()
                    .apply_update(update)
                    .map_err(|_| RoomDocumentError::InvalidSnapshot)?;
                validate_document(&doc, &limits)?;
                Ok(doc)
            })?;
        Ok(Self {
            doc,
            limits,
            server_sequence,
            frozen: None,
        })
    }

    #[must_use]
    pub fn frozen_reason(&self) -> Option<&RoomFreezeReason> {
        self.frozen.as_ref()
    }

    #[must_use]
    pub const fn server_sequence(&self) -> u64 {
        self.server_sequence
    }

    pub fn freeze(&mut self, reason: RoomFreezeReason) {
        self.frozen = Some(reason);
    }

    pub fn stage_group(&self, chunks: &[Vec<u8>]) -> Result<StagedUpdate, RoomDocumentError> {
        if let Some(reason) = &self.frozen {
            return Err(RoomDocumentError::Frozen(reason.clone()));
        }
        if chunks.is_empty() {
            return Err(RoomDocumentError::EmptyGroup);
        }
        let max_update = usize::try_from(self.limits.max_update_bytes).unwrap_or(usize::MAX);
        if chunks.iter().any(|chunk| chunk.len() > max_update) {
            return Err(RoomDocumentError::UpdateTooLarge);
        }
        let group_bytes = chunks
            .iter()
            .try_fold(0usize, |total, chunk| total.checked_add(chunk.len()))
            .ok_or(RoomDocumentError::GroupTooLarge)?;
        if group_bytes
            > usize::try_from(self.limits.max_operation_group_bytes).unwrap_or(usize::MAX)
        {
            return Err(RoomDocumentError::GroupTooLarge);
        }

        // A group is one logical Yjs update split into bounded transport chunks.
        // Reassemble it before decoding, and apply to a disposable document so a
        // malformed or oversized group never partially mutates acknowledged state.
        let mut encoded_update = Vec::with_capacity(group_bytes);
        for chunk in chunks {
            encoded_update.extend_from_slice(chunk);
        }
        let source_before = normalized_source(&self.doc)?;
        let current_snapshot = self.snapshot();
        let staged = yjs_document();
        staged
            .transact_mut()
            .apply_update(
                update_decoder::decode_update_v1(current_snapshot.as_slice())
                    .map_err(|_| RoomDocumentError::InvalidSnapshot)?,
            )
            .map_err(|_| RoomDocumentError::InvalidSnapshot)?;
        let validated =
            update_decoder::contain_untrusted_panic(RoomDocumentError::InvalidUpdate, || {
                let update = update_decoder::decode_update_v1(encoded_update.as_slice())
                    .map_err(|_| RoomDocumentError::InvalidUpdate)?;
                staged
                    .transact_mut()
                    .apply_update(update)
                    .map_err(|_| RoomDocumentError::InvalidUpdate)?;
                validate_document(&staged, &self.limits)
            })?;

        let first_sequence = self.server_sequence.saturating_add(1);
        let last_sequence = first_sequence;
        let state_vector = staged.transact().state_vector().encode_v1();
        let state_digest = digest(&validated.snapshot);
        Ok(StagedUpdate {
            doc: staged,
            receipt: ApplyReceipt {
                first_sequence,
                last_sequence,
                state_vector,
                state_digest,
                source_before_digest: normalized_markdown_source_digest(&source_before),
                source_after_digest: normalized_markdown_source_digest(&validated.source),
            },
        })
    }

    pub fn commit_staged(
        &mut self,
        staged: StagedUpdate,
    ) -> Result<ApplyReceipt, RoomDocumentError> {
        if staged.receipt.first_sequence != self.server_sequence.saturating_add(1) {
            return Err(RoomDocumentError::StaleSequence);
        }
        self.server_sequence = staged.receipt.last_sequence;
        self.doc = staged.doc;
        Ok(staged.receipt)
    }

    pub fn apply_group(&mut self, chunks: &[Vec<u8>]) -> Result<ApplyReceipt, RoomDocumentError> {
        let staged = self.stage_group(chunks)?;
        self.commit_staged(staged)
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        snapshot(&self.doc)
    }

    pub fn checkpoint(&self) -> Result<Checkpoint, RoomDocumentError> {
        let transaction = self.doc.transact();
        let source = transaction
            .get_text(MARKDOWN_ROOT)
            .map(|text| text.get_string(&transaction))
            .unwrap_or_default()
            .into_bytes();
        if source.len() > MAX_MARKDOWN_SOURCE_BYTES {
            return Err(RoomDocumentError::SourceTooLarge);
        }
        if source.contains(&0) {
            return Err(RoomDocumentError::SourceContainsNul);
        }
        let state_vector = transaction.state_vector().encode_v1();
        let snapshot = transaction.encode_state_as_update_v1(&StateVector::default());
        Ok(Checkpoint {
            source_digest: digest(&source),
            snapshot_digest: digest(&snapshot),
            source,
            state_vector,
            snapshot,
            server_sequence: self.server_sequence,
        })
    }
}

fn yjs_document() -> Doc {
    let options = Options {
        offset_kind: OffsetKind::Utf16,
        ..Options::default()
    };
    Doc::with_options(options)
}

fn snapshot(doc: &Doc) -> Vec<u8> {
    doc.transact()
        .encode_state_as_update_v1(&StateVector::default())
}

fn normalized_source(doc: &Doc) -> Result<Vec<u8>, RoomDocumentError> {
    let transaction = doc.transact();
    let source = transaction
        .get_text(MARKDOWN_ROOT)
        .map(|text| text.get_string(&transaction))
        .unwrap_or_default()
        .into_bytes();
    if source.len() > MAX_MARKDOWN_SOURCE_BYTES {
        return Err(RoomDocumentError::SourceTooLarge);
    }
    if source.contains(&0) {
        return Err(RoomDocumentError::SourceContainsNul);
    }
    Ok(source)
}

fn validate_document(
    doc: &Doc,
    limits: &CollaborationLimitConfig,
) -> Result<ValidatedDocument, RoomDocumentError> {
    let transaction = doc.transact();
    let snapshot = transaction.encode_state_as_update_v1(&StateVector::default());
    if snapshot.len() > usize::try_from(limits.max_state_bytes).unwrap_or(usize::MAX) {
        return Err(RoomDocumentError::StateTooLarge);
    }
    drop(transaction);
    Ok(ValidatedDocument {
        source: normalized_source(doc)?,
        snapshot,
    })
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let hash: Hash = blake3::hash(bytes);
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update_for_insert(source: &str) -> Vec<u8> {
        let doc = yjs_document();
        let text = doc.get_or_insert_text(MARKDOWN_ROOT);
        text.push(&mut doc.transact_mut(), source);
        doc.transact()
            .encode_state_as_update_v1(&StateVector::default())
    }

    #[test]
    fn yjs_update_is_applied_and_checkpointed() {
        let mut room = RoomDocument::from_source("", CollaborationLimitConfig::default());
        let receipt = room.apply_group(&[update_for_insert("hello 👋")]).unwrap();
        assert_eq!(receipt.first_sequence, 1);
        assert_eq!(receipt.last_sequence, 1);
        assert_eq!(
            receipt.source_before_digest,
            normalized_markdown_source_digest(b"")
        );
        assert_eq!(
            receipt.source_after_digest,
            normalized_markdown_source_digest("hello 👋".as_bytes())
        );
        assert_eq!(room.checkpoint().unwrap().source, "hello 👋".as_bytes());
    }

    #[test]
    fn malformed_group_does_not_mutate_room() {
        let mut room = RoomDocument::from_source("base", CollaborationLimitConfig::default());
        let before = room.checkpoint().unwrap();
        assert_eq!(
            room.apply_group(&[vec![0xff, 0xff]]),
            Err(RoomDocumentError::InvalidUpdate),
        );
        assert_eq!(room.checkpoint().unwrap(), before);
    }

    #[test]
    fn nul_source_update_is_rejected_without_mutating_room() {
        let mut room = RoomDocument::from_source("base", CollaborationLimitConfig::default());
        let before = room.checkpoint().unwrap();
        assert_eq!(
            room.apply_group(&[update_for_insert("bad\0source")]),
            Err(RoomDocumentError::SourceContainsNul),
        );
        assert_eq!(room.checkpoint().unwrap(), before);
    }

    #[test]
    fn staged_group_is_invisible_until_durable_commit() {
        let mut room = RoomDocument::from_source("base", CollaborationLimitConfig::default());
        let staged = room.stage_group(&[update_for_insert("next")]).unwrap();
        assert_eq!(room.checkpoint().unwrap().source, b"base");
        let receipt = room.commit_staged(staged).unwrap();
        assert_eq!(receipt.last_sequence, 1);
        let source = room.checkpoint().unwrap().source;
        assert!(source == b"basenext" || source == b"nextbase");
    }

    #[test]
    fn snapshot_round_trip_preserves_unicode_and_sequence() {
        let limits = CollaborationLimitConfig::default();
        let room = RoomDocument::from_source("e\u{301} 😀", limits.clone());
        let restored = RoomDocument::from_snapshot(&room.snapshot(), 9, limits).unwrap();
        let checkpoint = restored.checkpoint().unwrap();
        assert_eq!(checkpoint.source, "e\u{301} 😀".as_bytes());
        assert_eq!(checkpoint.server_sequence, 9);
    }

    #[test]
    fn deterministic_base_identity_replays_edits_after_restart() {
        let limits = CollaborationLimitConfig::default();
        let initial = RoomDocument::from_source_with_client_id("base", limits.clone(), 42);
        let peer = yjs_document();
        peer.transact_mut()
            .apply_update(update_decoder::decode_update_v1(&initial.snapshot()).unwrap())
            .unwrap();
        let known = peer.transact().state_vector();
        let text = peer.get_or_insert_text(MARKDOWN_ROOT);
        text.remove_range(&mut peer.transact_mut(), 0, 4);
        text.push(&mut peer.transact_mut(), "changed");
        let update = peer.transact().encode_diff_v1(&known);

        let mut restored = RoomDocument::from_source_with_client_id("base", limits, 42);
        restored.apply_group(&[update]).unwrap();
        assert_eq!(restored.checkpoint().unwrap().source, b"changed");
    }

    #[test]
    fn frozen_room_rejects_updates() {
        let mut room = RoomDocument::from_source("", CollaborationLimitConfig::default());
        room.freeze(RoomFreezeReason::ExternalHead);
        assert_eq!(
            room.apply_group(&[update_for_insert("no")]),
            Err(RoomDocumentError::Frozen(RoomFreezeReason::ExternalHead)),
        );
    }
}
