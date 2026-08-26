// SPDX-License-Identifier: Apache-2.0

use yrs::encoding::write::Write as _;
use yrs::updates::decoder::Decode as _;
use yrs::updates::encoder::{Encoder as _, EncoderV1};

use super::*;

// Repository-constructed update: no blocks, one delete-set client, and an
// input-amplified range count with no complete ranges behind it.
const DELETE_SET_RANGE_LENGTH_AMPLIFICATION: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/fuzz-regressions/collaboration_wire/8abb3daa6dec1eea1777b68b794bf554f4536571b60029f415be8dcee18d61c0"
));

// Repository-constructed zero-length GC update plus an inert trailing byte.
const ZERO_LENGTH_GC_RANGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/fuzz-regressions/collaboration_wire/f9654d9a75dc6cd2fc8de95630188d5643b7b90ad449573d06c5fd8cf6443068"
));

// Repository-constructed overflow range. Its valid UTF-8 varuint spelling is
// noncanonical but decodes with Yrs's compatibility wrapping to u32::MAX.
const OVERFLOWING_GC_RANGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/fuzz-regressions/collaboration_wire/dd24c4cd842a14c2ffeb8cb5a878e16466a935512eda6aab991463d2ba8ed866"
));

fn update_for_insert_with_client_id(source: &str, client_id: u64) -> Vec<u8> {
    let options = Options {
        offset_kind: OffsetKind::Utf16,
        ..Options::with_client_id(ClientID::new(client_id))
    };
    let doc = Doc::with_options(options);
    let text = doc.get_or_insert_text(MARKDOWN_ROOT);
    text.push(&mut doc.transact_mut(), source);
    doc.transact()
        .encode_state_as_update_v1(&StateVector::default())
}

fn gc_update(clock: u32, len: u32) -> Vec<u8> {
    let mut encoder = EncoderV1::new();
    encoder.write_var(1u32);
    encoder.write_var(1u32);
    encoder.write_client(ClientID::new(42));
    encoder.write_var(clock);
    encoder.write_info(yrs::block::BLOCK_GC_REF_NUMBER);
    encoder.write_len(len);
    encoder.write_var(0u32);
    encoder.to_vec()
}

#[test]
fn delete_set_range_length_amplification_is_rejected_at_both_update_boundaries() {
    let limits = CollaborationLimitConfig::default();
    assert!(matches!(
        RoomDocument::from_snapshot(DELETE_SET_RANGE_LENGTH_AMPLIFICATION, 1, limits.clone()),
        Err(RoomDocumentError::InvalidSnapshot)
    ));

    let room = RoomDocument::from_source("base", limits);
    let before = room.checkpoint().unwrap();
    assert!(matches!(
        room.stage_group(&[DELETE_SET_RANGE_LENGTH_AMPLIFICATION.to_vec()]),
        Err(RoomDocumentError::InvalidUpdate)
    ));
    assert_eq!(room.checkpoint().unwrap(), before);
}

#[test]
fn zero_length_block_is_rejected_at_both_update_boundaries() {
    let malformed = gc_update(1, 0);
    assert_eq!(malformed, [1, 1, 42, 1, 0, 0, 0]);
    assert_eq!(&ZERO_LENGTH_GC_RANGE[..malformed.len()], malformed);

    let limits = CollaborationLimitConfig::default();
    assert!(matches!(
        RoomDocument::from_snapshot(&malformed, 1, limits.clone()),
        Err(RoomDocumentError::InvalidSnapshot)
    ));

    let room = RoomDocument::from_source("base", limits);
    let before = room.checkpoint().unwrap();
    assert!(matches!(
        room.stage_group(&[malformed]),
        Err(RoomDocumentError::InvalidUpdate)
    ));
    assert_eq!(room.checkpoint().unwrap(), before);
}

#[test]
fn overflowing_block_range_is_contained_at_both_update_boundaries() {
    for malformed in [gc_update(2, u32::MAX), OVERFLOWING_GC_RANGE.to_vec()] {
        let limits = CollaborationLimitConfig::default();
        assert!(matches!(
            RoomDocument::from_snapshot(&malformed, 1, limits.clone()),
            Err(RoomDocumentError::InvalidSnapshot)
        ));

        let room = RoomDocument::from_source("base", limits);
        let before = room.checkpoint().unwrap();
        assert!(matches!(
            room.stage_group(&[malformed]),
            Err(RoomDocumentError::InvalidUpdate)
        ));
        assert_eq!(room.checkpoint().unwrap(), before);
    }
}

#[test]
fn overflowing_fixture_reaches_the_upstream_panic_path() {
    let result = std::panic::catch_unwind(|| {
        let update = yrs::Update::decode_v1(OVERFLOWING_GC_RANGE).unwrap();
        let doc = yjs_document();
        doc.transact_mut().apply_update(update).unwrap();
        let _ = doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default());
    });
    assert!(result.is_err());
}

#[test]
fn sparse_dependency_free_update_with_zero_state_vector_is_accepted() {
    let mut sparse = update_for_insert_with_client_id("sparse", 42);
    assert_eq!(&sparse[..4], &[1, 1, 42, 0]);
    sparse[3] = 1;

    let sparse_doc = yjs_document();
    sparse_doc
        .transact_mut()
        .apply_update(update_decoder::decode_update_v1(&sparse).unwrap())
        .unwrap();
    assert_eq!(
        sparse_doc.transact().state_vector().get(&ClientID::new(42)),
        0
    );

    let limits = CollaborationLimitConfig::default();
    let restored = RoomDocument::from_snapshot(&sparse, 1, limits.clone()).unwrap();
    assert_eq!(restored.checkpoint().unwrap().source, b"sparse");

    let room = RoomDocument::from_source_with_client_id("base", limits, 7);
    assert!(room.stage_group(&[sparse]).is_ok());
}
