// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral media controller/transcoder Protobuf messages.

#![deny(unsafe_code)]

use prost::Message as _;

mod generated {
    include!("../../generated/rust/filebelt/media/v1/filebelt.media.v1.rs");
}

pub use generated::{
    MediaAudioCodec, MediaAuthorizationGenerations, MediaProfile, MediaSource, MediaVideoCodec,
    PlaybackManifestRevision, TranscodeAttempt, TranscodeResult, TranscodeResultState,
    VerifiedSegmentReceipt,
};

#[must_use]
pub fn encode_attempt(attempt: &TranscodeAttempt) -> Vec<u8> {
    attempt.encode_to_vec()
}

pub fn decode_attempt(bytes: &[u8]) -> Result<TranscodeAttempt, prost::DecodeError> {
    TranscodeAttempt::decode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_round_trips_across_the_provider_neutral_boundary() {
        let attempt = TranscodeAttempt {
            preview_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            attempt_id: "550e8400-e29b-41d4-a716-446655440001".into(),
            job_epoch: 1,
            source: Some(MediaSource {
                tenant_id: "550e8400-e29b-41d4-a716-446655440002".into(),
                drive_id: "550e8400-e29b-41d4-a716-446655440003".into(),
                node_id: "550e8400-e29b-41d4-a716-446655440004".into(),
                source_version_id: "550e8400-e29b-41d4-a716-446655440005".into(),
                source_blake3: vec![7; 32],
                source_size_bytes: 1,
            }),
            profile: Some(MediaProfile {
                profile_id: "vp9-opus-v1".into(),
                video_codec: MediaVideoCodec::Vp9 as i32,
                audio_codec: MediaAudioCodec::Opus as i32,
                maximum_width: 1_920,
                maximum_height: 1_080,
                maximum_frame_rate: 30,
                maximum_duration_seconds: 60,
                container_format: "configured".into(),
                segment_format: "configured".into(),
                segment_duration_seconds: 6,
            }),
            profile_digest: vec![8; 32],
            transcoder_build_identity: vec![9; 32],
            source_capability: b"opaque-source".to_vec(),
            output_capability: b"opaque-output".to_vec(),
            callback_capability: b"opaque-callback".to_vec(),
            generations: Some(MediaAuthorizationGenerations {
                membership_generation: 1,
                drive_acl_generation: 2,
                namespace_generation: 3,
                resource_acl_generation: 4,
            }),
            expires_at_unix_seconds: 100,
        };
        assert_eq!(decode_attempt(&encode_attempt(&attempt)).unwrap(), attempt);
    }
}
