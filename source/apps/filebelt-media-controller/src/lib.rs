// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral media admission checks. This role deliberately owns no
//! FFmpeg invocation, cache mount, payload locator, or adapter implementation.

#![deny(unsafe_code)]

use std::process::ExitCode;

pub const MAXIMUM_INPUT_BYTES: u64 = 100 * 1024 * 1024 * 1024;
pub const MAXIMUM_DURATION_SECONDS: u64 = 4 * 60 * 60;
pub const MAXIMUM_WIDTH: u32 = 8_192;
pub const MAXIMUM_HEIGHT: u32 = 4_320;
pub const MAXIMUM_FRAME_RATE: u32 = 60;
pub const MAXIMUM_STREAMS: u32 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoCodec {
    Av1,
    Vp9,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioCodec {
    Opus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaProfile<'a> {
    pub profile_id: &'a str,
    pub video_codec: VideoCodec,
    pub audio_codec: AudioCodec,
    pub maximum_width: u32,
    pub maximum_height: u32,
    pub maximum_frame_rate: u32,
    pub maximum_duration_seconds: u64,
    pub maximum_streams: u32,
    pub container_format: &'a str,
    pub segment_format: &'a str,
    pub segment_duration_seconds: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscodeAttempt<'a> {
    pub preview_id: &'a str,
    pub attempt_id: &'a str,
    pub job_epoch: u64,
    pub source_version_id: &'a str,
    pub source_size_bytes: u64,
    pub source_capability: &'a str,
    pub output_capability: &'a str,
    pub callback_capability: &'a str,
    pub profile: MediaProfile<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    InvalidProfile,
    InvalidAttempt,
    InputTooLarge,
}

impl MediaProfile<'_> {
    /// Validates only cross-provider limits. The activated configuration owns
    /// the exact container and segment allowlists; this layer never infers a
    /// codec fallback or FFmpeg option from a browser request.
    pub fn validate(&self) -> Result<(), AdmissionError> {
        if self.profile_id.is_empty()
            || self.profile_id.len() > 128
            || self.container_format.is_empty()
            || self.container_format.len() > 32
            || self.segment_format.is_empty()
            || self.segment_format.len() > 32
            || self.maximum_width == 0
            || self.maximum_width > MAXIMUM_WIDTH
            || self.maximum_height == 0
            || self.maximum_height > MAXIMUM_HEIGHT
            || self.maximum_frame_rate == 0
            || self.maximum_frame_rate > MAXIMUM_FRAME_RATE
            || self.maximum_duration_seconds == 0
            || self.maximum_duration_seconds > MAXIMUM_DURATION_SECONDS
            || self.maximum_streams == 0
            || self.maximum_streams > MAXIMUM_STREAMS
            || self.segment_duration_seconds == 0
        {
            return Err(AdmissionError::InvalidProfile);
        }
        // `AudioCodec` has only Opus and `VideoCodec` has only AV1/VP9. Keeping
        // the explicit fields makes the protocol closed without adapter types.
        Ok(())
    }
}

impl TranscodeAttempt<'_> {
    /// Validates a controller-issued dispatch projection before it crosses the
    /// replaceable process boundary. Opaque capabilities are not logged,
    /// stored, or interpreted by this type.
    pub fn validate(&self) -> Result<(), AdmissionError> {
        self.profile.validate()?;
        if self.preview_id.is_empty()
            || self.attempt_id.is_empty()
            || self.source_version_id.is_empty()
            || self.source_capability.is_empty()
            || self.output_capability.is_empty()
            || self.callback_capability.is_empty()
            || self.job_epoch == 0
        {
            return Err(AdmissionError::InvalidAttempt);
        }
        if self.source_size_bytes > MAXIMUM_INPUT_BYTES {
            return Err(AdmissionError::InputTooLarge);
        }
        Ok(())
    }
}

/// The image remains a disabled-by-default probe until configuration, mTLS,
/// Kubernetes Job, and grants integration are enabled by the shared runtime.
pub fn run() -> ExitCode {
    filebelt_deployment_diagnostics::run_probe("filebelt-media-controller")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> MediaProfile<'static> {
        MediaProfile {
            profile_id: "vp9-opus-v1",
            video_codec: VideoCodec::Vp9,
            audio_codec: AudioCodec::Opus,
            maximum_width: 1_920,
            maximum_height: 1_080,
            maximum_frame_rate: 30,
            maximum_duration_seconds: 3_600,
            maximum_streams: 2,
            container_format: "configured",
            segment_format: "configured",
            segment_duration_seconds: 6,
        }
    }

    #[test]
    fn accepts_only_bounded_av1_or_vp9_with_opus_profiles() {
        assert_eq!(profile().video_codec, VideoCodec::Vp9);
        assert_eq!(profile().audio_codec, AudioCodec::Opus);
        assert!(profile().validate().is_ok());
        assert_eq!(
            MediaProfile {
                maximum_width: MAXIMUM_WIDTH + 1,
                ..profile()
            }
            .validate(),
            Err(AdmissionError::InvalidProfile)
        );
    }

    #[test]
    fn dispatch_requires_scoped_capabilities_and_a_fence() {
        let attempt = TranscodeAttempt {
            preview_id: "preview",
            attempt_id: "attempt",
            job_epoch: 1,
            source_version_id: "version",
            source_size_bytes: MAXIMUM_INPUT_BYTES,
            source_capability: "opaque-source-capability",
            output_capability: "opaque-output-capability",
            callback_capability: "opaque-callback-capability",
            profile: profile(),
        };
        assert!(attempt.validate().is_ok());
        assert_eq!(
            TranscodeAttempt {
                job_epoch: 0,
                ..attempt
            }
            .validate(),
            Err(AdmissionError::InvalidAttempt)
        );
    }

    #[test]
    fn dispatch_rejects_input_above_the_approved_ceiling() {
        assert_eq!(
            TranscodeAttempt {
                preview_id: "preview",
                attempt_id: "attempt",
                job_epoch: 1,
                source_version_id: "version",
                source_size_bytes: MAXIMUM_INPUT_BYTES + 1,
                source_capability: "source",
                output_capability: "output",
                callback_capability: "callback",
                profile: profile(),
            }
            .validate(),
            Err(AdmissionError::InputTooLarge)
        );
    }
}
