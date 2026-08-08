// SPDX-License-Identifier: Apache-2.0

//! Shared Protobuf frame bounds for WebSocket and WebTransport.

use filebelt_collaboration_protocol::{
    Awareness, CollaborationFrame, MAX_FRAME_BYTES, collaboration_frame::Frame,
};
use prost::Message as _;
use thiserror::Error;
use uuid::Uuid;
use yrs::StickyIndex;
use yrs::updates::decoder::Decode as _;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FrameError {
    #[error("the collaboration frame exceeds the wire limit")]
    TooLarge,
    #[error("the collaboration frame is malformed")]
    Invalid,
    #[error("the collaboration frame is empty")]
    Empty,
    #[error("the collaboration awareness payload is invalid")]
    InvalidAwareness,
}

pub fn decode_frame(bytes: &[u8]) -> Result<CollaborationFrame, FrameError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let frame = CollaborationFrame::decode(bytes).map_err(|_| FrameError::Invalid)?;
    if frame.frame.is_none() {
        return Err(FrameError::Empty);
    }
    Ok(frame)
}

pub fn encode_frame(frame: Frame) -> Result<Vec<u8>, FrameError> {
    let bytes = CollaborationFrame { frame: Some(frame) }.encode_to_vec();
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    Ok(bytes)
}

pub fn validate_awareness(awareness: &Awareness, max_bytes: u64) -> Result<(), FrameError> {
    let encoded_size = u64::try_from(awareness.encoded_len()).map_err(|_| FrameError::TooLarge)?;
    if encoded_size > max_bytes
        || Uuid::parse_str(&awareness.client_id).is_err()
        || awareness.display_label.is_empty()
        || awareness.display_label.len() > 120
        || awareness.display_label.chars().any(char::is_control)
        || awareness.same_user_tabs == 0
        || awareness.same_user_tabs > 32
        || awareness.color_index > 31
        || awareness.cursor_anchor.len() > 256
        || awareness.cursor_head.len() > 256
        || (awareness.cursor_anchor.is_empty() != awareness.cursor_head.is_empty())
        || (!awareness.cursor_anchor.is_empty()
            && (StickyIndex::decode_v1(&awareness.cursor_anchor).is_err()
                || StickyIndex::decode_v1(&awareness.cursor_head).is_err()))
    {
        return Err(FrameError::InvalidAwareness);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use filebelt_collaboration_protocol::{Heartbeat, PresenceState};

    use super::*;

    #[test]
    fn rejects_empty_and_oversized_frames() {
        assert_eq!(decode_frame(&[]), Err(FrameError::Empty));
        assert_eq!(
            decode_frame(&vec![0; MAX_FRAME_BYTES + 1]),
            Err(FrameError::TooLarge)
        );
    }

    #[test]
    fn round_trips_bounded_frames() {
        let frame = Frame::Heartbeat(Heartbeat {
            durable_sequence: 7,
            sent_at_unix_millis: 9,
        });
        let encoded = encode_frame(frame.clone()).unwrap();
        assert_eq!(decode_frame(&encoded).unwrap().frame, Some(frame));
    }

    #[test]
    fn awareness_is_structured_and_bounded() {
        let valid = Awareness {
            client_id: Uuid::new_v4().to_string(),
            display_label: "Editor 4".into(),
            same_user_tabs: 1,
            cursor_anchor: Vec::new(),
            cursor_head: Vec::new(),
            state: PresenceState::Updated as i32,
            color_index: 4,
        };
        assert_eq!(validate_awareness(&valid, 8_192), Ok(()));
        let mut invalid = valid.clone();
        invalid.display_label = "private\nlabel".into();
        assert_eq!(
            validate_awareness(&invalid, 8_192),
            Err(FrameError::InvalidAwareness)
        );
        let mut invalid_cursor = valid;
        invalid_cursor.cursor_anchor = vec![0xff];
        invalid_cursor.cursor_head = vec![0xff];
        assert_eq!(
            validate_awareness(&invalid_cursor, 8_192),
            Err(FrameError::InvalidAwareness)
        );
    }
}
