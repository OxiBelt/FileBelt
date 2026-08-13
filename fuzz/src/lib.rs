// SPDX-License-Identifier: Apache-2.0

//! Side-effect-free exercise functions shared by libFuzzer and regressions.

#![deny(unsafe_code)]

use aws_lc_rs::digest::{SHA256, digest};
use filebelt_control_protocol::Config;
use filebelt_mcp_protocol::{
    InvocationFrame, RunnerRelayFrame, RunnerRelayHello, decode_frame, decode_frames,
    decode_runner_hello, decode_runner_relay_frame, encode_frame, encode_runner_hello,
    encode_runner_relay_frame,
};
use filebelt_revision_protocol::{
    RevisionExecuteRequest, RevisionExecuteResponse, decode_frame as decode_revision_frame,
    encode_frame as encode_revision_frame, validate_request, validate_response,
};
use prost::Message as _;

pub const NFS_VFS_BOUNDARY_MAX_INPUT_BYTES: usize = 4 * 1024;
pub const MCP_RUNNER_RELAY_MAX_INPUT_BYTES: usize = 128 * 1024;
pub const COLLABORATION_WIRE_MAX_INPUT_BYTES: usize = 256 * 1024;
pub const REVISION_PROTOCOL_MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const RUNTIME_CONFIG_MAX_INPUT_BYTES: usize = 64 * 1024;

pub fn nfs_vfs_boundary(input: &[u8]) {
    if input.len() <= NFS_VFS_BOUNDARY_MAX_INPUT_BYTES {
        filebelt_vfs::fuzzing::exercise_nfs_vfs_boundary(input);
    }
}

pub fn mcp_runner_relay(input: &[u8]) {
    if input.len() > MCP_RUNNER_RELAY_MAX_INPUT_BYTES {
        return;
    }
    if let Ok(frame) = decode_frame(input) {
        let encoded = encode_frame(&frame).expect("an accepted MCP invocation frame re-encodes");
        assert_eq!(decode_frame(&encoded), Ok(frame));
    }
    if let Ok(frames) = decode_frames(input) {
        let mut encoded = Vec::new();
        for frame in &frames {
            encoded.extend(
                encode_frame(frame).expect("an accepted MCP invocation sequence re-encodes"),
            );
        }
        assert_eq!(decode_frames(&encoded), Ok(frames));
    }
    if let Ok(hello) = decode_runner_hello(input) {
        let encoded = encode_runner_hello(&hello).expect("an accepted runner hello re-encodes");
        assert_eq!(decode_runner_hello(&encoded), Ok(hello));
    }
    if let Ok(frame) = decode_runner_relay_frame(input) {
        let encoded =
            encode_runner_relay_frame(&frame).expect("an accepted runner relay frame re-encodes");
        assert_eq!(decode_runner_relay_frame(&encoded), Ok(frame));
    }
    let _ = InvocationFrame::decode(input);
    let _ = RunnerRelayHello::decode(input);
    let _ = RunnerRelayFrame::decode(input);
}

pub fn collaboration_wire(input: &[u8]) {
    if input.len() <= COLLABORATION_WIRE_MAX_INPUT_BYTES {
        filebelt_collaboration::fuzzing::exercise_collaboration_wire(input);
    }
}

pub fn revision_protocol(input: &[u8]) {
    if input.len() > REVISION_PROTOCOL_MAX_INPUT_BYTES {
        return;
    }
    if let Ok(request) = decode_revision_frame::<RevisionExecuteRequest>(input) {
        let encoded =
            encode_revision_frame(&request).expect("an accepted revision request frame re-encodes");
        assert_eq!(
            decode_revision_frame::<RevisionExecuteRequest>(&encoded),
            Ok(request.clone())
        );
        let _ = validate_request(&request);
    }
    if input.len() >= 8 {
        let split = 4 + usize::from(u16::from_be_bytes([input[0], input[1]]))
            .min(input.len().saturating_sub(8));
        let (request_bytes, response_bytes) = input.split_at(split);
        if let (Ok(request), Ok(response)) = (
            decode_revision_frame::<RevisionExecuteRequest>(request_bytes),
            decode_revision_frame::<RevisionExecuteResponse>(response_bytes),
        ) {
            let _ = validate_response(&request, &response);
        }
    }
    let _ = RevisionExecuteRequest::decode(input);
    let _ = RevisionExecuteResponse::decode(input);
}

pub fn runtime_config(input: &[u8]) {
    if input.len() > RUNTIME_CONFIG_MAX_INPUT_BYTES {
        return;
    }
    let Ok(source) = std::str::from_utf8(input) else {
        return;
    };
    if let Ok(config) = toml::from_str::<Config>(source) {
        let first = config.validate().is_ok();
        assert_eq!(first, config.validate().is_ok());
        if let Ok(encoded) = toml::to_string(&config) {
            let reparsed: Config = toml::from_str(&encoded)
                .expect("a parsed runtime configuration serializes to valid TOML");
            assert_eq!(first, reparsed.validate().is_ok());
        }
    }
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
