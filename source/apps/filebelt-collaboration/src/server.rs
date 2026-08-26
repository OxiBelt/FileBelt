// SPDX-License-Identifier: Apache-2.0

//! Authenticated WebSocket collaboration sessions backed by durable manifests.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing};
use filebelt_capability_keyset::ApiCollaborationGrantKeyset;
use filebelt_collaboration_protocol::collaboration_frame::Frame;
use filebelt_collaboration_protocol::{
    Acknowledgement, Authenticate, Checkpoint as CheckpointFrame, CheckpointRequest,
    CheckpointState, CollaborationCodec, CollaborationError, CollaborationErrorCode,
    CollaborationGrantClaims, Heartbeat, PROTOCOL_VERSION, PresenceState, SyncChunk, UpdateGroup,
    grant_digest, verify_collaboration_grant,
};
use filebelt_control_protocol::CollaborationLimitConfig;
use filebelt_database::collaboration::{
    CollaborationAuthorizationContext, CollaborationAuthorizationGenerations,
    CollaborationReplayGroupRecord, CollaborationUpdateChunkInput,
};
use filebelt_database::{Database, DatabaseError};
use futures_util::{SinkExt as _, StreamExt as _};
use prost::Message as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Mutex, broadcast};
use tracing::{info, warn};
use url::Url;
use uuid::Uuid;

use crate::io_client::{CollaborationIoClient, IoClientError, PersistUpdateGroupInput};
use crate::{
    AdmissionKind, MarkdownSource, RateAdmission, RateLimiter, RoomDocument, RoomDocumentError,
    decode_frame, encode_frame, validate_awareness,
};

const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(5);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const CROSS_REPLICA_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_SYNC_CHUNK_BYTES: usize = 256 * 1024;
const SNAPSHOT_INTERVAL_GROUPS: u64 = 64;

fn deterministic_base_client_id(claims: &CollaborationGrantClaims) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"filebelt-collaboration-base-client-v1\0");
    hasher.update(&(claims.room_id.len() as u64).to_be_bytes());
    hasher.update(claims.room_id.as_bytes());
    hasher.update(&claims.room_epoch.to_be_bytes());
    hasher.update(&(claims.base_version_id.len() as u64).to_be_bytes());
    hasher.update(claims.base_version_id.as_bytes());
    let digest = hasher.finalize();
    let mut raw = [0_u8; 8];
    raw.copy_from_slice(&digest.as_bytes()[..8]);

    // Yjs client identifiers are JavaScript-safe integers. A nonzero, stable
    // identifier ensures that durable pre-snapshot updates continue to refer
    // to the same bootstrap items after a collaboration replica restarts.
    (u64::from_be_bytes(raw) & ((1_u64 << 53) - 1)).max(1)
}

#[derive(Clone)]
pub struct CollaborationServerState {
    pub database: Database,
    pub tenant_id: Uuid,
    pub public_origin: String,
    pub grant_verification_keys: Arc<ApiCollaborationGrantKeyset>,
    pub io: CollaborationIoClient,
    pub limits: CollaborationLimitConfig,
    room_loads: Arc<Mutex<HashMap<RoomKey, Arc<Mutex<()>>>>>,
    rooms: Arc<Mutex<HashMap<RoomKey, Arc<Mutex<LiveRoom>>>>>,
}

impl CollaborationServerState {
    #[must_use]
    pub fn new(
        database: Database,
        tenant_id: Uuid,
        public_origin: String,
        grant_verification_keys: Arc<ApiCollaborationGrantKeyset>,
        io: CollaborationIoClient,
        limits: CollaborationLimitConfig,
    ) -> Self {
        Self {
            database,
            tenant_id,
            public_origin,
            grant_verification_keys,
            io,
            limits,
            room_loads: Arc::new(Mutex::new(HashMap::new())),
            rooms: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RoomKey {
    room_id: Uuid,
    epoch: u64,
}

struct LiveRoom {
    document: RoomDocument,
    source_format: MarkdownSource,
    clients: HashSet<Uuid>,
    rate_limiter: RateLimiter,
    sender: broadcast::Sender<Vec<u8>>,
}

#[derive(Debug)]
enum SessionError {
    Authentication,
    Authorization,
    Capacity,
    Protocol,
    RateLimited,
    Conflict,
    Unavailable,
    Internal,
}

pub fn router(state: CollaborationServerState) -> Router {
    Router::new()
        .route("/collaboration/v1/ws", routing::get(websocket))
        .with_state(state)
}

async fn websocket(
    State(state): State<CollaborationServerState>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    validate_upgrade_headers(&state.public_origin, &headers)?;
    Ok(upgrade
        .max_frame_size(filebelt_collaboration_protocol::MAX_FRAME_BYTES)
        .max_message_size(filebelt_collaboration_protocol::MAX_FRAME_BYTES)
        .on_upgrade(move |socket| session(socket, state))
        .into_response())
}

fn validate_upgrade_headers(public_origin: &str, headers: &HeaderMap) -> Result<(), StatusCode> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::FORBIDDEN)?;
    let expected = Url::parse(public_origin).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let received = Url::parse(origin).map_err(|_| StatusCode::FORBIDDEN)?;
    if received.origin() != expected.origin() {
        return Err(StatusCode::FORBIDDEN);
    }
    if headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !matches!(value, "same-origin" | "same-site"))
    {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

async fn session(mut socket: WebSocket, state: CollaborationServerState) {
    let result = authenticate_socket(&mut socket, &state).await;
    let (claims, room, mut receiver, connection_id) = match result {
        Ok(authenticated) => authenticated,
        Err(error) => {
            send_session_error(&mut socket, error).await;
            return;
        }
    };
    let client_id = match Uuid::parse_str(&claims.client_id) {
        Ok(client_id) => client_id,
        Err(_) => {
            send_session_error(&mut socket, SessionError::Authentication).await;
            return;
        }
    };
    let room_key = match Uuid::parse_str(&claims.room_id) {
        Ok(room_id) => RoomKey {
            room_id,
            epoch: claims.room_epoch,
        },
        Err(_) => {
            send_session_error(&mut socket, SessionError::Authentication).await;
            return;
        }
    };
    if let Err(error) = send_initial_sync(&mut socket, &room).await {
        send_session_error(&mut socket, error).await;
        leave_room(&state, &room, room_key, client_id, connection_id).await;
        return;
    }

    let (mut sender, mut incoming) = socket.split();
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut poll = tokio::time::interval(CROSS_REPLICA_POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let recheck_seconds = state.limits.generation_recheck_seconds;
    let mut recheck = tokio::time::interval(Duration::from_secs(recheck_seconds));
    recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    poll.tick().await;
    recheck.tick().await;

    let outcome = loop {
        tokio::select! {
            message = incoming.next() => {
                let Some(message) = message else { break Ok(()); };
                let message = match message { Ok(message) => message, Err(_) => break Err(SessionError::Protocol) };
                match handle_message(&state, &claims, &room, message).await {
                    Ok(frames) => {
                        for frame in frames {
                            if sender.send(Message::Binary(frame.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(error) => break Err(error),
                }
            }
            broadcast = receiver.recv() => {
                match broadcast {
                    Ok(frame) => if sender.send(Message::Binary(frame.into())).await.is_err() { break Ok(()); },
                    Err(broadcast::error::RecvError::Lagged(_)) => break Err(SessionError::Unavailable),
                    Err(broadcast::error::RecvError::Closed) => break Ok(()),
                }
            }
            _ = heartbeat.tick() => {
                if state.database.collaboration_heartbeat_participant(state.tenant_id, connection_id).await.is_err() {
                    break Err(SessionError::Authorization);
                }
                let sequence = room.lock().await.document.server_sequence();
                let frame = encode_frame(Frame::Heartbeat(Heartbeat {
                    durable_sequence: sequence,
                    sent_at_unix_millis: unix_millis(),
                })).map_err(|_| SessionError::Internal);
                match frame {
                    Ok(frame) => if sender.send(Message::Binary(frame.into())).await.is_err() { break Ok(()); },
                    Err(error) => break Err(error),
                }
            }
            _ = poll.tick() => {
                if let Err(error) = catch_up_room(&state, &claims, &room).await { break Err(error); }
            }
            _ = recheck.tick() => {
                match authority_is_current(&state, &claims).await {
                    Ok(true) => {}
                    Ok(false) => break Err(SessionError::Authorization),
                    Err(_) => {
                        freeze_claimed_room(&state, &claims, "authorization_uncertain").await;
                        break Err(SessionError::Authorization);
                    }
                }
            }
        }
    };
    leave_room(&state, &room, room_key, client_id, connection_id).await;
    if let Err(error) = outcome {
        let frame = error_frame(error);
        if let Ok(bytes) = encode_frame(Frame::Error(frame)) {
            let _ = sender.send(Message::Binary(bytes.into())).await;
        }
    }
    let _ = sender
        .send(Message::Close(Some(CloseFrame {
            code: 1000,
            reason: Utf8Bytes::from_static("session ended"),
        })))
        .await;
}

/// Runs the collaboration protocol on the single client-created reliable
/// WebTransport stream. Each item is a bounded Protobuf length-delimited frame;
/// credentials never enter the CONNECT URI or a datagram.
pub async fn webtransport_stream<S>(mut stream: S, state: CollaborationServerState)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authenticated = async {
        let bytes = read_length_delimited(&mut stream)
            .await?
            .ok_or(SessionError::Authentication)?;
        let frame = decode_frame(&bytes).map_err(|_| SessionError::Authentication)?;
        let Some(Frame::Authenticate(authenticate)) = frame.frame else {
            return Err(SessionError::Authentication);
        };
        authenticate_grant(&state, &authenticate).await
    };
    let (claims, room, mut receiver, connection_id) =
        match tokio::time::timeout(AUTHENTICATION_TIMEOUT, authenticated).await {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                send_webtransport_error(&mut stream, error).await;
                return;
            }
            Err(_) => {
                send_webtransport_error(&mut stream, SessionError::Authentication).await;
                return;
            }
        };
    let client_id = match parse_claim_uuid(&claims.client_id) {
        Ok(value) => value,
        Err(error) => {
            send_webtransport_error(&mut stream, error).await;
            return;
        }
    };
    let room_key = match parse_claim_uuid(&claims.room_id) {
        Ok(room_id) => RoomKey {
            room_id,
            epoch: claims.room_epoch,
        },
        Err(error) => {
            send_webtransport_error(&mut stream, error).await;
            return;
        }
    };
    let initial = initial_sync_frames(&room).await;
    let initial = match initial {
        Ok(value) => value,
        Err(error) => {
            send_webtransport_error(&mut stream, error).await;
            leave_room(&state, &room, room_key, client_id, connection_id).await;
            return;
        }
    };
    for frame in initial {
        if write_length_delimited(&mut stream, &frame).await.is_err() {
            leave_room(&state, &room, room_key, client_id, connection_id).await;
            return;
        }
    }

    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut poll = tokio::time::interval(CROSS_REPLICA_POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut recheck =
        tokio::time::interval(Duration::from_secs(state.limits.generation_recheck_seconds));
    recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    poll.tick().await;
    recheck.tick().await;

    let outcome = 'session: loop {
        tokio::select! {
            message = read_length_delimited(&mut stream) => {
                let bytes = match message {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => break Ok(()),
                    Err(error) => break Err(error),
                };
                match handle_binary_frame(&state, &claims, &room, &bytes).await {
                    Ok(frames) => for frame in frames {
                        if write_length_delimited(&mut stream, &frame).await.is_err() {
                            break 'session Ok(());
                        }
                    },
                    Err(error) => break Err(error),
                }
            }
            broadcast = receiver.recv() => match broadcast {
                Ok(frame) => if write_length_delimited(&mut stream, &frame).await.is_err() { break Ok(()); },
                Err(broadcast::error::RecvError::Lagged(_)) => break Err(SessionError::Unavailable),
                Err(broadcast::error::RecvError::Closed) => break Ok(()),
            },
            _ = heartbeat.tick() => {
                if state.database.collaboration_heartbeat_participant(state.tenant_id, connection_id).await.is_err() {
                    break Err(SessionError::Authorization);
                }
                let sequence = room.lock().await.document.server_sequence();
                let frame = encode_frame(Frame::Heartbeat(Heartbeat {
                    durable_sequence: sequence,
                    sent_at_unix_millis: unix_millis(),
                })).map_err(|_| SessionError::Internal);
                match frame {
                    Ok(frame) => if write_length_delimited(&mut stream, &frame).await.is_err() { break Ok(()); },
                    Err(error) => break Err(error),
                }
            }
            _ = poll.tick() => if let Err(error) = catch_up_room(&state, &claims, &room).await { break Err(error); },
            _ = recheck.tick() => match authority_is_current(&state, &claims).await {
                Ok(true) => {}
                Ok(false) => break Err(SessionError::Authorization),
                Err(_) => {
                    freeze_claimed_room(&state, &claims, "authorization_uncertain").await;
                    break Err(SessionError::Authorization);
                }
            }
        }
    };
    leave_room(&state, &room, room_key, client_id, connection_id).await;
    if let Err(error) = outcome {
        send_webtransport_error(&mut stream, error).await;
    }
    let _ = stream.shutdown().await;
}

async fn read_length_delimited<S>(stream: &mut S) -> Result<Option<Vec<u8>>, SessionError>
where
    S: AsyncRead + Unpin,
{
    let mut first = [0_u8; 1];
    match stream.read_exact(&mut first).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err(SessionError::Protocol),
    }
    let mut value = u32::from(first[0] & 0x7f);
    let mut shift = 7_u32;
    let mut byte = first[0];
    for _ in 1..5 {
        if byte & 0x80 == 0 {
            break;
        }
        let mut next = [0_u8; 1];
        stream
            .read_exact(&mut next)
            .await
            .map_err(|_| SessionError::Protocol)?;
        byte = next[0];
        let part = u32::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(SessionError::Protocol)?;
        value = value.checked_add(part).ok_or(SessionError::Protocol)?;
        shift += 7;
    }
    if byte & 0x80 != 0 {
        return Err(SessionError::Protocol);
    }
    let length = usize::try_from(value).map_err(|_| SessionError::Protocol)?;
    if length == 0 || length > filebelt_collaboration_protocol::MAX_FRAME_BYTES {
        return Err(SessionError::Protocol);
    }
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| SessionError::Protocol)?;
    Ok(Some(bytes))
}

async fn write_length_delimited<S>(stream: &mut S, frame: &[u8]) -> Result<(), SessionError>
where
    S: AsyncWrite + Unpin,
{
    if frame.is_empty() || frame.len() > filebelt_collaboration_protocol::MAX_FRAME_BYTES {
        return Err(SessionError::Protocol);
    }
    let mut value = u32::try_from(frame.len()).map_err(|_| SessionError::Internal)?;
    let mut prefix = [0_u8; 5];
    let mut length = 0_usize;
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        prefix[length] = byte;
        length += 1;
        if value == 0 {
            break;
        }
    }
    stream
        .write_all(&prefix[..length])
        .await
        .map_err(|_| SessionError::Unavailable)?;
    stream
        .write_all(frame)
        .await
        .map_err(|_| SessionError::Unavailable)?;
    stream.flush().await.map_err(|_| SessionError::Unavailable)
}

async fn send_webtransport_error<S>(stream: &mut S, error: SessionError)
where
    S: AsyncWrite + Unpin,
{
    if let Ok(frame) = encode_frame(Frame::Error(error_frame(error))) {
        let _ = write_length_delimited(stream, &frame).await;
    }
}

async fn authenticate_socket(
    socket: &mut WebSocket,
    state: &CollaborationServerState,
) -> Result<
    (
        CollaborationGrantClaims,
        Arc<Mutex<LiveRoom>>,
        broadcast::Receiver<Vec<u8>>,
        Uuid,
    ),
    SessionError,
> {
    let message = tokio::time::timeout(AUTHENTICATION_TIMEOUT, socket.recv())
        .await
        .map_err(|_| SessionError::Authentication)?
        .ok_or(SessionError::Authentication)?
        .map_err(|_| SessionError::Authentication)?;
    let Message::Binary(bytes) = message else {
        return Err(SessionError::Authentication);
    };
    let frame = decode_frame(&bytes).map_err(|_| SessionError::Authentication)?;
    let Some(Frame::Authenticate(authenticate)) = frame.frame else {
        return Err(SessionError::Authentication);
    };
    authenticate_grant(state, &authenticate).await
}

async fn authenticate_grant(
    state: &CollaborationServerState,
    authenticate: &Authenticate,
) -> Result<
    (
        CollaborationGrantClaims,
        Arc<Mutex<LiveRoom>>,
        broadcast::Receiver<Vec<u8>>,
        Uuid,
    ),
    SessionError,
> {
    let (claims, wire) =
        verify_grant_before_state(authenticate, &state.grant_verification_keys, unix_seconds())?;
    let tenant_id = parse_claim_uuid(&claims.tenant_id)?;
    if tenant_id != state.tenant_id {
        return Err(SessionError::Authorization);
    }
    let stored = state
        .database
        .collaboration_consume_join_grant(tenant_id, &grant_digest(wire))
        .await
        .map_err(database_session_error)?;
    if stored.id != parse_claim_uuid(&claims.grant_id)?
        || stored.room_id != parse_claim_uuid(&claims.room_id)?
        || u64::try_from(stored.epoch).ok() != Some(claims.room_epoch)
        || stored.principal_id != parse_claim_uuid(&claims.principal_id)?
        || stored.session_id != parse_claim_uuid(&claims.session_id)?
        || stored.client_id != parse_claim_uuid(&claims.client_id)?
        || stored.presence_label != claims.presence_label
        || stored.can_checkpoint != claims.can_checkpoint
    {
        return Err(SessionError::Authentication);
    }
    if !authority_is_current(state, &claims).await? {
        return Err(SessionError::Authorization);
    }
    let room = load_room(state, &claims).await?;
    let client_id = parse_claim_uuid(&claims.client_id)?;
    let connection_id = state
        .database
        .collaboration_join_participant(
            tenant_id,
            stored.room_id,
            stored.epoch,
            stored.client_id,
            stored.principal_id,
            stored.session_id,
            i64::from(state.limits.max_participants),
        )
        .await
        .map_err(database_session_error)?;
    let receiver = {
        let mut live = room.lock().await;
        if live.clients.len()
            >= usize::try_from(state.limits.max_participants).unwrap_or(usize::MAX)
            || !live.clients.insert(client_id)
        {
            let _ = state
                .database
                .collaboration_leave_participant(tenant_id, connection_id)
                .await;
            return Err(SessionError::Capacity);
        }
        live.sender.subscribe()
    };
    info!(room_id = %claims.room_id, client_id = %claims.client_id, "collaboration participant joined");
    Ok((claims, room, receiver, connection_id))
}

fn verify_grant_before_state<'a>(
    authenticate: &'a Authenticate,
    keys: &ApiCollaborationGrantKeyset,
    now: i64,
) -> Result<(CollaborationGrantClaims, &'a str), SessionError> {
    if authenticate.protocol_version != PROTOCOL_VERSION
        || authenticate.codec != CollaborationCodec::YjsV1 as i32
    {
        return Err(SessionError::Protocol);
    }
    let wire =
        std::str::from_utf8(&authenticate.grant).map_err(|_| SessionError::Authentication)?;
    let claims = verify_collaboration_grant(wire, keys, now)
        .map_err(|_| SessionError::Authentication)?
        .claims;
    if authenticate.room_id != claims.room_id {
        return Err(SessionError::Authentication);
    }
    Ok((claims, wire))
}

async fn load_room(
    state: &CollaborationServerState,
    claims: &CollaborationGrantClaims,
) -> Result<Arc<Mutex<LiveRoom>>, SessionError> {
    let key = RoomKey {
        room_id: parse_claim_uuid(&claims.room_id)?,
        epoch: claims.room_epoch,
    };
    if let Some(room) = cached_room(&state.rooms, key).await {
        return Ok(room);
    }
    let load_lock = room_load_lock(&state.room_loads, key).await;
    let load_guard = load_lock.lock().await;
    let result = load_room_after_lock(state, claims, key).await;
    drop(load_guard);
    release_room_load_lock(&state.room_loads, key, &load_lock).await;
    result
}

async fn load_room_after_lock(
    state: &CollaborationServerState,
    claims: &CollaborationGrantClaims,
    key: RoomKey,
) -> Result<Arc<Mutex<LiveRoom>>, SessionError> {
    if let Some(room) = cached_room(&state.rooms, key).await {
        return Ok(room);
    }
    let bytes = state
        .io
        .download_bootstrap(claims)
        .await
        .map_err(io_session_error)?;
    let source = MarkdownSource::decode(&bytes).map_err(|_| SessionError::Protocol)?;
    let snapshot = state
        .database
        .collaboration_current_snapshot(
            state.tenant_id,
            key.room_id,
            i64::try_from(key.epoch).map_err(|_| SessionError::Protocol)?,
        )
        .await
        .map_err(database_session_error)?;
    let mut document = if let Some(snapshot) = snapshot {
        let bytes = match state.io.read_object(claims, &snapshot.object).await {
            Ok(bytes) => bytes,
            Err(error) => {
                freeze_corrupt_room(state, key).await;
                return Err(io_session_error(error));
            }
        };
        match RoomDocument::from_snapshot(
            &bytes,
            u64::try_from(snapshot.covered_sequence).map_err(|_| SessionError::Protocol)?,
            state.limits.clone(),
        ) {
            Ok(document) => document,
            Err(error) => {
                freeze_corrupt_room(state, key).await;
                return Err(document_session_error(error));
            }
        }
    } else {
        RoomDocument::from_source_with_client_id(
            &source.text,
            state.limits.clone(),
            deterministic_base_client_id(claims),
        )
    };
    if let Err(error) = replay_durable_groups(state, claims, &mut document).await {
        freeze_corrupt_room(state, key).await;
        return Err(error);
    }
    let (sender, _) = broadcast::channel(2_048);
    let room = Arc::new(Mutex::new(LiveRoom {
        document,
        source_format: source,
        clients: HashSet::new(),
        rate_limiter: RateLimiter::new(state.limits.clone(), Instant::now()),
        sender,
    }));
    // Initialization performs I/O and database work. Do it outside the global
    // cache lock so a slow or maliciously expensive cold room cannot delay
    // unrelated rooms. Concurrent initializers may each construct a candidate,
    // but only one is published and every caller uses that single live room.
    Ok(cache_loaded_room(&state.rooms, key, room).await)
}

async fn freeze_corrupt_room(state: &CollaborationServerState, key: RoomKey) {
    let epoch = i64::try_from(key.epoch).unwrap_or(i64::MAX);
    let _ = state
        .database
        .collaboration_freeze(state.tenant_id, key.room_id, epoch, "corrupt_state")
        .await;
}

async fn room_load_lock(
    room_loads: &Mutex<HashMap<RoomKey, Arc<Mutex<()>>>>,
    key: RoomKey,
) -> Arc<Mutex<()>> {
    room_loads
        .lock()
        .await
        .entry(key)
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

async fn release_room_load_lock(
    room_loads: &Mutex<HashMap<RoomKey, Arc<Mutex<()>>>>,
    key: RoomKey,
    load_lock: &Arc<Mutex<()>>,
) {
    let mut room_loads = room_loads.lock().await;
    if room_loads
        .get(&key)
        .is_some_and(|current| Arc::ptr_eq(current, load_lock))
        && Arc::strong_count(load_lock) == 2
    {
        room_loads.remove(&key);
    }
}

async fn cached_room(
    rooms: &Mutex<HashMap<RoomKey, Arc<Mutex<LiveRoom>>>>,
    key: RoomKey,
) -> Option<Arc<Mutex<LiveRoom>>> {
    rooms.lock().await.get(&key).cloned()
}

async fn cache_loaded_room(
    rooms: &Mutex<HashMap<RoomKey, Arc<Mutex<LiveRoom>>>>,
    key: RoomKey,
    candidate: Arc<Mutex<LiveRoom>>,
) -> Arc<Mutex<LiveRoom>> {
    let mut rooms = rooms.lock().await;
    rooms
        .entry(key)
        .or_insert_with(|| candidate.clone())
        .clone()
}

async fn replay_durable_groups(
    state: &CollaborationServerState,
    claims: &CollaborationGrantClaims,
    document: &mut RoomDocument,
) -> Result<(), SessionError> {
    let groups = state
        .database
        .collaboration_replay_groups(
            state.tenant_id,
            parse_claim_uuid(&claims.room_id)?,
            i64::try_from(claims.room_epoch).map_err(|_| SessionError::Protocol)?,
            i64::try_from(document.server_sequence()).map_err(|_| SessionError::Protocol)?,
        )
        .await
        .map_err(database_session_error)?;
    for group in groups {
        apply_replay_group(state, claims, document, &group).await?;
    }
    Ok(())
}

async fn apply_replay_group(
    state: &CollaborationServerState,
    claims: &CollaborationGrantClaims,
    document: &mut RoomDocument,
    group: &CollaborationReplayGroupRecord,
) -> Result<Vec<Vec<u8>>, SessionError> {
    let bytes = state
        .io
        .read_object(claims, &group.object)
        .await
        .map_err(io_session_error)?;
    let chunks = split_replay_chunks(&bytes, &group.chunks)?;
    let receipt = document
        .apply_group(&chunks)
        .map_err(document_session_error)?;
    if i64::try_from(receipt.first_sequence).ok() != Some(group.first_sequence)
        || i64::try_from(receipt.last_sequence).ok() != Some(group.last_sequence)
    {
        return Err(SessionError::Conflict);
    }
    Ok(chunks)
}

fn split_replay_chunks(
    bytes: &[u8],
    manifest: &[CollaborationUpdateChunkInput],
) -> Result<Vec<Vec<u8>>, SessionError> {
    let mut chunks = Vec::with_capacity(manifest.len());
    let mut expected_offset = 0_usize;
    for (expected_index, chunk) in manifest.iter().enumerate() {
        let offset = usize::try_from(chunk.object_offset).map_err(|_| SessionError::Conflict)?;
        let size = usize::try_from(chunk.size_bytes).map_err(|_| SessionError::Conflict)?;
        if chunk.chunk_index != i32::try_from(expected_index).unwrap_or(i32::MAX)
            || offset != expected_offset
            || size == 0
            || size > MAX_SYNC_CHUNK_BYTES
        {
            return Err(SessionError::Conflict);
        }
        let end = offset.checked_add(size).ok_or(SessionError::Conflict)?;
        let value = bytes.get(offset..end).ok_or(SessionError::Conflict)?;
        if blake3::hash(value).as_bytes().as_slice() != chunk.blake3.as_slice() {
            return Err(SessionError::Conflict);
        }
        chunks.push(value.to_vec());
        expected_offset = end;
    }
    if expected_offset != bytes.len() {
        return Err(SessionError::Conflict);
    }
    Ok(chunks)
}

async fn send_initial_sync(
    socket: &mut WebSocket,
    room: &Arc<Mutex<LiveRoom>>,
) -> Result<(), SessionError> {
    for bytes in initial_sync_frames(room).await? {
        socket
            .send(Message::Binary(bytes.into()))
            .await
            .map_err(|_| SessionError::Unavailable)?;
    }
    Ok(())
}

async fn initial_sync_frames(room: &Arc<Mutex<LiveRoom>>) -> Result<Vec<Vec<u8>>, SessionError> {
    let (sequence, snapshot) = {
        let live = room.lock().await;
        (live.document.server_sequence(), live.document.snapshot())
    };
    let chunks = if snapshot.is_empty() {
        vec![Vec::new()]
    } else {
        snapshot
            .chunks(MAX_SYNC_CHUNK_BYTES)
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>()
    };
    let count = u32::try_from(chunks.len()).map_err(|_| SessionError::Internal)?;
    let mut frames = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.into_iter().enumerate() {
        let bytes = encode_frame(Frame::SyncChunk(SyncChunk {
            sequence,
            chunk_index: u32::try_from(index).map_err(|_| SessionError::Internal)?,
            chunk_count: count,
            update: chunk,
            snapshot: true,
        }))
        .map_err(|_| SessionError::Internal)?;
        frames.push(bytes);
    }
    Ok(frames)
}

async fn handle_message(
    state: &CollaborationServerState,
    claims: &CollaborationGrantClaims,
    room: &Arc<Mutex<LiveRoom>>,
    message: Message,
) -> Result<Vec<Vec<u8>>, SessionError> {
    match message {
        Message::Binary(bytes) => handle_binary_frame(state, claims, room, &bytes).await,
        Message::Ping(_) => Ok(Vec::new()),
        Message::Pong(_) => Ok(Vec::new()),
        Message::Close(_) => Err(SessionError::Unavailable),
        Message::Text(_) => Err(SessionError::Protocol),
    }
}

async fn handle_binary_frame(
    state: &CollaborationServerState,
    claims: &CollaborationGrantClaims,
    room: &Arc<Mutex<LiveRoom>>,
    bytes: &[u8],
) -> Result<Vec<Vec<u8>>, SessionError> {
    let frame = decode_frame(bytes).map_err(|_| SessionError::Protocol)?;
    match frame.frame {
        Some(Frame::UpdateGroup(group)) => apply_update(state, claims, room, group).await,
        Some(Frame::Awareness(awareness)) => {
            validate_awareness(&awareness, state.limits.max_awareness_bytes)
                .map_err(|_| SessionError::Protocol)?;
            if awareness.client_id != claims.client_id
                || awareness.display_label != claims.presence_label
                || PresenceState::try_from(awareness.state).ok() == Some(PresenceState::Unspecified)
            {
                return Err(SessionError::Authorization);
            }
            let mut live = room.lock().await;
            if live.rate_limiter.admit(
                parse_claim_uuid(&claims.client_id)?,
                AdmissionKind::Awareness,
                u64::try_from(awareness.encoded_len()).unwrap_or(u64::MAX),
                Instant::now(),
            ) != RateAdmission::Admitted
            {
                return Err(SessionError::RateLimited);
            }
            let encoded =
                encode_frame(Frame::Awareness(awareness)).map_err(|_| SessionError::Internal)?;
            let _ = live.sender.send(encoded);
            Ok(Vec::new())
        }
        Some(Frame::SyncRequest(_)) => {
            drop(frame);
            Ok(Vec::new())
        }
        Some(Frame::Heartbeat(_)) => Ok(Vec::new()),
        Some(Frame::CheckpointRequest(request)) => {
            prepare_checkpoint(state, claims, room, request).await
        }
        _ => Err(SessionError::Protocol),
    }
}

async fn prepare_checkpoint(
    state: &CollaborationServerState,
    claims: &CollaborationGrantClaims,
    room: &Arc<Mutex<LiveRoom>>,
    request: CheckpointRequest,
) -> Result<Vec<Vec<u8>>, SessionError> {
    if !claims.can_checkpoint {
        return Err(SessionError::Authorization);
    }
    let live = room.lock().await;
    if request.expected_durable_sequence != live.document.server_sequence() {
        return Err(SessionError::Conflict);
    }
    let checkpoint = live.document.checkpoint().map_err(document_session_error)?;
    let source = MarkdownSource {
        text: String::from_utf8(checkpoint.source).map_err(|_| SessionError::Internal)?,
        bom: live.source_format.bom,
        line_ending: live.source_format.line_ending,
    }
    .encode_for_save();
    let checkpoint_id = state
        .database
        .collaboration_prepare_checkpoint(
            state.tenant_id,
            parse_claim_uuid(&claims.room_id)?,
            i64::try_from(claims.room_epoch).map_err(|_| SessionError::Protocol)?,
            state
                .database
                .collaboration_room(
                    state.tenant_id,
                    parse_claim_uuid(&claims.drive_id)?,
                    parse_claim_uuid(&claims.node_id)?,
                )
                .await
                .map_err(database_session_error)?
                .ok_or(SessionError::Conflict)?
                .fencing_token,
            authorization_context(claims)?,
            i64::try_from(checkpoint.server_sequence).map_err(|_| SessionError::Internal)?,
            &checkpoint.state_vector,
            i64::try_from(source.len()).map_err(|_| SessionError::Internal)?,
            blake3::hash(&source).as_bytes(),
        )
        .await
        .map_err(database_session_error)?;
    let response = encode_frame(Frame::Checkpoint(CheckpointFrame {
        checkpoint_id: checkpoint_id.to_string(),
        durable_sequence: checkpoint.server_sequence,
        state: CheckpointState::Durable as i32,
        version_id: String::new(),
    }))
    .map_err(|_| SessionError::Internal)?;
    Ok(vec![response])
}

async fn apply_update(
    state: &CollaborationServerState,
    claims: &CollaborationGrantClaims,
    room: &Arc<Mutex<LiveRoom>>,
    group: UpdateGroup,
) -> Result<Vec<Vec<u8>>, SessionError> {
    let update_id = Uuid::parse_str(&group.client_update_id).map_err(|_| SessionError::Protocol)?;
    let mcp_invocation_id = if group.mcp_invocation_id.is_empty() {
        None
    } else {
        Some(Uuid::parse_str(&group.mcp_invocation_id).map_err(|_| SessionError::Protocol)?)
    };
    if group.chunks.is_empty() || group.chunks.len() > 16 {
        return Err(SessionError::Protocol);
    }
    let mut chunks = Vec::with_capacity(group.chunks.len());
    for (expected, chunk) in group.chunks.into_iter().enumerate() {
        if chunk.chunk_index != u32::try_from(expected).unwrap_or(u32::MAX) {
            return Err(SessionError::Protocol);
        }
        chunks.push(chunk.update);
    }
    let total = chunks.iter().try_fold(0_u64, |size, chunk| {
        size.checked_add(u64::try_from(chunk.len()).ok()?)
    });
    let total = total.ok_or(SessionError::Protocol)?;
    // A connection can land on a replica that has not observed the latest
    // durable group yet. Rehydrate it before validating the client's base.
    catch_up_room(state, claims, room).await?;
    let mut live = room.lock().await;
    if group.base_sequence > live.document.server_sequence() {
        return Err(SessionError::Conflict);
    }
    if live.rate_limiter.admit(
        parse_claim_uuid(&claims.client_id)?,
        AdmissionKind::Update,
        total,
        Instant::now(),
    ) != RateAdmission::Admitted
    {
        return Err(SessionError::RateLimited);
    }
    let mut persistence_attempts = 0_u8;
    let (staged, expected, object_id, first, last) = loop {
        persistence_attempts = persistence_attempts.saturating_add(1);
        let staged = live
            .document
            .stage_group(&chunks)
            .map_err(document_session_error)?;
        let expected = staged.receipt().clone();
        let expected_base =
            i64::try_from(live.document.server_sequence()).map_err(|_| SessionError::Protocol)?;
        match state
            .io
            .persist_update_group(
                &state.database,
                PersistUpdateGroupInput {
                    claims,
                    chunks: &chunks,
                    receipt: &expected,
                    client_update_id: update_id,
                    mcp_invocation_id,
                    expected_base_sequence: expected_base,
                },
            )
            .await
        {
            Ok((object_id, first, last)) => {
                break (staged, expected, object_id, first, last);
            }
            Err(IoClientError::Database(DatabaseError::StaleGeneration)) => {
                if persistence_attempts >= 3 {
                    return Err(SessionError::Conflict);
                }
                drop(live);
                catch_up_room(state, claims, room).await?;
                live = room.lock().await;
            }
            Err(error) => return Err(io_session_error(error)),
        }
    };
    if i64::try_from(expected.first_sequence).ok() != Some(first)
        || i64::try_from(expected.last_sequence).ok() != Some(last)
    {
        return Err(SessionError::Conflict);
    }
    let receipt = live
        .document
        .commit_staged(staged)
        .map_err(document_session_error)?;
    let snapshot = if receipt.last_sequence % SNAPSHOT_INTERVAL_GROUPS == 0 {
        let checkpoint = live.document.checkpoint().map_err(document_session_error)?;
        Some((
            checkpoint.snapshot,
            i64::try_from(checkpoint.server_sequence).map_err(|_| SessionError::Internal)?,
            checkpoint.state_vector,
        ))
    } else {
        None
    };
    let count = u32::try_from(chunks.len()).map_err(|_| SessionError::Internal)?;
    for (index, chunk) in chunks.into_iter().enumerate() {
        let sequence = receipt.first_sequence;
        let broadcast = encode_frame(Frame::SyncChunk(SyncChunk {
            sequence,
            chunk_index: u32::try_from(index).map_err(|_| SessionError::Internal)?,
            chunk_count: count,
            update: chunk,
            snapshot: false,
        }))
        .map_err(|_| SessionError::Internal)?;
        let _ = live.sender.send(broadcast);
    }
    let acknowledgement = encode_frame(Frame::Acknowledgement(Acknowledgement {
        client_update_id: group.client_update_id,
        durable_sequence: receipt.last_sequence,
        manifest_id: object_id.to_string(),
    }))
    .map_err(|_| SessionError::Internal)?;
    if let Some((snapshot, covered_sequence, state_vector)) = snapshot {
        persist_snapshot(
            state.clone(),
            claims.clone(),
            snapshot,
            covered_sequence,
            state_vector,
        );
    }
    Ok(vec![acknowledgement])
}

fn persist_snapshot(
    state: CollaborationServerState,
    claims: CollaborationGrantClaims,
    snapshot: Vec<u8>,
    covered_sequence: i64,
    state_vector: Vec<u8>,
) {
    tokio::spawn(async move {
        if let Err(error) = state
            .io
            .persist_snapshot(
                &state.database,
                &claims,
                snapshot,
                covered_sequence,
                &state_vector,
            )
            .await
        {
            warn!(room_id = %claims.room_id, covered_sequence, %error, "collaboration snapshot deferred");
        }
    });
}

async fn catch_up_room(
    state: &CollaborationServerState,
    claims: &CollaborationGrantClaims,
    room: &Arc<Mutex<LiveRoom>>,
) -> Result<(), SessionError> {
    let mut live = room.lock().await;
    let after =
        i64::try_from(live.document.server_sequence()).map_err(|_| SessionError::Internal)?;
    let groups = state
        .database
        .collaboration_replay_groups(
            state.tenant_id,
            parse_claim_uuid(&claims.room_id)?,
            i64::try_from(claims.room_epoch).map_err(|_| SessionError::Protocol)?,
            after,
        )
        .await
        .map_err(database_session_error)?;
    for group in groups {
        let chunks = match apply_replay_group(state, claims, &mut live.document, &group).await {
            Ok(chunks) => chunks,
            Err(error) => {
                freeze_claimed_room(state, claims, "corrupt_state").await;
                return Err(error);
            }
        };
        let count = u32::try_from(chunks.len()).map_err(|_| SessionError::Internal)?;
        for (index, chunk) in chunks.into_iter().enumerate() {
            let sequence =
                u64::try_from(group.first_sequence).map_err(|_| SessionError::Conflict)?;
            let frame = encode_frame(Frame::SyncChunk(SyncChunk {
                sequence,
                chunk_index: u32::try_from(index).map_err(|_| SessionError::Internal)?,
                chunk_count: count,
                update: chunk,
                snapshot: false,
            }))
            .map_err(|_| SessionError::Internal)?;
            let _ = live.sender.send(frame);
        }
    }
    Ok(())
}

async fn authority_is_current(
    state: &CollaborationServerState,
    claims: &CollaborationGrantClaims,
) -> Result<bool, SessionError> {
    let tenant_id = parse_claim_uuid(&claims.tenant_id)?;
    let principal_id = parse_claim_uuid(&claims.principal_id)?;
    let session_id = parse_claim_uuid(&claims.session_id)?;
    let drive_id = parse_claim_uuid(&claims.drive_id)?;
    let node_id = parse_claim_uuid(&claims.node_id)?;
    let room_id = parse_claim_uuid(&claims.room_id)?;
    let base_version_id = parse_claim_uuid(&claims.base_version_id)?;
    let room = state
        .database
        .collaboration_room(tenant_id, drive_id, node_id)
        .await
        .map_err(database_session_error)?
        .ok_or(SessionError::Authorization)?;
    if room.room_id != room_id
        || u64::try_from(room.epoch).ok() != Some(claims.room_epoch)
        || room.base_version_id != base_version_id
    {
        return Ok(false);
    }
    let generations = state
        .database
        .authorization_generations_match(
            tenant_id,
            session_id,
            principal_id,
            drive_id,
            node_id,
            i64::try_from(claims.membership_generation).map_err(|_| SessionError::Authorization)?,
            i64::try_from(claims.drive_acl_generation).map_err(|_| SessionError::Authorization)?,
            i64::try_from(claims.namespace_generation).map_err(|_| SessionError::Authorization)?,
            i64::try_from(claims.resource_acl_generation)
                .map_err(|_| SessionError::Authorization)?,
        )
        .await
        .map_err(database_session_error)?;
    let head = state
        .database
        .collaboration_epoch_is_current(
            tenant_id,
            room_id,
            room.epoch,
            room.fencing_token,
            base_version_id,
        )
        .await
        .map_err(database_session_error)?;
    if !generations {
        freeze_claimed_room(state, claims, "authorization_uncertain").await;
    } else if !head {
        freeze_claimed_room(state, claims, "external_head").await;
    }
    Ok(generations && head)
}

async fn freeze_claimed_room(
    state: &CollaborationServerState,
    claims: &CollaborationGrantClaims,
    reason: &str,
) {
    let (Ok(room_id), Ok(epoch)) = (
        Uuid::parse_str(&claims.room_id),
        i64::try_from(claims.room_epoch),
    ) else {
        return;
    };
    let _ = state
        .database
        .collaboration_freeze(state.tenant_id, room_id, epoch, reason)
        .await;
}

async fn leave_room(
    state: &CollaborationServerState,
    room: &Arc<Mutex<LiveRoom>>,
    room_key: RoomKey,
    client_id: Uuid,
    connection_id: Uuid,
) {
    let empty = {
        let mut live = room.lock().await;
        live.clients.remove(&client_id);
        live.rate_limiter.remove_client(client_id);
        live.clients.is_empty()
    };
    if empty {
        let mut rooms = state.rooms.lock().await;
        if rooms
            .get(&room_key)
            .is_some_and(|current| Arc::ptr_eq(current, room))
            && room.lock().await.clients.is_empty()
        {
            rooms.remove(&room_key);
        }
    }
    if let Err(error) = state
        .database
        .collaboration_leave_participant(state.tenant_id, connection_id)
        .await
    {
        warn!(%connection_id, %error, "collaboration participant cleanup deferred");
    }
}

async fn send_session_error(socket: &mut WebSocket, error: SessionError) {
    if let Ok(bytes) = encode_frame(Frame::Error(error_frame(error))) {
        let _ = socket.send(Message::Binary(bytes.into())).await;
    }
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: 1008,
            reason: Utf8Bytes::from_static("collaboration rejected"),
        })))
        .await;
}

fn error_frame(error: SessionError) -> CollaborationError {
    let (code, message, retry_after_millis) = match error {
        SessionError::Authentication => (
            CollaborationErrorCode::AuthenticationRequired,
            "Authentication failed",
            0,
        ),
        SessionError::Authorization => (
            CollaborationErrorCode::ReauthenticationRequired,
            "Authorization changed",
            0,
        ),
        SessionError::Capacity => (
            CollaborationErrorCode::RoomLimit,
            "Room participant limit reached",
            5_000,
        ),
        SessionError::Protocol => (
            CollaborationErrorCode::ProtocolViolation,
            "Protocol frame rejected",
            0,
        ),
        SessionError::RateLimited => (
            CollaborationErrorCode::RateLimited,
            "Rate limit reached",
            1_000,
        ),
        SessionError::Conflict => (
            CollaborationErrorCode::ConflictReviewRequired,
            "Durable state resynchronization required",
            0,
        ),
        SessionError::Unavailable => (
            CollaborationErrorCode::Unavailable,
            "Authoritative state is unavailable",
            1_000,
        ),
        SessionError::Internal => (CollaborationErrorCode::Internal, "Collaboration failed", 0),
    };
    CollaborationError {
        code: code as i32,
        message: message.into(),
        retry_after_millis,
    }
}

fn parse_claim_uuid(value: &str) -> Result<Uuid, SessionError> {
    Uuid::parse_str(value).map_err(|_| SessionError::Authentication)
}

fn authorization_context(
    claims: &CollaborationGrantClaims,
) -> Result<CollaborationAuthorizationContext, SessionError> {
    Ok(CollaborationAuthorizationContext {
        principal_id: parse_claim_uuid(&claims.principal_id)?,
        session_id: parse_claim_uuid(&claims.session_id)?,
        drive_id: parse_claim_uuid(&claims.drive_id)?,
        node_id: parse_claim_uuid(&claims.node_id)?,
        generations: CollaborationAuthorizationGenerations {
            membership: i64::try_from(claims.membership_generation)
                .map_err(|_| SessionError::Authorization)?,
            drive_acl: i64::try_from(claims.drive_acl_generation)
                .map_err(|_| SessionError::Authorization)?,
            namespace: i64::try_from(claims.namespace_generation)
                .map_err(|_| SessionError::Authorization)?,
            resource_acl: i64::try_from(claims.resource_acl_generation)
                .map_err(|_| SessionError::Authorization)?,
        },
    })
}

fn database_session_error(error: DatabaseError) -> SessionError {
    match error {
        DatabaseError::NotFound | DatabaseError::StaleGeneration => SessionError::Authorization,
        DatabaseError::Conflict => SessionError::Conflict,
        DatabaseError::QuotaExceeded | DatabaseError::AdmissionLimited => SessionError::Capacity,
        DatabaseError::StorageUnavailable
        | DatabaseError::SecurityAdmissionBlocked
        | DatabaseError::Sql(_)
        | DatabaseError::Migration(_) => SessionError::Unavailable,
        DatabaseError::InvalidPersistedValue => SessionError::Internal,
    }
}

fn io_session_error(error: IoClientError) -> SessionError {
    match error {
        IoClientError::InvalidContext | IoClientError::InvalidCapability => {
            SessionError::Authorization
        }
        IoClientError::Rejected => SessionError::Conflict,
        IoClientError::Unavailable | IoClientError::Database(_) => SessionError::Unavailable,
        IoClientError::SourceTooLarge => SessionError::Capacity,
    }
}

fn document_session_error(error: RoomDocumentError) -> SessionError {
    match error {
        RoomDocumentError::Frozen(_) => SessionError::Authorization,
        RoomDocumentError::UpdateTooLarge
        | RoomDocumentError::GroupTooLarge
        | RoomDocumentError::StateTooLarge
        | RoomDocumentError::SourceTooLarge => SessionError::Capacity,
        RoomDocumentError::EmptyGroup
        | RoomDocumentError::InvalidUpdate
        | RoomDocumentError::InvalidSnapshot
        | RoomDocumentError::SourceContainsNul => SessionError::Protocol,
        RoomDocumentError::StaleSequence => SessionError::Conflict,
    }
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
    use axum::http::HeaderValue;

    fn grant_claims() -> CollaborationGrantClaims {
        CollaborationGrantClaims {
            grant_id: Uuid::new_v4().to_string(),
            tenant_id: Uuid::new_v4().to_string(),
            room_id: Uuid::new_v4().to_string(),
            room_epoch: 1,
            drive_id: Uuid::new_v4().to_string(),
            node_id: Uuid::new_v4().to_string(),
            base_version_id: Uuid::new_v4().to_string(),
            principal_id: Uuid::new_v4().to_string(),
            session_id: Uuid::new_v4().to_string(),
            client_id: Uuid::new_v4().to_string(),
            presence_mode: filebelt_collaboration_protocol::PresenceMode::Pseudonym as i32,
            presence_label: "Editor 7".into(),
            resource_acl_generation: 1,
            drive_acl_generation: 1,
            membership_generation: 1,
            namespace_generation: 1,
            can_checkpoint: true,
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 160,
            nonce: vec![7; 32],
            bootstrap_download_capability: "fbcap1.test".into(),
        }
    }

    fn test_room() -> Arc<Mutex<LiveRoom>> {
        let limits = CollaborationLimitConfig::default();
        let (sender, _) = broadcast::channel(1);
        Arc::new(Mutex::new(LiveRoom {
            document: RoomDocument::from_source("", limits.clone()),
            source_format: MarkdownSource::decode(b"").unwrap(),
            clients: HashSet::new(),
            rate_limiter: RateLimiter::new(limits, Instant::now()),
            sender,
        }))
    }

    #[test]
    fn upgrade_origin_is_exact() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://files.example"),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        assert_eq!(
            validate_upgrade_headers("https://files.example/", &headers),
            Ok(())
        );
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert_eq!(
            validate_upgrade_headers("https://files.example/", &headers),
            Err(StatusCode::FORBIDDEN)
        );
    }

    #[test]
    fn collaboration_admission_rejects_foreign_signer_before_grant_consumption() {
        let retiring = Ed25519KeyPair::generate().unwrap();
        let current = Ed25519KeyPair::generate().unwrap();
        let foreign = Ed25519KeyPair::generate().unwrap();
        let keys = ApiCollaborationGrantKeyset::parse(
            &filebelt_capability_keyset::encode_keyset(
                filebelt_capability_keyset::KeyPurpose::ApiCollaborationGrant,
                &[
                    (1, retiring.public_key().as_ref().try_into().unwrap()),
                    (2, current.public_key().as_ref().try_into().unwrap()),
                ],
            )
            .unwrap(),
        )
        .unwrap();
        let _foreign_storage_keys = filebelt_capability_keyset::CollaborationStorageKeyset::parse(
            &filebelt_capability_keyset::encode_keyset(
                filebelt_capability_keyset::KeyPurpose::CollaborationStorage,
                &[(1, foreign.public_key().as_ref().try_into().unwrap())],
            )
            .unwrap(),
        )
        .unwrap();
        let claims = grant_claims();

        for (generation, signer) in [(1, &retiring), (2, &current)] {
            let wire = filebelt_collaboration_protocol::sign_collaboration_grant(
                &claims, generation, signer,
            )
            .unwrap();
            let authenticate = Authenticate {
                grant: wire.into_bytes(),
                room_id: claims.room_id.clone(),
                codec: CollaborationCodec::YjsV1 as i32,
                protocol_version: PROTOCOL_VERSION,
            };
            assert!(verify_grant_before_state(&authenticate, &keys, 120).is_ok());
        }

        let wire = filebelt_collaboration_protocol::sign_collaboration_grant(&claims, 1, &foreign)
            .unwrap();
        let authenticate = Authenticate {
            grant: wire.into_bytes(),
            room_id: claims.room_id,
            codec: CollaborationCodec::YjsV1 as i32,
            protocol_version: PROTOCOL_VERSION,
        };
        assert!(matches!(
            verify_grant_before_state(&authenticate, &keys, 120),
            Err(SessionError::Authentication)
        ));
    }

    #[test]
    fn replay_chunks_require_exact_offsets_and_digests() {
        let bytes = b"onetwo";
        let manifest = vec![
            CollaborationUpdateChunkInput {
                chunk_index: 0,
                object_offset: 0,
                size_bytes: 3,
                blake3: blake3::hash(b"one").as_bytes().to_vec(),
            },
            CollaborationUpdateChunkInput {
                chunk_index: 1,
                object_offset: 3,
                size_bytes: 3,
                blake3: blake3::hash(b"two").as_bytes().to_vec(),
            },
        ];
        assert_eq!(
            split_replay_chunks(bytes, &manifest).unwrap(),
            [b"one", b"two"]
        );
        let mut invalid = manifest;
        invalid[1].object_offset = 2;
        assert!(split_replay_chunks(bytes, &invalid).is_err());
    }

    #[tokio::test]
    async fn concurrent_cold_load_candidates_publish_one_live_room() {
        let rooms = Mutex::new(HashMap::new());
        let key = RoomKey {
            room_id: Uuid::new_v4(),
            epoch: 1,
        };
        let first = test_room();
        let second = test_room();
        let (first_cached, second_cached) = tokio::join!(
            cache_loaded_room(&rooms, key, first),
            cache_loaded_room(&rooms, key, second),
        );

        assert!(Arc::ptr_eq(&first_cached, &second_cached));
        let cached = cached_room(&rooms, key).await.unwrap();
        assert!(Arc::ptr_eq(&first_cached, &cached));
        assert_eq!(rooms.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn cold_room_loading_is_single_flight_per_room_and_reclaims_locks() {
        let loads = Mutex::new(HashMap::new());
        let first_key = RoomKey {
            room_id: Uuid::new_v4(),
            epoch: 1,
        };
        let second_key = RoomKey {
            room_id: Uuid::new_v4(),
            epoch: 1,
        };
        let first = room_load_lock(&loads, first_key).await;
        let same = room_load_lock(&loads, first_key).await;
        let other = room_load_lock(&loads, second_key).await;
        assert!(Arc::ptr_eq(&first, &same));
        assert!(!Arc::ptr_eq(&first, &other));

        release_room_load_lock(&loads, first_key, &first).await;
        assert_eq!(loads.lock().await.len(), 2);
        drop(same);
        release_room_load_lock(&loads, first_key, &first).await;
        assert_eq!(loads.lock().await.len(), 1);
    }
}
