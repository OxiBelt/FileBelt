// SPDX-License-Identifier: Apache-2.0

//! Bounded one-second admission windows for collaboration traffic.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use filebelt_control_protocol::CollaborationLimitConfig;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionKind {
    Update,
    Awareness,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateAdmission {
    Admitted,
    ClientLimited,
    RoomLimited,
}

#[derive(Clone, Copy, Debug)]
struct Window {
    started: Instant,
    events: u64,
    bytes: u64,
}

impl Window {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            events: 0,
            bytes: 0,
        }
    }

    fn reset_if_elapsed(&mut self, now: Instant) {
        if now.duration_since(self.started) >= Duration::from_secs(1) {
            *self = Self::new(now);
        }
    }
}

pub struct RateLimiter {
    limits: CollaborationLimitConfig,
    room_updates: Window,
    room_awareness: Window,
    client_updates: HashMap<Uuid, Window>,
    client_awareness: HashMap<Uuid, Window>,
}

impl RateLimiter {
    #[must_use]
    pub fn new(limits: CollaborationLimitConfig, now: Instant) -> Self {
        Self {
            limits,
            room_updates: Window::new(now),
            room_awareness: Window::new(now),
            client_updates: HashMap::new(),
            client_awareness: HashMap::new(),
        }
    }

    pub fn admit(
        &mut self,
        client_id: Uuid,
        kind: AdmissionKind,
        bytes: u64,
        now: Instant,
    ) -> RateAdmission {
        let (client, room, client_events, client_bytes, room_events, room_bytes) = match kind {
            AdmissionKind::Update => (
                self.client_updates
                    .entry(client_id)
                    .or_insert_with(|| Window::new(now)),
                &mut self.room_updates,
                u64::from(self.limits.client_updates_per_second),
                self.limits.client_bytes_per_second,
                u64::from(self.limits.room_updates_per_second),
                self.limits.room_bytes_per_second,
            ),
            AdmissionKind::Awareness => (
                self.client_awareness
                    .entry(client_id)
                    .or_insert_with(|| Window::new(now)),
                &mut self.room_awareness,
                u64::from(self.limits.client_awareness_per_second),
                self.limits.max_awareness_bytes,
                u64::from(self.limits.room_awareness_per_second),
                self.limits
                    .max_awareness_bytes
                    .saturating_mul(u64::from(self.limits.room_awareness_per_second)),
            ),
        };
        client.reset_if_elapsed(now);
        room.reset_if_elapsed(now);
        if client.events.saturating_add(1) > client_events
            || client.bytes.saturating_add(bytes) > client_bytes
        {
            return RateAdmission::ClientLimited;
        }
        if room.events.saturating_add(1) > room_events
            || room.bytes.saturating_add(bytes) > room_bytes
        {
            return RateAdmission::RoomLimited;
        }
        client.events += 1;
        client.bytes += bytes;
        room.events += 1;
        room.bytes += bytes;
        RateAdmission::Admitted
    }

    pub fn remove_client(&mut self, client_id: Uuid) {
        self.client_updates.remove(&client_id);
        self.client_awareness.remove(&client_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_without_partially_charging_room_windows() {
        let now = Instant::now();
        let limits = CollaborationLimitConfig {
            client_updates_per_second: 1,
            room_updates_per_second: 2,
            ..CollaborationLimitConfig::default()
        };
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut limiter = RateLimiter::new(limits, now);
        assert_eq!(
            limiter.admit(first, AdmissionKind::Update, 1, now),
            RateAdmission::Admitted
        );
        assert_eq!(
            limiter.admit(first, AdmissionKind::Update, 1, now),
            RateAdmission::ClientLimited
        );
        assert_eq!(
            limiter.admit(second, AdmissionKind::Update, 1, now),
            RateAdmission::Admitted
        );
        assert_eq!(
            limiter.admit(Uuid::new_v4(), AdmissionKind::Update, 1, now),
            RateAdmission::RoomLimited
        );
    }

    #[test]
    fn admits_again_after_window_rolls() {
        let now = Instant::now();
        let client = Uuid::new_v4();
        let limits = CollaborationLimitConfig {
            client_updates_per_second: 1,
            ..CollaborationLimitConfig::default()
        };
        let mut limiter = RateLimiter::new(limits, now);
        assert_eq!(
            limiter.admit(client, AdmissionKind::Update, 1, now),
            RateAdmission::Admitted
        );
        assert_eq!(
            limiter.admit(
                client,
                AdmissionKind::Update,
                1,
                now + Duration::from_secs(1)
            ),
            RateAdmission::Admitted
        );
    }

    #[test]
    fn leaving_client_releases_its_windows() {
        let now = Instant::now();
        let client = Uuid::new_v4();
        let limits = CollaborationLimitConfig {
            client_updates_per_second: 1,
            ..CollaborationLimitConfig::default()
        };
        let mut limiter = RateLimiter::new(limits, now);
        assert_eq!(
            limiter.admit(client, AdmissionKind::Update, 1, now),
            RateAdmission::Admitted
        );
        limiter.remove_client(client);
        assert_eq!(
            limiter.admit(client, AdmissionKind::Update, 1, now),
            RateAdmission::Admitted
        );
    }
}
