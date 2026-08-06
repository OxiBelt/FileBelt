// SPDX-License-Identifier: Apache-2.0

//! Versioned notification envelope generated from the public Protobuf schema.

#![deny(unsafe_code)]

mod generated {
    include!("../../../../protocol/generated/rust/filebelt/events/v1/filebelt.events.v1.rs");
}

pub use generated::EventEnvelope;

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn event_round_trips_without_unordered_fields() {
        let event = EventEnvelope {
            event_id: "00000000-0000-4000-8000-000000000001".into(),
            tenant_id: "00000000-0000-4000-8000-000000000002".into(),
            aggregate_type: "node".into(),
            aggregate_id: "00000000-0000-4000-8000-000000000003".into(),
            aggregate_generation: 2,
            event_type: "filebelt.v1.namespace.changed".into(),
            occurred_at_unix_seconds: 1,
            payload: br#"{"reason":"test"}"#.to_vec(),
        };
        let encoded = event.encode_to_vec();
        assert_eq!(EventEnvelope::decode(encoded.as_slice()).unwrap(), event);
    }
}
