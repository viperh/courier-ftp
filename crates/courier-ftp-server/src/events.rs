//! Events handlers publish after a commit; T85's bus and WebSocket hub deliver
//! them (until then [`NoopSink`] drops them).

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Most device ids in one [`BusEvent::DevicesRevoked`]; longer lists are split.
pub const MAX_DEVICES_PER_EVENT: usize = 200;

/// How a user's access to a vault changed (T85/T89).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessChange {
    /// The user can now open the vault.
    Granted,
    /// The user's permission changed.
    Changed,
    /// The user lost access.
    Revoked,
}

/// One event for the live-update fan-out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "e", rename_all = "snake_case")]
pub enum BusEvent {
    /// A push committed (T85).
    VaultChanged {
        /// The vault.
        vault_id: Uuid,
        /// Its new head revision.
        head_revision: u64,
    },
    /// A membership changed (T85/T89).
    VaultAccess {
        /// The member.
        user_id: Uuid,
        /// The vault.
        vault_id: Uuid,
        /// What changed.
        change: AccessChange,
    },
    /// The account keys changed (password change, recovery).
    AccountChanged {
        /// The account.
        user_id: Uuid,
        /// The new account key version.
        key_version: u32,
        /// The device that made the change (not notified); `None` for recovery.
        origin_device: Option<Uuid>,
    },
    /// These devices lost their tokens; their WebSockets close with 4401.
    DevicesRevoked {
        /// At most [`MAX_DEVICES_PER_EVENT`] ids.
        device_ids: Vec<Uuid>,
    },
    /// An admin disabled the account (T86).
    UserDisabled {
        /// The account.
        user_id: Uuid,
    },
}

/// Where handlers publish events.
pub trait EventSink: Send + Sync + 'static {
    /// Publishes one event (never blocks, never fails the request).
    fn publish(&self, ev: BusEvent);
}

/// Drops every event (until T85 wires the bus).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSink;

impl EventSink for NoopSink {
    fn publish(&self, _ev: BusEvent) {}
}

/// Keeps every event (tests).
#[derive(Debug, Default)]
pub struct RecordingSink(Mutex<Vec<BusEvent>>);

impl RecordingSink {
    /// An empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The events published so far.
    #[must_use]
    pub fn events(&self) -> Vec<BusEvent> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }

    /// Forgets the recorded events.
    pub fn clear(&self) {
        if let Ok(mut v) = self.0.lock() {
            v.clear();
        }
    }
}

impl EventSink for RecordingSink {
    fn publish(&self, ev: BusEvent) {
        if let Ok(mut v) = self.0.lock() {
            v.push(ev);
        }
    }
}

/// Publishes [`BusEvent::DevicesRevoked`] for `ids`, split into chunks of
/// [`MAX_DEVICES_PER_EVENT`]; nothing for an empty list.
pub fn publish_devices_revoked(sink: &dyn EventSink, ids: &[Uuid]) {
    for chunk in ids.chunks(MAX_DEVICES_PER_EVENT) {
        sink.publish(BusEvent::DevicesRevoked {
            device_ids: chunk.to_vec(),
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn wire_shape_and_chunking() {
        let ev = BusEvent::AccountChanged {
            user_id: Uuid::nil(),
            key_version: 2,
            origin_device: None,
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["e"], "account_changed");
        assert_eq!(serde_json::from_value::<BusEvent>(json).unwrap(), ev);

        let sink = RecordingSink::new();
        let ids: Vec<Uuid> = (0..401u128).map(Uuid::from_u128).collect();
        publish_devices_revoked(&sink, &ids);
        publish_devices_revoked(&sink, &[]);
        let lens: Vec<usize> = sink
            .events()
            .iter()
            .map(|e| match e {
                BusEvent::DevicesRevoked { device_ids } => device_ids.len(),
                _ => 0,
            })
            .collect();
        assert_eq!(lens, [200, 200, 1]);
    }
}
