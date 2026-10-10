//! The `vaults.rotation` column: non-NULL while a vault key rotation is in
//! progress (`{by, device, new_key_version, started_at}`). Pushes get
//! `409 rotating` meanwhile ([`super::push::check_access`]) and
//! `GET /v1/vaults` reports it. Beginning, uploading and committing a
//! rotation are T89 (team vaults).

use chrono::{DateTime, TimeDelta, Utc};
use courier_ftp_proto::rotation::ROTATION_ABANDON_SECS;
use courier_ftp_proto::sync::{RotationView, VaultView};
use uuid::Uuid;

use crate::auth::clock::to_offset;

/// The parsed `vaults.rotation` column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationState {
    /// The rotating user.
    pub by: Uuid,
    /// Their device (`None` for rows written without it).
    pub device: Option<Uuid>,
    /// The key version being rotated to.
    pub new_key_version: i32,
    /// When the rotation began.
    pub started_at: DateTime<Utc>,
}

impl RotationState {
    /// Parses the JSON column (`None` when malformed).
    #[must_use]
    pub fn parse(v: &serde_json::Value) -> Option<Self> {
        let by = v.get("by")?.as_str()?.parse().ok()?;
        let device = v
            .get("device")
            .and_then(serde_json::Value::as_str)
            .and_then(|d| d.parse().ok());
        let new_key_version = i32::try_from(v.get("new_key_version")?.as_i64()?).ok()?;
        let started_at = DateTime::parse_from_rfc3339(v.get("started_at")?.as_str()?)
            .ok()?
            .with_timezone(&Utc);
        Some(Self {
            by,
            device,
            new_key_version,
            started_at,
        })
    }

    /// The JSON column.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "by": self.by,
            "device": self.device,
            "new_key_version": self.new_key_version,
            "started_at": self.started_at.to_rfc3339(),
        })
    }
}

/// Whether a rotation begun at `started_at` is abandoned at `now`.
#[must_use]
pub fn is_abandoned(started_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now - started_at > TimeDelta::seconds(ROTATION_ABANDON_SECS)
}

/// The wire view of the column. A malformed column is reported as an
/// abandoned rotation by nobody (so a `manage` client restarts it).
#[must_use]
pub fn view(rotation: Option<&serde_json::Value>) -> Option<RotationView> {
    let r = rotation?;
    Some(match RotationState::parse(r) {
        Some(s) => RotationView {
            new_key_version: u32::try_from(s.new_key_version).unwrap_or(0),
            by: s.by,
            started_at: to_offset(s.started_at),
            abandoned: false,
        },
        None => RotationView {
            new_key_version: 0,
            by: Uuid::nil(),
            started_at: time::OffsetDateTime::UNIX_EPOCH,
            abandoned: true,
        },
    })
}

/// Sets `abandoned` on the rotations of `views` (server clock).
pub fn mark_abandoned(views: &mut [VaultView], now: DateTime<Utc>) {
    for r in views.iter_mut().filter_map(|v| v.rotation.as_mut()) {
        let started = DateTime::<Utc>::from_timestamp(r.started_at.unix_timestamp(), 0)
            .unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
        r.abandoned = r.abandoned || is_abandoned(started, now);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip_and_abandonment() {
        let now = Utc::now();
        let s = RotationState {
            by: Uuid::now_v7(),
            device: None,
            new_key_version: 3,
            started_at: now - TimeDelta::minutes(20),
        };
        let json = s.to_json();
        let back = RotationState::parse(&json).unwrap();
        assert_eq!(back.by, s.by);
        assert_eq!(back.new_key_version, 3);
        let v = view(Some(&json)).unwrap();
        assert_eq!(v.new_key_version, 3);
        assert!(!v.abandoned);
        assert!(is_abandoned(s.started_at, now));
        assert!(!is_abandoned(now - TimeDelta::minutes(5), now));
        assert!(view(Some(&serde_json::json!({"x": 1}))).unwrap().abandoned);
        assert!(view(None).is_none());
    }
}
