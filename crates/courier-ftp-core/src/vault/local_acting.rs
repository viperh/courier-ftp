//! Synced values that act on this machine (T91 §8, sverb §17.1).
//!
//! Some site fields make this device do something locally when it connects:
//! a local key file path, SSH agent use. A teammate or a compromised account
//! could plant them through sync, so the connect path asks before acting on
//! such a value the first time and whenever it changes; approvals are rows
//! `(item_id, field, sha256(value))` in the device-local `local_approvals`
//! table (T82). The sync engine (T88) revokes the approval of a field whose
//! value a pull changed, so the next connect asks again.

use sha2::{Digest, Sha256};

use crate::model::item::{ItemBody, ItemKind};

/// A site's local key file path (`logon.key_path`).
pub const KEY_PATH_FIELD: &str = "logon.key_path";
/// A site's logon type (value `agent`: offers the local SSH agent's keys).
pub const LOGON_TYPE_FIELD: &str = "logon.type";
/// A site's "try the SSH agent first" flag.
pub const TRY_AGENT_FIELD: &str = "try_agent_first";

/// The local-acting fields of `body` that are set to a value that acts, as
/// `(field, value)`. Values are not secrets but may be paths: log them at
/// `debug` only.
#[must_use]
pub fn local_acting_values(body: &ItemBody) -> Vec<(&'static str, String)> {
    if body.kind != ItemKind::Site || body.is_deleted() {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Some(path) = body
        .get(KEY_PATH_FIELD)
        .and_then(|v| v.as_text())
        .filter(|p| !p.trim().is_empty())
    {
        out.push((KEY_PATH_FIELD, path.to_owned()));
    }
    if body.get(LOGON_TYPE_FIELD).and_then(|v| v.as_text()) == Some("agent") {
        out.push((LOGON_TYPE_FIELD, "agent".to_owned()));
    }
    if body.get(TRY_AGENT_FIELD).and_then(|v| v.as_bool()) == Some(true) {
        out.push((TRY_AGENT_FIELD, "true".to_owned()));
    }
    out
}

/// The local-acting fields whose value differs between `before` (the local
/// copy, `None` for a new item) and `after` (what a pull stored): a value
/// that appeared, changed or went away.
#[must_use]
pub fn changed_local_acting(before: Option<&ItemBody>, after: &ItemBody) -> Vec<&'static str> {
    let old = before.map(local_acting_values).unwrap_or_default();
    let new = local_acting_values(after);
    let mut fields: Vec<&'static str> = Vec::new();
    for (f, v) in &new {
        if !old.iter().any(|(of, ov)| of == f && ov == v) {
            fields.push(f);
        }
    }
    for (f, _) in &old {
        if !new.iter().any(|(nf, _)| nf == f) && !fields.contains(f) {
            fields.push(f);
        }
    }
    fields
}

/// SHA-256 of the exact value (the approval key's third part).
#[must_use]
pub fn value_sha256(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::item::{DeviceId, HlcClock, SystemClock};

    #[test]
    fn detects_acting_values_and_changes() {
        let mut c = HlcClock::new(SystemClock);
        let d = DeviceId::new();
        let mut a = ItemBody::new(ItemKind::Site, 1);
        a.set("host", "h", &mut c, d);
        assert!(local_acting_values(&a).is_empty());
        let mut b = a.clone();
        b.set(KEY_PATH_FIELD, "/home/me/.ssh/id", &mut c, d);
        b.set(TRY_AGENT_FIELD, true, &mut c, d);
        assert_eq!(
            changed_local_acting(Some(&a), &b),
            vec![KEY_PATH_FIELD, TRY_AGENT_FIELD]
        );
        assert!(changed_local_acting(Some(&b), &b).is_empty());
        let mut e = b.clone();
        e.set(KEY_PATH_FIELD, "/tmp/other", &mut c, d);
        e.set(LOGON_TYPE_FIELD, "agent", &mut c, d);
        assert_eq!(
            changed_local_acting(Some(&b), &e),
            vec![KEY_PATH_FIELD, LOGON_TYPE_FIELD]
        );
        // Removed values count too.
        assert_eq!(
            changed_local_acting(Some(&b), &a),
            vec![KEY_PATH_FIELD, TRY_AGENT_FIELD]
        );
        assert_eq!(value_sha256("x").len(), 32);
    }
}
