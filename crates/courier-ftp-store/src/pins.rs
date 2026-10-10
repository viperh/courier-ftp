//! The `pinned_keys` table: TOFU pins of account public keys (T89).
//!
//! Every org member's keys (and this account's own keys, `is_self`) are pinned
//! the first time this device sees them. A later, different key never replaces
//! the pin silently: [`WriteTx::observe_pin`] parks it as a pending
//! [`KeyChange`], clears the `verified` flag, and the pin's [`PinTrust`] becomes
//! [`PinTrust::KeyChanged`] until the user compares safety numbers and accepts
//! the new key ([`WriteTx::accept_key_change`]).
//!
//! Pins are a per-device trust decision. They are never synced: rows are not
//! items, have no envelope and never enter the outbox, so a malicious server
//! cannot poison them through sync. The `label` is the server's display name
//! for the user (an email); it is untrusted and only used to find a pin by name.

use rusqlite::{Connection, OptionalExtension, params};

use courier_ftp_crypto::fingerprint::{key_fingerprint, safety_number};

use crate::Id16;
use crate::db::{ReadTx, Store, WriteTx};
use crate::error::{Result, StoreError, id16};

/// A key seen for a pinned user that differs from the pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChange {
    /// Fingerprint of the new keys (`key_fingerprint(x25519, ed25519)`).
    pub fingerprint: [u8; 32],
    /// The new X25519 public key.
    pub x25519_pub: [u8; 32],
    /// The new Ed25519 public key.
    pub ed25519_pub: [u8; 32],
    /// When it was (last) seen (Unix ms).
    pub seen_at: i64,
}

/// One row of `pinned_keys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedKey {
    /// The user (the server's account UUID).
    pub user_id: Id16,
    /// The server's display name (email), untrusted.
    pub label: Option<String>,
    /// `key_fingerprint(x25519_pub, ed25519_pub)` of the pinned keys.
    pub fingerprint: [u8; 32],
    /// The pinned X25519 public key.
    pub x25519_pub: [u8; 32],
    /// The pinned Ed25519 public key.
    pub ed25519_pub: [u8; 32],
    /// When the keys were first seen (Unix ms).
    pub first_seen_at: i64,
    /// The user compared safety numbers out of band and confirmed.
    pub verified: bool,
    /// When `verified` was set (Unix ms).
    pub verified_at: Option<i64>,
    /// This is the device's own account.
    pub is_self: bool,
    /// A different key seen after the pin, not accepted yet.
    pub changed: Option<KeyChange>,
}

/// The trust state of a pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinTrust {
    /// Pinned on first sight, not compared out of band.
    Pinned,
    /// Pinned and verified by safety number.
    Verified,
    /// A different key was seen: warn, block grants to and from this user.
    KeyChanged,
}

impl PinnedKey {
    /// The pin's trust state.
    #[must_use]
    pub const fn trust(&self) -> PinTrust {
        if self.changed.is_some() {
            PinTrust::KeyChanged
        } else if self.verified {
            PinTrust::Verified
        } else {
            PinTrust::Pinned
        }
    }

    /// The fingerprint a safety number for this user is computed from: the
    /// pending new keys while a change is pending (the user compares them
    /// before accepting), else the pinned keys.
    #[must_use]
    pub fn current_fingerprint(&self) -> [u8; 32] {
        self.changed
            .as_ref()
            .map_or(self.fingerprint, |c| c.fingerprint)
    }

    /// The safety number between this pin and `other` (symmetric), from
    /// their [`PinnedKey::current_fingerprint`]s.
    #[must_use]
    pub fn safety_number_with(&self, other: &Self) -> String {
        safety_number(&self.current_fingerprint(), &other.current_fingerprint())
    }
}

/// Parses a user id written as a UUID (`8-4-4-4-12` hex, or 32 hex digits).
#[must_use]
pub fn parse_user_id(text: &str) -> Option<Id16> {
    let hex: Vec<u8> = text.bytes().filter(|b| *b != b'-').collect();
    if hex.len() != 32 || text.len() > 36 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in hex.chunks(2).enumerate() {
        let s = std::str::from_utf8(pair).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// The pin named `query`: a user id, an exact label (email, case-insensitive)
/// or a unique email local part (`bob` for `bob@example.com`). The error is a
/// user-facing message.
///
/// # Errors
/// When nothing or several pins match.
pub fn find_pin<'a>(
    pins: &'a [PinnedKey],
    query: &str,
) -> std::result::Result<&'a PinnedKey, String> {
    let q = query.trim();
    if let Some(id) = parse_user_id(q) {
        return pins
            .iter()
            .find(|p| p.user_id == id)
            .ok_or_else(|| format!("no pinned key for user {q}"));
    }
    let ql = q.to_lowercase();
    let label = |p: &PinnedKey| p.label.as_deref().unwrap_or_default().to_lowercase();
    if let Some(p) = pins.iter().find(|p| label(p) == ql) {
        return Ok(p);
    }
    let matches: Vec<&PinnedKey> = pins
        .iter()
        .filter(|p| label(p).split('@').next() == Some(ql.as_str()))
        .collect();
    match matches.as_slice() {
        [one] => Ok(one),
        [] => Err(format!(
            "no known team member matches \"{q}\" (members are pinned when first seen)"
        )),
        _ => Err(format!(
            "\"{q}\" matches several members; use the full email or user id"
        )),
    }
}

/// Keys the server presented for a user ([`WriteTx::observe_pin`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinObservation {
    /// The user.
    pub user_id: Id16,
    /// The server's display name; updated when given.
    pub label: Option<String>,
    /// The presented X25519 public key.
    pub x25519_pub: [u8; 32],
    /// The presented Ed25519 public key.
    pub ed25519_pub: [u8; 32],
    /// This device's own account (recorded only when the pin is created).
    pub is_self: bool,
}

/// What [`WriteTx::observe_pin`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinState {
    /// No pin existed: the keys are now pinned, unverified.
    FirstSeen,
    /// The keys equal the pin.
    Unchanged,
    /// The keys differ from the pin: recorded as a pending change.
    Changed {
        /// The pinned fingerprint.
        pinned: [u8; 32],
        /// The fingerprint just seen.
        seen: [u8; 32],
    },
}

/// The verification flag to set ([`WriteTx::set_verified`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetVerified {
    /// The user confirmed the safety number.
    Verified,
    /// Clear the flag.
    Unverified,
}

/// What [`WriteTx::set_verified`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The flag was written.
    Set,
    /// There is no pin for this user.
    NoPin,
    /// A key change is pending: nothing was written (accept the new key
    /// instead).
    KeyChangePending,
}

const COLS: &str = "user_id, label, fingerprint, x25519_pub, ed25519_pub, first_seen_at, \
                    verified, verified_at, is_self, changed_fingerprint, changed_x25519_pub, \
                    changed_ed25519_pub, changed_at";

/// The `changed_*` columns: fingerprint, X25519, Ed25519, seen at.
type RawChange = (
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
);

struct Raw {
    user_id: Vec<u8>,
    label: Option<String>,
    fingerprint: Vec<u8>,
    x25519_pub: Vec<u8>,
    ed25519_pub: Vec<u8>,
    first_seen_at: i64,
    verified: bool,
    verified_at: Option<i64>,
    is_self: bool,
    changed: RawChange,
}

fn raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<Raw> {
    Ok(Raw {
        user_id: r.get(0)?,
        label: r.get(1)?,
        fingerprint: r.get(2)?,
        x25519_pub: r.get(3)?,
        ed25519_pub: r.get(4)?,
        first_seen_at: r.get(5)?,
        verified: r.get(6)?,
        verified_at: r.get(7)?,
        is_self: r.get(8)?,
        changed: (r.get(9)?, r.get(10)?, r.get(11)?, r.get(12)?),
    })
}

fn key32(bytes: Vec<u8>, what: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt(format!("pinned_keys.{what} is not 32 bytes")))
}

fn decode(r: Raw) -> Result<PinnedKey> {
    let changed = match r.changed {
        (Some(f), Some(x), Some(e), Some(at)) => Some(KeyChange {
            fingerprint: key32(f, "changed_fingerprint")?,
            x25519_pub: key32(x, "changed_x25519_pub")?,
            ed25519_pub: key32(e, "changed_ed25519_pub")?,
            seen_at: at,
        }),
        (None, None, None, None) => None,
        _ => {
            return Err(StoreError::Corrupt(
                "pinned_keys.changed_* columns are partially set".into(),
            ));
        }
    };
    Ok(PinnedKey {
        user_id: id16(r.user_id, "pinned_keys.user_id")?,
        label: r.label,
        fingerprint: key32(r.fingerprint, "fingerprint")?,
        x25519_pub: key32(r.x25519_pub, "x25519_pub")?,
        ed25519_pub: key32(r.ed25519_pub, "ed25519_pub")?,
        first_seen_at: r.first_seen_at,
        verified: r.verified,
        verified_at: r.verified_at,
        is_self: r.is_self,
        changed,
    })
}

fn get_on(conn: &Connection, user: &Id16) -> Result<Option<PinnedKey>> {
    let found = conn
        .prepare_cached(&format!(
            "SELECT {COLS} FROM pinned_keys WHERE user_id = ?1"
        ))?
        .query_row(params![&user[..]], raw)
        .optional()?;
    found.map(decode).transpose()
}

impl ReadTx<'_> {
    /// The pin of `user`.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an undecodable row (including partially set
    /// `changed_*` columns), or a SQLite error.
    pub fn get_pin(&self, user: Id16) -> Result<Option<PinnedKey>> {
        get_on(self.conn, &user)
    }

    /// Every pin: this account first, then by label.
    ///
    /// # Errors
    /// As [`ReadTx::get_pin`].
    pub fn list_pins(&self) -> Result<Vec<PinnedKey>> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT {COLS} FROM pinned_keys ORDER BY is_self DESC, label, user_id"
        ))?;
        let raws = stmt
            .query_map([], raw)?
            .collect::<rusqlite::Result<Vec<Raw>>>()?;
        raws.into_iter().map(decode).collect()
    }
}

impl WriteTx<'_> {
    /// Records that the server presented keys for a user (TOFU):
    /// - no pin yet → pins them unverified ([`PinState::FirstSeen`]);
    /// - equal to the pin → [`PinState::Unchanged`] (a pending change, if any,
    ///   stays pending: the server presented two different keys);
    /// - different → stores them as the pending change and clears `verified`
    ///   ([`PinState::Changed`]). The pin itself is never replaced here.
    ///
    /// # Errors
    /// As [`ReadTx::get_pin`].
    pub fn observe_pin(&self, obs: &PinObservation) -> Result<PinState> {
        let user = &obs.user_id[..];
        let seen = key_fingerprint(&obs.x25519_pub, &obs.ed25519_pub);
        let Some(pin) = get_on(self.conn, &obs.user_id)? else {
            self.conn.execute(
                "INSERT INTO pinned_keys (user_id, label, fingerprint, x25519_pub, ed25519_pub,
                                          first_seen_at, verified, is_self)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)",
                params![
                    user,
                    obs.label,
                    &seen[..],
                    &obs.x25519_pub[..],
                    &obs.ed25519_pub[..],
                    self.now,
                    obs.is_self
                ],
            )?;
            return Ok(PinState::FirstSeen);
        };
        if let Some(l) = obs.label.as_deref()
            && pin.label.as_deref() != Some(l)
        {
            self.conn.execute(
                "UPDATE pinned_keys SET label = ?2 WHERE user_id = ?1",
                params![user, l],
            )?;
        }
        if seen == pin.fingerprint {
            return Ok(PinState::Unchanged);
        }
        self.conn.execute(
            "UPDATE pinned_keys SET verified = 0, verified_at = NULL,
                    changed_fingerprint = ?2, changed_x25519_pub = ?3,
                    changed_ed25519_pub = ?4, changed_at = ?5
             WHERE user_id = ?1",
            params![
                user,
                &seen[..],
                &obs.x25519_pub[..],
                &obs.ed25519_pub[..],
                self.now
            ],
        )?;
        tracing::debug!("pinned key change recorded");
        Ok(PinState::Changed {
            pinned: pin.fingerprint,
            seen,
        })
    }

    /// Sets or clears the `verified` flag (and `verified_at`) of the pin of
    /// `user`. Setting it is refused while a key change is pending
    /// ([`VerifyOutcome::KeyChangePending`]): the new key must be accepted with
    /// [`WriteTx::accept_key_change`] first.
    ///
    /// # Errors
    /// As [`ReadTx::get_pin`].
    pub fn set_verified(&self, user: Id16, flag: SetVerified) -> Result<VerifyOutcome> {
        let Some(pin) = get_on(self.conn, &user)? else {
            return Ok(VerifyOutcome::NoPin);
        };
        let verified = flag == SetVerified::Verified;
        if pin.changed.is_some() && verified {
            return Ok(VerifyOutcome::KeyChangePending);
        }
        let at = verified.then_some(self.now);
        self.conn.execute(
            "UPDATE pinned_keys SET verified = ?2, verified_at = ?3 WHERE user_id = ?1",
            params![&user[..], verified, at],
        )?;
        Ok(VerifyOutcome::Set)
    }

    /// Replaces the pin of `user` by the pending changed key ("Accept new
    /// key"). The new pin is unverified and `first_seen_at` restarts at now;
    /// the user verifies it separately with [`WriteTx::set_verified`]. Returns
    /// whether a change was pending.
    ///
    /// # Errors
    /// As [`ReadTx::get_pin`].
    pub fn accept_key_change(&self, user: Id16) -> Result<bool> {
        let Some(pin) = get_on(self.conn, &user)? else {
            return Ok(false);
        };
        let Some(c) = pin.changed else {
            return Ok(false);
        };
        self.conn.execute(
            "UPDATE pinned_keys SET fingerprint = ?2, x25519_pub = ?3, ed25519_pub = ?4,
                    first_seen_at = ?5, verified = 0, verified_at = NULL,
                    changed_fingerprint = NULL, changed_x25519_pub = NULL,
                    changed_ed25519_pub = NULL, changed_at = NULL
             WHERE user_id = ?1",
            params![
                &user[..],
                &c.fingerprint[..],
                &c.x25519_pub[..],
                &c.ed25519_pub[..],
                self.now
            ],
        )?;
        Ok(true)
    }

    /// Forgets the pin of `user` (the next sight pins again). Returns whether a
    /// row existed.
    ///
    /// # Errors
    /// A SQLite error.
    pub fn delete_pin(&self, user: Id16) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM pinned_keys WHERE user_id = ?1",
            params![&user[..]],
        )?;
        Ok(n > 0)
    }
}

impl Store {
    /// See [`ReadTx::get_pin`].
    ///
    /// # Errors
    /// As [`ReadTx::get_pin`].
    pub async fn get_pin(&self, user: Id16) -> Result<Option<PinnedKey>> {
        self.read(move |r| r.get_pin(user)).await
    }

    /// See [`ReadTx::list_pins`].
    ///
    /// # Errors
    /// As [`ReadTx::list_pins`].
    pub async fn list_pins(&self) -> Result<Vec<PinnedKey>> {
        self.read(|r| r.list_pins()).await
    }

    /// See [`WriteTx::observe_pin`].
    ///
    /// # Errors
    /// As [`WriteTx::observe_pin`].
    pub async fn observe_pin(&self, obs: PinObservation) -> Result<PinState> {
        self.write(move |w| w.observe_pin(&obs)).await
    }

    /// See [`WriteTx::set_verified`].
    ///
    /// # Errors
    /// As [`WriteTx::set_verified`].
    pub async fn set_verified(&self, user: Id16, flag: SetVerified) -> Result<VerifyOutcome> {
        self.write(move |w| w.set_verified(user, flag)).await
    }

    /// See [`WriteTx::accept_key_change`].
    ///
    /// # Errors
    /// As [`WriteTx::accept_key_change`].
    pub async fn accept_key_change(&self, user: Id16) -> Result<bool> {
        self.write(move |w| w.accept_key_change(user)).await
    }

    /// See [`WriteTx::delete_pin`].
    ///
    /// # Errors
    /// As [`WriteTx::delete_pin`].
    pub async fn delete_pin(&self, user: Id16) -> Result<bool> {
        self.write(move |w| w.delete_pin(user)).await
    }
}
