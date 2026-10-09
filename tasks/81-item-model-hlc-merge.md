# T81 — Item model, HLC and merge

**Phase:** H Sync (also used by the local vault) · **Depends on:** T80 · **Crate:** `courier-ftp-core` (`model::item`) · **Decisions:** D4, D12
**Reference:** sverb `crates/sverb-core/src/model/{body,hlc,merge,migrate,kinds,ids}.rs`, `tests/merge_props.rs`.

## Goal

A generic, mergeable record format for everything stored in the vault, so two
devices editing offline converge to the same result.

## Scope

1. **IDs**: UUIDv7 newtypes `ItemId`, `VaultId`, `DeviceId`, `UserId`, `OrgId`
   (16 raw bytes in CBOR, hyphenated in JSON).
2. **Item kinds** (`ItemKind`, kebab-case):
   - `site` — one Site Manager entry (T31), including password fields.
   - `site-folder` — Site Manager folder (tree via `parent` id field).
   - `bookmark` — global or site bookmark (T33).
   - `known-host` — trusted SSH host key (T21).
   - `trusted-cert` — trusted TLS certificate (T12).
   - `ssh-key` — optional private key stored in the vault, so key-file sites work on every device (site references it by id instead of a path).
   - `proxy-credential` — proxy user/password referenced from settings.
   - `credential-override` — a member's own credentials for a site in a team vault, stored in their personal vault (T89).
   - `history-entry` — quickconnect history; synced only if `sync.history` is on (default off).
3. **ItemBody**: CBOR map `{kind, schema_version: u16, fields: BTreeMap<String, Stamped<Value>>, deleted: Option<Stamped<bool>>}`.
   - `Stamped` = `[value, hlc: u64, device: 16 bytes]`.
   - Nested structs flattened to dotted keys (`proxy.host`); lists are single values.
   - Unknown keys preserved (older clients don't drop newer fields).
   - `set` stamps a field only when the value actually changes.
   - Typed views: `Site::from_body(&ItemBody)` / `Site::apply_to(&mut ItemBody)` for each kind.
4. **HLC** (hybrid logical clock, crate `uhlc`): 64-bit NTP-style timestamp with a
   logical counter; injectable physical clock for tests; `MAX_SKEW = 5 min` — a remote
   stamp further ahead only advances the local clock up to the skew limit and returns
   a `ClockSkew` warning for the UI. Last value persisted in `meta.hlc_last`.
5. **Merge**: `merge(local, remote) -> MergeOutcome`:
   - Each field is last-writer-wins by `(hlc, device)`, with the CBOR bytes as the final tie-break.
   - Must be commutative, associative and idempotent (property tests).
   - Tombstone: item is deleted iff `deleted.value == true` and its hlc is newer than every field's hlc; a newer edit resurrects it (UI shows a toast, T90).
   - `schema_version` = max of both.
6. **Migrations**: per-kind `CURRENT_SCHEMA`; pure `fn(ItemBody) -> ItemBody` steps run on read; an item from a newer schema opens read-only ("Update courier-ftp to edit this item").
7. **Device-local fields** never go into items: last connected time, frecency, local
   paths that differ per device (`default_local_dir` is stored as a device-local
   override keyed by site id, T82 `device_local`), window/tab state.

## Acceptance criteria

- [ ] Property tests (proptest) prove merge is commutative, associative, idempotent.
- [ ] Clock-skew handling tested with an injected clock.
- [ ] Round-trip of every kind's typed view ↔ ItemBody.
- [ ] Unknown fields survive a load/save by an older schema.

## Tests

- Port sverb's `merge_props.rs` and model tests, adapted to our kinds.
