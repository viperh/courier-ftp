# T05 — Settings model

**Phase:** A Foundation · **Depends on:** T02 · **Crates:** `courier-ftp-core` (`settings`), `courier-ftp` (`config.rs`) · **Decisions:** D10 · **FEATURES.md:** §1, §3, §5, §6, §9, §10
**Related (integrates with, not blocking):** T30, T41b, T42, T45, T88

## Goal

Typed, documented, defaulted settings for everything FileZilla puts in its
Settings dialog, loaded through the existing layered config system.

## Scope

1. In core, `pub struct Settings` with nested sections, all `#[serde(default)]` so a partial user config works:
   - **connection**: `timeout_secs` (20), `retries` (2), `retry_delay_secs` (5), `keepalive` (bool, true), `keepalive_interval_secs` (30), `prefer_ipv6` (false).
   - **ftp**: `transfer_mode` (`Passive` | `Active`), `fallback_to_active` (true), `active_external_ip` (`Auto` | `Fixed(IpAddr)` | `FromUrl(String)`), `active_port_range` (Option<(u16,u16)>), `passive_ignore_unroutable_ip` (true — use control-connection host when PASV returns a private IP), `use_mlsd` (true), `send_keepalive_command` (`NOOP`).
   - **proxy**: `generic` (`None` | `Http{host,port,user?,pass?}` | `Socks4{..}` | `Socks5{..}`), `ftp_proxy` (`None` | `UserAtHost` | `Site` | `Open` | `Custom(script)`). Proxy passwords are **not** stored here — they go into the vault (T30) and are referenced by id.
   - **transfers**: `max_concurrent` (4, see T41b), `max_downloads` (0 = unlimited within max), `max_uploads` (0), `speed_limit_enabled` (false), `download_limit_kib`, `upload_limit_kib`, `burst_tolerance` (`Normal` | `High` | `VeryHigh`), `preallocate` (false), `preserve_timestamps` (false), `replace_invalid_chars` (true), `invalid_char_replacement` ('_'), `on_exists_download` / `on_exists_upload` (default `Ask`, see T42), `empty_dirs` (create), `follow_symlinks` (false).
   - **file_types**: `default_type` (`Auto` | `Ascii` | `Binary`), `ascii_extensions` (FileZilla's default list: `am asp bat c cfm cgi conf cpp css dhtml diz h hpp htm html in inc java js jsp lua m4 mak md5 nfo nsh nsi pas patch php phtml pl po povray py qmail rb rss sfv sh shtml sql svg tcl tpl txt vbs xhtml xml`), `dotfiles_ascii` (true), `no_extension_ascii` (true).
   - **interface**: `layout` (`Classic` | `Explorer` | `Widescreen`), `swap_panes` (false), `show_tree` (false), `show_log` (true), `show_queue` (true), `size_format` (`Bytes` | `Iec` | `Si`), `thousands_separator` (true), `date_format` (strftime-like string, default ISO), `time_format`, `dirs_first` (true), `sort_case_sensitive` (false), `show_hidden_local` (false), `force_show_hidden_remote` (false — sends `LIST -a`), `confirm_delete` (true), `show_splash` (false), `check_updates` (true), `language` ("auto").
   - **logging**: `level` (0–4, default 2), `log_to_file` (false), `log_file` (path, default `<data dir>/session.log`), `log_file_max_mib` (10), `log_file_keep` (3), `show_raw_listing` (false).
   - **editing**: `editor` (`Auto` = `$VISUAL`/`$EDITOR`/platform default), `associations: Vec<{ pattern, command, terminal: bool }>`, `watch_and_prompt_upload` (true).
   - **queue**: `on_complete` (`None` | `ShowMessage` | `RunCommand(String)` | `Disconnect` | `CloseApp`), `persist` (true), `refresh_remote_after` (true).
   - **cache**: `listing_cache` (true), `listing_cache_ttl_secs` (0 = until refresh).
1b. **Enums used by settings live here** so this task doesn't depend on later ones: `ExistsAction` (used by T42), `TransferTypeChoice` (T11/T40), `OnComplete` and `NotifyMethod` (T45), `Layout`, `SizeFormat`, `BurstTolerance`.
1c. **Sections added by later tasks** (each task adds its fields to `Settings` with defaults and docs when it lands; listed here so the structure is planned once):
   - `vault`: `store_passwords` (true), `auto_lock_minutes` (15), `lock_on_suspend` (true), `lock_disconnects` (false), `argon2_cost` — T30/T60.
   - `sync`: `history` (false), `push_debounce_ms` (2000), `poll_fallback_secs` (300) — T88.
   - `transfers.segmented`: `enabled`, `min_file_size_mib`, `max_segments`, `min_segment_size_mib`; `sftp`: `max_outstanding_requests`, `request_size` — T41b.
   - `interface`: `show_quickconnect`, `restore_tabs`, `unicode_symbols`, `confirm_transfer`, `columns`, `natural_sort` — T50/T53/T57/T58/T61/T62.
   - `logging.show_timestamps` — T55; `queue.notify` — T45; `editing.max_size_mib` — T63; `interface.check_prereleases` — T74; `filters` — T47.
2. Wire into `courier-ftp/src/config.rs`: `Config` gets a `pub settings: Settings` field (`#[serde(default)]`). Defaults also written into `.config/config.json` so users can see them (keep keybindings/styles there too).
3. **Validation** after load: port ranges valid, limits non-negative, replacement char not itself invalid on the local OS. Invalid values → log warning + fall back to default for that field (do not crash).
4. **Writing settings back**: `Settings::save_user(&self, config_dir)` writes only *non-default* values into `config.json` in the user config dir (used by T68). Preserve unknown keys (load JSON as `serde_json::Value`, merge, write).
5. Remove `#![allow(dead_code)]` from `config.rs` once used.

## Acceptance criteria

- [ ] Every setting above exists with rustdoc explaining FileZilla equivalent and default.
- [ ] Empty user config ⇒ all defaults; partial user config ⇒ only those fields overridden.
- [ ] Invalid value warns and falls back without aborting startup.
- [ ] `save_user` round-trips and keeps keybindings/styles/unknown keys intact.

## Tests

- Deserialize `{}` → `Settings::default()`.
- Partial JSON overrides one nested field only.
- Port range `(5000, 4000)` → warning + default.
- `save_user` writes minimal diff; reload equals original.
