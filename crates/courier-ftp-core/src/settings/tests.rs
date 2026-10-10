//! Unit tests of the settings model (T05).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use pretty_assertions::assert_eq;
use proptest::prelude::*;
use serde_json::{Value, json};

use super::*;
use crate::edit::{Association, EditorChoice};

fn load(v: Value) -> (Settings, Vec<SettingsWarning>) {
    Settings::from_json_lenient(&v)
}

/// Loads `v`, expects exactly one warning at `path`, returns the settings.
fn one_warning(v: Value, path: &str) -> Settings {
    let (s, w) = load(v.clone());
    assert_eq!(w.len(), 1, "{v}: {w:#?}");
    assert_eq!(w[0].path, path, "{v}: {w:#?}");
    s
}

#[test]
fn default_settings_match_registry_tables() {
    let s = Settings::default();
    // connection
    assert_eq!(s.connection.timeout_secs, 20);
    assert_eq!(s.connection.retries, 2);
    assert_eq!(s.connection.retry_delay_secs, 5);
    assert!(s.connection.keepalive);
    assert_eq!(s.connection.keepalive_interval_secs, 30);
    assert!(!s.connection.prefer_ipv6);
    assert!(s.connection.ipv6);
    // ftp
    assert_eq!(s.ftp.transfer_mode, FtpTransferMode::Passive);
    assert!(s.ftp.fallback_to_active);
    assert_eq!(s.ftp.active_external_ip, ActiveExternalIp::Auto);
    assert!(s.ftp.active_no_external_ip_on_local);
    assert_eq!(s.ftp.active_port_range, None);
    assert!(s.ftp.passive_ignore_unroutable_ip);
    assert!(s.ftp.use_mlsd);
    assert_eq!(s.ftp.send_keepalive_command, KeepaliveCommand::Noop);
    // sftp
    assert_eq!(s.sftp.max_outstanding_requests, 64);
    assert_eq!(s.sftp.request_size, 32768);
    assert!(s.sftp.use_openssh_known_hosts);
    // proxy
    assert_eq!(s.proxy.generic.kind, ProxyKind::None);
    assert_eq!(s.proxy.generic.host, "");
    assert_eq!(s.proxy.generic.port, 0);
    assert_eq!(s.proxy.generic.user, "");
    assert_eq!(s.proxy.generic.password_ref, None);
    assert_eq!(s.proxy.ftp_proxy.kind, FtpProxyKind::None);
    assert_eq!(s.proxy.ftp_proxy.host, "");
    assert_eq!(s.proxy.ftp_proxy.port, 21);
    assert_eq!(s.proxy.ftp_proxy.user, "");
    assert_eq!(s.proxy.ftp_proxy.password_ref, None);
    assert_eq!(s.proxy.ftp_proxy.custom_script, "");
    // transfers
    let t = &s.transfers;
    assert_eq!(t.max_concurrent, 4);
    assert_eq!(t.max_downloads, 0);
    assert_eq!(t.max_uploads, 0);
    assert!(!t.speed_limit_enabled);
    assert_eq!(t.download_limit_kib, 0);
    assert_eq!(t.upload_limit_kib, 0);
    assert_eq!(t.burst_tolerance, BurstTolerance::Normal);
    assert!(!t.preallocate);
    assert!(!t.preserve_timestamps);
    assert!(t.replace_invalid_chars);
    assert_eq!(t.invalid_char_replacement, '_');
    assert_eq!(t.on_exists_download, ExistsAction::Ask);
    assert_eq!(t.on_exists_upload, ExistsAction::Ask);
    assert_eq!(t.empty_dirs, EmptyDirs::Create);
    assert!(!t.follow_symlinks);
    assert!(t.segmented.enabled);
    assert_eq!(t.segmented.min_file_size_mib, 32);
    assert_eq!(t.segmented.max_segments, 4);
    assert_eq!(t.segmented.min_segment_size_mib, 8);
    // file_types
    assert_eq!(s.file_types.default_type, TransferTypeChoice::Auto);
    assert_eq!(
        s.file_types.ascii_extensions.join(" "),
        "am asp bat c cfm cgi conf cpp css dhtml diz h hpp htm html in inc java js jsp lua m4 \
         mak md5 nfo nsh nsi pas patch php phtml pl po povray py qmail rb rss sfv sh shtml sql \
         svg tcl tpl txt vbs xhtml xml"
    );
    assert!(s.file_types.dotfiles_ascii);
    assert!(s.file_types.no_extension_ascii);
    // interface
    let i = &s.interface;
    assert_eq!(i.layout, Layout::Classic);
    assert!(!i.swap_panes);
    assert!(!i.show_tree);
    assert!(i.show_log);
    assert!(i.show_queue);
    assert!(i.show_quickconnect);
    assert_eq!(i.theme, Theme::Default);
    assert_eq!(i.unicode_symbols, UnicodeSymbols::Auto);
    assert_eq!(i.key_sequence_timeout_ms, 1000);
    assert_eq!(i.enter_on_file, EnterOnFile::Transfer);
    assert_eq!(i.connect_target, ConnectTarget::Ask);
    assert_eq!(i.size_format, SizeFormat::Iec);
    assert!(i.thousands_separator);
    assert_eq!(i.date_format, "%Y-%m-%d");
    assert_eq!(i.time_format, "%H:%M");
    assert!(i.dirs_first);
    assert!(!i.sort_case_sensitive);
    assert!(i.natural_sort);
    let vis = |cols: &[ColumnSpec]| -> Vec<(Column, bool)> {
        cols.iter().map(|c| (c.column, c.visible)).collect()
    };
    assert_eq!(
        vis(&i.columns.local),
        vec![
            (Column::Name, true),
            (Column::Size, true),
            (Column::Type, true),
            (Column::Modified, true),
            (Column::Permissions, false),
            (Column::OwnerGroup, false),
        ]
    );
    assert_eq!(
        vis(&i.columns.remote),
        Column::ALL.iter().map(|c| (*c, true)).collect::<Vec<_>>()
    );
    let name_asc = SortSpec {
        column: Column::Name,
        descending: false,
    };
    assert_eq!(i.sort.local, name_asc);
    assert_eq!(i.sort.remote, name_asc);
    assert!(!i.show_hidden_local);
    assert!(!i.force_show_hidden_remote);
    assert!(i.confirm_delete);
    assert!(!i.confirm_transfer);
    assert!(!i.restore_tabs);
    assert_eq!(i.language, "auto");
    assert!(!i.show_splash);
    assert!(i.check_updates);
    assert!(!i.check_prereleases);
    // logging
    let l = &s.logging;
    assert_eq!(l.level, DebugLevel::Info);
    assert!(l.show_timestamps);
    assert!(!l.show_raw_listing);
    assert_eq!(l.pane_max_lines, 5000);
    assert!(!l.log_to_file);
    assert_eq!(l.log_file, None);
    assert_eq!(l.log_file_max_mib, 10);
    assert_eq!(l.log_file_keep, 3);
    // editing
    assert_eq!(s.editing.editor, EditorChoice::Auto);
    assert!(s.editing.associations.is_empty());
    assert!(s.editing.watch_and_prompt_upload);
    assert_eq!(s.editing.max_size_mib, 50);
    // queue
    assert_eq!(s.queue.on_complete, OnComplete::None);
    assert_eq!(s.queue.on_complete_command, "");
    assert_eq!(s.queue.notify, NotifyMethod::Bell);
    assert!(s.queue.persist);
    assert!(s.queue.refresh_remote_after);
    assert_eq!(s.queue.max_successful, 1000);
    // cache
    assert!(s.cache.listing_cache);
    assert_eq!(s.cache.listing_cache_ttl_secs, 0);
    assert_eq!(s.cache.listing_cache_max_dirs, 200);
    // vault
    assert!(s.vault.store_passwords);
    assert_eq!(s.vault.auto_lock_minutes, 15);
    assert!(s.vault.lock_on_suspend);
    assert!(!s.vault.lock_disconnects);
    assert_eq!(s.vault.argon2_cost, Argon2Preset::Standard);
    // sync
    assert!(!s.sync.history);
    assert_eq!(s.sync.push_debounce_ms, 2000);
    assert_eq!(s.sync.poll_fallback_secs, 300);

    // The defaults pass validation unchanged.
    let mut v = s.clone();
    assert!(v.validate().is_empty());
    assert_eq!(v, s);
}

/// Resolves a dotted path (`sort.local`) in the schema, following `$ref`s.
fn schema_has(schema: &Value, dotted: &str) -> bool {
    let resolve = |v: &Value| -> Value {
        match v.get("$ref").and_then(Value::as_str) {
            Some(r) => r
                .strip_prefix("#/")
                .map(|p| p.split('/').fold(schema, |v, seg| &v[seg]))
                .cloned()
                .unwrap_or(Value::Null),
            None => v.clone(),
        }
    };
    let mut node = schema.clone();
    for seg in dotted.split('.') {
        let props = resolve(&node)["properties"].clone();
        match props.get(seg) {
            Some(n) => node = n.clone(),
            None => return false,
        }
    }
    true
}

#[test]
fn settings_schema_lists_registry_keys() {
    let schema = Settings::json_schema();
    let keys = [
        "ftp.active_no_external_ip_on_local",
        "proxy.ftp_proxy.kind",
        "proxy.ftp_proxy.host",
        "proxy.ftp_proxy.port",
        "proxy.ftp_proxy.user",
        "proxy.ftp_proxy.password_ref",
        "proxy.ftp_proxy.custom_script",
        "ftp.send_keepalive_command",
        "sftp.max_outstanding_requests",
        "sftp.request_size",
        "sftp.use_openssh_known_hosts",
        "cache.listing_cache_max_dirs",
        "interface.key_sequence_timeout_ms",
        "interface.theme",
        "interface.sort.local",
        "interface.sort.remote",
        "interface.enter_on_file",
        "interface.connect_target",
        "interface.unicode_symbols",
        "logging.pane_max_lines",
        "queue.max_successful",
        "editing.editor",
        "editing.associations",
        "vault.argon2_cost",
        "vault.auto_lock_minutes",
    ];
    for key in keys {
        assert!(schema_has(&schema, key), "{key} missing from the schema");
    }
    assert!(!schema_has(&schema, "ftp.no_such_key"));
    let text = schema.to_string();
    for word in [
        "\"noop\"",
        "\"random\"",
        "\"light\"",
        "\"standard\"",
        "\"strong\"",
    ] {
        assert!(text.contains(word), "{word}");
    }
}

#[test]
fn keepalive_command_accepts_only_noop_and_random() {
    let (s, w) = load(json!({"ftp": {"send_keepalive_command": "noop"}}));
    assert!(w.is_empty());
    assert_eq!(s.ftp.send_keepalive_command, KeepaliveCommand::Noop);
    let (s, w) = load(json!({"ftp": {"send_keepalive_command": "random"}}));
    assert!(w.is_empty());
    assert_eq!(s.ftp.send_keepalive_command, KeepaliveCommand::Random);
    let s = one_warning(
        json!({"ftp": {"send_keepalive_command": "pwd"}}),
        "ftp.send_keepalive_command",
    );
    assert_eq!(s.ftp.send_keepalive_command, KeepaliveCommand::Noop);
}

#[test]
fn sftp_ranges_follow_t22() {
    for bad in [0, 257] {
        let s = one_warning(
            json!({"sftp": {"max_outstanding_requests": bad}}),
            "sftp.max_outstanding_requests",
        );
        assert_eq!(s.sftp.max_outstanding_requests, 64);
    }
    for bad in [4095, 261_121] {
        let s = one_warning(json!({"sftp": {"request_size": bad}}), "sftp.request_size");
        assert_eq!(s.sftp.request_size, 32768);
    }
    let (s, w) = load(json!({"sftp": {"max_outstanding_requests": 256, "request_size": 261_120}}));
    assert!(w.is_empty(), "{w:#?}");
    assert_eq!(s.sftp.max_outstanding_requests, 256);
    assert_eq!(s.sftp.request_size, 261_120);
}

#[test]
fn editor_choice_serde() {
    assert_eq!(
        serde_json::to_value(EditorChoice::Auto).unwrap(),
        json!("auto")
    );
    let vim = EditorChoice::Command {
        command: "vim".into(),
        terminal: true,
    };
    let vim_json = json!({"command": {"command": "vim", "terminal": true}});
    assert_eq!(serde_json::to_value(&vim).unwrap(), vim_json);
    assert_eq!(
        serde_json::from_value::<EditorChoice>(vim_json.clone()).unwrap(),
        vim
    );

    let (s, w) = load(json!({"editing": {"editor": vim_json}}));
    assert!(w.is_empty(), "{w:#?}");
    assert_eq!(s.editing.editor, vim);
    let (s, w) = load(json!({"editing": {"editor": "auto"}}));
    assert!(w.is_empty());
    assert_eq!(s.editing.editor, EditorChoice::Auto);

    let s = one_warning(json!({"editing": {"editor": "Auto"}}), "editing.editor");
    assert_eq!(s.editing.editor, EditorChoice::Auto);
    let s = one_warning(
        json!({"editing": {"editor": {"command": {"command": "", "terminal": false}}}}),
        "editing.editor",
    );
    assert_eq!(s.editing.editor, EditorChoice::Auto);
}

#[test]
fn connect_target_and_sort_keys() {
    let (s, w) = load(json!({"interface": {
        "connect_target": "new_tab",
        "sort": {"remote": {"column": "size", "descending": true}}
    }}));
    assert!(w.is_empty(), "{w:#?}");
    let mut expected = Settings::default();
    expected.interface.connect_target = ConnectTarget::NewTab;
    expected.interface.sort.remote = SortSpec {
        column: Column::Size,
        descending: true,
    };
    assert_eq!(s, expected);
}

#[test]
fn vault_auto_lock_max_1440() {
    let s = one_warning(
        json!({"vault": {"auto_lock_minutes": 1441}}),
        "vault.auto_lock_minutes",
    );
    assert_eq!(s.vault.auto_lock_minutes, 15);
    let (s, w) = load(json!({"vault": {"auto_lock_minutes": 1440, "argon2_cost": "strong"}}));
    assert!(w.is_empty());
    assert_eq!(s.vault.auto_lock_minutes, 1440);
    assert_eq!(s.vault.argon2_cost, Argon2Preset::Strong);
}

#[test]
fn empty_and_null_settings_give_defaults() {
    for v in [json!({}), Value::Null] {
        let (s, w) = load(v);
        assert_eq!(s, Settings::default());
        assert!(w.is_empty());
    }
}

#[test]
fn partial_override_changes_only_that_leaf() {
    let (s, w) = load(json!({"connection": {"timeout_secs": 30}}));
    assert!(w.is_empty());
    let mut expected = Settings::default();
    expected.connection.timeout_secs = 30;
    assert_eq!(s, expected);
}

#[test]
fn wrong_type_leaf_is_dropped_with_warning() {
    let s = one_warning(
        json!({"transfers": {"max_concurrent": "many", "max_uploads": 2}}),
        "transfers.max_concurrent",
    );
    assert_eq!(s.transfers.max_concurrent, 4);
    assert_eq!(s.transfers.max_uploads, 2);
    // An object where a scalar is expected is one invalid leaf.
    let s = one_warning(
        json!({"connection": {"timeout_secs": {"a": 1, "b": 2}}}),
        "connection.timeout_secs",
    );
    assert_eq!(s.connection.timeout_secs, 20);
    // And a scalar where a section is expected.
    let s = one_warning(json!({"ftp": 3}), "ftp");
    assert_eq!(s.ftp, FtpSettings::default());
}

/// A check that a field was reset.
type Check = dyn Fn(&Settings) -> bool;

#[test]
fn validation_table() {
    let rows: Vec<(Value, &str, Box<Check>)> = vec![
        (
            json!({"ftp": {"active_port_range": {"min": 6000, "max": 5000}}}),
            "ftp.active_port_range",
            Box::new(|s| s.ftp.active_port_range.is_none()),
        ),
        (
            json!({"ftp": {"active_port_range": {"min": 80, "max": 5000}}}),
            "ftp.active_port_range",
            Box::new(|s| s.ftp.active_port_range.is_none()),
        ),
        (
            json!({"transfers": {"max_concurrent": 0}}),
            "transfers.max_concurrent",
            Box::new(|s| s.transfers.max_concurrent == 4),
        ),
        (
            json!({"transfers": {"max_concurrent": 17}}),
            "transfers.max_concurrent",
            Box::new(|s| s.transfers.max_concurrent == 4),
        ),
        (
            json!({"transfers": {"max_downloads": 5}}),
            "transfers.max_downloads",
            Box::new(|s| s.transfers.max_downloads == 0),
        ),
        (
            json!({"connection": {"timeout_secs": 2}}),
            "connection.timeout_secs",
            Box::new(|s| s.connection.timeout_secs == 20),
        ),
        (
            json!({"transfers": {"invalid_char_replacement": "/"}}),
            "transfers.invalid_char_replacement",
            Box::new(|s| s.transfers.invalid_char_replacement == '_'),
        ),
        (
            json!({"ftp": {"active_external_ip": {"from_url": "ftp://x"}}}),
            "ftp.active_external_ip",
            Box::new(|s| s.ftp.active_external_ip == ActiveExternalIp::Auto),
        ),
        (
            json!({"ftp": {"active_external_ip": {"from_url": "https://x"}}}),
            "ftp.active_external_ip",
            Box::new(|s| s.ftp.active_external_ip == ActiveExternalIp::Auto),
        ),
        (
            json!({"ftp": {"active_external_ip": {"fixed": "not-an-ip"}}}),
            "ftp.active_external_ip",
            Box::new(|s| s.ftp.active_external_ip == ActiveExternalIp::Auto),
        ),
        (
            json!({"proxy": {
                "generic": {"kind": "socks5", "host": "proxy.example"},
                "ftp_proxy": {"kind": "site", "host": "ftpproxy.example"}
            }}),
            "proxy.ftp_proxy.kind",
            Box::new(|s| {
                s.proxy.ftp_proxy.kind == FtpProxyKind::None
                    && s.proxy.generic.kind == ProxyKind::Socks5
            }),
        ),
        (
            json!({"proxy": {"generic": {"kind": "http"}}}),
            "proxy.generic.kind",
            Box::new(|s| s.proxy.generic.kind == ProxyKind::None),
        ),
        (
            json!({"proxy": {"ftp_proxy": {"kind": "open", "host": "bad host"}}}),
            "proxy.ftp_proxy.kind",
            Box::new(|s| s.proxy.ftp_proxy.kind == FtpProxyKind::None),
        ),
        (
            json!({"proxy": {"ftp_proxy": {"port": 0}}}),
            "proxy.ftp_proxy.port",
            Box::new(|s| s.proxy.ftp_proxy.port == 21),
        ),
        (
            json!({"proxy": {"ftp_proxy": {"custom_script": "x\n".repeat(40)}}}),
            "proxy.ftp_proxy.custom_script",
            Box::new(|s| s.proxy.ftp_proxy.custom_script.is_empty()),
        ),
        (
            json!({"proxy": {"ftp_proxy": {"custom_script": "x".repeat(513)}}}),
            "proxy.ftp_proxy.custom_script",
            Box::new(|s| s.proxy.ftp_proxy.custom_script.is_empty()),
        ),
        (
            json!({"interface": {"date_format": "%Q"}}),
            "interface.date_format",
            Box::new(|s| s.interface.date_format == "%Y-%m-%d"),
        ),
        (
            json!({"interface": {"time_format": "%H:%M:%S and a much too long literal text"}}),
            "interface.time_format",
            Box::new(|s| s.interface.time_format == "%H:%M"),
        ),
        (
            json!({"interface": {"language": "not a tag"}}),
            "interface.language",
            Box::new(|s| s.interface.language == "auto"),
        ),
        (
            json!({"logging": {"log_file": "logs/session.log"}}),
            "logging.log_file",
            Box::new(|s| s.logging.log_file.is_none()),
        ),
        (
            json!({"logging": {"level": 5}}),
            "logging.level",
            Box::new(|s| s.logging.level == DebugLevel::Info),
        ),
        (
            json!({"editing": {"associations": [
                {"pattern": "*.txt", "command": "vim", "terminal": true},
                {"pattern": "", "command": "vim", "terminal": true}
            ]}}),
            "editing.associations",
            Box::new(|s| s.editing.associations.len() == 1),
        ),
        (
            json!({"editing": {"associations": [
                {"pattern": "a[", "command": "vim", "terminal": true}
            ]}}),
            "editing.associations",
            Box::new(|s| s.editing.associations.is_empty()),
        ),
        (
            json!({"queue": {"on_complete_command": "x".repeat(1025)}}),
            "queue.on_complete_command",
            Box::new(|s| s.queue.on_complete_command.is_empty()),
        ),
        (
            json!({"interface": {"columns": {"local": [{"column": "size", "visible": true}]}}}),
            "interface.columns.local",
            Box::new(|s| {
                s.interface
                    .columns
                    .local
                    .first()
                    .map(|c| (c.column, c.visible))
                    == Some((Column::Name, true))
            }),
        ),
    ];
    for (input, path, check) in rows {
        let s = one_warning(input.clone(), path);
        assert!(check(&s), "{input}: field not reset");
    }
}

#[test]
fn valid_values_are_accepted() {
    let (s, w) = load(json!({
        "ftp": {
            "active_port_range": {"min": 5000, "max": 6000},
            "active_external_ip": {"from_url": "http://ip.example/"}
        },
        "proxy": {"generic": {"kind": "socks5", "host": "proxy.example", "port": 1080}},
        "logging": {"level": 4},
        "interface": {"language": "pt-BR"}
    }));
    assert!(w.is_empty(), "{w:#?}");
    assert_eq!(
        s.ftp.active_port_range,
        Some(PortRange {
            min: 5000,
            max: 6000
        })
    );
    assert_eq!(s.logging.level, DebugLevel::Debug);
    let (s, w) = load(json!({"ftp": {"active_external_ip": {"fixed": "203.0.113.5"}}}));
    assert!(w.is_empty());
    assert_eq!(
        s.ftp.active_external_ip,
        ActiveExternalIp::Fixed(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)))
    );
}

#[test]
fn columns_dedupe_and_skip_unknown() {
    let (s, w) = load(json!({"interface": {"columns": {"remote": [
        {"column": "name", "visible": false},
        {"column": "bogus", "visible": true},
        {"column": "size", "visible": true},
        {"column": "size", "visible": false}
    ]}}}));
    let got: Vec<_> = s
        .interface
        .columns
        .remote
        .iter()
        .map(|c| (c.column, c.visible))
        .collect();
    assert_eq!(got, vec![(Column::Name, true), (Column::Size, true)]);
    assert_eq!(w.len(), 2, "{w:#?}");
    assert!(w.iter().all(|w| w.path == "interface.columns.remote"));
}

#[test]
fn unknown_key_warns() {
    let (s, w) = load(json!({"ftp": {"use_mlsd": false, "no_such": 1}, "future": {"x": 1}}));
    assert!(!s.ftp.use_mlsd);
    let paths: Vec<_> = w.iter().map(|w| w.path.as_str()).collect();
    assert_eq!(paths, vec!["ftp.no_such", "future"]);
    assert!(w.iter().all(|w| w.message.starts_with("unknown setting")));
}

#[test]
fn password_key_gets_vault_hint() {
    let (_, w) = load(json!({"proxy": {"generic": {"password": "hunter2"}, "pass": "x"}}));
    assert_eq!(w.len(), 2, "{w:#?}");
    for warning in &w {
        assert!(
            warning
                .message
                .contains("passwords are stored in the vault"),
            "{warning:?}"
        );
        assert!(!warning.message.contains("hunter2"));
        assert!(!warning.to_string().contains("hunter2"));
    }
    assert_eq!(w[0].path, "proxy.generic.password");
}

#[test]
fn ascii_extensions_are_normalised() {
    let s = one_warning(
        json!({"file_types": {"ascii_extensions": [".PHP", "php", "a b"]}}),
        "file_types.ascii_extensions",
    );
    assert_eq!(s.file_types.ascii_extensions, vec!["php".to_owned()]);
}

#[test]
fn debug_level_serialises_as_integer() {
    assert_eq!(serde_json::to_value(DebugLevel::Info).unwrap(), json!(2));
    assert_eq!(serde_json::to_value(DebugLevel::None).unwrap(), json!(0));
    assert_eq!(
        serde_json::from_value::<DebugLevel>(json!(4)).unwrap(),
        DebugLevel::Debug
    );
    assert!(serde_json::from_value::<DebugLevel>(json!(5)).is_err());
    assert!(serde_json::from_value::<DebugLevel>(json!("info")).is_err());
}

#[test]
fn enums_serialise_snake_case() {
    assert_eq!(
        serde_json::to_value(ConnectTarget::NewTab).unwrap(),
        json!("new_tab")
    );
    assert_eq!(
        serde_json::to_value(ExistsAction::OverwriteIfNewerOrSizeDiffers).unwrap(),
        json!("overwrite_if_newer_or_size_differs")
    );
    assert_eq!(
        serde_json::to_value(FtpProxyKind::UserAtHost).unwrap(),
        json!("user_at_host")
    );
    assert_eq!(
        serde_json::to_value(ActiveExternalIp::FromUrl("http://x".into())).unwrap(),
        json!({"from_url": "http://x"})
    );
}

#[test]
fn warning_display_names_the_path() {
    let s = SettingsWarning {
        path: "ftp.active_port_range".into(),
        message: "min (6000) > max (5000); using default".into(),
    };
    assert_eq!(
        s.to_string(),
        "Setting ftp.active_port_range ignored: min (6000) > max (5000); using default"
    );
    let (_, w) = load(json!({"ftp": {"active_port_range": {"min": 6000, "max": 5000}}}));
    assert_eq!(w[0], s);
}

#[test]
fn to_user_json_only_diffs() {
    assert_eq!(Settings::default().to_user_json(), json!({}));
    let mut s = Settings::default();
    s.interface.sort.remote.column = Column::Size;
    s.file_types.ascii_extensions.push("rs".into());
    s.logging.log_file = Some(PathBuf::from("/var/log/x.log"));
    let mut expected_exts = serde_json::to_value(&s.file_types.ascii_extensions).unwrap();
    let user = s.to_user_json();
    assert_eq!(
        user,
        json!({
            "interface": {"sort": {"remote": {"column": "size"}}},
            "file_types": {"ascii_extensions": expected_exts.take()},
            "logging": {"log_file": "/var/log/x.log"}
        })
    );
}

#[test]
fn json_schema_has_defaults_and_draft() {
    let schema = Settings::json_schema();
    assert_eq!(
        schema["$schema"],
        json!("https://json-schema.org/draft/2020-12/schema")
    );
    assert!(schema.to_string().contains("\"default\""));
}

// ---- settings_schema_is_current (snapshot) -----------------------------------------

fn committed_schema_path() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/settings.schema.json")
}

fn schema_text() -> String {
    let mut out = serde_json::to_string_pretty(&Settings::json_schema()).unwrap();
    out.push('\n');
    out
}

#[test]
fn settings_schema_is_current() {
    let generated = schema_text();
    if std::env::var_os("COURIER_FTP_BLESS").is_some() {
        std::fs::write(committed_schema_path(), &generated).unwrap();
    }
    let committed = std::fs::read_to_string(committed_schema_path())
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        committed == generated,
        "docs/settings.schema.json is stale; run \
         `COURIER_FTP_BLESS=1 cargo test -p courier-ftp-core settings_schema`"
    );
}

// ---- property tests ------------------------------------------------------------------

/// Random JSON trees of depth ≤ 4, with keys drawn partly from real setting names.
fn arb_json() -> impl Strategy<Value = Value> {
    let key = prop_oneof![
        Just("connection".to_owned()),
        Just("ftp".to_owned()),
        Just("transfers".to_owned()),
        Just("interface".to_owned()),
        Just("timeout_secs".to_owned()),
        Just("max_concurrent".to_owned()),
        Just("active_port_range".to_owned()),
        Just("min".to_owned()),
        Just("columns".to_owned()),
        Just("local".to_owned()),
        Just("editor".to_owned()),
        Just("editing".to_owned()),
        Just("password".to_owned()),
        "[a-z_]{1,8}",
    ];
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        (0u32..70_000).prop_map(Value::from),
        any::<f64>()
            .prop_map(|f| serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)),
        ".{0,12}".prop_map(Value::from),
    ];
    leaf.prop_recursive(4, 64, 6, move |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map(key.clone(), inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

fn arb_column() -> impl Strategy<Value = Column> {
    prop::sample::select(Column::ALL.to_vec())
}

/// Valid settings: every field varied within its range.
fn arb_settings() -> impl Strategy<Value = Settings> {
    (
        (
            5u32..=600,
            0u8..=10,
            0u32..=600,
            any::<bool>(),
            10u32..=3600,
        ),
        (
            any::<bool>(),
            prop::option::of((1024u16..=65535).prop_flat_map(|min| (Just(min), min..=65535))),
            prop_oneof![
                Just(ActiveExternalIp::Auto),
                any::<[u8; 4]>().prop_map(|o| ActiveExternalIp::Fixed(IpAddr::from(o))),
                "[a-z]{1,10}".prop_map(|h| ActiveExternalIp::FromUrl(format!("http://{h}/"))),
            ],
            prop::sample::select(vec![KeepaliveCommand::Noop, KeepaliveCommand::Random]),
        ),
        (1u32..=256, 4096u32..=261_120),
        (1u8..=16).prop_flat_map(|m| {
            (
                Just(m),
                0..=m,
                0..=m,
                prop::sample::select(vec!['_', '-', '~', '+']),
            )
        }),
        (
            prop::collection::vec("[a-z0-9]{1,6}", 0..5),
            arb_column(),
            any::<bool>(),
            prop::sample::select(vec!["%Y-%m-%d", "%d.%m.%y", "%e %b %Y"]),
            prop::sample::select(vec!["auto", "en", "pt-BR", "de-CH-1996"]),
        ),
        (
            prop::option::of("[a-z]{1,8}".prop_map(|n| std::env::temp_dir().join(n))),
            prop::sample::select(vec![
                DebugLevel::None,
                DebugLevel::Warning,
                DebugLevel::Info,
                DebugLevel::Verbose,
                DebugLevel::Debug,
            ]),
        ),
        (
            prop::option::of(("[a-z]{1,6}", any::<bool>())),
            prop::collection::vec(("\\*\\.[a-z]{1,4}", "[a-z]{1,6}", any::<bool>()), 0..3),
            0u32..=1440,
            prop::sample::select(vec![
                Argon2Preset::Light,
                Argon2Preset::Standard,
                Argon2Preset::Strong,
            ]),
        ),
    )
        .prop_map(|(conn, ftp, sftp, tr, ui, log, ed)| {
            let mut s = Settings::default();
            s.connection.timeout_secs = conn.0;
            s.connection.retries = conn.1;
            s.connection.retry_delay_secs = conn.2;
            s.connection.keepalive = conn.3;
            s.connection.keepalive_interval_secs = conn.4;
            s.ftp.use_mlsd = ftp.0;
            s.ftp.active_port_range = ftp.1.map(|(min, max)| PortRange { min, max });
            s.ftp.active_external_ip = ftp.2;
            s.ftp.send_keepalive_command = ftp.3;
            s.sftp.max_outstanding_requests = sftp.0;
            s.sftp.request_size = sftp.1;
            s.transfers.max_concurrent = tr.0;
            s.transfers.max_downloads = tr.1;
            s.transfers.max_uploads = tr.2;
            s.transfers.invalid_char_replacement = tr.3;
            let mut exts = Vec::new();
            for e in ui.0 {
                if !exts.contains(&e) {
                    exts.push(e);
                }
            }
            s.file_types.ascii_extensions = exts;
            s.interface.sort.local.column = ui.1;
            s.interface.sort.local.descending = ui.2;
            s.interface.date_format = ui.3.to_owned();
            s.interface.language = ui.4.to_owned();
            s.logging.log_file = log.0;
            s.logging.level = log.1;
            s.editing.editor = match ed.0 {
                None => EditorChoice::Auto,
                Some((command, terminal)) => EditorChoice::Command { command, terminal },
            };
            s.editing.associations =
                ed.1.into_iter()
                    .map(|(pattern, command, terminal)| Association {
                        pattern,
                        command,
                        terminal,
                    })
                    .collect();
            s.vault.auto_lock_minutes = ed.2;
            s.vault.argon2_cost = ed.3;
            s
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn prop_lenient_load_never_panics(user in arb_json()) {
        let (mut s, _) = Settings::from_json_lenient(&user);
        prop_assert_eq!(s.validate(), Vec::<SettingsWarning>::new());
        // Also under a real section name.
        let (mut s, _) = Settings::from_json_lenient(&json!({"interface": user}));
        prop_assert_eq!(s.validate(), Vec::<SettingsWarning>::new());
    }

    #[test]
    fn prop_user_json_roundtrip(s in arb_settings()) {
        let mut checked = s.clone();
        prop_assert_eq!(checked.validate(), Vec::<SettingsWarning>::new());
        let (back, w) = Settings::from_json_lenient(&s.to_user_json());
        prop_assert_eq!(w, Vec::<SettingsWarning>::new());
        prop_assert_eq!(back, s);
    }
}
