//! Unit tests of the backend types, `ConnectInfo` and the mock (T03).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::mock::{MockServer, conformance_env, test_context};
use super::*;
use crate::Error;
use crate::model::{
    FtpEncryption, KeySource, LocalPath, LogonType, Protocol, RemotePath, ServerAddress,
    TransferType,
};

// The whole conformance suite against MockBackend (AC2).
crate::backend_conformance_tests!(conformance_env);

fn address(protocol: Protocol) -> ServerAddress {
    ServerAddress {
        protocol,
        encryption: FtpEncryption::ExplicitIfAvailable,
        host: "example.com".into(),
        port: None,
        user: Some("alice".into()),
    }
}

#[test]
fn capabilities_none_is_all_false() {
    let c = Capabilities::NONE;
    let flags = [
        c.chmod,
        c.set_mtime,
        c.resume_download,
        c.resume_upload,
        c.append,
        c.raw_commands,
        c.symlinks,
        c.server_side_rename_across_dirs,
        c.ascii_mode,
        c.parallel_connections_allowed,
        c.positional_writes,
        c.case_insensitive_names,
    ];
    assert!(flags.iter().all(|f| !f));
    assert_eq!(c.path_style, crate::model::PathStyle::Unix);
}

#[test]
fn connect_info_validate_table() {
    let quick = ConnectInfo::quick(address(Protocol::Ftp), LogonType::Anonymous);
    assert!(quick.validate().is_ok(), "quick() defaults must be valid");
    assert_eq!(quick.label, "alice@example.com");
    assert_eq!(quick.transfer_mode, TransferModeOverride::Default);
    assert_eq!(quick.proxy, ProxyChoice::Default);

    let invalid: Vec<(&str, ConnectInfo)> = vec![
        (
            "agent over ftp",
            ConnectInfo::quick(address(Protocol::Ftp), LogonType::Agent),
        ),
        (
            "anonymous over sftp",
            ConnectInfo::quick(address(Protocol::Sftp), LogonType::Anonymous),
        ),
        (
            "unresolved vault key",
            ConnectInfo::quick(
                address(Protocol::Sftp),
                LogonType::KeyFile {
                    key: KeySource::VaultItem(uuid::Uuid::nil()),
                    passphrase: None,
                },
            ),
        ),
        ("limit 0", {
            let mut i = ConnectInfo::quick(address(Protocol::Sftp), LogonType::Agent);
            i.limit_connections = Some(0);
            i
        }),
        ("limit 11", {
            let mut i = ConnectInfo::quick(address(Protocol::Sftp), LogonType::Agent);
            i.limit_connections = Some(11);
            i
        }),
        ("offset 1441", {
            let mut i = ConnectInfo::quick(address(Protocol::Sftp), LogonType::Agent);
            i.timezone_offset_minutes = 1441;
            i
        }),
        ("offset -1441", {
            let mut i = ConnectInfo::quick(address(Protocol::Sftp), LogonType::Agent);
            i.timezone_offset_minutes = -1441;
            i
        }),
    ];
    for (what, info) in invalid {
        assert!(
            matches!(info.validate(), Err(Error::InvalidInput(_))),
            "{what} must be InvalidInput"
        );
    }

    let mut ok = ConnectInfo::quick(
        address(Protocol::Sftp),
        LogonType::KeyFile {
            key: KeySource::Path(LocalPath::new("/k")),
            passphrase: None,
        },
    );
    ok.limit_connections = Some(10);
    ok.timezone_offset_minutes = -1440;
    assert!(ok.validate().is_ok());
}

#[test]
fn connect_info_debug_redacted() {
    let mut info = ConnectInfo::quick(
        address(Protocol::Ftp),
        LogonType::Normal {
            password: Some("hunter2-login".into()),
        },
    );
    info.proxy_password = Some("hunter2-proxy".into());
    info.ftp_proxy_password = Some("hunter2-ftpproxy".into());
    let dbg = format!("{info:?}");
    assert!(!dbg.contains("hunter2"), "{dbg}");
    assert!(dbg.contains("REDACTED"), "{dbg}");
    assert!(dbg.contains("example.com"));
}

#[test]
fn transfer_opts_default_is_binary() {
    let o = TransferOpts::default();
    assert_eq!(o.transfer_type, TransferType::Binary);
    assert_eq!(o.preallocate_hint, None);
    assert_eq!(o.range_len, None);
}

#[test]
fn dyn_backend_is_object_safe() {
    let (ctx, _rx) = test_context();
    let mock = MockServer::new().backend(ctx);
    let b: Box<dyn Backend> = Box::new(mock);
    assert!(!b.is_connected());
    assert_eq!(b.security_info(), SessionSecurityInfo::default());
}

#[test]
fn listing_raw_max_is_16_mib() {
    assert_eq!(Listing::RAW_MAX, 16 * 1024 * 1024);
}

#[test]
fn listing_build_applies_hygiene() {
    use crate::model::{Entry, EntryKind};
    let entries = vec![
        Entry::new(".", EntryKind::Dir),
        Entry::new("..", EntryKind::Dir),
        Entry::new("a", EntryKind::File),
        Entry::new("a", EntryKind::Dir),
        Entry::new("x/y", EntryKind::File),
        Entry::new("b", EntryKind::File),
    ];
    let (ctx, mut rx) = test_context();
    let l = Listing::build(RemotePath::root(), entries, None, Some(&ctx.log()));
    let names: Vec<&str> = l.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["a", "b"]);
    assert_eq!(l.entries[0].kind, EntryKind::File);
    let mut lines = Vec::new();
    while let Some(ev) = rx.try_recv() {
        if let crate::events::CoreEvent::Log(m) = ev {
            lines.push(m.text);
        }
    }
    assert_eq!(lines, ["Ignored 4 entries with invalid names"]);
}

#[test]
fn listing_cap_raw_truncates_at_line_boundary() {
    let line = "x".repeat(1023) + "\n";
    let raw = line.repeat(Listing::RAW_MAX / 1024 + 10);
    let capped = Listing::cap_raw(raw);
    assert!(capped.len() <= Listing::RAW_MAX);
    assert!(capped.ends_with("x\n[truncated]"));
    assert_eq!(Listing::cap_raw("short\n".into()), "short\n");
}

#[test]
fn factory_validates_connect_info() {
    let server = MockServer::new();
    let (ctx, _rx) = test_context();
    let bad = ConnectInfo::quick(address(Protocol::Ftp), LogonType::Agent);
    let res = server.create(std::sync::Arc::new(bad), ctx.clone());
    assert!(matches!(res, Err(Error::InvalidInput(_))));
    let good = ConnectInfo::quick(address(Protocol::Sftp), LogonType::Agent);
    let b = server.create(std::sync::Arc::new(good), ctx).unwrap();
    assert_eq!(b.address().map(|a| a.host.as_str()), Some("example.com"));
}

#[tokio::test]
async fn conformance_case_runner_reports_skips_and_unknown_names() {
    use super::conformance::{CaseOutcome, run_case_outcome};
    let mut env = conformance_env();
    env.skip.push(("keepalive_ok", "server quirk"));
    assert_eq!(
        run_case_outcome("keepalive_ok", &env).await.unwrap(),
        CaseOutcome::Skipped("server quirk".into())
    );
    assert!(matches!(
        run_case_outcome("no_such_case", &env).await,
        Err(Error::InvalidInput(_))
    ));
    env.large_files = false;
    assert!(matches!(
        run_case_outcome("large_offset_resume_beyond_4gib", &env)
            .await
            .unwrap(),
        CaseOutcome::Skipped(_)
    ));
    // Capability missing → skipped, not passed.
    let mut caps = Capabilities::NONE;
    caps.parallel_connections_allowed = true;
    let server = MockServer::new().with_capabilities(caps);
    server.add_dir("/scratch");
    let env = super::conformance::ConformanceEnv {
        scratch: RemotePath::parse("/scratch").unwrap(),
        make: Box::new(move || {
            let (ctx, _rx) = test_context();
            Ok(Box::new(server.backend(ctx)) as Box<dyn Backend>)
        }),
        large_files: true,
        skip: Vec::new(),
        make_symlink: None,
    };
    for case in [
        "chmod_roundtrip",
        "append_write",
        "remove_symlink_keeps_target",
    ] {
        assert!(
            matches!(
                run_case_outcome(case, &env).await.unwrap(),
                CaseOutcome::Skipped(_)
            ),
            "{case}"
        );
    }
}

#[derive(Clone, Debug)]
enum WriteOp {
    WriteAt(u64, Vec<u8>),
    ResumeAt(u64, Vec<u8>),
    Append(Vec<u8>),
}

fn write_op() -> impl Strategy<Value = WriteOp> {
    let data = proptest::collection::vec(any::<u8>(), 0..300);
    prop_oneof![
        (0u64..200_000, data.clone()).prop_map(|(o, d)| WriteOp::WriteAt(o, d)),
        (0u64..1_000_000, data.clone()).prop_map(|(o, d)| WriteOp::ResumeAt(o, d)),
        data.prop_map(WriteOp::Append),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_mock_write_read_roundtrip(ops in proptest::collection::vec(write_op(), 1..12)) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        rt.block_on(async {
            let server = MockServer::new();
            let (ctx, _rx) = test_context();
            let mut b = server.backend(ctx);
            b.connect(CancellationToken::new()).await.unwrap();
            let path = RemotePath::parse("/home/test/f").unwrap();
            let mut model: Vec<u8> = Vec::new();
            for op in ops {
                let (mode, data) = match op {
                    WriteOp::WriteAt(o, d) => (WriteMode::WriteAt(o), d),
                    WriteOp::ResumeAt(o, d) => {
                        // Offsets past the end are InvalidInput; keep them in range.
                        let o = if model.is_empty() { 0 } else { o % (model.len() as u64 + 1) };
                        (WriteMode::ResumeAt(o), d)
                    }
                    WriteOp::Append(d) => (WriteMode::Append, d),
                };
                let mut w = b.open_write(&path, mode, &TransferOpts::default()).await.unwrap();
                w.write_all(&data).await.unwrap();
                w.shutdown().await.unwrap();
                drop(w);
                b.finish_transfer(TransferEnd::Complete).await.unwrap();
                let start = match mode {
                    WriteMode::WriteAt(o) => usize::try_from(o).unwrap(),
                    WriteMode::ResumeAt(o) => {
                        model.truncate(usize::try_from(o).unwrap());
                        model.len()
                    }
                    _ => model.len(),
                };
                // A zero-byte write never extends the file (like pwrite).
                if !data.is_empty() {
                    let end = start + data.len();
                    if model.len() < end {
                        model.resize(end, 0);
                    }
                    model[start..end].copy_from_slice(&data);
                }
            }
            let mut r = b.open_read(&path, 0, &TransferOpts::default()).await.unwrap();
            let mut back = Vec::new();
            r.read_to_end(&mut back).await.unwrap();
            drop(r);
            b.finish_transfer(TransferEnd::Complete).await.unwrap();
            assert_eq!(back.len(), model.len());
            assert!(back == model, "contents differ");
            assert_eq!(server.read_file("/home/test/f"), Some(model));
        });
    }
}
