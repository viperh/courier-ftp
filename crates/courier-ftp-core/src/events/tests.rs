#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::*;
use crate::Error;
use crate::model::{Direction, Entry, EntryKind, Protocol};
use crate::secret::SecretString;
use crate::settings::{DebugLevel, ExistsAction};

fn drain(rx: &mut EventReceiver) -> Vec<CoreEvent> {
    std::iter::from_fn(|| rx.try_recv()).collect()
}

fn logs(rx: &mut EventReceiver) -> Vec<LogMessage> {
    drain(rx)
        .into_iter()
        .filter_map(|e| match e {
            CoreEvent::Log(m) => Some(m),
            _ => None,
        })
        .collect()
}

fn host_key_prompt(can_save: bool) -> PromptKind {
    PromptKind::TrustHostKey(HostKeyPrompt {
        host: "web01.example.com".into(),
        port: 22,
        key_type: "ssh-ed25519".into(),
        bits: 256,
        fingerprint_sha256: "SHA256:abc".into(),
        fingerprint_md5: "MD5:aa:bb".into(),
        changed: None,
        other_known_types: vec![],
        can_save,
    })
}

fn password_prompt() -> PromptKind {
    PromptKind::Password(PasswordPrompt {
        purpose: PasswordPurpose::Login,
        target: "alice@web01.example.com:22".into(),
        retry: false,
        attempt: 1,
        max_attempts: 3,
        cache_key: SecretCacheKey::Password {
            protocol: Protocol::Sftp,
            host: "web01.example.com".into(),
            port: 22,
            user: "alice".into(),
        },
        can_save: true,
    })
}

fn progress(id: u64, bytes_done: u64) -> TransferProgress {
    TransferProgress {
        id: TransferId(id),
        bytes_done,
        total: Some(1_000_000),
        speed_bps: 100,
        eta: Some(Duration::from_secs(1)),
    }
}

/// Spawns a task that answers the next prompt with `answer`.
fn responder(
    mut rx: EventReceiver,
    answer: impl FnOnce(&PromptRequest) -> PromptResponse + Send + 'static,
) -> tokio::task::JoinHandle<(EventReceiver, PromptId)> {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Some(CoreEvent::Prompt(req)) => {
                    let id = req.id;
                    let response = answer(&req);
                    assert!(req.respond(response));
                    return (rx, id);
                }
                Some(_) => {}
                None => panic!("senders gone"),
            }
        }
    })
}

#[test]
fn events_types_are_send_static() {
    fn assert_send_static<T: Send + 'static>() {}
    fn assert_sync<T: Sync>() {}
    assert_send_static::<SessionId>();
    assert_send_static::<TransferId>();
    assert_send_static::<OperationId>();
    assert_send_static::<PromptId>();
    assert_send_static::<LogKind>();
    assert_send_static::<LogMessage>();
    assert_send_static::<CoreEvent>();
    assert_send_static::<SessionPurpose>();
    assert_send_static::<DisconnectReason>();
    assert_send_static::<TransferProgress>();
    assert_send_static::<QueueStats>();
    assert_send_static::<NoticeLevel>();
    assert_send_static::<PromptRequest>();
    assert_send_static::<PromptKind>();
    assert_send_static::<HostKeyPrompt>();
    assert_send_static::<OldKey>();
    assert_send_static::<OldKeySource>();
    assert_send_static::<HostKeyInfo>();
    assert_send_static::<CertificateDetails>();
    assert_send_static::<CertProblem>();
    assert_send_static::<TlsSessionInfo>();
    assert_send_static::<TrustSource>();
    assert_send_static::<DataProtection>();
    assert_send_static::<CertPromptDetails>();
    assert_send_static::<PreviousCert>();
    assert_send_static::<PasswordPrompt>();
    assert_send_static::<PasswordPurpose>();
    assert_send_static::<PassphrasePrompt>();
    assert_send_static::<SecretCacheKey>();
    assert_send_static::<KbdInteractivePrompt>();
    assert_send_static::<KbdField>();
    assert_send_static::<FileExistsPrompt>();
    assert_send_static::<MessagePrompt>();
    assert_send_static::<PromptResponse>();
    assert_send_static::<TrustAnswer>();
    assert_send_static::<HostKeyAnswer>();
    assert_send_static::<ApplyTo>();
    assert_send_static::<EventSender>();
    assert_send_static::<EventReceiver>();
    assert_send_static::<SessionLog>();
    assert_send_static::<LogLevelHandle>();
    assert_sync::<EventSender>();
    assert_sync::<SessionLog>();
}

#[test]
fn log_level_filter_table() {
    let kinds = [
        LogKind::Status,
        LogKind::Command,
        LogKind::Response,
        LogKind::Error,
        LogKind::ListingRaw,
        LogKind::Debug(0),
        LogKind::Debug(1),
        LogKind::Debug(2),
        LogKind::Debug(3),
        LogKind::Debug(4),
        LogKind::Debug(9),
    ];
    for level in [
        DebugLevel::None,
        DebugLevel::Warning,
        DebugLevel::Info,
        DebugLevel::Verbose,
        DebugLevel::Debug,
    ] {
        let (tx, mut rx) = channel(level);
        assert_eq!(tx.level(), level);
        for kind in kinds {
            tx.log(SessionId::APP, kind, "x");
            let got = logs(&mut rx);
            let expected = match kind {
                LogKind::Debug(l) => l.clamp(1, 4) <= level as u8,
                _ => true,
            };
            assert_eq!(got.len(), usize::from(expected), "{level:?} {kind:?}");
            if let (true, LogKind::Debug(l)) = (expected, kind) {
                assert_eq!(got[0].kind, LogKind::Debug(l.clamp(1, 4)));
            }
            assert_eq!(
                tx.enabled(match kind {
                    LogKind::Debug(l) => l,
                    _ => 1,
                }),
                match kind {
                    LogKind::Debug(_) => expected,
                    _ => level >= DebugLevel::Warning,
                }
            );
        }
    }
    // AC3 explicitly: level 2.
    let (tx, mut rx) = channel(DebugLevel::Info);
    let log = SessionLog {
        events: tx,
        session: SessionId::APP,
    };
    for l in 1..=4 {
        log.debug(l, format!("d{l}"));
    }
    log.status("s");
    log.command("PASS x");
    log.response("r");
    log.error("e");
    log.listing("l");
    let texts: Vec<_> = logs(&mut rx).into_iter().map(|m| m.text).collect();
    assert_eq!(texts, ["d1", "d2", "s", "PASS ****", "r", "e", "l"]);
    assert!(log.enabled(2));
    assert!(!log.enabled(3));
}

#[test]
fn set_level_applies_to_clones() {
    let (tx, mut rx) = channel(DebugLevel::None);
    let clone = tx.clone();
    tx.set_level(DebugLevel::Debug);
    assert_eq!(clone.level(), DebugLevel::Debug);
    clone.log(SessionId::APP, LogKind::Debug(4), "x");
    assert_eq!(logs(&mut rx).len(), 1);
    clone.log_level().set(9);
    assert_eq!(tx.log_level().get(), 4);
    clone.log_level().set(1);
    assert_eq!(tx.level(), DebugLevel::Warning);
    assert!(!tx.enabled(2));
}

#[test]
fn multiline_text_splits_into_messages() {
    let (tx, mut rx) = channel(DebugLevel::Info);
    let session = SessionId::next();
    tx.log(session, LogKind::Response, "a\r\nb\n");
    let got = logs(&mut rx);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].text, "a");
    assert_eq!(got[1].text, "b");
    assert!(
        got.iter()
            .all(|m| m.session == session && m.kind == LogKind::Response && m.time == got[0].time)
    );
}

#[test]
fn long_line_truncated_to_4096_chars() {
    let (tx, mut rx) = channel(DebugLevel::Info);
    tx.log(SessionId::APP, LogKind::Status, "é".repeat(5000));
    let got = logs(&mut rx);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].text.chars().count(), MAX_LINE_CHARS + 1);
    assert!(got[0].text.ends_with('…'));
}

#[test]
fn log_sanitises_control_chars() {
    let (tx, mut rx) = channel(DebugLevel::Info);
    tx.log(SessionId::APP, LogKind::Response, "a\x1b[31mb\u{9b}\tc");
    assert_eq!(logs(&mut rx)[0].text, "a^[[31mb\\u{9b}\tc");
}

#[test]
fn prompt_response_debug_redacted() {
    let secret = PromptResponse::Secret {
        value: SecretString::from("hunter2"),
        remember_session: true,
        save_in_vault: false,
    };
    let dbg = format!("{secret:?}");
    assert!(!dbg.contains("hunter2"), "{dbg}");
    assert!(dbg.contains("REDACTED"));
    let answers = PromptResponse::Answers(vec![
        SecretString::from("otp-123456"),
        SecretString::from("pw-xyz"),
    ]);
    let dbg = format!("{answers:?}");
    assert!(
        !dbg.contains("otp-123456") && !dbg.contains("pw-xyz"),
        "{dbg}"
    );
    assert_eq!(
        format!("{:?}", PromptResponse::HostKey(TrustAnswer::Reject)),
        "HostKey(Reject)"
    );
}

#[tokio::test(start_paused = true)]
async fn progress_coalescing_bounds_memory() {
    let (tx, mut rx) = channel(DebugLevel::Info);
    for i in 0..10_000u64 {
        for id in [3, 1, 2] {
            tx.progress(progress(id, i * 10 + id));
        }
    }
    assert!(tx.shared_progress_len() <= 3);
    let mut got = Vec::new();
    while let Some(ev) = rx.try_recv() {
        match ev {
            CoreEvent::TransferProgress(p) => got.push(p),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(
        got,
        vec![
            progress(1, 99_990 + 1),
            progress(2, 99_990 + 2),
            progress(3, 99_990 + 3)
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn progress_comes_after_queued_events() {
    let (tx, mut rx) = channel(DebugLevel::Info);
    tx.progress(progress(1, 5));
    tx.send(CoreEvent::QueueChanged);
    assert!(matches!(rx.recv().await, Some(CoreEvent::QueueChanged)));
    assert!(matches!(
        rx.recv().await,
        Some(CoreEvent::TransferProgress(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn transfer_state_discards_stale_progress() {
    let (tx, mut rx) = channel(DebugLevel::Info);
    tx.progress(progress(1, 5));
    tx.progress(progress(2, 7));
    tx.transfer_state(TransferId(1));
    let events = drain(&mut rx);
    assert_eq!(events.len(), 2);
    assert!(matches!(
        events[0],
        CoreEvent::TransferStateChanged { id: TransferId(1) }
    ));
    assert!(matches!(&events[1], CoreEvent::TransferProgress(p) if p.id == TransferId(2)));
}

#[tokio::test(start_paused = true)]
async fn log_flood_is_bounded_and_reported() {
    let (tx, mut rx) = channel(DebugLevel::Info);
    for i in 0..20_000 {
        tx.log(SessionId::APP, LogKind::Status, format!("line {i}"));
    }
    let first = logs(&mut rx);
    assert!(first.len() <= 10_000);
    assert_eq!(first.len(), 10_000);
    assert_eq!(first[0].text, "line 0");
    assert!(
        !first.iter().any(|m| m.text.contains("dropped")),
        "notice must follow the drain"
    );
    tx.log(SessionId::APP, LogKind::Status, "after");
    tx.log(SessionId::APP, LogKind::Status, "after 2");
    let next = logs(&mut rx);
    let texts: Vec<_> = next.iter().map(|m| m.text.as_str()).collect();
    assert_eq!(
        texts,
        [
            "10000 log messages dropped (message log could not keep up)",
            "after",
            "after 2"
        ]
    );
    assert_eq!(next[0].kind, LogKind::Status);
    // Non-log events are never dropped.
    for _ in 0..10_001 {
        tx.log(SessionId::APP, LogKind::Status, "x");
    }
    tx.send(CoreEvent::QueueChanged);
    assert!(
        drain(&mut rx)
            .iter()
            .any(|e| matches!(e, CoreEvent::QueueChanged))
    );
}

#[tokio::test(start_paused = true)]
async fn prompt_roundtrip_answer() {
    let (tx, rx) = channel(DebugLevel::Info);
    let session = SessionId::next();
    let task = responder(rx, |req| {
        assert!(matches!(req.kind, PromptKind::TrustHostKey(_)));
        assert!(!req.is_withdrawn());
        PromptResponse::HostKey(TrustAnswer::AlwaysTrust)
    });
    let answer = tx.prompt(session, host_key_prompt(true)).await.unwrap();
    assert!(matches!(
        answer,
        PromptResponse::HostKey(TrustAnswer::AlwaysTrust)
    ));
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn prompt_tracked_returns_id_and_credential_accepted_event() {
    let (tx, rx) = channel(DebugLevel::Info);
    let session = SessionId::next();
    let task = responder(rx, |_| PromptResponse::Secret {
        value: SecretString::from("hunter2"),
        remember_session: true,
        save_in_vault: false,
    });
    let (id, answer) = tx
        .prompt_tracked(session, password_prompt(), None)
        .await
        .unwrap();
    let (mut rx, request_id) = task.await.unwrap();
    assert_eq!(id, request_id);
    match answer {
        PromptResponse::Secret { value, .. } => assert_eq!(value.expose(), "hunter2"),
        other => panic!("{other:?}"),
    }
    tx.credential_accepted(session, id);
    match rx.recv().await {
        Some(CoreEvent::CredentialAccepted {
            session: s,
            prompt_id,
        }) => {
            assert_eq!(s, session);
            assert_eq!(prompt_id, id);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn always_trust_without_can_save_downgraded_to_once() {
    let (tx, rx) = channel(DebugLevel::Info);
    let task = responder(rx, |_| PromptResponse::HostKey(TrustAnswer::AlwaysTrust));
    let answer = tx
        .prompt(SessionId::APP, host_key_prompt(false))
        .await
        .unwrap();
    assert!(matches!(
        answer,
        PromptResponse::HostKey(TrustAnswer::TrustOnce)
    ));
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn prompt_dropped_request_is_cancelled() {
    let (tx, mut rx) = channel(DebugLevel::Info);
    let task = tokio::spawn(async move {
        match rx.recv().await {
            Some(CoreEvent::Prompt(req)) => drop(req),
            other => panic!("{other:?}"),
        }
        rx
    });
    let err = tx
        .prompt(SessionId::APP, host_key_prompt(true))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Cancelled));
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn prompt_cancel_response_is_cancelled() {
    let (tx, rx) = channel(DebugLevel::Info);
    let task = responder(rx, |_| PromptResponse::Cancel);
    let err = tx
        .prompt(SessionId::APP, password_prompt())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Cancelled));
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn prompt_without_receiver_is_cancelled() {
    let (tx, rx) = channel(DebugLevel::Info);
    drop(rx);
    assert!(tx.is_closed());
    let err = tx
        .prompt(SessionId::APP, host_key_prompt(true))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Cancelled));
    // Sending to a closed bus is a no-op.
    tx.send(CoreEvent::QueueChanged);
    tx.log(SessionId::APP, LogKind::Status, "x");
    tx.progress(progress(1, 1));
}

#[tokio::test(start_paused = true)]
async fn receiver_dropped_with_pending_prompt_cancels_it() {
    let (tx, rx) = channel(DebugLevel::Info);
    let tx2 = tx.clone();
    let prompt =
        tokio::spawn(async move { tx2.prompt(SessionId::APP, host_key_prompt(true)).await });
    tokio::task::yield_now().await;
    drop(rx);
    assert!(matches!(prompt.await.unwrap(), Err(Error::Cancelled)));
}

#[tokio::test(start_paused = true)]
async fn prompt_with_cancel_token_fires() {
    let (tx, mut rx) = channel(DebugLevel::Info);
    let token = CancellationToken::new();
    let t2 = token.clone();
    let tx2 = tx.clone();
    let prompt = tokio::spawn(async move {
        tx2.prompt_with_cancel(SessionId::APP, host_key_prompt(true), &t2)
            .await
    });
    let Some(CoreEvent::Prompt(req)) = rx.recv().await else {
        panic!("expected a prompt");
    };
    assert!(!req.is_withdrawn());
    token.cancel();
    assert!(matches!(prompt.await.unwrap(), Err(Error::Cancelled)));
    assert!(req.is_withdrawn());
    assert!(!req.respond(PromptResponse::HostKey(TrustAnswer::TrustOnce)));
    // An already-fired token does not even send the prompt.
    let err = tx
        .prompt_with_cancel(SessionId::APP, host_key_prompt(true), &token)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Cancelled));
    assert!(rx.try_recv().is_none());
}

#[tokio::test(start_paused = true)]
async fn dropping_prompt_future_withdraws_request() {
    let (tx, mut rx) = channel(DebugLevel::Info);
    let mut fut = Box::pin(tx.prompt(SessionId::APP, host_key_prompt(true)));
    let req = tokio::select! {
        biased;
        _ = &mut fut => panic!("prompt answered without a responder"),
        ev = rx.recv() => match ev {
            Some(CoreEvent::Prompt(req)) => req,
            other => panic!("{other:?}"),
        },
    };
    assert!(!req.is_withdrawn());
    drop(fut);
    tokio::task::yield_now().await;
    assert!(req.is_withdrawn());
}

#[tokio::test(start_paused = true)]
async fn prompt_mismatched_response_is_internal_error() {
    async fn ask(kind: PromptKind, response: PromptResponse) -> crate::Result<PromptResponse> {
        let (tx, rx) = channel(DebugLevel::Info);
        let task = responder(rx, move |_| response);
        let r = tx.prompt(SessionId::APP, kind).await;
        task.await.unwrap();
        r
    }
    let entry = Entry::new("a.txt", EntryKind::File);
    let file_exists = || {
        PromptKind::FileExists(Box::new(FileExistsPrompt {
            direction: Direction::Download,
            source_path: "/a.txt".into(),
            source: entry.clone(),
            target_path: "a.txt".into(),
            target: entry.clone(),
            can_resume: false,
            suggested_name: Some("a (1).txt".into()),
        }))
    };
    let kbd = || {
        PromptKind::KeyboardInteractive(KbdInteractivePrompt {
            host: "h:22".into(),
            name: String::new(),
            instructions: String::new(),
            prompts: vec![
                KbdField {
                    text: "Password:".into(),
                    echo: false,
                },
                KbdField {
                    text: "OTP:".into(),
                    echo: true,
                },
            ],
        })
    };
    let message = || {
        PromptKind::Message(MessagePrompt {
            level: NoticeLevel::Info,
            title: "t".into(),
            text: "x".into(),
        })
    };
    let fe = |action, new_name: Option<&str>| PromptResponse::FileExists {
        action,
        apply_to: ApplyTo::Once,
        new_name: new_name.map(str::to_owned),
    };
    let internal = |r: crate::Result<PromptResponse>| matches!(r, Err(Error::Internal(_)));

    assert!(internal(
        ask(host_key_prompt(true), PromptResponse::Ack).await
    ));
    assert!(internal(
        ask(
            host_key_prompt(true),
            PromptResponse::Certificate(TrustAnswer::TrustOnce)
        )
        .await
    ));
    assert!(internal(
        ask(
            password_prompt(),
            PromptResponse::Answers(vec![SecretString::from("x")])
        )
        .await
    ));
    assert!(internal(
        ask(
            kbd(),
            PromptResponse::Answers(vec![SecretString::from("x")])
        )
        .await
    ));
    assert!(
        ask(
            kbd(),
            PromptResponse::Answers(vec![SecretString::from("x"), SecretString::from("y")])
        )
        .await
        .is_ok()
    );
    assert!(internal(
        ask(file_exists(), fe(ExistsAction::Ask, None)).await
    ));
    assert!(internal(
        ask(file_exists(), fe(ExistsAction::Rename, None)).await
    ));
    assert!(internal(
        ask(file_exists(), fe(ExistsAction::Skip, Some("b"))).await
    ));
    assert!(
        ask(file_exists(), fe(ExistsAction::Rename, Some("b")))
            .await
            .is_ok()
    );
    assert!(
        ask(file_exists(), fe(ExistsAction::Overwrite, None))
            .await
            .is_ok()
    );
    assert!(ask(message(), PromptResponse::Ack).await.is_ok());
    assert!(matches!(
        ask(message(), PromptResponse::Cancel).await,
        Err(Error::Cancelled)
    ));
}

#[tokio::test(start_paused = true)]
async fn receiver_returns_none_after_all_senders_dropped() {
    let (tx, mut rx) = channel(DebugLevel::Info);
    let tx2 = tx.clone();
    let log = SessionLog {
        events: tx.clone(),
        session: SessionId::APP,
    };
    tx.send(CoreEvent::QueueChanged);
    tx2.progress(progress(1, 1));
    drop(tx);
    drop(tx2);
    log.status("last");
    drop(log);
    assert!(matches!(rx.recv().await, Some(CoreEvent::QueueChanged)));
    assert!(matches!(rx.recv().await, Some(CoreEvent::Log(_))));
    assert!(matches!(
        rx.recv().await,
        Some(CoreEvent::TransferProgress(_))
    ));
    assert!(rx.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn recv_wakes_on_send_from_other_task() {
    let (tx, mut rx) = channel(DebugLevel::Info);
    let task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        tx.send(CoreEvent::Notice {
            level: NoticeLevel::Warning,
            text: "n".into(),
        });
    });
    assert!(matches!(rx.recv().await, Some(CoreEvent::Notice { .. })));
    task.await.unwrap();
    assert!(rx.recv().await.is_none());
}
