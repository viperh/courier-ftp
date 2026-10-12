//! `/v1/ws` notifications and multi-replica fan-out (T85).
//!
//! * `e2e_*`: the real axum upgrade on an in-process server on 127.0.0.1
//!   with a tokio-tungstenite client, accounts made over HTTP;
//! * the timing tests drive `ws::session::run` over in-memory channels on
//!   paused Tokio time (5 s auth window, 30 s heartbeat, token expiry).
//!
//! The two-replica tests run two servers on one store: the in-memory model
//! sharing a `LocalBus`, and PostgreSQL with real `LISTEN/NOTIFY`
//! (`COURIER_SERVER_PG_TEST=1` + `DATABASE_URL`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use common::client::{Account, login, new_password_material, open_and_register, reauth};
use common::sync::{new_items, push};
use common::{Server, config, generous};
use courier_ftp_proto::b64;
use courier_ftp_proto::ws::{AccessChange, ClientMsg, ServerMsg};
use courier_ftp_server::auth::store::mem::{
    MemDevice, MemMember, MemStore, MemToken, MemUser, MemVault,
};
use courier_ftp_server::auth::tokens::{ACCESS_TTL, NewToken, TokenKind};
use courier_ftp_server::auth::{AuthRuntime, AuthStore, ManualClock};
use courier_ftp_server::ws::{Bus, Frame, LocalBus, Topic};
use courier_ftp_server::{AppState, db};
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use reqwest::StatusCode;
use serde_json::json;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

// ============================================================ real sockets

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A tokio-tungstenite client on `/v1/ws`.
struct Client {
    ws: WsStream,
}

impl Client {
    async fn connect(addr: SocketAddr) -> Self {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/ws"))
            .await
            .unwrap();
        Self { ws }
    }

    async fn send(&mut self, m: &ClientMsg) {
        let _ = self
            .ws
            .send(Message::Text(serde_json::to_string(m).unwrap().into()))
            .await;
    }

    /// Connects and authenticates; returns after the first server ping
    /// (sent once the subscriptions are in place).
    async fn authed(addr: SocketAddr, token: &str) -> Self {
        let mut c = Self::connect(addr).await;
        c.send(&ClientMsg::Auth {
            token: token.to_owned(),
        })
        .await;
        assert_eq!(c.next().await, Ok(ServerMsg::Ping));
        c.send(&ClientMsg::Pong).await;
        c
    }

    /// The next message, or `Err(close code)`.
    async fn next(&mut self) -> Result<ServerMsg, u16> {
        loop {
            let m = tokio::time::timeout(Duration::from_secs(10), self.ws.next())
                .await
                .expect("no frame within 10 s");
            match m {
                Some(Ok(Message::Text(t))) => return Ok(serde_json::from_str(t.as_str()).unwrap()),
                Some(Ok(Message::Close(c))) => return Err(c.map_or(1005, |c| u16::from(c.code))),
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return Err(1006),
            }
        }
    }

    /// The next non-heartbeat message within `within`, answering pings.
    async fn notification(&mut self, within: Duration) -> ServerMsg {
        tokio::time::timeout(within, async {
            loop {
                match self.next().await.expect("socket closed") {
                    ServerMsg::Ping => self.send(&ClientMsg::Pong).await,
                    m => return m,
                }
            }
        })
        .await
        .expect("no notification in time")
    }

    /// Asserts nothing but heartbeats arrives within `d`.
    async fn quiet_for(&mut self, d: Duration) {
        let deadline = Instant::now() + d;
        loop {
            match tokio::time::timeout_at(deadline, self.ws.next()).await {
                Err(_) => return,
                Ok(Some(Ok(Message::Text(t)))) => {
                    let m: ServerMsg = serde_json::from_str(t.as_str()).unwrap();
                    assert_eq!(m, ServerMsg::Ping, "unexpected notification");
                    self.send(&ClientMsg::Pong).await;
                }
                Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
                Ok(other) => panic!("unexpected {other:?}"),
            }
        }
    }

    /// Reads until the close frame; its code.
    async fn close_code(&mut self) -> u16 {
        loop {
            match self.next().await {
                Err(code) => return code,
                Ok(ServerMsg::Ping) => self.send(&ClientMsg::Pong).await,
                Ok(_) => {}
            }
        }
    }
}

/// A push from one device reaches the user's other device within 1 s, and
/// not a stranger.
#[tokio::test]
async fn e2e_push_notifies_other_device() {
    let h = Server::mem().await;
    let a = open_and_register(&h, "alice@example.com").await;
    let other = login(&h, &a).await;
    let stranger = common::client::register(&h, "bob@example.com", "pw").await;
    let mut c = Client::authed(h.addr, &other.tokens.access_token).await;
    let mut s = Client::authed(h.addr, stranger.access()).await;
    let res = push(&h, a.access(), a.vault_id, new_items(2, 8)).await;
    assert_eq!(res.results[1].revision, Some(2));
    assert_eq!(
        c.notification(Duration::from_secs(1)).await,
        ServerMsg::VaultChanged {
            vault_id: a.vault_id,
            head_revision: 2
        }
    );
    s.quiet_for(Duration::from_millis(300)).await;
    // Client pings are answered.
    c.send(&ClientMsg::Ping).await;
    assert_eq!(
        c.notification(Duration::from_secs(1)).await,
        ServerMsg::Pong
    );
}

/// Bad or missing auth → 4401; the token is never taken from the URL.
#[tokio::test]
async fn e2e_auth_failures_close_4401() {
    let h = Server::mem().await;
    let a = open_and_register(&h, "alice@example.com").await;
    for bad in [String::new(), "garbage".into(), b64::encode(&[7; 32])] {
        let mut c = Client::connect(h.addr).await;
        c.send(&ClientMsg::Auth { token: bad }).await;
        assert_eq!(c.close_code().await, 4401);
    }
    // First message not an auth message.
    let mut c = Client::connect(h.addr).await;
    c.send(&ClientMsg::Ping).await;
    assert_eq!(c.close_code().await, 4401);
    // A token in the query string does not authenticate.
    let (mut ws, _) =
        tokio_tungstenite::connect_async(format!("ws://{}/v1/ws?token={}", h.addr, a.access()))
            .await
            .unwrap();
    ws.send(Message::Text(r#"{"type":"ping"}"#.into()))
        .await
        .unwrap();
    let mut c = Client { ws };
    assert_eq!(c.close_code().await, 4401);
    // A plain GET without upgrade is an error envelope.
    let (st, _) = h.get("/v1/ws", None).await;
    assert!(st.is_client_error(), "{st}");
}

/// Revoking a device closes its socket with 4401 at once; the other
/// device stays connected. Account deletion closes all sockets.
#[tokio::test]
async fn e2e_device_revoke_and_delete_close_4401() {
    let h = Server::mem().await;
    let a = open_and_register(&h, "alice@example.com").await;
    let b = login(&h, &a).await;
    let mut ca = Client::authed(h.addr, a.access()).await;
    let mut cb = Client::authed(h.addr, &b.tokens.access_token).await;
    let (st, _) = h
        .call(
            "DELETE",
            &format!("/v1/devices/{}", b.device_id),
            None,
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), cb.close_code())
            .await
            .unwrap(),
        4401
    );
    ca.quiet_for(Duration::from_millis(200)).await;

    let token = reauth(&h, &a, &a.password).await;
    let (st, _) = h
        .call(
            "DELETE",
            "/v1/account",
            Some(json!({ "reauth_token": token })),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), ca.close_code())
            .await
            .unwrap(),
        4401
    );
}

/// A password change sends `account_changed` to the other devices, not to
/// the device that made the change.
#[tokio::test]
async fn e2e_password_change_sends_account_changed() {
    let h = Server::mem().await;
    let a: Account = open_and_register(&h, "alice@example.com").await;
    let mut origin = Client::authed(h.addr, a.access()).await;
    // A second device; its token dies with the change, but the message is
    // delivered before the socket is revalidated.
    let b = login(&h, &a).await;
    let mut other = Client::authed(h.addr, &b.tokens.access_token).await;
    let token = reauth(&h, &a, &a.password).await;
    let (upload, bundle, _) = new_password_material(
        &h,
        ("/v1/account/password/start", json!({}), Some(a.access())),
        "registration_response",
        "new password",
        a.user_id,
        &a.keys,
        2,
    )
    .await;
    let (st, _) = h
        .post(
            "/v1/account/password",
            json!({
                "reauth_token": token,
                "registration_upload": b64::encode(&upload),
                "private_bundle_enc": b64::encode(&bundle),
                "version": 2,
            }),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        other.notification(Duration::from_secs(1)).await,
        ServerMsg::AccountChanged { key_version: 2 }
    );
    origin.quiet_for(Duration::from_millis(300)).await;
}

/// Grants, rotations and revocations reach an open socket live.
#[tokio::test]
async fn e2e_vault_access_live() {
    let h = Server::mem().await;
    let a = open_and_register(&h, "alice@example.com").await;
    let b = common::client::register(&h, "bob@example.com", "pw").await;
    let mut cb = Client::authed(h.addr, b.access()).await;
    let ws = h.state.ws();
    ws.vault_access(b.user_id, a.vault_id, AccessChange::Granted);
    assert_eq!(
        cb.notification(Duration::from_secs(1)).await,
        ServerMsg::VaultAccess {
            vault_id: a.vault_id,
            change: AccessChange::Granted
        }
    );
    push(&h, a.access(), a.vault_id, new_items(1, 8)).await;
    assert_eq!(
        cb.notification(Duration::from_secs(1)).await,
        ServerMsg::VaultChanged {
            vault_id: a.vault_id,
            head_revision: 1
        }
    );
    ws.vault_rotated(a.vault_id);
    assert_eq!(
        cb.notification(Duration::from_secs(1)).await,
        ServerMsg::VaultAccess {
            vault_id: a.vault_id,
            change: AccessChange::Rotated
        }
    );
    ws.vault_access(b.user_id, a.vault_id, AccessChange::Revoked);
    assert_eq!(
        cb.notification(Duration::from_secs(1)).await,
        ServerMsg::VaultAccess {
            vault_id: a.vault_id,
            change: AccessChange::Revoked
        }
    );
    push(&h, a.access(), a.vault_id, new_items(1, 8)).await;
    cb.quiet_for(Duration::from_millis(300)).await;
}

/// Two replicas on one in-memory store sharing a `LocalBus`: a push on A
/// reaches a socket on B within 1 s.
#[tokio::test]
async fn e2e_two_replicas_fan_out_mem() {
    common::install_crypto();
    let mem = Arc::new(MemStore::new());
    let clock = Arc::new(ManualClock::new());
    let bus: Arc<dyn Bus> = Arc::new(LocalBus::new());
    let replica = || {
        let auth = AuthRuntime::new(AuthStore::Memory(mem.clone()), clock.clone());
        AppState::with_bus(
            config(&[]),
            db::connect_lazy(common::UNREACHABLE_DB).unwrap(),
            generous(),
            auth,
            bus.clone(),
        )
    };
    let (sa, sb) = (replica(), replica());
    courier_ftp_server::serve::startup_checks(&sa)
        .await
        .unwrap();
    let h = Server::from_state(sa, common::Backend::Mem(mem.clone()), clock.clone()).await;
    let (addr_b, _task_b) = common::spawn(sb).await;
    let a = open_and_register(&h, "alice@example.com").await;
    let other = login(&h, &a).await;
    let mut cb = Client::authed(addr_b, &other.tokens.access_token).await;
    let t0 = std::time::Instant::now();
    push(&h, a.access(), a.vault_id, new_items(1, 8)).await;
    assert_eq!(
        cb.notification(Duration::from_secs(1)).await,
        ServerMsg::VaultChanged {
            vault_id: a.vault_id,
            head_revision: 1
        }
    );
    assert!(t0.elapsed() < Duration::from_secs(1));
}

/// The same on PostgreSQL with real `LISTEN/NOTIFY` between two replicas
/// (each with its own `PgBus`).
#[tokio::test]
async fn e2e_two_replicas_fan_out_pg() {
    let Some(h) = Server::pg().await else {
        eprintln!("SKIPPED (needs PostgreSQL): set COURIER_SERVER_PG_TEST=1 and DATABASE_URL");
        return;
    };
    let pool = h.pool().unwrap().clone();
    let auth = AuthRuntime::new(AuthStore::Postgres(pool.clone()), h.clock.clone());
    let sb = AppState::with_auth(config(&[]), pool, generous(), auth);
    sb.ws().ensure_started(&sb);
    h.state.ws().ensure_started(&h.state);
    let (addr_b, _task_b) = common::spawn(sb.clone()).await;
    let a = open_and_register(&h, "alice@example.com").await;
    let other = login(&h, &a).await;
    let mut cb = Client::authed(addr_b, &other.tokens.access_token).await;
    // Both listeners must be up before the push.
    for _ in 0..100 {
        if h.state.readiness().degraded().is_empty() && sb.readiness().degraded().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let t0 = std::time::Instant::now();
    push(&h, a.access(), a.vault_id, new_items(1, 8)).await;
    assert_eq!(
        cb.notification(Duration::from_secs(1)).await,
        ServerMsg::VaultChanged {
            vault_id: a.vault_id,
            head_revision: 1
        }
    );
    assert!(t0.elapsed() < Duration::from_secs(1));
    drop(cb);
    h.cleanup().await;
}

// ===================================================== paused-time session

/// One "database" (memory model + clock) and a replica on it.
struct Env {
    mem: Arc<MemStore>,
    clock: Arc<ManualClock>,
    state: AppState,
}

#[derive(Clone)]
struct TUser {
    id: Uuid,
    vault: Uuid,
    token: String,
}

impl Env {
    fn new() -> Self {
        let mem = Arc::new(MemStore::new());
        let clock = Arc::new(ManualClock::new());
        let auth = AuthRuntime::new(AuthStore::Memory(mem.clone()), clock.clone());
        let state = AppState::with_bus(
            config(&[]),
            db::connect_lazy(common::UNREACHABLE_DB).unwrap(),
            generous(),
            auth,
            Arc::new(LocalBus::new()),
        );
        Self { mem, clock, state }
    }

    fn now(&self) -> chrono::DateTime<Utc> {
        use courier_ftp_server::auth::Clock;
        self.clock.now()
    }

    /// A user with one device, an access token and a personal vault.
    fn user(&self) -> TUser {
        let user_id = Uuid::now_v7();
        let vault = Uuid::now_v7();
        let now = self.now();
        self.mem.with_data(|d| {
            d.users.insert(
                user_id,
                MemUser {
                    email: format!("{user_id}@example.com"),
                    created_at: now,
                    is_instance_admin: false,
                    opaque_record: vec![0],
                    totp_secret_enc: None,
                    totp_pending_enc: None,
                    totp_last_step: None,
                    disabled: false,
                },
            );
            d.vaults
                .insert(vault, MemVault::personal(user_id, vec![1], 1));
            d.vault_members.push(MemMember {
                vault_id: vault,
                user_id,
                permission: "manage".into(),
                key_version: 1,
                wrapped_vault_key: vec![2],
                wrapped_by: user_id,
                signature: vec![3; 64],
            });
        });
        let device_id = Uuid::now_v7();
        let tok = NewToken::generate();
        self.mem.with_data(|d| {
            d.devices.insert(
                device_id,
                MemDevice {
                    user_id,
                    name: "laptop".into(),
                    platform: "linux".into(),
                    created_at: now,
                    last_seen_at: None,
                    revoked_at: None,
                },
            );
            d.tokens.insert(
                tok.hash,
                MemToken {
                    device_id,
                    kind: TokenKind::Access,
                    expires_at: now + ACCESS_TTL,
                    family: Uuid::now_v7(),
                    used_at: None,
                },
            );
        });
        TUser {
            id: user_id,
            vault,
            token: tok.wire.to_string(),
        }
    }
}

/// A socket on the in-memory transport.
struct Sock {
    tx: mpsc::UnboundedSender<Frame>,
    rx: mpsc::UnboundedReceiver<Frame>,
    _task: JoinHandle<()>,
}

impl Sock {
    fn open(state: &AppState) -> Self {
        let (tx, srv_in) = mpsc::unbounded();
        let (srv_out, rx) = mpsc::unbounded();
        let task = tokio::spawn(courier_ftp_server::ws::session::run(
            state.clone(),
            srv_in,
            srv_out,
        ));
        Self {
            tx,
            rx,
            _task: task,
        }
    }

    async fn send(&mut self, m: &ClientMsg) {
        let _ = self
            .tx
            .send(Frame::Text(serde_json::to_string(m).unwrap()))
            .await;
    }

    async fn authed(state: &AppState, token: &str) -> Self {
        let mut s = Self::open(state);
        s.send(&ClientMsg::Auth {
            token: token.to_owned(),
        })
        .await;
        assert_eq!(s.next_msg().await, Some(ServerMsg::Ping));
        s.send(&ClientMsg::Pong).await;
        s
    }

    async fn frame(&mut self) -> Option<Frame> {
        tokio::time::timeout(Duration::from_secs(3600), self.rx.next())
            .await
            .expect("no frame within an hour")
    }

    async fn next_msg(&mut self) -> Option<ServerMsg> {
        match self.frame().await? {
            Frame::Text(t) => Some(serde_json::from_str(&t).unwrap()),
            other => panic!("expected a message, got {other:?}"),
        }
    }

    /// Reads until the close frame (answering pings when `pong`); returns
    /// its code and how many pings came before it.
    async fn close_code(&mut self, pong: bool) -> (u16, u32) {
        let mut pings = 0;
        loop {
            match self.frame().await.expect("ended without a close frame") {
                Frame::Close { code, .. } => return (code, pings),
                Frame::Text(t) => {
                    if serde_json::from_str::<ServerMsg>(&t).unwrap() == ServerMsg::Ping {
                        pings += 1;
                        if pong {
                            self.send(&ClientMsg::Pong).await;
                        }
                    }
                }
                Frame::Other => {}
            }
        }
    }
}

/// No auth message within 5 s → 4401 at exactly 5 s; just in time works.
#[tokio::test(start_paused = true)]
async fn no_auth_within_5s_closes_4401() {
    let env = Env::new();
    let t0 = Instant::now();
    let mut s = Sock::open(&env.state);
    assert_eq!(s.close_code(false).await.0, 4401);
    assert_eq!(t0.elapsed(), Duration::from_secs(5));

    let u = env.user();
    let mut s = Sock::open(&env.state);
    tokio::time::sleep(Duration::from_millis(4900)).await;
    s.send(&ClientMsg::Auth { token: u.token }).await;
    assert_eq!(s.next_msg().await, Some(ServerMsg::Ping));
}

/// A valid token subscribes the user and vault topics; an expired one is
/// refused.
#[tokio::test(start_paused = true)]
async fn token_validation_and_subscriptions() {
    let env = Env::new();
    let u = env.user();
    let _s = Sock::authed(&env.state, &u.token).await;
    let hub = env.state.ws().hub();
    assert_eq!(hub.subscribers(Topic::User(u.id)), 1);
    assert_eq!(hub.subscribers(Topic::Vault(u.vault)), 1);
    env.clock.advance(ACCESS_TTL);
    let mut s = Sock::open(&env.state);
    s.send(&ClientMsg::Auth { token: u.token }).await;
    assert_eq!(s.close_code(false).await.0, 4401);
}

/// The access token expires → 4401 at expiry, not before.
#[tokio::test(start_paused = true)]
async fn token_expiry_closes_4401() {
    let env = Env::new();
    let u = env.user();
    let t0 = Instant::now();
    let mut s = Sock::authed(&env.state, &u.token).await;
    let (code, pings) = s.close_code(true).await;
    assert_eq!(code, 4401);
    let left = ACCESS_TTL.to_std().unwrap();
    let elapsed = t0.elapsed();
    assert!(
        elapsed >= left && elapsed < left + Duration::from_secs(1),
        "{elapsed:?}"
    );
    assert!(pings >= 28, "{pings} pings");
}

/// Pings every 30 s; 2 missed pongs → 4408, 60 s after the first ping.
#[tokio::test(start_paused = true)]
async fn missed_pongs_close_4408() {
    let env = Env::new();
    let u = env.user();
    let mut s = Sock::open(&env.state);
    s.send(&ClientMsg::Auth { token: u.token }).await;
    let t0 = Instant::now();
    let (code, pings) = s.close_code(false).await;
    assert_eq!(code, 4408);
    assert_eq!(t0.elapsed(), Duration::from_secs(60));
    assert_eq!(pings, 2);
}

/// Tokens deleted behind the bus' back close the socket at the next
/// heartbeat.
#[tokio::test(start_paused = true)]
async fn revalidation_on_heartbeat_closes_4401() {
    let env = Env::new();
    let u = env.user();
    let mut s = Sock::authed(&env.state, &u.token).await;
    let t0 = Instant::now();
    env.mem.with_data(|d| d.tokens.clear());
    assert_eq!(s.close_code(true).await.0, 4401);
    assert!(t0.elapsed() <= Duration::from_secs(30));
}
