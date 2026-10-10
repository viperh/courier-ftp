//! Property tests: the fuzz bodies never panic, and Happy Eyeballs picks the first
//! attempt to succeed.

use std::{io, net::SocketAddr, time::Duration};

use proptest::prelude::*;
use tokio::time::Instant;

use super::super::{STAGGER, fuzz_http_connect_response, fuzz_socks_reply, happy_eyeballs};

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, ..ProptestConfig::default() })]

    #[test]
    fn prop_fuzz_http_connect_response_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        fuzz_http_connect_response(&data);
    }

    #[test]
    fn prop_fuzz_http_connect_response_http_like(
        text in "(HTTP/1\\.[01] |HTTP/2 |[0-9]{1,4}| |OK|\r\n|\r|\n|:|[a-z]|\u{1b}){0,40}",
        tail in proptest::collection::vec(any::<u8>(), 0..32),
    ) {
        let mut data = text.into_bytes();
        data.extend_from_slice(&tail);
        fuzz_http_connect_response(&data);
    }

    #[test]
    fn prop_fuzz_socks_reply_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        fuzz_socks_reply(&data);
    }

    #[test]
    fn prop_fuzz_socks_reply_structured(
        ver in prop_oneof![Just(0_u8), Just(1), Just(5), any::<u8>()],
        code in any::<u8>(),
        atyp in prop_oneof![Just(1_u8), Just(3), Just(4), any::<u8>()],
        rest in proptest::collection::vec(any::<u8>(), 0..40),
    ) {
        let mut data = vec![ver, code, 0, atyp];
        data.extend_from_slice(&rest);
        fuzz_socks_reply(&data);
    }
}

/// One attempt of the mock dialer: `None` hangs, else `(delay ms, success)`.
type Plan = Option<(u64, bool)>;

/// Simulates the Happy Eyeballs schedule. `Err(())` when two events coincide (the
/// real `select!` order is then random). `Ok(Some((index, finish_ms)))` is the winner.
fn simulate(plans: &[Plan]) -> Result<Option<(usize, u64)>, ()> {
    let stagger = u64::try_from(STAGGER.as_millis()).unwrap_or(250);
    let mut running: Vec<(usize, u64, bool)> = Vec::new(); // (index, finish, success)
    let start = |i: usize, at: u64, running: &mut Vec<(usize, u64, bool)>| {
        if let Some((delay, ok)) = plans[i] {
            running.push((i, at + delay, ok));
        }
    };
    start(0, 0, &mut running);
    let mut next = 1;
    let mut timer = stagger;
    loop {
        running.sort_by_key(|r| r.1);
        let first = running.first().copied();
        if let (Some(a), Some(b)) = (running.first(), running.get(1))
            && a.1 == b.1
        {
            return Err(());
        }
        let more = next < plans.len();
        match first {
            Some((_, finish, _)) if more && timer == finish => return Err(()),
            Some((_, finish, _)) if !more || finish < timer => {
                running.remove(0);
                let (i, _, ok) = first.unwrap_or((0, 0, false));
                if ok {
                    return Ok(Some((i, finish)));
                }
                if more {
                    start(next, finish, &mut running);
                    next += 1;
                    timer = finish + stagger;
                } else if running.is_empty() {
                    return Ok(None);
                }
            }
            _ if more => {
                start(next, timer, &mut running);
                next += 1;
                timer += stagger;
            }
            _ => return Ok(None),
        }
    }
}

fn addr(i: usize) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, u8::try_from(i + 1).unwrap_or(255)], 21))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn prop_happy_eyeballs_first_success_wins(
        plans in proptest::collection::vec(
            prop_oneof![
                1 => Just(None),
                4 => (0_u64..1200, any::<bool>()).prop_map(Some),
            ],
            1..6,
        ),
    ) {
        let Ok(expected) = simulate(&plans) else {
            return Err(TestCaseError::reject("coinciding events"));
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        let got = runtime.block_on(async {
            let t0 = Instant::now();
            let addrs: Vec<SocketAddr> = (0..plans.len()).map(addr).collect();
            let index_of = |a: SocketAddr| (0..plans.len()).find(|i| addr(*i) == a);
            let race = happy_eyeballs(&addrs, STAGGER, |a| {
                let plan = index_of(a).and_then(|i| plans[i]);
                async move {
                    match plan {
                        None => std::future::pending().await,
                        Some((delay, ok)) => {
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                            if ok {
                                Ok(a)
                            } else {
                                Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                            }
                        }
                    }
                }
            });
            match tokio::time::timeout(Duration::from_secs(3600), race).await {
                Ok(Ok((_, won))) => {
                    let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
                    Some((index_of(won).unwrap_or(usize::MAX), ms))
                }
                Ok(Err(_)) | Err(_) => None,
            }
        });
        prop_assert_eq!(got, expected);
    }
}
