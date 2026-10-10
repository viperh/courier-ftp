#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;

use super::*;

fn parser() -> ReplyParser {
    ReplyParser::new(LineDecoder::new(Charset::Auto))
}

fn parse(bytes: &[u8]) -> Result<Vec<Reply>, ReplyError> {
    parser().push(bytes)
}

fn one(text: &str) -> Reply {
    let mut r = parse(text.as_bytes()).unwrap();
    assert_eq!(r.len(), 1, "{text:?} → {r:?}");
    r.remove(0)
}

#[test]
fn reply_single_line_parses_code_and_text() {
    let r = one("220 Ready\r\n");
    assert_eq!(r.code(), 220);
    assert_eq!(r.text(), "Ready");
    assert_eq!(r.lines, ["220 Ready"]);
    assert!(r.is_ok() && !r.is_preliminary() && !r.is_intermediate());
    assert_eq!(r.class(), ReplyClass::Completion);
    assert!(one("150 x\r\n").is_preliminary());
    assert!(one("331 x\r\n").is_intermediate());
    assert!(one("421 x\r\n").is_transient_err());
    assert!(one("530 x\r\n").is_permanent_err());
}

#[test]
fn reply_multiline_rfc959_example() {
    let r = one(
        "123-First line\r\nSecond line\r\n  234 A line beginning with numbers\r\n234 A line beginning with numbers\r\n123 The last line\r\n",
    );
    assert_eq!(r.code(), 123);
    assert_eq!(r.lines.len(), 5);
    assert_eq!(
        r.text(),
        "First line\nSecond line\n  234 A line beginning with numbers\n234 A line beginning with numbers\nThe last line"
    );
    // The exact RFC example: four lines.
    let r = one(
        "123-First line\r\nSecond line\r\n234 A line beginning with numbers\r\n123 The last line\r\n",
    );
    assert_eq!(r.lines.len(), 4);
}

#[test]
fn reply_multiline_proftpd_prefixed_lines() {
    let r = one("211-Features:\r\n211-MDTM\r\n211-SIZE\r\n211 End\r\n");
    assert_eq!(r.code(), 211);
    assert_eq!(r.lines.len(), 4);
    assert_eq!(r.text(), "Features:\nMDTM\nSIZE\nEnd");
}

#[test]
fn reply_multiline_indented_continuation() {
    let r = one("230-Welcome\r\n  to the server\r\n\r\n230 Logged in\r\n");
    assert_eq!(r.lines.len(), 4);
    assert_eq!(r.text(), "Welcome\n  to the server\n\nLogged in");
}

#[test]
fn reply_bare_code_terminates() {
    let r = one("220-Hello\r\n220\r\n");
    assert_eq!(r.lines, ["220-Hello", "220"]);
    assert_eq!(r.text(), "Hello\n");
    let single = one("200\r\n");
    assert_eq!(single.text(), "");
}

#[test]
fn reply_lf_only_line_endings() {
    let r = parse(b"220-a\nb\n220 c\n200 OK\n").unwrap();
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].lines, ["220-a", "b", "220 c"]);
    assert_eq!(r[1].text(), "OK");
}

#[test]
fn reply_first_line_without_code_is_malformed() {
    for bad in [
        "hello\r\n",
        "22 short\r\n",
        "620 protected\r\n",
        "220xNo separator\r\n",
        "\r\n",
    ] {
        assert!(
            matches!(parse(bad.as_bytes()), Err(ReplyError::Malformed(_))),
            "{bad:?}"
        );
    }
    let e: Error = ReplyError::Malformed("x".into()).into();
    assert!(matches!(e, Error::Protocol { code: None, .. }));
}

#[test]
fn reply_line_over_64k_rejected() {
    let mut line = b"220 ".to_vec();
    line.resize(MAX_LINE_BYTES, b'a');
    line.extend_from_slice(b"\r\n");
    assert!(parse(&line).is_ok());
    let mut long = b"220 ".to_vec();
    long.resize(MAX_LINE_BYTES + 1, b'a');
    long.extend_from_slice(b"\r\n");
    assert_eq!(parse(&long), Err(ReplyError::LineTooLong));
    // Without a terminator, detected while buffering.
    let endless = vec![b'a'; MAX_LINE_BYTES + 10];
    let mut p = parser();
    assert_eq!(p.push(&endless), Err(ReplyError::LineTooLong));
    assert!(!p.has_partial());
}

#[test]
fn reply_more_than_10000_lines_rejected() {
    let mut text = String::from("211-start\r\n");
    for _ in 0..MAX_REPLY_LINES - 2 {
        text.push_str(" x\r\n");
    }
    text.push_str("211 end\r\n");
    assert_eq!(
        parse(text.as_bytes()).unwrap()[0].lines.len(),
        MAX_REPLY_LINES
    );
    let mut text = String::from("211-start\r\n");
    for _ in 0..MAX_REPLY_LINES {
        text.push_str(" x\r\n");
    }
    text.push_str("211 end\r\n");
    assert_eq!(parse(text.as_bytes()), Err(ReplyError::ReplyTooLarge));
}

#[test]
fn reply_over_4mib_rejected() {
    let mut p = parser();
    p.push(b"211-start\r\n").unwrap();
    let line = format!(" {}\r\n", "y".repeat(60_000));
    let mut result = Ok(Vec::new());
    for _ in 0..(MAX_REPLY_BYTES / 60_000 + 2) {
        result = p.push(line.as_bytes());
        if result.is_err() {
            break;
        }
    }
    assert_eq!(result, Err(ReplyError::ReplyTooLarge));
}

#[test]
fn reply_telnet_iac_sequences_stripped() {
    // IAC WILL 1, IAC DO 3, IAC NOP, IAC IAC (→ 0xFF, windows-1252 'ÿ' after fallback).
    let mut p = ReplyParser::new(LineDecoder::new(Charset::Custom(encoding_rs::WINDOWS_1252)));
    let r = p
        .push(b"\xff\xfb\x01220 a\xff\xfd\x03b\xff\xf1c \xff\xffx\r\n")
        .unwrap();
    assert_eq!(r[0].lines, ["220 abc ÿx"]);
    // Split inside the sequences.
    let mut p = ReplyParser::new(LineDecoder::new(Charset::Custom(encoding_rs::WINDOWS_1252)));
    assert!(p.push(b"220 a\xff").unwrap().is_empty());
    assert!(p.has_partial());
    assert!(p.push(b"\xfb").unwrap().is_empty());
    let r = p.push(b"\x01b\xff").unwrap();
    assert!(r.is_empty());
    let r = p.push(b"\xff\r\n").unwrap();
    assert_eq!(r[0].lines, ["220 abÿ"]);
    assert!(!p.has_partial());
}

#[test]
fn reply_control_chars_replaced() {
    let r = one("220 \x1b[31mred\x07 \u{9b}x\ttab\rcr\r\n");
    assert_eq!(
        r.lines,
        ["220 \u{fffd}[31mred\u{fffd} \u{fffd}x\ttab\u{fffd}cr"]
    );
}

#[test]
fn reply_parser_reports_charset_switch() {
    let mut p = parser();
    let r = p.push(b"220 gr\xfc\xdfe\r\n").unwrap();
    assert_eq!(r[0].text(), "grüße");
    assert_eq!(p.take_notes(), [DecodeNote::SwitchedToFallback]);
    assert!(p.take_notes().is_empty());
}

#[test]
fn reply_has_partial_tracks_unterminated_multiline() {
    let mut p = parser();
    assert!(!p.has_partial());
    assert!(p.push(b"211-a\r\n").unwrap().is_empty());
    assert!(p.has_partial());
    assert_eq!(p.push(b"211 b\r\n").unwrap().len(), 1);
    assert!(!p.has_partial());
}

fn reply_257(text: &str) -> Reply {
    one(&format!("257 {text}\r\n"))
}

#[test]
fn pwd_parses_doubled_quotes() {
    assert_eq!(
        parse_pwd(&reply_257(r#""/a ""b"" c" created"#)).unwrap(),
        r#"/a "b" c"#
    );
    assert_eq!(
        parse_pwd(&reply_257(r#""/home/test" is the current directory"#)).unwrap(),
        "/home/test"
    );
    assert_eq!(parse_pwd(&reply_257(r#"PWD is "/x y""#)).unwrap(), "/x y");
}

#[test]
fn pwd_unquoted_fallback() {
    assert_eq!(
        parse_pwd(&reply_257("/srv/ftp is current")).unwrap(),
        "/srv/ftp"
    );
    assert_eq!(
        parse_pwd(&reply_257("'DSN1.' is working directory")).unwrap(),
        "'DSN1.'"
    );
}

#[test]
fn pwd_empty_is_error() {
    for text in [r#""" is current"#, ""] {
        let r = if text.is_empty() {
            one("257\r\n")
        } else {
            reply_257(text)
        };
        assert!(
            matches!(
                parse_pwd(&r),
                Err(Error::Protocol {
                    code: Some(257),
                    ..
                })
            ),
            "{text:?}"
        );
    }
}

#[test]
fn fuzz_body_runs_on_seeds() {
    for seed in [
        &b"\x00220 Welcome\r\n"[..],
        b"\x7f230-Hello\r\n there\r\n230 Logged in\r\n",
        b"\xff211-Features:\n MLST type*;size*;modify*;\n UTF8\n211 End\n",
        b"\x10garbage\xff\xff\xfb",
        b"",
    ] {
        fuzz_reply_parser(seed);
    }
}

/// A random valid reply, serialised.
fn arb_reply() -> impl Strategy<Value = Vec<u8>> {
    (
        1u16..=5,
        0u16..100,
        proptest::collection::vec(("[ -~]{0,20}", 0u8..4), 0..20),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(first, rest, lines, crlf, bare_end)| {
            let code = first * 100 + rest;
            let eol = if crlf { "\r\n" } else { "\n" };
            let mut out = String::new();
            if lines.is_empty() {
                out.push_str(&format!("{code} single{eol}"));
                return out.into_bytes();
            }
            out.push_str(&format!("{code}-first{eol}"));
            for (text, style) in lines {
                let other = if code == 599 { 100 } else { code + 1 };
                let line = match style {
                    0 => format!(" {text}"),
                    1 => format!("{code}-{text}"),
                    2 => format!("{other} {text}"),
                    _ => format!("x{text}"),
                };
                out.push_str(&line);
                out.push_str(eol);
            }
            if bare_end {
                out.push_str(&format!("{code}{eol}"));
            } else {
                out.push_str(&format!("{code} end{eol}"));
            }
            out.into_bytes()
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn prop_reply_parse_is_chunking_invariant(
        replies in proptest::collection::vec(arb_reply(), 1..4),
        cuts in proptest::collection::vec(any::<prop::sample::Index>(), 1..=3),
    ) {
        let data: Vec<u8> = replies.concat();
        let whole = parse(&data).unwrap();
        prop_assert_eq!(whole.len(), replies.len());
        let mut points: Vec<usize> = cuts.iter().map(|i| i.index(data.len() + 1)).collect();
        points.sort_unstable();
        let mut p = parser();
        let mut split = Vec::new();
        let mut start = 0;
        for point in points.into_iter().chain(std::iter::once(data.len())) {
            split.extend(p.push(&data[start..point]).unwrap());
            start = point;
        }
        prop_assert_eq!(whole, split);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_reply_parser_never_panics(data in proptest::collection::vec(any::<u8>(), 0..131_072)) {
        fuzz_reply_parser(&data);
    }

    #[test]
    fn prop_reply_parser_never_panics_reply_like(
        parts in proptest::collection::vec(
            prop_oneof![
                arb_reply(),
                Just(b"\xff\xff".to_vec()),
                Just(b"\xff\xfb\x01".to_vec()),
                Just(b"\r".to_vec()),
                proptest::collection::vec(any::<u8>(), 0..8),
            ],
            0..12,
        ),
        sel in any::<u8>(),
    ) {
        let mut data = vec![sel];
        data.extend(parts.concat());
        fuzz_reply_parser(&data);
    }
}
