use std::collections::HashMap;

use stem::Error;
use stem::response::{
    AddOnionResponse, ControlLine, ControlMessage, GetConfResponse, GetInfoResponse,
    MapAddressResponse, escape_quoted, format_for_sending, unescape_bytes,
};
use stem::socket::receive_message;

const OK_REPLY: &str = "250 OK\r\n";
const EVENT_BW: &str = "650 BW 32326 2856\r\n";
const GETINFO_VERSION: &str =
    "250-version=0.2.2.23-alpha (git-b85eb949b528f4d7)\r\n250 OK\r\n";
const GETINFO_INFONAMES: &str = "250+info/names=\r\n\
accounting/bytes -- Number of bytes read/written so far in the accounting interval.\r\n\
accounting/enabled -- Is accounting currently enabled?\r\n\
version -- The current version of Tor.\r\n\
.\r\n\
250 OK\r\n";

async fn received(content: &str) -> Result<ControlMessage, Error> {
    receive_message(&mut content.as_bytes()).await
}

#[tokio::test]
async fn parses_basic_replies() {
    let message = received(OK_REPLY).await.unwrap();
    assert_eq!(message.to_string(), "OK");
    assert_eq!(message.content(), vec![("250".into(), ' ', "OK".into())]);
    assert_eq!(message.raw_content(), OK_REPLY);
    assert!(message.is_ok());
    assert!(!message.is_event());

    let event = received(EVENT_BW).await.unwrap();
    assert_eq!(event.to_string(), "BW 32326 2856");
    assert!(event.is_event());
    assert_eq!(event.status_code(), "650");
}

#[tokio::test]
async fn parses_multiline_replies() {
    let message = received(GETINFO_VERSION).await.unwrap();
    assert_eq!(message.len(), 2);
    assert_eq!(message.raw_content(), GETINFO_VERSION);
    let content = message.content();
    assert_eq!(content[0].1, '-');
    assert_eq!(content[1], ("250".into(), ' ', "OK".into()));

    let message = received(GETINFO_INFONAMES).await.unwrap();
    assert_eq!(message.len(), 2);
    assert_eq!(message.to_string().lines().count(), 5);
    let first = &message.content()[0];
    assert_eq!(first.1, '+');
    assert!(first.2.starts_with("info/names=\naccounting/bytes"));
    assert!(!first.2.ends_with("\n."));
    assert_eq!(message.raw_content(), GETINFO_INFONAMES);
}

#[tokio::test]
async fn rejects_missing_carriage_returns() {
    let lines: Vec<String> = GETINFO_INFONAMES
        .split_inclusive("\r\n")
        .map(str::to_string)
        .collect();
    for index in 0..lines.len() {
        let mut broken = lines.clone();
        broken[index] = broken[index].replace("\r\n", "\n");
        let result = received(&broken.concat()).await;
        assert!(
            matches!(result, Err(Error::Protocol(_))),
            "line {index} was accepted"
        );
    }
}

#[tokio::test]
async fn rejects_malformed_prefixes() {
    for index in 0..EVENT_BW.len() {
        let removed = format!("{}{}", &EVENT_BW[..index], &EVENT_BW[index + 1..]);
        let replaced = format!("{}#{}", &EVENT_BW[..index], &EVENT_BW[index + 1..]);
        let is_framing = index < 4 || index >= EVENT_BW.len() - 2;
        for input in [removed, replaced] {
            let result = received(&input).await;
            match is_framing {
                true => assert!(result.is_err(), "{input:?} was accepted"),
                false => assert!(result.is_ok(), "{input:?} was rejected"),
            }
        }
    }
}

#[tokio::test]
async fn reports_closed_sockets_and_truncation() {
    assert!(matches!(received("").await, Err(Error::SocketClosed)));
    assert!(matches!(received("250-OK").await, Err(Error::SocketClosed)));
    assert!(matches!(
        received("250-version=1\r\n").await,
        Err(Error::SocketClosed)
    ));
}

#[tokio::test]
async fn rejects_inconsistent_status_codes_and_oversized_lines() {
    assert!(received("250-a\r\n251 b\r\n").await.is_ok());
    assert!(received("250-a\r\n\r\n").await.is_err());
    assert!(received("25 OK\r\n").await.is_err());
    assert!(received("abc OK\r\n").await.is_err());
    assert!(received("250?OK\r\n").await.is_err());

    let huge = format!(
        "250 {}\r\n",
        "A".repeat(stem::response::MAX_LINE_LENGTH + 1)
    );
    assert!(received(&huge).await.is_err());
}

#[tokio::test]
async fn handles_dot_stuffed_data_blocks() {
    let reply = "250+data=\r\n..leading dot\r\n...\r\nplain\r\n.\r\n250 OK\r\n";
    let message = received(reply).await.unwrap();
    let data = &message.content()[0].2;
    assert!(data.contains("\n.leading dot\n"));
    assert!(data.contains("\n..\n"));
}

#[test]
fn escapes_outgoing_data_blocks() {
    assert_eq!(format_for_sending("GETINFO version"), "GETINFO version\r\n");
    let multiline = format_for_sending("LOADCONF\nfoo\n.bar\n..\n.");
    assert_eq!(multiline, "+LOADCONF\r\nfoo\r\n..bar\r\n...\r\n..\r\n.\r\n");
}

#[test]
fn quotes_and_unquotes_strings() {
    assert_eq!(escape_quoted("plain"), "\"plain\"");
    assert_eq!(escape_quoted("a\"b\\c"), "\"a\\\"b\\\\c\"");
    assert_eq!(escape_quoted("line\r\nbreak"), "\"line\\r\\nbreak\"");
    for value in [
        "",
        "a b",
        "quote\"",
        "back\\slash",
        "\r\n\t",
        "ünïcode",
        "\u{7f}\u{1}",
    ] {
        let quoted = escape_quoted(value);
        let inner = &quoted[1..quoted.len() - 1];
        assert_eq!(unescape_bytes(inner).unwrap(), value.as_bytes());
    }
    assert!(unescape_bytes("trailing\\").is_err());
    assert_eq!(unescape_bytes("\\101\\x42\\n").unwrap(), b"AB\n");
}

#[test]
fn pops_values_from_control_lines() {
    let mut line = ControlLine::new("\"We're all mad here.\" says the grinning cat.");
    assert_eq!(line.pop(true, false).unwrap(), "We're all mad here.");
    assert_eq!(line.pop(false, false).unwrap(), "says");
    assert_eq!(line.remainder(), "the grinning cat.");

    let mut line =
        ControlLine::new("\"this has a \\\" and \\\\ in it\" foo=bar more_data");
    assert_eq!(line.pop(true, true).unwrap(), "this has a \" and \\ in it");
}

#[test]
fn walks_through_general_control_line_usage() {
    let mut line = ControlLine::new("PROTOCOLINFO 1");
    assert_eq!(line.remainder(), "PROTOCOLINFO 1");
    assert!(!line.is_empty());
    assert!(!line.is_next_quoted(false));
    assert!(!line.is_next_mapping(None, false, false));
    assert_eq!(line.peek_key(), None);
    assert!(line.pop_mapping(false, false).is_err());
    assert_eq!(line.pop(false, false).unwrap(), "PROTOCOLINFO");
    assert_eq!(line.pop(false, false).unwrap(), "1");
    assert!(line.is_empty());
    assert!(line.pop(false, false).is_err());
    assert!(line.pop_mapping(false, false).is_err());
    assert_eq!(&*line, "PROTOCOLINFO 1");
}

#[test]
fn pops_mappings_quoted_and_unquoted() {
    let entry = "Tor=\"0.2.1.30 (0a083b0188cacd2f07838ff0446113bd5211a024)\"";
    let mut line = ControlLine::new(entry);
    assert!(line.is_next_mapping(Some("Tor"), true, false));
    assert!(!line.is_next_mapping(Some("Other"), false, false));
    assert_eq!(line.peek_key(), Some("Tor"));
    assert_eq!(
        line.pop_mapping(false, false).unwrap(),
        ("Tor".into(), "\"0.2.1.30".into())
    );
    assert_eq!(
        line.remainder(),
        "(0a083b0188cacd2f07838ff0446113bd5211a024)\""
    );
    assert!(line.pop_mapping(false, false).is_err());

    let mut line = ControlLine::new(entry);
    assert_eq!(
        line.pop_mapping(true, false).unwrap(),
        (
            "Tor".into(),
            "0.2.1.30 (0a083b0188cacd2f07838ff0446113bd5211a024)".into()
        )
    );
    assert!(line.is_empty());
}

#[test]
fn handles_escaped_quotes_in_control_lines() {
    let auth =
        r#"AUTH METHODS=COOKIE COOKIEFILE="/tmp/my data\\\"dir//control_auth_cookie""#;
    let mut line = ControlLine::new(auth);
    assert_eq!(line.pop(false, false).unwrap(), "AUTH");
    assert_eq!(
        line.pop_mapping(false, false).unwrap(),
        ("METHODS".into(), "COOKIE".into())
    );
    let cookie_entry = line.remainder().to_string();
    assert!(line.is_next_mapping(Some("COOKIEFILE"), true, true));

    let mut line = ControlLine::new(cookie_entry.clone());
    assert_eq!(line.pop(false, true).unwrap(), "COOKIEFILE=\"/tmp/my");
    assert_eq!(
        line.pop(false, true).unwrap(),
        r#"data\"dir//control_auth_cookie""#
    );

    let mut line = ControlLine::new(cookie_entry.clone());
    assert_eq!(
        line.pop_mapping(true, true).unwrap(),
        (
            "COOKIEFILE".into(),
            r#"/tmp/my data\"dir//control_auth_cookie"#.into()
        )
    );
    assert!(line.is_empty());

    let mut line =
        ControlLine::new(r#"COOKIEFILE="C:\\Users\\Atagar\\AppData\\tor\\cookie""#);
    assert_eq!(
        line.pop_mapping(true, true).unwrap(),
        (
            "COOKIEFILE".into(),
            r"C:\Users\Atagar\AppData\tor\cookie".into()
        )
    );
}

fn message(content: &str) -> ControlMessage {
    ControlMessage::parse(content, true).unwrap()
}

#[test]
fn parses_getinfo_responses() {
    let empty = GetInfoResponse::parse(&message("250 OK")).unwrap();
    assert!(empty.entries.is_empty());

    let single =
        GetInfoResponse::parse(&message("250-version=0.2.3.11-alpha-dev\n250 OK"))
            .unwrap();
    assert_eq!(single.entries["version"], b"0.2.3.11-alpha-dev");

    let multiline = GetInfoResponse::parse(&message(
        "250-version=0.2.3.11-alpha-dev (git-ef0bc7f8f26a917c)\n\
         250+config-text=\nControlPort 9051\nDataDirectory /home/atagar/.tor\n\
         ORPort 9050\n.\n\
         250 OK",
    ))
    .unwrap();
    assert_eq!(multiline.entries.len(), 2);
    assert_eq!(
        multiline.entries["config-text"],
        b"ControlPort 9051\nDataDirectory /home/atagar/.tor\nORPort 9050"
    );
}

#[test]
fn rejects_malformed_getinfo_responses() {
    let non_mapping =
        message("250-version=0.2.3.11-alpha-dev\n250-address 67.137.76.214\n250 OK");
    assert!(matches!(
        GetInfoResponse::parse(&non_mapping),
        Err(Error::Protocol(_))
    ));

    let missing_newline =
        message("250+config-text=ControlPort 9051\nDataDirectory /x\n.\n250 OK");
    assert!(matches!(
        GetInfoResponse::parse(&missing_newline),
        Err(Error::Protocol(_))
    ));

    let unrecognized = message("552 Unrecognized key \"blackhole\"");
    match GetInfoResponse::parse(&unrecognized) {
        Err(Error::InvalidArguments { arguments, .. }) => {
            assert_eq!(arguments, vec!["blackhole"])
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn matches_getinfo_responses_against_requests() {
    let response = GetInfoResponse::parse(&message("250-a=1\n250-b=2\n250 OK")).unwrap();
    assert!(response.assert_matches(&["a".into(), "b".into()]).is_ok());
    assert!(response.assert_matches(&["a".into()]).is_err());
    assert!(response.assert_matches(&["a".into(), "c".into()]).is_err());
}

#[test]
fn parses_getconf_responses() {
    let single =
        GetConfResponse::parse(&message("250 DataDirectory=/home/neena/.tor")).unwrap();
    assert_eq!(single.entries["DataDirectory"], vec!["/home/neena/.tor"]);

    let batch = GetConfResponse::parse(&message(
        "250-CookieAuthentication=0\n250-ControlPort=9100\n\
         250-DataDirectory=/tmp/fake dir\n250 DirPort",
    ))
    .unwrap();
    let expected: HashMap<String, Vec<String>> = HashMap::from([
        ("CookieAuthentication".into(), vec!["0".into()]),
        ("ControlPort".into(), vec!["9100".into()]),
        ("DataDirectory".into(), vec!["/tmp/fake dir".into()]),
        ("DirPort".into(), vec![]),
    ]);
    assert_eq!(batch.entries, expected);

    let multivalue = GetConfResponse::parse(&message(
        "250-ControlPort=9100\n250-ExitPolicy=accept 34.3.4.5\n\
         250-ExitPolicy=accept 3.4.53.3\n250 ExitPolicy=reject 23.245.54.3",
    ))
    .unwrap();
    assert_eq!(multivalue.entries["ExitPolicy"].len(), 3);

    let quoted = GetConfResponse::parse(&message(
        "250 ContactInfo=\"line one\\r\\nSIGNAL HALT \\\"q\\\"\"",
    ))
    .unwrap();
    assert_eq!(
        quoted.entries["ContactInfo"],
        vec!["line one\r\nSIGNAL HALT \"q\""]
    );
}

#[test]
fn rejects_malformed_getconf_responses() {
    let unrecognized = message(
        "552-Unrecognized configuration key \"brickroad\"\n\
         552 Unrecognized configuration key \"submarine\"",
    );
    match GetConfResponse::parse(&unrecognized) {
        Err(Error::InvalidArguments { arguments, .. }) => {
            assert_eq!(arguments, vec!["brickroad", "submarine"])
        }
        other => panic!("unexpected {other:?}"),
    }
    let invalid = message("123-FOO\n232 BAR");
    assert!(matches!(
        GetConfResponse::parse(&invalid),
        Err(Error::Protocol(_))
    ));
}

#[test]
fn parses_mapaddress_responses() {
    let single = MapAddressResponse::parse(&message("250 foo=bar")).unwrap();
    assert_eq!(single.entries["foo"], "bar");

    let batch = MapAddressResponse::parse(&message(
        "250-foo=bar\n250-baz=quux\n250-gzzz=bzz\n250 120.23.23.2=torproject.org",
    ))
    .unwrap();
    assert_eq!(batch.entries.len(), 4);
    assert_eq!(batch.entries["120.23.23.2"], "torproject.org");

    let partial = MapAddressResponse::parse(&message(
        "512-syntax error: mapping '2389' is not of expected form 'foo=bar'\n\
         512-syntax error: mapping '23' is not of expected form 'foo=bar'.\n\
         250 23=324",
    ))
    .unwrap();
    assert_eq!(
        partial.entries,
        HashMap::from([("23".into(), "324".into())])
    );
}

#[test]
fn rejects_malformed_mapaddress_responses() {
    let invalid_request =
        message("512 syntax error: mapping '2389' is not of expected form 'foo=bar'");
    assert!(matches!(
        MapAddressResponse::parse(&invalid_request),
        Err(Error::InvalidRequest { .. })
    ));
    assert!(matches!(
        MapAddressResponse::parse(&message("451 Resource exhausted")),
        Err(Error::OperationFailed { .. })
    ));
    assert!(MapAddressResponse::parse(&message("250 OK")).is_err());
    assert!(MapAddressResponse::parse(&message("250 foo is bar")).is_err());
}

#[test]
fn parses_add_onion_responses() {
    let with_key = AddOnionResponse::parse(&message(
        "250-ServiceID=gfzprpioee3hoppz\n250-PrivateKey=RSA1024:MIICXgIBAAKB\n250 OK",
    ))
    .unwrap();
    assert_eq!(with_key.service_id.as_deref(), Some("gfzprpioee3hoppz"));
    assert_eq!(with_key.private_key_type.as_deref(), Some("RSA1024"));
    assert_eq!(with_key.private_key.as_deref(), Some("MIICXgIBAAKB"));
    assert!(with_key.client_auth.is_empty());

    let with_auth = AddOnionResponse::parse(&message(
        "250-ServiceID=oekn5sqrvcu4wote\n250-ClientAuth=bob:lhwLVFt0Kd5/0Gy9DkKoyA\n\
         250-ClientAuth=alice:T9UADxtrvqx2HnLKWp/fWQ\n250-ClientAuthV3=abc\n250 OK",
    ))
    .unwrap();
    assert_eq!(with_auth.private_key, None);
    assert_eq!(with_auth.client_auth["bob"], "lhwLVFt0Kd5/0Gy9DkKoyA");
    assert_eq!(with_auth.client_auth_v3, vec!["abc"]);

    let bare =
        AddOnionResponse::parse(&message("250-ServiceID=gfzprpioee3hoppz\n250 OK"))
            .unwrap();
    assert_eq!(bare.private_key, None);
}

#[test]
fn rejects_malformed_add_onion_responses() {
    let wrong_first =
        message("250-MyKey=gfzprpioee3hoppz\n250-ServiceID=gfzprpioee3hoppz\n250 OK");
    assert!(AddOnionResponse::parse(&wrong_first).is_err());
    let no_key_type =
        message("250-ServiceID=gfzprpioee3hoppz\n250-PrivateKey=MIICXgIBAAKB\n250 OK");
    assert!(AddOnionResponse::parse(&no_key_type).is_err());
    assert!(AddOnionResponse::parse(&message("512 Bad request")).is_err());
}

#[test]
fn compares_messages_by_content() {
    let one = message("650 BW 1 2");
    assert_eq!(one, message("650 BW 1 2"));
    assert_ne!(one, message("650 BW 1 3"));
}
