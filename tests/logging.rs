use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::Duration;

use log::{Level, LevelFilter, Log, Metadata, Record};
use stem::socket::ControlSocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

static RECORDS: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Collector;

impl Log for Collector {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        RECORDS.lock().unwrap().push(format!("{}", record.args()));
    }

    fn flush(&self) {}
}

fn logged() -> String {
    RECORDS.lock().unwrap().join("\n")
}

#[tokio::test]
async fn keeps_secrets_out_of_the_logs() {
    log::set_logger(&Collector).unwrap();
    log::set_max_level(LevelFilter::Trace);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = vec![0u8; 4096];
        for reply in [
            &b"250-PROTOCOLINFO 1\r\n250-AUTH METHODS=HASHEDPASSWORD\r\n250-VERSION \
                Tor=\"0.4.9.13\"\r\n250 OK\r\n"[..],
            b"250 OK\r\n",
            b"250-ServiceID=abcdefghijklmnop\r\n\
              250-PrivateKey=ED25519-V3:TOPSECRETKEYMATERIAL\r\n250 OK\r\n",
            b"250-CLIENT abcdefghijklmnop x25519:SECRETCLIENTKEY ClientName=bob\r\n250 \
                OK\r\n",
        ] {
            let _ = stream.read(&mut buffer).await.unwrap();
            stream.write_all(reply).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    let socket = ControlSocket::port(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    socket.connect().await.unwrap();
    for command in [
        "PROTOCOLINFO 1",
        "AUTHENTICATE \"hunter2-password\"",
        "ADD_ONION ED25519-V3:ANOTHERSECRETKEY Port=80",
        "ONION_CLIENT_AUTH_ADD abcdefghijklmnop x25519:SECRETCLIENTKEY",
    ] {
        socket.send(command).await.unwrap();
        socket.recv().await.unwrap();
    }

    let logs = logged();
    assert!(logs.contains("Sent to tor"), "nothing was logged:\n{logs}");
    assert!(
        logs.contains("<redacted>"),
        "no redaction happened:\n{logs}"
    );
    for secret in [
        "hunter2-password",
        "TOPSECRETKEYMATERIAL",
        "ANOTHERSECRETKEY",
        "SECRETCLIENTKEY",
    ] {
        assert!(
            !logs.contains(secret),
            "{secret} leaked into the logs:\n{logs}"
        );
    }
}
