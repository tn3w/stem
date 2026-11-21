use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use stem::Error;
use stem::controller::Controller;
use stem::socket::{ControlSocket, ControlTarget};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};

async fn listener() -> (TcpListener, ControlSocket) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (
        listener,
        ControlSocket::port(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
    )
}

async fn read_until(stream: &mut tokio::net::TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut received = Vec::new();
    let mut chunk = [0u8; 1024];
    while !received
        .windows(needle.len())
        .any(|window| window == needle)
    {
        let count = stream.read(&mut chunk).await.unwrap();
        assert!(count > 0, "peer closed early");
        received.extend_from_slice(&chunk[..count]);
    }
    received
}

#[tokio::test]
async fn sends_commands_with_crlf_and_receives_replies() {
    let (listener, socket) = listener().await;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_until(&mut stream, b"\r\n").await;
        stream
            .write_all(b"250-version=1.2.3\r\n250 OK\r\n")
            .await
            .unwrap();
        request
    });
    socket.connect().await.unwrap();
    assert!(socket.is_alive());
    assert!(socket.is_localhost());
    assert!(socket.control_port().is_some());
    assert!(socket.socket_path().is_none());
    socket.send("GETINFO version").await.unwrap();
    let reply = socket.recv().await.unwrap();
    assert_eq!(reply.raw_content(), "250-version=1.2.3\r\n250 OK\r\n");
    assert_eq!(server.await.unwrap(), b"GETINFO version\r\n");
    socket.close().await;
    assert!(!socket.is_alive());
    assert!(matches!(
        socket.send("GETINFO version").await,
        Err(Error::SocketClosed)
    ));
    assert!(matches!(socket.recv().await, Err(Error::SocketClosed)));
}

#[tokio::test]
async fn turns_embedded_newlines_into_data_blocks() {
    let (listener, socket) = listener().await;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_until(&mut stream, b"\r\n.\r\n").await
    });
    socket.connect().await.unwrap();
    socket
        .send("LOADCONF\nFoo bar\n.sneaky\nSIGNAL HALT")
        .await
        .unwrap();
    let wire = String::from_utf8(server.await.unwrap()).unwrap();
    assert_eq!(
        wire,
        "+LOADCONF\r\nFoo bar\r\n..sneaky\r\nSIGNAL HALT\r\n.\r\n"
    );
    assert!(!wire.contains("\r\nSIGNAL HALT\r\n") || wire.contains("\r\n.\r\n"));
}

#[tokio::test]
async fn refuses_to_send_nul_bytes() {
    let (listener, socket) = listener().await;
    tokio::spawn(async move {
        let _ = listener.accept().await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    socket.connect().await.unwrap();
    assert!(matches!(
        socket.send("GETINFO\0version").await,
        Err(Error::InvalidInput(_))
    ));
    assert!(socket.is_alive());
}

#[tokio::test]
async fn reports_remote_close_and_reconnects() {
    let (listener, socket) = listener().await;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        drop(stream);
        let (mut second, _) = listener.accept().await.unwrap();
        second.write_all(b"250 OK\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    });
    socket.connect().await.unwrap();
    assert!(matches!(socket.recv().await, Err(Error::SocketClosed)));
    assert!(!socket.is_alive());
    socket.connect().await.unwrap();
    assert_eq!(socket.recv().await.unwrap().to_string(), "OK");
    server.await.unwrap();
}

#[tokio::test]
async fn rejects_oversized_lines_and_garbage() {
    let (listener, socket) = listener().await;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut huge = b"250 ".to_vec();
        huge.extend(std::iter::repeat_n(
            b'A',
            stem::response::MAX_LINE_LENGTH + 10,
        ));
        let _ = stream.write_all(&huge).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    socket.connect().await.unwrap();
    let outcome = socket.recv().await;
    assert!(matches!(
        outcome,
        Err(Error::Protocol(_)) | Err(Error::SocketClosed)
    ));
    server.abort();

    let (listener, socket) = self::listener().await;
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream
            .write_all(b"this is not a control reply\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    socket.connect().await.unwrap();
    assert!(matches!(socket.recv().await, Err(Error::Protocol(_))));
}

#[tokio::test]
async fn aborts_pending_receives() {
    let (listener, socket) = listener().await;
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    socket.connect().await.unwrap();
    let socket = std::sync::Arc::new(socket);
    let waiting = {
        let socket = socket.clone();
        tokio::spawn(async move { socket.recv().await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    socket.abort();
    let outcome = tokio::time::timeout(Duration::from_secs(2), waiting)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(outcome, Err(Error::SocketClosed)));
}

#[tokio::test]
async fn connects_over_unix_sockets() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sock");
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 64];
        let count = stream.read(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..count], b"PROTOCOLINFO 1\r\n");
        stream.write_all(b"250 OK\r\n").await.unwrap();
    });
    let socket = ControlSocket::connect_to(ControlTarget::File(path.clone()))
        .await
        .unwrap();
    assert_eq!(socket.socket_path(), Some(path.as_path()));
    assert!(socket.is_localhost() && socket.control_port().is_none());
    socket.send("PROTOCOLINFO 1").await.unwrap();
    assert_eq!(socket.recv().await.unwrap().to_string(), "OK");

    let missing = ControlSocket::file(directory.path().join("missing.sock"));
    assert!(matches!(missing.connect().await, Err(Error::Socket(_))));
}

#[tokio::test]
async fn treats_non_loopback_ports_as_remote() {
    let socket = ControlSocket::port(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 9051);
    assert!(!socket.is_localhost());
    assert!(!socket.is_alive());
}

async fn scripted_controller(
    script: &'static [(&'static [u8], &'static [u8])],
) -> Controller {
    let (listener, socket) = listener().await;
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        for (expected, reply) in script {
            let received = read_until(&mut stream, b"\r\n").await;
            assert_eq!(&received, expected);
            stream.write_all(reply).await.unwrap();
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    socket.connect().await.unwrap();
    Controller::new(socket)
}

#[tokio::test]
async fn matches_replies_to_requests_in_order() {
    let controller = scripted_controller(&[
        (b"GETINFO version\r\n", b"250-version=9.9.9\r\n250 OK\r\n"),
        (b"GETINFO address\r\n", b"250-address=1.2.3.4\r\n250 OK\r\n"),
    ])
    .await;
    assert_eq!(controller.get_info("version").await.unwrap(), "9.9.9");
    assert_eq!(controller.get_info("address").await.unwrap(), "1.2.3.4");
}

#[tokio::test]
async fn delivers_events_that_arrive_between_replies() {
    let (listener, socket) = listener().await;
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        stream.write_all(b"650 BW 10 20\r\n").await.unwrap();
        stream.write_all(b"650 BW 30 40\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    socket.connect().await.unwrap();
    let controller = Controller::new(socket);
    let (_, mut events) = controller
        .subscribe(&[stem::events::EventType::Bw])
        .await
        .unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.message.to_string(), "BW 10 20");
    assert_eq!(second.message.to_string(), "BW 30 40");
}

#[tokio::test]
async fn times_out_when_tor_never_answers() {
    let (listener, socket) = listener().await;
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    socket.connect().await.unwrap();
    let controller = Controller::new(socket);
    controller.set_request_timeout(Some(Duration::from_millis(200)));
    let outcome = controller.msg("GETINFO version").await;
    assert!(matches!(outcome, Err(Error::Timeout(_))));
    assert!(!controller.is_alive());
}

#[tokio::test]
async fn survives_panicking_event_listeners() {
    let (listener, socket) = listener().await;
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        stream
            .write_all(b"650 BW 1 2\r\n650 BW 3 4\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    socket.connect().await.unwrap();
    let controller = Controller::new(socket);
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = seen.clone();
    controller
        .add_event_listener(
            move |_| {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                panic!("listener failure");
            },
            &[stem::events::EventType::Bw],
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(controller.is_alive());
}
