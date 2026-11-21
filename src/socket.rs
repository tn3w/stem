use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
    ReadHalf, WriteHalf,
};
use tokio::net::TcpStream;
use tokio::sync::Notify;

use crate::error::{Error, Result};
use crate::response::{
    ControlMessage, MAX_LINE_LENGTH, MessageBuilder, format_for_sending,
};

const SECRET_COMMANDS: [&str; 4] = [
    "AUTHENTICATE",
    "ADD_ONION",
    "ONION_CLIENT_AUTH_ADD",
    "AUTHCHALLENGE",
];

type BoxedStream = Box<dyn AsyncStream>;

trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlTarget {
    Port(SocketAddr),
    File(PathBuf),
}

struct Connection {
    reader: tokio::sync::Mutex<BufReader<ReadHalf<BoxedStream>>>,
    writer: tokio::sync::Mutex<WriteHalf<BoxedStream>>,
    closed: Notify,
    alive: AtomicBool,
}

pub struct ControlSocket {
    target: ControlTarget,
    connection: Mutex<Option<Arc<Connection>>>,
    connection_time: Mutex<SystemTime>,
}

impl ControlSocket {
    pub fn port(address: IpAddr, port: u16) -> Self {
        Self::new(ControlTarget::Port(SocketAddr::new(address, port)))
    }

    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::new(ControlTarget::File(path.into()))
    }

    fn new(target: ControlTarget) -> Self {
        Self {
            target,
            connection: Mutex::new(None),
            connection_time: Mutex::new(SystemTime::now()),
        }
    }

    pub async fn connect_to(target: ControlTarget) -> Result<Self> {
        let socket = Self::new(target);
        socket.connect().await?;
        Ok(socket)
    }

    pub fn target(&self) -> &ControlTarget {
        &self.target
    }

    pub fn socket_path(&self) -> Option<&Path> {
        match &self.target {
            ControlTarget::File(path) => Some(path),
            ControlTarget::Port(_) => None,
        }
    }

    pub fn control_port(&self) -> Option<SocketAddr> {
        match &self.target {
            ControlTarget::Port(address) => Some(*address),
            ControlTarget::File(_) => None,
        }
    }

    pub fn is_localhost(&self) -> bool {
        match &self.target {
            ControlTarget::Port(address) => address.ip().is_loopback(),
            ControlTarget::File(_) => true,
        }
    }

    pub fn is_alive(&self) -> bool {
        self.current()
            .is_some_and(|connection| connection.alive.load(Ordering::SeqCst))
    }

    pub fn connection_time(&self) -> SystemTime {
        *self.connection_time.lock().unwrap()
    }

    fn current(&self) -> Option<Arc<Connection>> {
        self.connection.lock().unwrap().clone()
    }

    async fn open_stream(&self) -> Result<BoxedStream> {
        match &self.target {
            ControlTarget::Port(address) => {
                let stream = TcpStream::connect(address)
                    .await
                    .map_err(|error| Error::Socket(error.to_string()))?;
                Ok(Box::new(stream))
            }
            #[cfg(unix)]
            ControlTarget::File(path) => {
                let stream = tokio::net::UnixStream::connect(path)
                    .await
                    .map_err(|error| Error::Socket(error.to_string()))?;
                Ok(Box::new(stream))
            }
            #[cfg(not(unix))]
            ControlTarget::File(_) => Err(Error::Socket(
                "Unix domain sockets aren't supported on this platform".to_string(),
            )),
        }
    }

    pub async fn connect(&self) -> Result<()> {
        self.close().await;
        let stream = self.open_stream().await?;
        let (reader, writer) = tokio::io::split(stream);
        let connection = Arc::new(Connection {
            reader: tokio::sync::Mutex::new(BufReader::new(reader)),
            writer: tokio::sync::Mutex::new(writer),
            closed: Notify::new(),
            alive: AtomicBool::new(true),
        });
        *self.connection.lock().unwrap() = Some(connection);
        *self.connection_time.lock().unwrap() = SystemTime::now();
        Ok(())
    }

    pub fn abort(&self) {
        if let Some(connection) = self.connection.lock().unwrap().take() {
            connection.alive.store(false, Ordering::SeqCst);
            connection.closed.notify_one();
        }
    }

    pub async fn close(&self) {
        let Some(connection) = self.connection.lock().unwrap().take() else {
            return;
        };
        connection.alive.store(false, Ordering::SeqCst);
        connection.closed.notify_one();
        let _ = connection.writer.lock().await.shutdown().await;
        *self.connection_time.lock().unwrap() = SystemTime::now();
    }

    fn drop_connection(&self, dead: &Arc<Connection>) {
        dead.alive.store(false, Ordering::SeqCst);
        let mut current = self.connection.lock().unwrap();
        if current
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, dead))
        {
            *current = None;
            *self.connection_time.lock().unwrap() = SystemTime::now();
        }
    }

    pub async fn send(&self, message: &str) -> Result<()> {
        self.send_raw(&format_for_sending(message)).await?;
        log_sent(message);
        Ok(())
    }

    pub async fn send_raw(&self, wire_content: &str) -> Result<()> {
        if wire_content.contains('\0') {
            return Err(Error::invalid_input(
                "Control messages can't contain NUL bytes",
            ));
        }
        let Some(connection) = self.current() else {
            return Err(Error::SocketClosed);
        };
        let mut writer = connection.writer.lock().await;
        let result = async {
            writer.write_all(wire_content.as_bytes()).await?;
            writer.flush().await
        }
        .await;
        drop(writer);
        result.map_err(|error| {
            log::info!("Failed to send: {error}");
            self.drop_connection(&connection);
            match error.kind() {
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset => {
                    Error::SocketClosed
                }
                _ => Error::Socket(error.to_string()),
            }
        })
    }

    pub async fn recv(&self) -> Result<ControlMessage> {
        let Some(connection) = self.current() else {
            return Err(Error::SocketClosed);
        };
        let mut reader = connection.reader.lock().await;
        let outcome = tokio::select! {
            biased;
            () = connection.closed.notified() => Err(Error::SocketClosed),
            message = receive_message(&mut *reader) => message,
        };
        drop(reader);
        if matches!(outcome, Err(Error::SocketClosed) | Err(Error::Io(_))) {
            self.drop_connection(&connection);
        }
        outcome.map_err(|error| match error {
            Error::Io(io_error) => Error::Socket(io_error.to_string()),
            other => other,
        })
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.lock().unwrap().take() {
            connection.alive.store(false, Ordering::SeqCst);
            connection.closed.notify_one();
        }
    }
}

fn log_sent(message: &str) {
    if !log::log_enabled!(log::Level::Trace) {
        return;
    }
    let keyword = message.split_whitespace().next().unwrap_or_default();
    let is_secret = SECRET_COMMANDS
        .iter()
        .any(|secret| keyword.eq_ignore_ascii_case(secret));
    match is_secret {
        true => log::trace!("Sent to tor: {keyword} <redacted>"),
        false => log::trace!("Sent to tor: {}", message.replace("\r\n", "\n").trim_end()),
    }
}

async fn read_bounded_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    let limit = (MAX_LINE_LENGTH + 1) as u64;
    let read = (&mut *reader)
        .take(limit)
        .read_until(b'\n', &mut line)
        .await;
    match read {
        Ok(0) => {
            log::debug!(
                "Error while receiving a control message (SocketClosed): empty socket \
                content"
            );
            Err(Error::SocketClosed)
        }
        Ok(_) if line.last() == Some(&b'\n') => Ok(line),
        Ok(_) if line.len() > MAX_LINE_LENGTH => Err(Error::protocol(
            "Control message line exceeded the length limit",
        )),
        Ok(_) => Err(Error::SocketClosed),
        Err(error) => {
            log::debug!(
                "Error while receiving a control message (SocketClosed): {error}"
            );
            Err(Error::SocketClosed)
        }
    }
}

pub async fn receive_message<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
) -> Result<ControlMessage> {
    let mut builder = MessageBuilder::default();
    loop {
        let line = read_bounded_line(reader).await?;
        if let Some(message) = builder.push_line(&line)? {
            log_received(&message);
            return Ok(message);
        }
    }
}

fn redact_line(line: &str) -> String {
    let words: Vec<String> = line
        .split(' ')
        .map(|word| match word.split_once('=') {
            Some((key @ ("PrivateKey" | "ClientAuth"), _)) => format!("{key}=<redacted>"),
            _ => match word.starts_with("x25519:") {
                true => "x25519:<redacted>".to_string(),
                false => word.to_string(),
            },
        })
        .collect();
    let body = words.join(" ");
    match body.split_once('=') {
        Some((key @ ("250-PrivateKey" | "250-ClientAuth"), _)) => {
            format!("{key}=<redacted>")
        }
        _ => body,
    }
}

fn log_received(message: &ControlMessage) {
    if !log::log_enabled!(log::Level::Trace) {
        return;
    }
    let content = message.raw_content().replace("\r\n", "\n");
    let redacted: Vec<String> = content.trim_end().split('\n').map(redact_line).collect();
    let lines: Vec<&str> = redacted.iter().map(String::as_str).collect();
    match lines.len() {
        0..=2 => log::trace!("Received from tor: {}", lines.join("\\n")),
        count if count > 10 => log::trace!(
            "Received from tor:\n{}\n... {} more lines...",
            lines[..10].join("\n"),
            count - 10
        ),
        _ => log::trace!("Received from tor:\n{}", lines.join("\n")),
    }
}
