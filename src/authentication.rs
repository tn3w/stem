use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Component, Path, PathBuf};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::controller::Controller;
use crate::error::{Error, Result};
use crate::response::{ControlMessage, SingleLineResponse, escape_quoted};
use crate::socket::ControlSocket;
use crate::validation::is_hex_digits;
use crate::version::Version;

const CLIENT_HASH_CONSTANT: &[u8] =
    b"Tor safe cookie authentication controller-to-server hash";
const SERVER_HASH_CONSTANT: &[u8] =
    b"Tor safe cookie authentication server-to-controller hash";
const COOKIE_LENGTH: usize = 32;
const DEFAULT_CONTROL_PORTS: [u16; 2] = [9051, 9151];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    None,
    Password,
    Cookie,
    SafeCookie,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieFailure {
    pub message: String,
    pub cookie_path: PathBuf,
    pub is_safecookie: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthenticationError {
    #[error("{0}")]
    Failure(String),
    #[error("{message}")]
    UnrecognizedMethods {
        message: String,
        unknown_methods: Vec<String>,
    },
    #[error("{0}")]
    IncorrectSocketType(String),
    #[error("{0}")]
    OpenAuthRejected(String),
    #[error("{0}")]
    PasswordAuthRejected(String),
    #[error("{0}")]
    IncorrectPassword(String),
    #[error("{0}")]
    MissingPassword(String),
    #[error("{}", .0.message)]
    CookieAuthRejected(CookieFailure),
    #[error("{}", .0.message)]
    IncorrectCookieValue(CookieFailure),
    #[error("{}", .0.message)]
    IncorrectCookieSize(CookieFailure),
    #[error("{}", .0.message)]
    UnreadableCookieFile(CookieFailure),
    #[error("{}", .0.message)]
    AuthChallengeFailed(CookieFailure),
    #[error("{}", .0.message)]
    AuthChallengeUnsupported(CookieFailure),
    #[error("{}", .0.message)]
    UnrecognizedAuthChallengeMethod(CookieFailure),
    #[error("{}", .0.message)]
    AuthSecurityFailure(CookieFailure),
    #[error("{}", .0.message)]
    InvalidClientNonce(CookieFailure),
    #[error("{0}")]
    NoAuthMethods(String),
    #[error("{message}")]
    NoAuthCookie {
        message: String,
        is_safecookie: bool,
    },
}

impl AuthenticationError {
    fn priority(&self) -> usize {
        match self {
            Self::IncorrectSocketType(_) => 0,
            Self::UnrecognizedMethods { .. } => 1,
            Self::MissingPassword(_) => 2,
            Self::IncorrectPassword(_) => 3,
            Self::IncorrectCookieSize(_) => 4,
            Self::UnreadableCookieFile(_) => 5,
            Self::IncorrectCookieValue(_) => 6,
            Self::AuthChallengeUnsupported(_) => 7,
            Self::UnrecognizedAuthChallengeMethod(_) => 8,
            Self::InvalidClientNonce(_) => 9,
            Self::AuthSecurityFailure(_) => 10,
            Self::OpenAuthRejected(_) => 11,
            Self::NoAuthMethods(_) | Self::NoAuthCookie { .. } => 12,
            _ => 13,
        }
    }
}

pub trait ControlChannel: Send + Sync {
    fn request(
        &self,
        message: &str,
    ) -> impl Future<Output = Result<ControlMessage>> + Send;

    fn reconnect(&self) -> impl Future<Output = Result<()>> + Send;

    fn post_authentication(&self) -> impl Future<Output = ()> + Send {
        async {}
    }
}

impl ControlChannel for ControlSocket {
    async fn request(&self, message: &str) -> Result<ControlMessage> {
        self.send(message).await?;
        self.recv().await
    }

    async fn reconnect(&self) -> Result<()> {
        self.connect().await
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProtocolInfoResponse {
    pub protocol_version: u32,
    pub tor_version: Option<Version>,
    pub auth_methods: Vec<AuthMethod>,
    pub unknown_auth_methods: Vec<String>,
    pub cookie_path: Option<String>,
}

impl ProtocolInfoResponse {
    pub fn parse(message: &ControlMessage) -> Result<Self> {
        let mut lines = message.lines();
        if !message.is_ok() || lines.pop().is_none_or(|last| &*last != "OK") {
            return Err(Error::protocol(format!(
                "PROTOCOLINFO response didn't have an OK status:\n{message}"
            )));
        }
        if !lines
            .first()
            .is_some_and(|line| line.starts_with("PROTOCOLINFO"))
        {
            return Err(Error::protocol(format!(
                "Message is not a PROTOCOLINFO response:\n{message}"
            )));
        }
        let mut response = Self::default();
        for mut line in lines {
            match line.pop(false, false)?.as_str() {
                "PROTOCOLINFO" => response.parse_version(&mut line)?,
                "AUTH" => response.parse_auth(&mut line)?,
                "VERSION" => response.parse_tor_version(&mut line)?,
                other => log::debug!(
                    "Unrecognized PROTOCOLINFO line type '{other}', ignoring it: {line}"
                ),
            }
        }
        Ok(response)
    }

    fn parse_version(&mut self, line: &mut crate::response::ControlLine) -> Result<()> {
        if line.is_empty() {
            return Err(Error::protocol(format!(
                "PROTOCOLINFO response's initial line is missing the protocol version: \
                {line}"
            )));
        }
        let version = line.pop(false, false)?;
        self.protocol_version = version.parse().map_err(|_| {
            Error::protocol(format!(
                "PROTOCOLINFO response version is non-numeric: {line}"
            ))
        })?;
        if self.protocol_version != 1 {
            log::info!(
                "We made a PROTOCOLINFO version 1 query but got a version {} response \
                instead.",
                self.protocol_version
            );
        }
        Ok(())
    }

    fn parse_auth(&mut self, line: &mut crate::response::ControlLine) -> Result<()> {
        if !line.is_next_mapping(Some("METHODS"), false, false) {
            return Err(Error::protocol(format!(
                "PROTOCOLINFO response's AUTH line is missing its mandatory 'METHODS' \
                mapping: {line}"
            )));
        }
        let (_, methods) = line.pop_mapping(false, false)?;
        for method in methods.split(',') {
            let known = match method {
                "NULL" => Some(AuthMethod::None),
                "HASHEDPASSWORD" => Some(AuthMethod::Password),
                "COOKIE" => Some(AuthMethod::Cookie),
                "SAFECOOKIE" => Some(AuthMethod::SafeCookie),
                _ => None,
            };
            match known {
                Some(method) => self.auth_methods.push(method),
                None => {
                    log::info!(
                        "PROTOCOLINFO response included a type of authentication that \
                        we don't recognize: {method}"
                    );
                    self.unknown_auth_methods.push(method.to_string());
                    if !self.auth_methods.contains(&AuthMethod::Unknown) {
                        self.auth_methods.push(AuthMethod::Unknown);
                    }
                }
            }
        }
        if line.is_next_mapping(Some("COOKIEFILE"), true, true) {
            let (_, path) = line.pop_mapping_bytes(true, true)?;
            self.cookie_path = Some(String::from_utf8_lossy(&path).into_owned());
        }
        Ok(())
    }

    fn parse_tor_version(
        &mut self,
        line: &mut crate::response::ControlLine,
    ) -> Result<()> {
        if !line.is_next_mapping(Some("Tor"), true, false) {
            return Err(Error::protocol(format!(
                "PROTOCOLINFO response's VERSION line is missing its mandatory tor \
                version mapping: {line}"
            )));
        }
        let (_, version) = line.pop_mapping(true, false)?;
        self.tor_version = Some(
            Version::new(&version).map_err(|error| Error::protocol(error.to_string()))?,
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AuthChallengeResponse {
    pub server_hash: Vec<u8>,
    pub server_nonce: Vec<u8>,
}

impl AuthChallengeResponse {
    pub fn parse(message: &ControlMessage) -> Result<Self> {
        if !message.is_ok() {
            return Err(Error::protocol(format!(
                "AUTHCHALLENGE response didn't have an OK status:\n{message}"
            )));
        }
        if message.len() > 1 {
            return Err(Error::protocol(format!(
                "Received multiline AUTHCHALLENGE response:\n{message}"
            )));
        }
        let mut line = message.lines().remove(0);
        if line.pop(false, false)? != "AUTHCHALLENGE" {
            return Err(Error::protocol(format!(
                "Message is not an AUTHCHALLENGE response ({message})"
            )));
        }
        let server_hash = Self::pop_hex(&mut line, "SERVERHASH")?;
        let server_nonce = Self::pop_hex(&mut line, "SERVERNONCE")?;
        Ok(Self {
            server_hash,
            server_nonce,
        })
    }

    fn pop_hex(line: &mut crate::response::ControlLine, key: &str) -> Result<Vec<u8>> {
        if !line.is_next_mapping(Some(key), false, false) {
            return Err(Error::protocol(format!("Missing {key} mapping: {line}")));
        }
        let (_, value) = line.pop_mapping(false, false)?;
        match is_hex_digits(&value, 64) {
            true => Ok(hex::decode(&value)
                .map_err(|error| Error::protocol(error.to_string()))?),
            false => Err(Error::protocol(format!(
                "{key} has an invalid value: {value}"
            ))),
        }
    }
}

pub async fn get_protocolinfo<C: ControlChannel>(
    channel: &C,
) -> Result<ProtocolInfoResponse> {
    let first_attempt = channel.request("PROTOCOLINFO 1").await;
    let message = match first_attempt {
        Ok(message) if message.to_string() != "Authentication required." => message,
        _ => {
            channel.reconnect().await?;
            channel
                .request("PROTOCOLINFO 1")
                .await
                .map_err(|error| match error {
                    Error::SocketClosed => Error::Socket("socket closed".to_string()),
                    other => other,
                })?
        }
    };
    ProtocolInfoResponse::parse(&message)
}

fn fail(error: AuthenticationError) -> Error {
    Error::Authentication(error)
}

fn cookie_failure(
    message: impl Into<String>,
    path: &Path,
    is_safecookie: bool,
) -> CookieFailure {
    CookieFailure {
        message: message.into(),
        cookie_path: path.to_path_buf(),
        is_safecookie,
    }
}

fn resolve_cookie_path(cookie_path: &str, chroot_path: Option<&Path>) -> Result<PathBuf> {
    let Some(chroot) = chroot_path else {
        return Ok(PathBuf::from(cookie_path));
    };
    let relative = Path::new(cookie_path)
        .strip_prefix("/")
        .unwrap_or(Path::new(cookie_path));
    if relative
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(fail(AuthenticationError::Failure(format!(
            "Refusing to read a cookie path that escapes the chroot: {cookie_path}"
        ))));
    }
    Ok(chroot.join(relative))
}

pub async fn authenticate<C: ControlChannel>(
    channel: &C,
    password: Option<&str>,
    chroot_path: Option<&Path>,
    protocolinfo: Option<ProtocolInfoResponse>,
) -> Result<()> {
    let protocolinfo = match protocolinfo {
        Some(protocolinfo) => protocolinfo,
        None => match get_protocolinfo(channel).await {
            Ok(protocolinfo) => protocolinfo,
            Err(Error::Protocol(_)) => {
                return Err(fail(AuthenticationError::IncorrectSocketType(
                    "unable to use the control socket".to_string(),
                )));
            }
            Err(Error::Socket(message)) => {
                return Err(fail(AuthenticationError::Failure(format!(
                    "socket connection failed ({message})"
                ))));
            }
            Err(Error::SocketClosed) => {
                return Err(fail(AuthenticationError::Failure(
                    "socket connection failed (socket closed)".to_string(),
                )));
            }
            Err(other) => return Err(other),
        },
    };

    let (methods, mut failures) = plan_methods(&protocolinfo, password)?;
    for method in [
        AuthMethod::None,
        AuthMethod::Password,
        AuthMethod::SafeCookie,
        AuthMethod::Cookie,
    ] {
        if !methods.contains(&method) {
            continue;
        }
        let attempt =
            attempt_method(channel, method, password, chroot_path, &protocolinfo).await;
        match attempt {
            Ok(()) => {
                channel.post_authentication().await;
                return Ok(());
            }
            Err(Error::Authentication(error)) => failures.push(error),
            Err(error) => failures.push(AuthenticationError::Failure(error.to_string())),
        }
    }
    let chosen = failures
        .into_iter()
        .min_by_key(AuthenticationError::priority)
        .unwrap_or_else(|| {
            AuthenticationError::Failure("Authentication failed".to_string())
        });
    Err(fail(chosen))
}

fn plan_methods(
    protocolinfo: &ProtocolInfoResponse,
    password: Option<&str>,
) -> Result<(Vec<AuthMethod>, Vec<AuthenticationError>)> {
    let mut methods = protocolinfo.auth_methods.clone();
    let mut failures = Vec::new();
    if methods.is_empty() {
        return Err(fail(AuthenticationError::NoAuthMethods(
            "our PROTOCOLINFO response did not have any methods for authenticating"
                .to_string(),
        )));
    }
    if methods.contains(&AuthMethod::Unknown) {
        methods.retain(|method| *method != AuthMethod::Unknown);
        let unknown = &protocolinfo.unknown_auth_methods;
        let plural = if unknown.len() > 1 { "s" } else { "" };
        if methods.is_empty() {
            failures.push(AuthenticationError::UnrecognizedMethods {
                message: format!(
                    "unrecognized authentication method{plural} ({})",
                    unknown.join(", ")
                ),
                unknown_methods: unknown.clone(),
            });
        } else {
            log::debug!(
                "Authenticating to a socket with unrecognized auth method{plural}, \
                ignoring them: {}",
                unknown.join(", ")
            );
        }
    }
    if protocolinfo.cookie_path.is_none() {
        for cookie_method in [AuthMethod::Cookie, AuthMethod::SafeCookie] {
            if methods.contains(&cookie_method) {
                methods.retain(|method| *method != cookie_method);
                failures.push(AuthenticationError::NoAuthCookie {
                    message: "our PROTOCOLINFO response did not have the location of \
                        our authentication cookie"
                        .to_string(),
                    is_safecookie: cookie_method == AuthMethod::SafeCookie,
                });
            }
        }
    }
    if methods.contains(&AuthMethod::Password) && password.is_none() {
        methods.retain(|method| *method != AuthMethod::Password);
        failures.push(AuthenticationError::MissingPassword(
            "no passphrase provided".to_string(),
        ));
    }
    Ok((methods, failures))
}

async fn attempt_method<C: ControlChannel>(
    channel: &C,
    method: AuthMethod,
    password: Option<&str>,
    chroot_path: Option<&Path>,
    protocolinfo: &ProtocolInfoResponse,
) -> Result<()> {
    match method {
        AuthMethod::None => authenticate_none(channel, false).await,
        AuthMethod::Password => {
            authenticate_password(channel, password.unwrap_or_default(), false).await
        }
        AuthMethod::Cookie | AuthMethod::SafeCookie => {
            let cookie_path = resolve_cookie_path(
                protocolinfo.cookie_path.as_deref().unwrap_or_default(),
                chroot_path,
            )?;
            match method {
                AuthMethod::SafeCookie => {
                    authenticate_safecookie(channel, &cookie_path, false).await
                }
                _ => authenticate_cookie(channel, &cookie_path, false).await,
            }
        }
        AuthMethod::Unknown => Ok(()),
    }
}

async fn reset_after_failure<C: ControlChannel>(channel: &C) {
    let _ = channel.reconnect().await;
}

async fn send_authenticate<C: ControlChannel>(
    channel: &C,
    message: &str,
) -> Result<SingleLineResponse> {
    let response = channel.request(message).await?;
    Ok(SingleLineResponse {
        code: response.status_code().to_string(),
        message: response.to_string(),
        raw: response,
    })
}

pub async fn authenticate_none<C: ControlChannel>(
    channel: &C,
    suppress_controller_errors: bool,
) -> Result<()> {
    match send_authenticate(channel, "AUTHENTICATE").await {
        Ok(response) if response.raw.to_string() == "OK" => Ok(()),
        Ok(response) => {
            reset_after_failure(channel).await;
            Err(fail(AuthenticationError::OpenAuthRejected(
                response.raw.to_string(),
            )))
        }
        Err(error) => {
            reset_after_failure(channel).await;
            match suppress_controller_errors {
                false => Err(error),
                true => Err(fail(AuthenticationError::OpenAuthRejected(format!(
                    "Socket failed ({error})"
                )))),
            }
        }
    }
}

pub async fn authenticate_password<C: ControlChannel>(
    channel: &C,
    password: &str,
    suppress_controller_errors: bool,
) -> Result<()> {
    let command = Zeroizing::new(format!("AUTHENTICATE {}", escape_quoted(password)));
    match send_authenticate(channel, &command).await {
        Ok(response) if response.raw.to_string() == "OK" => Ok(()),
        Ok(response) => {
            reset_after_failure(channel).await;
            let text = response.raw.to_string();
            Err(fail(
                match text.contains("Password did not match HashedControlPassword") {
                    true => AuthenticationError::IncorrectPassword(text),
                    false => AuthenticationError::PasswordAuthRejected(text),
                },
            ))
        }
        Err(error) => {
            reset_after_failure(channel).await;
            match suppress_controller_errors {
                false => Err(error),
                true => Err(fail(AuthenticationError::PasswordAuthRejected(format!(
                    "Socket failed ({error})"
                )))),
            }
        }
    }
}

fn read_cookie(cookie_path: &Path, is_safecookie: bool) -> Result<Zeroizing<Vec<u8>>> {
    let unreadable = |message: String| {
        fail(AuthenticationError::UnreadableCookieFile(cookie_failure(
            message,
            cookie_path,
            is_safecookie,
        )))
    };
    let mut file =
        std::fs::File::open(cookie_path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => unreadable(format!(
                "Authentication failed: '{}' doesn't exist",
                cookie_path.display()
            )),
            _ => unreadable(format!(
                "Authentication failed: unable to read '{}' ({error})",
                cookie_path.display()
            )),
        })?;
    let metadata = file.metadata().map_err(|error| {
        unreadable(format!(
            "Authentication failed: unable to read '{}' ({error})",
            cookie_path.display()
        ))
    })?;
    if !metadata.is_file() || metadata.len() != COOKIE_LENGTH as u64 {
        return Err(fail(AuthenticationError::IncorrectCookieSize(
            cookie_failure(
                format!(
                    "Authentication failed: authentication cookie '{}' is the wrong \
                    size ({} bytes instead of {COOKIE_LENGTH})",
                    cookie_path.display(),
                    metadata.len()
                ),
                cookie_path,
                is_safecookie,
            ),
        )));
    }
    let mut cookie = Zeroizing::new(Vec::with_capacity(COOKIE_LENGTH + 1));
    (&mut file)
        .take(COOKIE_LENGTH as u64 + 1)
        .read_to_end(&mut cookie)
        .map_err(|error| {
            unreadable(format!(
                "Authentication failed: unable to read '{}' ({error})",
                cookie_path.display()
            ))
        })?;
    match cookie.len() == COOKIE_LENGTH {
        true => Ok(cookie),
        false => Err(fail(AuthenticationError::IncorrectCookieSize(
            cookie_failure(
                format!(
                    "Authentication failed: authentication cookie '{}' changed size \
                    while reading",
                    cookie_path.display()
                ),
                cookie_path,
                is_safecookie,
            ),
        ))),
    }
}

pub async fn authenticate_cookie<C: ControlChannel>(
    channel: &C,
    cookie_path: &Path,
    suppress_controller_errors: bool,
) -> Result<()> {
    let cookie = read_cookie(cookie_path, false)?;
    let command = Zeroizing::new(format!("AUTHENTICATE {}", hex::encode(&*cookie)));
    let rejected = |message: String| {
        fail(AuthenticationError::CookieAuthRejected(cookie_failure(
            message,
            cookie_path,
            false,
        )))
    };
    match send_authenticate(channel, &command).await {
        Ok(response) if response.raw.to_string() == "OK" => Ok(()),
        Ok(response) => {
            reset_after_failure(channel).await;
            let text = response.raw.to_string();
            let mismatch = text.contains("*or* authentication cookie.")
                || text.contains("Authentication cookie did not match expected value.");
            Err(match mismatch {
                true => fail(AuthenticationError::IncorrectCookieValue(cookie_failure(
                    text,
                    cookie_path,
                    false,
                ))),
                false => rejected(text),
            })
        }
        Err(error) => {
            reset_after_failure(channel).await;
            match suppress_controller_errors {
                false => Err(error),
                true => Err(rejected(format!("Socket failed ({error})"))),
            }
        }
    }
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

pub async fn authenticate_safecookie<C: ControlChannel>(
    channel: &C,
    cookie_path: &Path,
    suppress_controller_errors: bool,
) -> Result<()> {
    let cookie = read_cookie(cookie_path, true)?;
    let client_nonce: [u8; 32] = rand::random();
    let failure = |message: String| cookie_failure(message, cookie_path, true);
    let challenge = match channel
        .request(&format!(
            "AUTHCHALLENGE SAFECOOKIE {}",
            hex::encode(client_nonce)
        ))
        .await
    {
        Ok(challenge) => challenge,
        Err(error) => {
            reset_after_failure(channel).await;
            return match suppress_controller_errors {
                false => Err(error),
                true => Err(fail(AuthenticationError::AuthChallengeFailed(failure(
                    format!("Socket failed ({error})"),
                )))),
            };
        }
    };
    if !challenge.is_ok() {
        reset_after_failure(channel).await;
        return Err(fail(challenge_failure(&challenge.to_string(), failure)));
    }
    let challenge = AuthChallengeResponse::parse(&challenge).map_err(|error| {
        match suppress_controller_errors {
            false => error,
            true => fail(AuthenticationError::AuthChallengeFailed(failure(format!(
                "Unable to parse AUTHCHALLENGE response: {error}"
            )))),
        }
    })?;
    let parts: [&[u8]; 3] = [&cookie, &client_nonce, &challenge.server_nonce];
    let expected_server_hash = hmac_sha256(SERVER_HASH_CONSTANT, &parts);
    if !bool::from(expected_server_hash.ct_eq(&challenge.server_hash)) {
        return Err(fail(AuthenticationError::AuthSecurityFailure(failure(
            "Tor provided the wrong server nonce".to_string(),
        ))));
    }
    let client_hash = hmac_sha256(CLIENT_HASH_CONSTANT, &parts);
    let command = format!("AUTHENTICATE {}", hex::encode(client_hash));
    let rejected =
        |message: String| fail(AuthenticationError::CookieAuthRejected(failure(message)));
    match send_authenticate(channel, &command).await {
        Ok(response) if response.raw.is_ok() => Ok(()),
        Ok(response) => {
            reset_after_failure(channel).await;
            let text = response.raw.to_string();
            let mismatch = text.contains("*or* authentication cookie.")
                || text.contains("Safe cookie response did not match expected value");
            Err(match mismatch {
                true => fail(AuthenticationError::IncorrectCookieValue(failure(text))),
                false => rejected(text),
            })
        }
        Err(error) => {
            reset_after_failure(channel).await;
            match suppress_controller_errors {
                false => Err(error),
                true => Err(rejected(format!("Socket failed ({error})"))),
            }
        }
    }
}

fn challenge_failure(
    text: &str,
    failure: impl Fn(String) -> CookieFailure,
) -> AuthenticationError {
    let details = failure(text.to_string());
    if text.contains("Authentication required.") {
        AuthenticationError::AuthChallengeUnsupported(failure(
            "SAFECOOKIE authentication isn't supported".to_string(),
        ))
    } else if text.contains("AUTHCHALLENGE only supports") {
        AuthenticationError::UnrecognizedAuthChallengeMethod(details)
    } else if text.contains("Invalid base16 client nonce") {
        AuthenticationError::InvalidClientNonce(details)
    } else if text.contains("Cookie authentication is disabled") {
        AuthenticationError::CookieAuthRejected(details)
    } else {
        AuthenticationError::AuthChallengeFailed(details)
    }
}

#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub control_port: Option<(IpAddr, Option<u16>)>,
    pub control_socket: Option<PathBuf>,
    pub password: Option<String>,
    pub password_prompt: bool,
    pub chroot_path: Option<PathBuf>,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            control_port: Some((IpAddr::V4(Ipv4Addr::LOCALHOST), None)),
            control_socket: Some(PathBuf::from("/var/run/tor/control")),
            password: None,
            password_prompt: false,
            chroot_path: None,
        }
    }
}

async fn control_port_connection(
    address: IpAddr,
    port: Option<u16>,
) -> Result<ControlSocket> {
    let ports: Vec<u16> = match port {
        Some(port) => vec![port],
        None => DEFAULT_CONTROL_PORTS.to_vec(),
    };
    let mut last_error = Error::Socket("no control port to try".to_string());
    for port in ports {
        let socket = ControlSocket::port(address, port);
        match socket.connect().await {
            Ok(()) => return Ok(socket),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

pub async fn connect(options: ConnectOptions) -> Result<Controller> {
    if options.control_port.is_none() && options.control_socket.is_none() {
        return Err(Error::invalid_input(
            "Neither a control port nor control socket were provided. Nothing to \
            connect to.",
        ));
    }
    let mut error_message = String::new();
    let mut socket = None;
    if let Some(path) = &options.control_socket {
        match path.exists() {
            true => match ControlSocket::file(path).connect_and_return().await {
                Ok(connected) => socket = Some(connected),
                Err(error) => {
                    error_message =
                        format!("Unable to connect to '{}': {error}", path.display())
                }
            },
            false => {
                error_message = format!(
                    "The socket file you specified ({}) doesn't exist",
                    path.display()
                )
            }
        }
    }
    if let (None, Some((address, port))) = (&socket, options.control_port) {
        match control_port_connection(address, port).await {
            Ok(connected) => socket = Some(connected),
            Err(error) => {
                error_message = format!(
                    "Unable to connect to {address}:{}: {error}",
                    port.map_or("default".to_string(), |port| port.to_string())
                )
            }
        }
    }
    let Some(socket) = socket else {
        if options.control_socket.is_some() && options.control_port.is_some() {
            error_message =
                "Unable to connect to tor. Are you sure it's running?".to_string();
        }
        return Err(Error::Socket(error_message));
    };
    authenticate_new_controller(
        Controller::new(socket),
        options.password,
        options.password_prompt,
        options.chroot_path,
    )
    .await
}

impl ControlSocket {
    async fn connect_and_return(self) -> Result<Self> {
        self.connect().await?;
        Ok(self)
    }
}

pub async fn connect_port(
    address: IpAddr,
    port: u16,
    password: Option<String>,
    chroot_path: Option<PathBuf>,
) -> Result<Controller> {
    let socket = ControlSocket::port(address, port)
        .connect_and_return()
        .await?;
    authenticate_new_controller(Controller::new(socket), password, true, chroot_path)
        .await
}

pub async fn connect_socket_file(
    path: impl Into<PathBuf>,
    password: Option<String>,
    chroot_path: Option<PathBuf>,
) -> Result<Controller> {
    let socket = ControlSocket::file(path).connect_and_return().await?;
    authenticate_new_controller(Controller::new(socket), password, true, chroot_path)
        .await
}

fn prompt_password() -> Option<String> {
    rpassword::prompt_password("Tor controller password: ").ok()
}

async fn authenticate_new_controller(
    controller: Controller,
    password: Option<String>,
    password_prompt: bool,
    chroot_path: Option<PathBuf>,
) -> Result<Controller> {
    let mut password = password.map(Zeroizing::new);
    loop {
        let outcome = authenticate(
            &controller,
            password.as_ref().map(|secret| secret.as_str()),
            chroot_path.as_deref(),
            None,
        )
        .await;
        match outcome {
            Ok(()) => return Ok(controller),
            Err(Error::Authentication(AuthenticationError::MissingPassword(_)))
                if password.is_none() && password_prompt =>
            {
                match prompt_password() {
                    Some(entered) => password = Some(Zeroizing::new(entered)),
                    None => {
                        controller.close().await;
                        return Err(Error::Authentication(
                            AuthenticationError::MissingPassword(
                                "Tor requires a password to authenticate".to_string(),
                            ),
                        ));
                    }
                }
            }
            Err(error) => {
                controller.close().await;
                return Err(describe_connect_error(&controller, error));
            }
        }
    }
}

fn describe_connect_error(controller: &Controller, error: Error) -> Error {
    match error {
        Error::Authentication(AuthenticationError::IncorrectSocketType(_)) => {
            let hint = match controller.socket().control_port() {
                Some(address) => format!(
                    "Please check in your torrc that {} is the ControlPort. Maybe you \
                    configured it to be the ORPort or SocksPort instead?",
                    address.port()
                ),
                None => "Unable to connect to tor. Are you sure the interface you \
                    specified belongs to tor?"
                    .to_string(),
            };
            Error::Authentication(AuthenticationError::IncorrectSocketType(hint))
        }
        Error::Authentication(AuthenticationError::MissingPassword(_)) => {
            Error::Authentication(AuthenticationError::MissingPassword(
                "Tor requires a password to authenticate".to_string(),
            ))
        }
        other => other,
    }
}
