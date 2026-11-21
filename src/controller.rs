use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chrono::NaiveDateTime;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::JoinHandle;

use crate::address::{is_valid_ipv4_address, is_valid_ipv6_address, parse_port};
use crate::authentication::{
    self, ControlChannel, ProtocolInfoResponse, get_protocolinfo,
};
use crate::descriptor::microdescriptor::Microdescriptor;
use crate::descriptor::router_status::RouterStatusEntryV3;
use crate::descriptor::server::RelayServerDescriptor;
use crate::enumerations::{CircPurpose, CircStatus, RelayEndReason, Signal, string_enum};
use crate::error::{Error, Result};
use crate::events::{
    CircuitEvent, Event, EventData, EventType, StreamEvent, parse_circuit_entry,
};
use crate::exit_policy::{ExitPolicy, get_config_policy_from};
use crate::formatting::parse_timestamp;
use crate::onion_services::HiddenServiceConfig;
use crate::process_inspection;
use crate::response::{
    ControlLine, ControlMessage, GetConfResponse, GetInfoResponse, MapAddressResponse,
    SingleLineResponse, escape_quoted,
};
use crate::socket::ControlSocket;
use crate::validation::{is_valid_fingerprint, is_valid_nickname};
use crate::version::{Requirement, Version};

pub type ListenerId = u64;
pub type EventListener = Arc<dyn Fn(&Event) + Send + Sync>;
pub type StatusListener = Arc<dyn Fn(State, SystemTime) + Send + Sync>;

const IMMUTABLE_CONFIG_OPTIONS: [&str; 15] = [
    "acceldir",
    "accelname",
    "datadirectory",
    "disableallswap",
    "disabledebuggerattachment",
    "hardwareaccel",
    "hiddenservicenonanonymousmode",
    "hiddenservicesinglehopmode",
    "keepbindcapabilities",
    "pidfile",
    "rundaemon",
    "sandbox",
    "syslogidentitytag",
    "tokenbucketrefillinterval",
    "user",
];

const MAPPED_CONFIG_KEYS: [(&str, &str); 5] = [
    ("hiddenservicedir", "HiddenServiceOptions"),
    ("hiddenserviceport", "HiddenServiceOptions"),
    ("hiddenserviceversion", "HiddenServiceOptions"),
    ("hiddenserviceauthorizeclient", "HiddenServiceOptions"),
    ("hiddenserviceoptions", "HiddenServiceOptions"),
];

const CACHEABLE_GETINFO_PARAMS: [&str; 12] = [
    "address",
    "version",
    "config-file",
    "exit-policy/default",
    "fingerprint",
    "config/names",
    "config/defaults",
    "info/names",
    "events/names",
    "features/names",
    "process/descriptor-limit",
    "status/version/current",
];

const CACHEABLE_GETINFO_UNTIL_SETCONF: [&str; 1] = ["accounting/enabled"];

const UNCACHEABLE_GETCONF_PARAMS: [&str; 5] = [
    "hiddenserviceoptions",
    "hiddenservicedir",
    "hiddenserviceport",
    "hiddenserviceversion",
    "hiddenserviceauthorizeclient",
];

const SERVER_DESCRIPTORS_UNSUPPORTED: &str = "Tor is currently not configured to \
    retrieve server descriptors. As of Tor version 0.2.3.25 it downloads \
    microdescriptors instead unless you set 'UseMicrodescriptors 0' in your torrc.";

const NEWNYM_COOLDOWN: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Init,
    Reset,
    Closed,
}

string_enum!(ListenerType {
    Or = "OR",
    Dir = "DIR",
    Socks = "SOCKS",
    Trans = "TRANS",
    Natd = "NATD",
    Dns = "DNS",
    Control = "CONTROL",
    ExtOr = "EXTOR",
    HttpTunnel = "HTTPTUNNEL",
});

#[derive(Debug, Clone, PartialEq)]
pub struct AccountingStats {
    pub retrieved: f64,
    pub status: String,
    pub interval_end: NaiveDateTime,
    pub time_until_reset: u64,
    pub read_bytes: u64,
    pub read_bytes_left: u64,
    pub read_limit: u64,
    pub written_bytes: u64,
    pub write_bytes_left: u64,
    pub write_limit: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserTrafficAllowed {
    pub inbound: bool,
    pub outbound: bool,
}

#[derive(Debug, Clone)]
pub enum ConfValue {
    Unset,
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Default)]
struct Cache {
    getinfo: HashMap<String, Vec<u8>>,
    getconf: HashMap<String, Vec<String>>,
    listeners: HashMap<String, Vec<(IpAddr, u16)>>,
    version: Option<Version>,
    exit_policy: Option<ExitPolicy>,
    user: Option<String>,
    pid: Option<u32>,
    start_time: Option<f64>,
    custom_options: Option<HashMap<String, String>>,
    hidden_service_conf: Option<Vec<HiddenServiceConfig>>,
    geoip_unavailable: Option<bool>,
    last_newnym: Option<Instant>,
}

#[derive(Default)]
struct EventListeners {
    by_type: HashMap<EventType, Vec<(ListenerId, EventListener)>>,
}

pub(crate) struct Shared {
    pub(crate) socket: ControlSocket,
    cache: Mutex<Cache>,
    caching_enabled: AtomicBool,
    event_listeners: Mutex<EventListeners>,
    status_listeners: Mutex<Vec<(ListenerId, StatusListener)>>,
    next_listener_id: AtomicU64,
    enabled_features: Mutex<Vec<String>>,
    last_heartbeat: Mutex<Option<SystemTime>>,
    is_authenticated: AtomicBool,
    is_connected: AtomicBool,
    last_address_error: Mutex<Option<Error>>,
    last_fingerprint_error: Mutex<Option<Error>>,
}

type ReplyReceiver = mpsc::UnboundedReceiver<Result<ControlMessage>>;

pub struct Controller {
    pub(crate) shared: Arc<Shared>,
    replies: AsyncMutex<Option<ReplyReceiver>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    request_timeout: Mutex<Option<Duration>>,
}

impl Shared {
    fn cache(&self) -> Option<std::sync::MutexGuard<'_, Cache>> {
        match self.caching_enabled.load(Ordering::SeqCst) {
            true => Some(self.cache.lock().unwrap()),
            false => None,
        }
    }

    fn clear_cache(&self) {
        *self.cache.lock().unwrap() = Cache::default();
    }

    fn notify_status(&self, state: State) {
        let timestamp = SystemTime::now();
        let listeners: Vec<StatusListener> = self
            .status_listeners
            .lock()
            .unwrap()
            .iter()
            .map(|(_, listener)| listener.clone())
            .collect();
        for listener in listeners {
            if catch_unwind(AssertUnwindSafe(|| listener(state, timestamp))).is_err() {
                log::warn!("Status listener raised an uncaught panic");
            }
        }
    }

    fn notify_closed(&self) {
        if self.is_connected.swap(false, Ordering::SeqCst) {
            self.is_authenticated.store(false, Ordering::SeqCst);
            self.notify_status(State::Closed);
        }
    }

    fn handle_event(&self, message: ControlMessage) {
        let event = match Event::parse(message.clone()) {
            Ok(event) => event,
            Err(error) => {
                log::error!("Tor sent a malformed event ({error}): {message}");
                Event::malformed(message, error.to_string())
            }
        };
        self.update_state_for(&event);
        let listener_type = event.listener_type();
        let listeners: Vec<EventListener> = self
            .event_listeners
            .lock()
            .unwrap()
            .by_type
            .get(&listener_type)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(_, listener)| listener.clone())
                    .collect()
            })
            .unwrap_or_default();
        for listener in listeners {
            if catch_unwind(AssertUnwindSafe(|| listener(&event))).is_err() {
                log::warn!("Event listener raised an uncaught panic: {}", event.message);
            }
        }
    }

    fn update_state_for(&self, event: &Event) {
        match &event.data {
            EventData::Signal(signal) if signal.signal == Signal::Reload => {
                self.clear_cache();
                self.notify_status(State::Reset);
            }
            EventData::ConfChanged(changed) => {
                let Some(mut cache) = self.cache() else {
                    return;
                };
                for (key, values) in &changed.changed {
                    cache.getconf.insert(key.to_lowercase(), values.clone());
                }
                for key in &changed.unset {
                    cache.getconf.insert(key.to_lowercase(), Vec::new());
                }
                for key in UNCACHEABLE_GETCONF_PARAMS {
                    cache.getconf.remove(key);
                }
                let keys: Vec<&String> = changed.config.keys().collect();
                Self::invalidate_after_conf_change(&mut cache, &keys);
            }
            EventData::Status(status)
                if matches!(
                    status.action.as_str(),
                    "EXTERNAL_ADDRESS" | "DNS_USELESS"
                ) =>
            {
                if let Some(mut cache) = self.cache() {
                    cache.exit_policy = None;
                    cache.getinfo.remove("address");
                }
                *self.last_address_error.lock().unwrap() = None;
            }
            _ => {}
        }
    }

    fn invalidate_after_conf_change(cache: &mut Cache, keys: &[&String]) {
        if keys.iter().any(|key| key.to_lowercase().contains("hidden")) {
            cache.hidden_service_conf = None;
        }
        for key in CACHEABLE_GETINFO_UNTIL_SETCONF {
            cache.getinfo.remove(key);
        }
        cache.listeners.clear();
        cache.custom_options = None;
        cache.exit_policy = None;
    }

    fn active_event_types(&self) -> Vec<EventType> {
        let mut types: Vec<EventType> = self
            .event_listeners
            .lock()
            .unwrap()
            .by_type
            .keys()
            .cloned()
            .collect();
        for internal in [
            EventType::Signal,
            EventType::ConfChanged,
            EventType::StatusServer,
        ] {
            if !types.contains(&internal) {
                types.push(internal);
            }
        }
        types.retain(|event_type| *event_type != EventType::MalformedEvents);
        types.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        types
    }
}

async fn reader_loop(
    shared: Arc<Shared>,
    replies: mpsc::UnboundedSender<Result<ControlMessage>>,
    events: mpsc::UnboundedSender<ControlMessage>,
) {
    loop {
        match shared.socket.recv().await {
            Ok(message) => {
                *shared.last_heartbeat.lock().unwrap() = Some(SystemTime::now());
                match message.is_event() {
                    true => {
                        let _ = events.send(message);
                    }
                    false => {
                        let _ = replies.send(Ok(message));
                    }
                }
            }
            Err(error) => {
                let is_alive = shared.socket.is_alive();
                let _ = replies.send(Err(error));
                if !is_alive {
                    shared.notify_closed();
                    break;
                }
            }
        }
    }
}

async fn event_loop(
    shared: Arc<Shared>,
    mut events: mpsc::UnboundedReceiver<ControlMessage>,
) {
    while let Some(message) = events.recv().await {
        shared.handle_event(message);
    }
}

fn validate_token(value: &str, label: &str) -> Result<()> {
    let is_valid = !value.is_empty()
        && value
            .chars()
            .all(|character| !character.is_whitespace() && !character.is_control());
    match is_valid {
        true => Ok(()),
        false => Err(Error::invalid_input(format!(
            "{label} can't be empty or contain whitespace or control characters: \
            {value:?}"
        ))),
    }
}

pub(crate) fn validate_option_name(name: &str) -> Result<()> {
    let is_valid = !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'/' | b'.' | b'-')
        });
    match is_valid {
        true => Ok(()),
        false => Err(Error::invalid_input(format!(
            "'{name}' isn't a valid configuration option name"
        ))),
    }
}

fn unix_time() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

impl ControlChannel for Controller {
    async fn request(&self, message: &str) -> Result<ControlMessage> {
        self.msg(message).await
    }

    async fn reconnect(&self) -> Result<()> {
        self.connect().await
    }

    async fn post_authentication(&self) {
        self.run_post_authentication().await;
    }
}

impl Controller {
    pub fn new(socket: ControlSocket) -> Self {
        let controller = Self {
            shared: Arc::new(Shared {
                socket,
                cache: Mutex::new(Cache::default()),
                caching_enabled: AtomicBool::new(true),
                event_listeners: Mutex::new(EventListeners::default()),
                status_listeners: Mutex::new(Vec::new()),
                next_listener_id: AtomicU64::new(1),
                enabled_features: Mutex::new(Vec::new()),
                last_heartbeat: Mutex::new(None),
                is_authenticated: AtomicBool::new(false),
                is_connected: AtomicBool::new(false),
                last_address_error: Mutex::new(None),
                last_fingerprint_error: Mutex::new(None),
            }),
            replies: AsyncMutex::new(None),
            tasks: Mutex::new(Vec::new()),
            request_timeout: Mutex::new(None),
        };
        if controller.shared.socket.is_alive() {
            controller.launch_tasks(false);
        }
        controller
    }

    pub async fn from_port(address: IpAddr, port: Option<u16>) -> Result<Self> {
        let ports: Vec<u16> = match port {
            Some(port) => vec![port],
            None => vec![9051, 9151],
        };
        let mut last_error = Error::Socket("no control port to try".to_string());
        for port in ports {
            let socket = ControlSocket::port(address, port);
            match socket.connect().await {
                Ok(()) => return Ok(Self::new(socket)),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    pub async fn from_socket_file(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        let socket = ControlSocket::file(path);
        socket.connect().await?;
        Ok(Self::new(socket))
    }

    fn launch_tasks(&self, notify_init: bool) {
        let (reply_sender, reply_receiver) = mpsc::unbounded_channel();
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        let reader =
            tokio::spawn(reader_loop(self.shared.clone(), reply_sender, event_sender));
        let events = tokio::spawn(event_loop(self.shared.clone(), event_receiver));
        let mut tasks = self.tasks.lock().unwrap();
        tasks.drain(..).for_each(|task| task.abort());
        tasks.extend([reader, events]);
        drop(tasks);
        if let Ok(mut replies) = self.replies.try_lock() {
            *replies = Some(reply_receiver);
        }
        self.shared.is_connected.store(true, Ordering::SeqCst);
        if notify_init {
            self.shared.notify_status(State::Init);
        }
    }

    pub async fn connect(&self) -> Result<()> {
        let mut replies = self.replies.lock().await;
        self.shared.socket.connect().await?;
        self.shared.is_authenticated.store(false, Ordering::SeqCst);
        let (reply_sender, reply_receiver) = mpsc::unbounded_channel();
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        let reader =
            tokio::spawn(reader_loop(self.shared.clone(), reply_sender, event_sender));
        let events = tokio::spawn(event_loop(self.shared.clone(), event_receiver));
        let mut tasks = self.tasks.lock().unwrap();
        tasks.drain(..).for_each(|task| task.abort());
        tasks.extend([reader, events]);
        drop(tasks);
        *replies = Some(reply_receiver);
        self.shared.is_connected.store(true, Ordering::SeqCst);
        self.shared.notify_status(State::Init);
        Ok(())
    }

    pub async fn close(&self) {
        self.shared.clear_cache();
        self.shared.socket.close().await;
        self.shared.notify_closed();
    }

    pub fn socket(&self) -> &ControlSocket {
        &self.shared.socket
    }

    pub fn is_alive(&self) -> bool {
        self.shared.socket.is_alive()
    }

    pub fn is_localhost(&self) -> bool {
        self.shared.socket.is_localhost()
    }

    pub fn connection_time(&self) -> SystemTime {
        self.shared.socket.connection_time()
    }

    pub fn is_authenticated(&self) -> bool {
        self.is_alive() && self.shared.is_authenticated.load(Ordering::SeqCst)
    }

    pub fn latest_heartbeat(&self) -> Option<SystemTime> {
        *self.shared.last_heartbeat.lock().unwrap()
    }

    pub fn set_request_timeout(&self, timeout: Option<Duration>) {
        *self.request_timeout.lock().unwrap() = timeout;
    }

    pub async fn authenticate(&self, password: Option<&str>) -> Result<()> {
        authentication::authenticate(self, password, None, None).await
    }

    pub async fn reconnect(&self, password: Option<&str>) -> Result<()> {
        self.connect().await?;
        self.shared.clear_cache();
        self.authenticate(password).await
    }

    pub async fn msg(&self, message: &str) -> Result<ControlMessage> {
        let mut replies = self.replies.lock().await;
        let Some(receiver) = replies.as_mut() else {
            return Err(Error::SocketClosed);
        };
        while let Ok(stale) = receiver.try_recv() {
            match stale {
                Ok(message) => log::info!("Failed to deliver a response: {message}"),
                Err(Error::SocketClosed) => {}
                Err(error) => log::info!("Socket experienced a problem ({error})"),
            }
        }
        if let Err(error) = self.shared.socket.send(message).await {
            if error.is_socket_closed() {
                self.close().await;
            }
            return Err(error);
        }
        let timeout = *self.request_timeout.lock().unwrap();
        let received = match timeout {
            Some(limit) => match tokio::time::timeout(limit, receiver.recv()).await {
                Ok(received) => received,
                Err(_) => {
                    drop(replies);
                    self.close().await;
                    return Err(Error::Timeout(format!(
                        "Tor didn't respond within {:.1} seconds",
                        limit.as_secs_f64()
                    )));
                }
            },
            None => receiver.recv().await,
        };
        match received {
            Some(Ok(response)) => Ok(response),
            Some(Err(error)) => Err(error),
            None => {
                drop(replies);
                self.close().await;
                Err(Error::SocketClosed)
            }
        }
    }

    pub(crate) fn cached_hidden_service_conf(&self) -> Option<Vec<HiddenServiceConfig>> {
        self.shared.cache()?.hidden_service_conf.clone()
    }

    pub(crate) fn store_hidden_service_conf(
        &self,
        conf: Option<Vec<HiddenServiceConfig>>,
    ) {
        if let Some(mut cache) = self.shared.cache() {
            cache.hidden_service_conf = conf;
        }
    }

    pub(crate) async fn single_line(&self, command: &str) -> Result<SingleLineResponse> {
        SingleLineResponse::parse(self.msg(command).await?)
    }

    pub(crate) async fn require_version(
        &self,
        requirement: Requirement,
        feature: &str,
    ) -> Result<()> {
        match self.get_version().await?.meets(requirement) {
            true => Ok(()),
            false => Err(Error::unsatisfiable(format!(
                "{feature} was added in tor version {requirement}"
            ))),
        }
    }

    pub fn add_status_listener(
        &self,
        listener: impl Fn(State, SystemTime) + Send + Sync + 'static,
    ) -> ListenerId {
        let id = self.shared.next_listener_id.fetch_add(1, Ordering::SeqCst);
        self.shared
            .status_listeners
            .lock()
            .unwrap()
            .push((id, Arc::new(listener)));
        id
    }

    pub fn remove_status_listener(&self, id: ListenerId) -> bool {
        let mut listeners = self.shared.status_listeners.lock().unwrap();
        let before = listeners.len();
        listeners.retain(|(listener_id, _)| *listener_id != id);
        listeners.len() != before
    }

    async fn run_post_authentication(&self) {
        self.shared.is_authenticated.store(true, Ordering::SeqCst);
        match self.attach_listeners().await {
            Ok((_, failed)) => {
                if !failed.is_empty() {
                    let mut listeners = self.shared.event_listeners.lock().unwrap();
                    failed.iter().for_each(|event_type| {
                        listeners.by_type.remove(event_type);
                    });
                    log::warn!(
                        "We were unable to re-attach our event listeners to the new tor \
                        instance for: {}",
                        failed
                            .iter()
                            .map(EventType::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
            }
            Err(error) => log::warn!(
                "Unable to issue the SETEVENTS request to re-attach our listeners \
                ({error})"
            ),
        }
        let owning_pid = self
            .get_conf("__OwningControllerProcess")
            .await
            .ok()
            .flatten();
        if owning_pid.as_deref() != Some(&std::process::id().to_string())
            || !self.is_localhost()
        {
            return;
        }
        match self.single_line("TAKEOWNERSHIP").await {
            Ok(response) if response.is_ok() => {
                if let Err(error) = self.reset_conf(&["__OwningControllerProcess"]).await
                {
                    log::warn!(
                        "We were unable to reset tor's __OwningControllerProcess \
                        configuration. It will continue to periodically check if our \
                        pid exists. ({error})"
                    );
                }
            }
            Ok(response) => log::warn!(
                "We were unable assert ownership of tor through TAKEOWNERSHIP, despite \
                being configured to be the owning process through \
                __OwningControllerProcess. ({})",
                response.raw
            ),
            Err(error) => log::warn!("TAKEOWNERSHIP failed: {error}"),
        }
    }

    pub async fn get_info(&self, param: &str) -> Result<String> {
        let bytes = self.get_info_bytes(param).await?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub async fn get_info_bytes(&self, param: &str) -> Result<Vec<u8>> {
        let mut entries = self.get_info_entries(&[param]).await?;
        entries
            .remove(param)
            .ok_or_else(|| Error::protocol(format!("GETINFO didn't provide {param}")))
    }

    pub async fn get_info_multiple(
        &self,
        params: &[&str],
    ) -> Result<HashMap<String, String>> {
        let entries = self.get_info_entries(params).await?;
        Ok(entries
            .into_iter()
            .map(|(key, value)| (key, String::from_utf8_lossy(&value).into_owned()))
            .collect())
    }

    pub async fn get_info_entries(
        &self,
        params: &[&str],
    ) -> Result<HashMap<String, Vec<u8>>> {
        let started = Instant::now();
        let mut remaining: Vec<String> = Vec::new();
        for param in params {
            validate_token(param, "A GETINFO parameter")?;
            if !remaining.iter().any(|existing| existing == param) {
                remaining.push((*param).to_string());
            }
        }
        if remaining.is_empty() {
            return Ok(HashMap::new());
        }
        for param in &remaining {
            self.check_known_failures(param).await?;
        }
        let mut reply: HashMap<String, Vec<u8>> = HashMap::new();
        if let Some(cache) = self.shared.cache() {
            remaining.retain(|param| match cache.getinfo.get(&param.to_lowercase()) {
                Some(cached) => {
                    reply.insert(param.clone(), cached.clone());
                    false
                }
                None => true,
            });
        }
        if remaining.is_empty() {
            log::trace!("GETINFO {} (cache fetch)", params.join(" "));
            return Ok(reply);
        }
        let outcome = self.query_info(&remaining).await;
        match outcome {
            Ok(entries) => {
                if let Some(mut cache) = self.shared.cache() {
                    for (key, value) in &entries {
                        let lowered = key.to_lowercase();
                        let is_cacheable = CACHEABLE_GETINFO_PARAMS
                            .contains(&lowered.as_str())
                            || CACHEABLE_GETINFO_UNTIL_SETCONF
                                .contains(&lowered.as_str())
                            || lowered.starts_with("ip-to-country/");
                        if is_cacheable {
                            cache.getinfo.insert(lowered, value.clone());
                        }
                    }
                }
                if remaining.iter().any(|param| param == "address") {
                    *self.shared.last_address_error.lock().unwrap() = None;
                }
                if remaining.iter().any(|param| param == "fingerprint") {
                    *self.shared.last_fingerprint_error.lock().unwrap() = None;
                }
                log::debug!(
                    "GETINFO {} (runtime: {:.4})",
                    remaining.join(" "),
                    started.elapsed().as_secs_f64()
                );
                reply.extend(entries);
                Ok(reply)
            }
            Err(error) => {
                if remaining.iter().any(|param| param == "address") {
                    *self.shared.last_address_error.lock().unwrap() = Some(error.clone());
                }
                if remaining.iter().any(|param| param == "fingerprint") {
                    *self.shared.last_fingerprint_error.lock().unwrap() =
                        Some(error.clone());
                }
                log::debug!("GETINFO {} (failed: {error})", remaining.join(" "));
                Err(error)
            }
        }
    }

    async fn query_info(&self, params: &[String]) -> Result<HashMap<String, Vec<u8>>> {
        let response = self.msg(&format!("GETINFO {}", params.join(" "))).await?;
        let parsed = GetInfoResponse::parse(&response)?;
        parsed.assert_matches(params)?;
        Ok(parsed.entries)
    }

    async fn check_known_failures(&self, param: &str) -> Result<()> {
        if param.starts_with("ip-to-country/")
            && param != "ip-to-country/0.0.0.0"
            && self.is_geoip_unavailable().await
        {
            return Err(Error::protocol("Tor geoip database is unavailable"));
        }
        if param == "address"
            && let Some(error) = self.shared.last_address_error.lock().unwrap().clone()
        {
            return Err(error);
        }
        if param == "fingerprint" {
            let remembered = self.shared.last_fingerprint_error.lock().unwrap().clone();
            if let Some(error) = remembered
                && self.get_conf("ORPort").await.ok().flatten().is_none()
            {
                return Err(error);
            }
        }
        Ok(())
    }

    pub async fn get_version(&self) -> Result<Version> {
        if let Some(cache) = self.shared.cache()
            && let Some(version) = &cache.version
        {
            return Ok(version.clone());
        }
        let text = self.get_info("version").await?;
        let version = Version::new(text.strip_prefix("Tor ").unwrap_or(&text))?;
        if let Some(mut cache) = self.shared.cache() {
            cache.version = Some(version.clone());
        }
        Ok(version)
    }

    pub async fn get_exit_policy(&self) -> Result<ExitPolicy> {
        if let Some(cache) = self.shared.cache()
            && let Some(policy) = &cache.exit_policy
        {
            return Ok(policy.clone());
        }
        let policy = match self.get_info("exit-policy/full").await {
            Ok(full) => {
                let lines: Vec<&str> = full.lines().collect();
                ExitPolicy::new(&lines)?
            }
            Err(Error::OperationFailed { .. }) => self.build_config_exit_policy().await?,
            Err(error) => return Err(error),
        };
        if let Some(mut cache) = self.shared.cache() {
            cache.exit_policy = Some(policy.clone());
        }
        Ok(policy)
    }

    async fn build_config_exit_policy(&self) -> Result<ExitPolicy> {
        let mut rules: Vec<String> = Vec::new();
        if self.get_conf("ExitRelay").await?.as_deref() == Some("0") {
            rules.push("reject *:*".to_string());
        }
        if self.get_conf("ExitPolicyRejectPrivate").await?.as_deref() == Some("1") {
            rules.push("reject private:*".to_string());
        }
        for line in self.get_conf_multiple("ExitPolicy").await? {
            rules.extend(line.split(',').map(str::to_string));
        }
        rules.extend(
            self.get_info("exit-policy/default")
                .await?
                .split(',')
                .map(str::to_string),
        );
        let address = self.get_info("address").await.ok();
        get_config_policy_from(&rules, address.as_deref())
    }

    pub async fn get_ports(&self, listener_type: &ListenerType) -> Result<Vec<u16>> {
        Ok(self
            .get_listeners(listener_type)
            .await?
            .into_iter()
            .filter(|(address, _)| match address {
                IpAddr::V4(address) => {
                    address.is_unspecified() || address.octets()[0] == 127
                }
                IpAddr::V6(address) => address.is_unspecified() || address.is_loopback(),
            })
            .map(|(_, port)| port)
            .collect())
    }

    pub async fn get_listeners(
        &self,
        listener_type: &ListenerType,
    ) -> Result<Vec<(IpAddr, u16)>> {
        let key = listener_type.as_str().to_string();
        if let Some(cache) = self.shared.cache()
            && let Some(listeners) = cache.listeners.get(&key)
        {
            return Ok(listeners.clone());
        }
        let query = format!("net/listeners/{}", key.to_lowercase());
        let addresses = match self.get_info(&query).await {
            Ok(text) => parse_listener_addresses(&query, &text)?,
            Err(Error::InvalidArguments { .. }) => {
                self.legacy_listeners(listener_type).await?
            }
            Err(error) => return Err(error),
        };
        let mut listeners = Vec::new();
        for (address, port) in addresses {
            let ip: IpAddr = address.parse().map_err(|_| {
                Error::protocol(format!(
                    "Invalid address for a {key} listener: {address}"
                ))
            })?;
            let port = parse_port(&port, false).ok_or_else(|| {
                Error::protocol(format!("Invalid port for a {key} listener: {port}"))
            })?;
            listeners.push((ip, port));
        }
        if let Some(mut cache) = self.shared.cache() {
            cache.listeners.insert(key, listeners.clone());
        }
        Ok(listeners)
    }

    async fn legacy_listeners(
        &self,
        listener_type: &ListenerType,
    ) -> Result<Vec<(String, String)>> {
        let (port_option, listener_option) = match listener_type {
            ListenerType::Or => ("ORPort", "ORListenAddress"),
            ListenerType::Dir => ("DirPort", "DirListenAddress"),
            ListenerType::Socks => ("SocksPort", "SocksListenAddress"),
            ListenerType::Trans => ("TransPort", "TransListenAddress"),
            ListenerType::Natd => ("NatdPort", "NatdListenAddress"),
            ListenerType::Dns => ("DNSPort", "DNSListenAddress"),
            ListenerType::Control => ("ControlPort", "ControlListenAddress"),
            other => {
                return Err(Error::unsatisfiable(format!(
                    "Tor doesn't support querying {other} listeners"
                )));
            }
        };
        let port_value = self
            .get_conf(port_option)
            .await?
            .and_then(|value| value.split_whitespace().next().map(str::to_string))
            .unwrap_or_default();
        let mut addresses = Vec::new();
        for listener in self.get_conf_multiple(listener_option).await? {
            match listener.rsplit_once(':') {
                Some((address, port)) => addresses.push((
                    address
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .to_string(),
                    port.to_string(),
                )),
                None => addresses.push((listener, port_value.clone())),
            }
        }
        Ok(addresses)
    }

    pub async fn get_socks_listeners(&self) -> Result<Vec<(IpAddr, u16)>> {
        self.get_listeners(&ListenerType::Socks).await
    }

    pub async fn get_accounting_stats(&self) -> Result<AccountingStats> {
        if self.get_info("accounting/enabled").await? != "1" {
            return Err(Error::operation_failed("551", "Accounting isn't enabled"));
        }
        let retrieved = unix_time();
        let status = self.get_info("accounting/hibernating").await?;
        let interval_end =
            parse_timestamp(&self.get_info("accounting/interval-end").await?)?;
        let used = self.get_info("accounting/bytes").await?;
        let left = self.get_info("accounting/bytes-left").await?;
        let pair = |text: &str| -> Result<(u64, u64)> {
            let (read, written) = text.split_once(' ').ok_or_else(|| {
                Error::protocol(format!("Unexpected accounting value: {text}"))
            })?;
            let parse = |value: &str| {
                value.trim().parse::<u64>().map_err(|_| {
                    Error::protocol(format!("Unexpected accounting value: {text}"))
                })
            };
            Ok((parse(read)?, parse(written)?))
        };
        let (used_read, used_written) = pair(&used)?;
        let (left_read, left_written) = pair(&left)?;
        let end_seconds = interval_end.and_utc().timestamp() as f64;
        Ok(AccountingStats {
            retrieved,
            status,
            interval_end,
            time_until_reset: (end_seconds - retrieved.floor()).max(0.0) as u64,
            read_bytes: used_read,
            read_bytes_left: left_read,
            read_limit: used_read + left_read,
            written_bytes: used_written,
            write_bytes_left: left_written,
            write_limit: used_written + left_written,
        })
    }

    pub async fn get_protocolinfo(&self) -> Result<ProtocolInfoResponse> {
        get_protocolinfo(self).await
    }

    pub async fn get_user(&self) -> Result<String> {
        if let Some(cache) = self.shared.cache()
            && let Some(user) = &cache.user
        {
            return Ok(user.clone());
        }
        let mut user = self
            .get_info("process/user")
            .await
            .ok()
            .filter(|user| !user.is_empty());
        if user.is_none()
            && self.is_localhost()
            && let Ok(pid) = self.get_pid().await
        {
            user = tokio::task::spawn_blocking(move || process_inspection::user(pid))
                .await
                .ok()
                .flatten();
        }
        match user {
            Some(user) => {
                if let Some(mut cache) = self.shared.cache() {
                    cache.user = Some(user.clone());
                }
                Ok(user)
            }
            None => Err(Error::invalid_input(match self.is_localhost() {
                true => "Unable to resolve tor's user",
                false => "Tor isn't running locally",
            })),
        }
    }

    pub async fn get_pid(&self) -> Result<u32> {
        if let Some(cache) = self.shared.cache()
            && let Some(pid) = cache.pid
        {
            return Ok(pid);
        }
        let mut pid = self
            .get_info("process/pid")
            .await
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok());
        if pid.is_none() && self.is_localhost() {
            pid = self.find_local_pid().await;
        }
        match pid {
            Some(pid) => {
                if let Some(mut cache) = self.shared.cache() {
                    cache.pid = Some(pid);
                }
                Ok(pid)
            }
            None => Err(Error::invalid_input(match self.is_localhost() {
                true => "Unable to resolve tor's pid",
                false => "Tor isn't running locally",
            })),
        }
    }

    async fn find_local_pid(&self) -> Option<u32> {
        if let Some(pid_file) = self.get_conf("PidFile").await.ok().flatten()
            && let Ok(content) = tokio::fs::read_to_string(&pid_file).await
            && let Ok(pid) = content.trim().parse::<u32>()
        {
            return Some(pid);
        }
        let by_name =
            tokio::task::spawn_blocking(|| process_inspection::pid_by_name("tor"))
                .await
                .ok()
                .flatten();
        if by_name.is_some() {
            return by_name;
        }
        let target = self.shared.socket.target().clone();
        tokio::task::spawn_blocking(move || match target {
            crate::socket::ControlTarget::Port(address) => {
                process_inspection::pid_by_port(address.port())
            }
            crate::socket::ControlTarget::File(path) => {
                process_inspection::pid_by_open_file(&path)
            }
        })
        .await
        .ok()
        .flatten()
    }

    pub async fn get_start_time(&self) -> Result<f64> {
        if let Some(cache) = self.shared.cache()
            && let Some(start) = cache.start_time
        {
            return Ok(start);
        }
        let mut start_time = None;
        if self.get_version().await?.meets(Requirement::GetinfoUptime)
            && let Ok(uptime) = self.get_info("uptime").await
        {
            let seconds = uptime.trim().parse::<u64>().map_err(|_| {
                Error::invalid_input(format!(
                    "'GETINFO uptime' did not provide a valid numeric response: {uptime}"
                ))
            })?;
            start_time = Some(unix_time() - seconds as f64);
        }
        if start_time.is_none() {
            if !self.is_localhost() {
                return Err(Error::invalid_input(
                    "Unable to determine the uptime when tor is not running locally",
                ));
            }
            let pid = self.get_pid().await.map_err(|_| {
                Error::invalid_input("Unable to determine the pid of the tor process")
            })?;
            start_time =
                tokio::task::spawn_blocking(move || process_inspection::start_time(pid))
                    .await
                    .ok()
                    .flatten();
        }
        let Some(start_time) = start_time else {
            return Err(Error::invalid_input("Unable to resolve when tor began"));
        };
        if let Some(mut cache) = self.shared.cache() {
            cache.start_time = Some(start_time);
        }
        Ok(start_time)
    }

    pub async fn get_uptime(&self) -> Result<f64> {
        Ok(unix_time() - self.get_start_time().await?)
    }

    pub async fn is_user_traffic_allowed(&self) -> UserTrafficAllowed {
        let mut inbound =
            self.get_conf("BridgeRelay").await.ok().flatten().as_deref() == Some("1");
        let mut outbound = false;
        if self.get_conf("ORPort").await.ok().flatten().is_some() {
            if !inbound && let Ok(entry) = self.get_network_status(None).await {
                inbound = entry.flags.iter().any(|flag| flag == "Guard");
            }
            outbound = self
                .get_exit_policy()
                .await
                .is_ok_and(|policy| policy.is_exiting_allowed());
        }
        UserTrafficAllowed { inbound, outbound }
    }

    async fn descriptor_query(
        &self,
        prefix: &str,
        relay: Option<&str>,
    ) -> Result<Vec<u8>> {
        let relay = match relay {
            Some(relay) => relay.to_string(),
            None => self.get_info("fingerprint").await.map_err(|error| {
                Error::operation_failed(
                    "551",
                    format!("Unable to determine our own fingerprint: {error}"),
                )
            })?,
        };
        let query = if is_valid_fingerprint(&relay, false) {
            format!("{prefix}/id/{relay}")
        } else if is_valid_nickname(&relay) {
            format!("{prefix}/name/{relay}")
        } else {
            return Err(Error::invalid_input(format!(
                "'{relay}' isn't a valid fingerprint or nickname"
            )));
        };
        let content = match self.get_info_bytes(&query).await {
            Ok(content) => content,
            Err(Error::InvalidArguments { message, .. })
                if message
                    .starts_with("GETINFO request contained unrecognized keywords:") =>
            {
                return Err(Error::DescriptorUnavailable(format!(
                    "Tor was unable to provide the descriptor for '{relay}'"
                )));
            }
            Err(error) => return Err(error),
        };
        match content.is_empty() {
            true => Err(Error::DescriptorUnavailable(
                "Descriptor information is unavailable, tor might still be downloading \
                it"
                .to_string(),
            )),
            false => Ok(content),
        }
    }

    async fn descriptor_bulk(&self, query: &str) -> Result<Vec<u8>> {
        let content = self.get_info_bytes(query).await?;
        match content.is_empty() {
            true => Err(Error::DescriptorUnavailable(
                "Descriptor information is unavailable, tor might still be downloading \
                it"
                .to_string(),
            )),
            false => Ok(content),
        }
    }

    pub async fn get_microdescriptor(
        &self,
        relay: Option<&str>,
    ) -> Result<Microdescriptor> {
        Microdescriptor::parse(&self.descriptor_query("md", relay).await?, false)
    }

    pub async fn get_microdescriptors(&self) -> Result<Vec<Microdescriptor>> {
        if self
            .get_version()
            .await?
            .meets(Requirement::GetinfoMicrodescriptors)
        {
            return Microdescriptor::parse_many(
                &self.descriptor_bulk("md/all").await?,
                false,
            );
        }
        let data_directory = self.get_conf("DataDirectory").await?.ok_or_else(|| {
            Error::operation_failed("551", "Unable to determine tor's data directory")
        })?;
        let directory = Path::new(&data_directory);
        if !directory.exists() {
            return Err(Error::operation_failed(
                "551",
                format!(
                    "Data directory reported by tor doesn't exist ({data_directory})"
                ),
            ));
        }
        let cached = ["cached-microdescs", "cached-microdescs.new"]
            .iter()
            .map(|name| directory.join(name))
            .find(|path| path.exists())
            .ok_or_else(|| {
                Error::operation_failed(
                    "551",
                    format!(
                        "Data directory doesn't contain cached microdescriptors \
                        ({data_directory})"
                    ),
                )
            })?;
        Microdescriptor::parse_many(&tokio::fs::read(cached).await?, false)
    }

    pub async fn get_server_descriptor(
        &self,
        relay: Option<&str>,
    ) -> Result<RelayServerDescriptor> {
        let outcome = self.descriptor_query("desc", relay).await;
        match outcome.and_then(|content| RelayServerDescriptor::parse(&content, false)) {
            Ok(descriptor) => Ok(descriptor),
            Err(error) => {
                if !self.server_descriptors_available().await {
                    return Err(Error::invalid_input(SERVER_DESCRIPTORS_UNSUPPORTED));
                }
                Err(error)
            }
        }
    }

    pub async fn get_server_descriptors(&self) -> Result<Vec<RelayServerDescriptor>> {
        let content = self.get_info_bytes("desc/all-recent").await?;
        if content.is_empty() {
            return Err(match self.server_descriptors_available().await {
                false => Error::operation_failed("551", SERVER_DESCRIPTORS_UNSUPPORTED),
                true => Error::DescriptorUnavailable(
                    "Descriptor information is unavailable, tor might still be \
                    downloading it"
                        .to_string(),
                ),
            });
        }
        RelayServerDescriptor::parse_many(&content, false)
    }

    async fn server_descriptors_available(&self) -> bool {
        let old_tor = self
            .get_version()
            .await
            .is_ok_and(|version| !version.meets(Requirement::MicrodescriptorIsDefault));
        old_tor
            || self
                .get_conf("UseMicrodescriptors")
                .await
                .ok()
                .flatten()
                .as_deref()
                == Some("0")
    }

    pub async fn get_network_status(
        &self,
        relay: Option<&str>,
    ) -> Result<RouterStatusEntryV3> {
        RouterStatusEntryV3::parse(&self.descriptor_query("ns", relay).await?, false)
    }

    pub async fn get_network_statuses(&self) -> Result<Vec<RouterStatusEntryV3>> {
        RouterStatusEntryV3::parse_many(&self.descriptor_bulk("ns/all").await?, false)
    }

    pub async fn get_conf(&self, param: &str) -> Result<Option<String>> {
        let param = param.trim();
        if param.is_empty() {
            return Ok(None);
        }
        let entries = self.get_conf_map(&[param]).await?;
        Ok(entries
            .into_iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(param))
            .and_then(|(_, values)| values.into_iter().next()))
    }

    pub async fn get_conf_multiple(&self, param: &str) -> Result<Vec<String>> {
        let param = param.trim();
        if param.is_empty() {
            return Ok(Vec::new());
        }
        let entries = self.get_conf_map(&[param]).await?;
        Ok(entries
            .into_iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(param))
            .map(|(_, values)| values)
            .unwrap_or_default())
    }

    pub async fn get_conf_map(
        &self,
        params: &[&str],
    ) -> Result<HashMap<String, Vec<String>>> {
        let started = Instant::now();
        let mut lookup: Vec<String> = Vec::new();
        for param in params
            .iter()
            .map(|param| param.trim())
            .filter(|param| !param.is_empty())
        {
            validate_option_name(param)?;
            let mapped = MAPPED_CONFIG_KEYS
                .iter()
                .find(|(key, _)| *key == param.to_lowercase())
                .map_or(param, |(_, target)| *target);
            if !lookup.iter().any(|existing| existing == mapped) {
                lookup.push(mapped.to_string());
            }
        }
        if lookup.is_empty() {
            return Ok(HashMap::new());
        }
        let mut reply: HashMap<String, Vec<String>> = HashMap::new();
        if let Some(cache) = self.shared.cache() {
            lookup.retain(|param| match cache.getconf.get(&param.to_lowercase()) {
                Some(cached) => {
                    reply.insert(param.clone(), cached.clone());
                    false
                }
                None => true,
            });
        }
        if lookup.is_empty() {
            return Ok(reply);
        }
        let response = self.msg(&format!("GETCONF {}", lookup.join(" "))).await?;
        let parsed = GetConfResponse::parse(&response).inspect_err(|error| {
            log::debug!("GETCONF {} (failed: {error})", lookup.join(" "))
        })?;
        if let Some(mut cache) = self.shared.cache() {
            for (key, values) in &parsed.entries {
                let lowered = key.to_lowercase();
                if !UNCACHEABLE_GETCONF_PARAMS.contains(&lowered.as_str()) {
                    cache.getconf.insert(lowered, values.clone());
                }
            }
        }
        for (key, values) in parsed.entries {
            let requested = params
                .iter()
                .find(|param| param.trim().eq_ignore_ascii_case(&key))
                .map_or(key, |param| param.trim().to_string());
            reply.insert(requested, values);
        }
        log::debug!(
            "GETCONF {} (runtime: {:.4})",
            lookup.join(" "),
            started.elapsed().as_secs_f64()
        );
        Ok(reply)
    }

    pub async fn is_set(&self, param: &str) -> Result<bool> {
        let options = self.custom_options().await?;
        Ok(options.keys().any(|key| key.eq_ignore_ascii_case(param)))
    }

    async fn custom_options(&self) -> Result<HashMap<String, String>> {
        if let Some(cache) = self.shared.cache()
            && let Some(options) = &cache.custom_options
        {
            return Ok(options.clone());
        }
        let text = self.get_info("config-text").await?;
        let user = self
            .get_user()
            .await
            .unwrap_or_else(|_| "undefined".to_string());
        let defaults = [
            "Log notice stdout".to_string(),
            "Log notice file /var/log/tor/log".to_string(),
            format!("DataDirectory /home/{user}/.tor"),
            "HiddenServiceStatistics 0".to_string(),
        ];
        let options: HashMap<String, String> = text
            .lines()
            .filter(|line| !defaults.iter().any(|default| default == line))
            .filter_map(|line| line.split_once(' '))
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        if let Some(mut cache) = self.shared.cache() {
            cache.custom_options = Some(options.clone());
        }
        Ok(options)
    }

    pub async fn set_conf(&self, param: &str, value: &str) -> Result<()> {
        self.set_options(&[(param, ConfValue::Single(value.to_string()))], false)
            .await
    }

    pub async fn set_conf_multiple(&self, param: &str, values: &[&str]) -> Result<()> {
        let values =
            ConfValue::Multiple(values.iter().map(|value| value.to_string()).collect());
        self.set_options(&[(param, values)], false).await
    }

    pub async fn reset_conf(&self, params: &[&str]) -> Result<()> {
        let entries: Vec<(&str, ConfValue)> = params
            .iter()
            .map(|param| (*param, ConfValue::Unset))
            .collect();
        self.set_options(&entries, true).await
    }

    pub async fn set_options(
        &self,
        params: &[(&str, ConfValue)],
        reset: bool,
    ) -> Result<()> {
        let started = Instant::now();
        let mut query = vec![if reset { "RESETCONF" } else { "SETCONF" }.to_string()];
        for (param, value) in params {
            validate_option_name(param)?;
            match value {
                ConfValue::Single(value) if !value.trim().is_empty() => {
                    query.push(format!("{param}={}", escape_quoted(value.trim())))
                }
                ConfValue::Single(_) | ConfValue::Unset => {
                    query.push((*param).to_string())
                }
                ConfValue::Multiple(values) if values.is_empty() => {
                    query.push((*param).to_string())
                }
                ConfValue::Multiple(values) => query.extend(
                    values
                        .iter()
                        .map(|value| format!("{param}={}", escape_quoted(value.trim()))),
                ),
            }
        }
        let query = query.join(" ");
        let response = self.single_line(&query).await?;
        if response.is_ok() {
            log::debug!(
                "{} (runtime: {:.4})",
                query_label(&query),
                started.elapsed().as_secs_f64()
            );
            if let Some(mut cache) = self.shared.cache() {
                for (param, _) in params {
                    cache.getconf.remove(&param.to_lowercase());
                }
                let keys: Vec<String> =
                    params.iter().map(|(param, _)| param.to_string()).collect();
                let key_refs: Vec<&String> = keys.iter().collect();
                Shared::invalidate_after_conf_change(&mut cache, &key_refs);
            }
            return Ok(());
        }
        log::debug!(
            "{} (failed, code: {}, message: {})",
            query_label(&query),
            response.code,
            response.message
        );
        let mut immutable: Vec<String> = params
            .iter()
            .filter(|(param, _)| {
                IMMUTABLE_CONFIG_OPTIONS.contains(&param.to_lowercase().as_str())
            })
            .map(|(param, _)| param.to_string())
            .collect();
        if !immutable.is_empty() {
            immutable.sort();
            return Err(Error::invalid_arguments(
                "553",
                format!(
                    "{} cannot be changed while tor's running",
                    immutable.join(", ")
                ),
                immutable,
            ));
        }
        match response.code.as_str() {
            "552" => {
                const PREFIX: &str = "Unrecognized option: Unknown option '";
                if let Some(rest) = response.message.strip_prefix(PREFIX) {
                    let key = rest.split('\'').next().unwrap_or_default().to_string();
                    return Err(Error::invalid_arguments(
                        "552",
                        response.message,
                        vec![key],
                    ));
                }
                Err(Error::invalid_request("552", response.message))
            }
            "513" | "553" => {
                Err(Error::invalid_request(&response.code, response.message))
            }
            code => Err(Error::protocol(format!(
                "Returned unexpected status code: {code}"
            ))),
        }
    }

    pub fn add_event_listener(
        &self,
        listener: impl Fn(&Event) + Send + Sync + 'static,
        events: &[EventType],
    ) -> impl Future<Output = Result<ListenerId>> + Send + '_ {
        let listener: EventListener = Arc::new(listener);
        let events = events.to_vec();
        async move { self.register_event_listener(listener, events).await }
    }

    async fn register_event_listener(
        &self,
        listener: EventListener,
        events: Vec<EventType>,
    ) -> Result<ListenerId> {
        for event_type in &events {
            if !event_type.is_sendable() && *event_type != EventType::MalformedEvents {
                return Err(Error::invalid_input(format!(
                    "'{event_type}' isn't a valid event type"
                )));
            }
        }
        if self.is_authenticated() {
            let version = self.get_version().await?;
            for event_type in &events {
                if let Some(requirement) = event_type.version_added()
                    && !version.meets(requirement)
                {
                    return Err(Error::invalid_request(
                        "552",
                        format!(
                            "{event_type} event requires Tor version {requirement} or \
                            later"
                        ),
                    ));
                }
            }
        }
        let id = self.shared.next_listener_id.fetch_add(1, Ordering::SeqCst);
        {
            let mut listeners = self.shared.event_listeners.lock().unwrap();
            for event_type in &events {
                listeners
                    .by_type
                    .entry(event_type.clone())
                    .or_default()
                    .push((id, listener.clone()));
            }
        }
        let (_, failed) = self.attach_listeners().await?;
        let rejected: Vec<EventType> = failed
            .into_iter()
            .filter(|failed| events.contains(failed))
            .collect();
        if rejected.is_empty() {
            return Ok(id);
        }
        self.drop_listener(id);
        Err(Error::protocol(format!(
            "SETEVENTS rejected {}",
            rejected
                .iter()
                .map(EventType::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }

    fn drop_listener(&self, id: ListenerId) -> bool {
        let mut listeners = self.shared.event_listeners.lock().unwrap();
        let mut removed = false;
        for entries in listeners.by_type.values_mut() {
            let before = entries.len();
            entries.retain(|(listener_id, _)| *listener_id != id);
            removed |= entries.len() != before;
        }
        listeners.by_type.retain(|_, entries| !entries.is_empty());
        removed
    }

    pub async fn remove_event_listener(&self, id: ListenerId) -> Result<()> {
        let before: HashSet<EventType> =
            self.shared.active_event_types().into_iter().collect();
        if !self.drop_listener(id) {
            return Ok(());
        }
        let after: HashSet<EventType> =
            self.shared.active_event_types().into_iter().collect();
        if before == after || !self.is_authenticated() {
            return Ok(());
        }
        let command = Self::setevents_command(&self.shared.active_event_types());
        let response = self.msg(&command).await?;
        match response.is_ok() {
            true => Ok(()),
            false => Err(Error::protocol(format!(
                "SETEVENTS received unexpected response\n{response}"
            ))),
        }
    }

    pub async fn subscribe(
        &self,
        events: &[EventType],
    ) -> Result<(ListenerId, mpsc::UnboundedReceiver<Event>)> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let id = self
            .add_event_listener(
                move |event| {
                    let _ = sender.send(event.clone());
                },
                events,
            )
            .await?;
        Ok((id, receiver))
    }

    fn setevents_command(types: &[EventType]) -> String {
        let names: Vec<&str> = types.iter().map(EventType::as_str).collect();
        format!("SETEVENTS {}", names.join(" "))
            .trim_end()
            .to_string()
    }

    async fn attach_listeners(&self) -> Result<(Vec<EventType>, Vec<EventType>)> {
        if !self.is_authenticated() {
            return Ok((Vec::new(), Vec::new()));
        }
        let types: Vec<EventType> = self
            .shared
            .active_event_types()
            .into_iter()
            .filter(EventType::is_sendable)
            .collect();
        let response = self.msg(&Self::setevents_command(&types)).await?;
        if response.is_ok() {
            return Ok((types, Vec::new()));
        }
        let (mut set_events, mut failed_events) = (Vec::new(), Vec::new());
        for event_type in types {
            let mut attempt = set_events.clone();
            attempt.push(event_type.clone());
            let response = self.msg(&Self::setevents_command(&attempt)).await?;
            match response.is_ok() {
                true => set_events.push(event_type),
                false => failed_events.push(event_type),
            }
        }
        Ok((set_events, failed_events))
    }

    pub fn is_caching_enabled(&self) -> bool {
        self.shared.caching_enabled.load(Ordering::SeqCst)
    }

    pub fn set_caching(&self, enabled: bool) {
        self.shared.caching_enabled.store(enabled, Ordering::SeqCst);
        if !enabled {
            self.clear_cache();
        }
    }

    pub fn clear_cache(&self) {
        self.shared.clear_cache();
    }

    pub async fn load_conf(&self, config_text: &str) -> Result<()> {
        let response = self
            .single_line(&format!("LOADCONF\n{config_text}"))
            .await?;
        match response.code.as_str() {
            "250" => Ok(()),
            "552" | "553" => {
                const PREFIX: &str = "Invalid config file: Failed to parse/validate \
                    config: Unknown option";
                if response.code == "552" && response.message.starts_with(PREFIX) {
                    let detail = response.message.get(70..).unwrap_or_default();
                    let key = detail
                        .split('.')
                        .next()
                        .unwrap_or_default()
                        .trim_end_matches('\'');
                    return Err(Error::invalid_arguments(
                        "552",
                        response.message.clone(),
                        vec![key.to_string()],
                    ));
                }
                Err(Error::invalid_request(&response.code, response.message))
            }
            _ => Err(Error::protocol(format!(
                "+LOADCONF Received unexpected response\n{}",
                response.raw
            ))),
        }
    }

    pub async fn save_conf(&self, force: bool) -> Result<()> {
        let force = force && self.get_version().await?.meets(Requirement::SaveConfForce);
        let response = self
            .single_line(if force { "SAVECONF FORCE" } else { "SAVECONF" })
            .await?;
        match response.code.as_str() {
            "250" => Ok(()),
            "551" => Err(Error::operation_failed("551", response.message)),
            _ => Err(Error::protocol(
                "SAVECONF returned unexpected response code",
            )),
        }
    }

    pub async fn is_feature_enabled(&self, feature: &str) -> bool {
        let feature = feature.to_uppercase();
        if self
            .shared
            .enabled_features
            .lock()
            .unwrap()
            .contains(&feature)
        {
            return true;
        }
        let defaulted = match feature.as_str() {
            "EXTENDED_EVENTS" => Some(Requirement::FeatureExtendedEvents),
            "VERBOSE_NAMES" => Some(Requirement::FeatureVerboseNames),
            _ => None,
        };
        let Some(requirement) = defaulted else {
            return false;
        };
        let is_default = self
            .get_version()
            .await
            .is_ok_and(|version| version.meets(requirement));
        if is_default {
            self.shared.enabled_features.lock().unwrap().push(feature);
        }
        is_default
    }

    pub async fn enable_feature(&self, features: &[&str]) -> Result<()> {
        for feature in features {
            validate_token(feature, "A feature name")?;
        }
        let response = self
            .single_line(&format!("USEFEATURE {}", features.join(" ")))
            .await?;
        if !response.is_ok() {
            if response.code == "552" {
                let invalid = response
                    .message
                    .strip_prefix("Unrecognized feature \"")
                    .map(|rest| rest.split('"').next().unwrap_or_default().to_string())
                    .into_iter()
                    .collect();
                return Err(Error::invalid_arguments("552", response.message, invalid));
            }
            return Err(Error::protocol(format!(
                "USEFEATURE provided an invalid response code: {}",
                response.code
            )));
        }
        self.shared
            .enabled_features
            .lock()
            .unwrap()
            .extend(features.iter().map(|feature| feature.to_uppercase()));
        Ok(())
    }

    pub async fn get_circuit(&self, circuit_id: &str) -> Result<CircuitEvent> {
        self.get_circuits()
            .await?
            .into_iter()
            .find(|circuit| circuit.id == circuit_id)
            .ok_or_else(|| {
                Error::invalid_input(format!(
                    "Tor currently does not have a circuit with the id of '{circuit_id}'"
                ))
            })
    }

    pub async fn get_circuits(&self) -> Result<Vec<CircuitEvent>> {
        let mut circuits = Vec::new();
        for line in self.get_info("circuit-status").await?.lines() {
            let event = Event::from_content(&format!("650 CIRC {line}\r\n"))?;
            if let EventData::Circuit(circuit) = event.data {
                circuits.push(circuit);
            }
        }
        Ok(circuits)
    }

    pub async fn new_circuit(
        &self,
        path: Option<&[&str]>,
        purpose: Option<&CircPurpose>,
        await_build: bool,
        timeout: Option<Duration>,
    ) -> Result<String> {
        self.extend_circuit("0", path, purpose, await_build, timeout)
            .await
    }

    pub async fn extend_circuit(
        &self,
        circuit_id: &str,
        path: Option<&[&str]>,
        purpose: Option<&CircPurpose>,
        await_build: bool,
        timeout: Option<Duration>,
    ) -> Result<String> {
        validate_token(circuit_id, "A circuit id")?;
        let started = Instant::now();
        let subscription = match await_build {
            true => Some(self.subscribe(&[EventType::Circ]).await?),
            false => None,
        };
        let created = self.request_circuit(circuit_id, path, purpose).await;
        let Some((listener_id, mut receiver)) = subscription else {
            return created;
        };
        let outcome = match created {
            Ok(circuit) => {
                self.wait_for_circuit(&mut receiver, &circuit, timeout, started)
                    .await
            }
            Err(error) => Err(error),
        };
        let _ = self.remove_event_listener(listener_id).await;
        outcome
    }

    async fn request_circuit(
        &self,
        circuit_id: &str,
        path: Option<&[&str]>,
        purpose: Option<&CircPurpose>,
    ) -> Result<String> {
        if path.is_none() && circuit_id == "0" {
            let requirement = Requirement::ExtendCircuitPathOptional;
            if !self.get_version().await?.meets(requirement) {
                return Err(Error::invalid_request(
                    "512",
                    format!(
                        "EXTENDCIRCUIT requires the path prior to version {requirement}"
                    ),
                ));
            }
        }
        let mut arguments = vec![circuit_id.to_string()];
        if let Some(path) = path.filter(|path| !path.is_empty()) {
            for entry in path {
                parse_circuit_entry(entry).map_err(|_| {
                    Error::invalid_input(format!(
                        "'{entry}' isn't a valid relay for a circuit path"
                    ))
                })?;
            }
            arguments.push(path.join(","));
        }
        if let Some(purpose) = purpose {
            validate_token(purpose.as_str(), "A circuit purpose")?;
            arguments.push(format!("purpose={}", purpose.as_str().to_lowercase()));
        }
        let response = self
            .single_line(&format!("EXTENDCIRCUIT {}", arguments.join(" ")))
            .await?;
        if matches!(response.code.as_str(), "512" | "552") {
            return Err(Error::invalid_request(&response.code, response.message));
        }
        if !response.is_ok() {
            return Err(Error::protocol(format!(
                "EXTENDCIRCUIT returned unexpected response code: {}",
                response.code
            )));
        }
        response
            .message
            .strip_prefix("EXTENDED ")
            .map(str::to_string)
            .ok_or_else(|| {
                Error::protocol(format!(
                    "EXTENDCIRCUIT response invalid:\n{}",
                    response.raw
                ))
            })
    }

    async fn wait_for_circuit(
        &self,
        receiver: &mut mpsc::UnboundedReceiver<Event>,
        circuit_id: &str,
        timeout: Option<Duration>,
        started: Instant,
    ) -> Result<String> {
        loop {
            let event = receive_with_timeout(receiver, timeout, started).await?;
            let EventData::Circuit(circuit) = event.data else {
                continue;
            };
            if circuit.id != circuit_id {
                continue;
            }
            match circuit.status {
                CircStatus::Built => return Ok(circuit_id.to_string()),
                CircStatus::Failed => {
                    let reason = circuit
                        .reason
                        .as_ref()
                        .map_or("None".to_string(), ToString::to_string);
                    return Err(Error::CircuitExtensionFailed {
                        message: format!("Circuit failed to be created: {reason}"),
                        circuit: Some(Box::new(circuit)),
                    });
                }
                CircStatus::Closed => {
                    return Err(Error::CircuitExtensionFailed {
                        message: "Circuit was closed prior to build".to_string(),
                        circuit: Some(Box::new(circuit)),
                    });
                }
                _ => {}
            }
        }
    }

    pub async fn repurpose_circuit(
        &self,
        circuit_id: &str,
        purpose: &CircPurpose,
    ) -> Result<()> {
        validate_token(circuit_id, "A circuit id")?;
        validate_token(purpose.as_str(), "A circuit purpose")?;
        let command = format!(
            "SETCIRCUITPURPOSE {circuit_id} purpose={}",
            purpose.as_str().to_lowercase()
        );
        let response = self.single_line(&command).await?;
        match response.code.as_str() {
            "250" => Ok(()),
            "552" => Err(Error::invalid_request("552", response.message)),
            code => Err(Error::protocol(format!(
                "SETCIRCUITPURPOSE returned unexpected response code: {code}"
            ))),
        }
    }

    pub async fn close_circuit(&self, circuit_id: &str, flag: &str) -> Result<()> {
        validate_token(circuit_id, "A circuit id")?;
        if !flag.is_empty() {
            validate_token(flag, "A close flag")?;
        }
        let response = self
            .single_line(format!("CLOSECIRCUIT {circuit_id} {flag}").trim_end())
            .await?;
        match response.code.as_str() {
            "250" => Ok(()),
            "512" | "552" => match response.message.starts_with("Unknown circuit ") {
                true => Err(Error::invalid_arguments(
                    &response.code,
                    response.message,
                    vec![circuit_id.to_string()],
                )),
                false => Err(Error::invalid_request(&response.code, response.message)),
            },
            code => Err(Error::protocol(format!(
                "CLOSECIRCUIT returned unexpected response code: {code}"
            ))),
        }
    }

    pub async fn get_streams(&self) -> Result<Vec<StreamEvent>> {
        let mut streams = Vec::new();
        for line in self.get_info("stream-status").await?.lines() {
            let event = Event::from_content(&format!("650 STREAM {line}\r\n"))?;
            if let EventData::Stream(stream) = event.data {
                streams.push(stream);
            }
        }
        Ok(streams)
    }

    pub async fn attach_stream(
        &self,
        stream_id: &str,
        circuit_id: &str,
        exiting_hop: Option<u32>,
    ) -> Result<()> {
        validate_token(stream_id, "A stream id")?;
        validate_token(circuit_id, "A circuit id")?;
        let mut query = format!("ATTACHSTREAM {stream_id} {circuit_id}");
        if let Some(hop) = exiting_hop {
            query.push_str(&format!(" HOP={hop}"));
        }
        let response = self.single_line(&query).await?;
        match response.code.as_str() {
            "250" => Ok(()),
            "552" => Err(Error::invalid_request("552", response.message)),
            "551" => Err(Error::operation_failed("551", response.message)),
            "555" => Err(Error::Unsatisfiable {
                code: Some("555".to_string()),
                message: response.message,
            }),
            code => Err(Error::protocol(format!(
                "ATTACHSTREAM returned unexpected response code: {code}"
            ))),
        }
    }

    pub async fn close_stream(
        &self,
        stream_id: &str,
        reason: &RelayEndReason,
        flag: &str,
    ) -> Result<()> {
        validate_token(stream_id, "A stream id")?;
        let code = reason.code().ok_or_else(|| {
            Error::invalid_arguments(
                "552",
                format!("Unrecognized reason {reason}"),
                vec![reason.to_string()],
            )
        })?;
        let command = format!("CLOSESTREAM {stream_id} {code} {flag}")
            .trim_end()
            .to_string();
        if !flag.is_empty() {
            validate_token(flag, "A close flag")?;
        }
        let response = self.single_line(&command).await?;
        match response.code.as_str() {
            "250" => Ok(()),
            "512" | "552" => {
                let message = response.message;
                if message.starts_with("Unknown stream ") {
                    return Err(Error::invalid_arguments(
                        &response.code,
                        message,
                        vec![stream_id.to_string()],
                    ));
                }
                if message.starts_with("Unrecognized reason ") {
                    return Err(Error::invalid_arguments(
                        &response.code,
                        message,
                        vec![reason.to_string()],
                    ));
                }
                Err(Error::invalid_request(&response.code, message))
            }
            code => Err(Error::protocol(format!(
                "CLOSESTREAM returned unexpected response code: {code}"
            ))),
        }
    }

    pub async fn signal(&self, signal: &Signal) -> Result<()> {
        validate_token(signal.as_str(), "A signal")?;
        let response = self.single_line(&format!("SIGNAL {signal}")).await?;
        match response.code.as_str() {
            "250" => {
                if *signal == Signal::Newnym
                    && let Some(mut cache) = self.shared.cache()
                {
                    cache.last_newnym = Some(Instant::now());
                }
                Ok(())
            }
            "552" => Err(Error::invalid_arguments(
                "552",
                response.message,
                vec![signal.to_string()],
            )),
            code => Err(Error::protocol(format!(
                "SIGNAL response contained unrecognized status code: {code}"
            ))),
        }
    }

    pub fn is_newnym_available(&self) -> bool {
        self.is_alive() && self.get_newnym_wait().is_zero()
    }

    pub fn get_newnym_wait(&self) -> Duration {
        let last = self.shared.cache.lock().unwrap().last_newnym;
        last.map_or(Duration::ZERO, |last| {
            NEWNYM_COOLDOWN.saturating_sub(last.elapsed())
        })
    }

    pub async fn get_effective_rate(&self, burst: bool) -> Result<Option<u64>> {
        let attributes: &[&str] = match burst {
            false => &[
                "BandwidthRate",
                "RelayBandwidthRate",
                "MaxAdvertisedBandwidth",
            ],
            true => &["BandwidthBurst", "RelayBandwidthBurst"],
        };
        let mut value: Option<u64> = None;
        for attribute in attributes {
            let text = self
                .get_conf(attribute)
                .await?
                .ok_or_else(|| Error::protocol(format!("{attribute} isn't set")))?;
            let amount: u64 = text.trim().parse().map_err(|_| {
                Error::protocol(format!("{attribute} has a non-numeric value: {text}"))
            })?;
            if amount == 0 && attribute.starts_with("Relay") {
                continue;
            }
            value = Some(value.map_or(amount, |current| current.min(amount)));
        }
        Ok(value)
    }

    pub async fn is_geoip_unavailable(&self) -> bool {
        if let Some(known) = self.shared.cache.lock().unwrap().geoip_unavailable {
            return known;
        }
        let unavailable = match self
            .query_info(&["ip-to-country/0.0.0.0".to_string()])
            .await
        {
            Ok(_) => false,
            Err(error) if error.to_string().contains("GeoIP data not loaded") => true,
            Err(_) => return false,
        };
        self.shared.cache.lock().unwrap().geoip_unavailable = Some(unavailable);
        unavailable
    }

    pub async fn map_address(
        &self,
        mapping: &[(&str, &str)],
    ) -> Result<HashMap<String, String>> {
        let mut arguments = Vec::new();
        for (source, target) in mapping {
            validate_token(source, "A MAPADDRESS source")?;
            validate_token(target, "A MAPADDRESS target")?;
            if source.contains('=') || target.contains('=') {
                return Err(Error::invalid_input(
                    "MAPADDRESS addresses can't contain '='",
                ));
            }
            arguments.push(format!("{source}={target}"));
        }
        let response = self
            .msg(&format!("MAPADDRESS {}", arguments.join(" ")))
            .await?;
        Ok(MapAddressResponse::parse(&response)?.entries)
    }

    pub async fn drop_guards(&self) -> Result<()> {
        self.require_version(Requirement::DropGuards, "DROPGUARDS")
            .await?;
        self.msg("DROPGUARDS").await.map(|_| ())
    }

    pub async fn resolve(&self, addresses: &[&str], reverse: bool) -> Result<()> {
        for address in addresses {
            validate_token(address, "A RESOLVE address")?;
        }
        let mode = if reverse { "mode=reverse " } else { "" };
        let response = self
            .single_line(&format!("RESOLVE {mode}{}", addresses.join(" ")))
            .await?;
        match response.code.as_str() {
            "250" => Ok(()),
            "512" => Err(Error::invalid_request("512", response.message)),
            code => Err(Error::protocol(format!(
                "RESOLVE returned unexpected response code: {code}"
            ))),
        }
    }

    pub async fn drop_timeouts(&self) -> Result<()> {
        let response = self.single_line("DROPTIMEOUTS").await?;
        match response.is_ok() {
            true => Ok(()),
            false => Err(Error::protocol(format!(
                "DROPTIMEOUTS returned unexpected response code: {}",
                response.code
            ))),
        }
    }

    pub async fn quit(&self) -> Result<()> {
        let response = self.single_line("QUIT").await?;
        self.close().await;
        match response.is_ok() {
            true => Ok(()),
            false => Err(Error::protocol(format!(
                "QUIT returned unexpected response code: {}",
                response.code
            ))),
        }
    }

    pub async fn post_descriptor(
        &self,
        descriptor: &str,
        purpose: &str,
        cache: bool,
    ) -> Result<String> {
        validate_token(purpose, "A descriptor purpose")?;
        let flag = if cache { " cache=yes" } else { "" };
        let command = format!("POSTDESCRIPTOR purpose={purpose}{flag}\n{descriptor}");
        let response = self.single_line(&command).await?;
        match response.code.as_str() {
            "250" => Ok(response.message),
            "251" => Ok(response.message),
            "554" => Err(Error::invalid_request("554", response.message)),
            code => Err(Error::protocol(format!(
                "POSTDESCRIPTOR returned unexpected response code: {code}"
            ))),
        }
    }

    pub async fn redirect_stream(
        &self,
        stream_id: &str,
        address: &str,
        port: Option<u16>,
    ) -> Result<()> {
        validate_token(stream_id, "A stream id")?;
        validate_token(address, "A redirect address")?;
        let port_text = port.map_or(String::new(), |port| format!(" {port}"));
        let response = self
            .single_line(&format!("REDIRECTSTREAM {stream_id} {address}{port_text}"))
            .await?;
        match response.code.as_str() {
            "250" => Ok(()),
            "552" => Err(Error::invalid_request("552", response.message)),
            "451" => Err(Error::operation_failed("451", response.message)),
            code => Err(Error::protocol(format!(
                "REDIRECTSTREAM returned unexpected response code: {code}"
            ))),
        }
    }

    pub async fn set_router_purpose(
        &self,
        fingerprint: &str,
        purpose: &str,
    ) -> Result<()> {
        validate_token(fingerprint, "A router")?;
        validate_token(purpose, "A router purpose")?;
        let response = self
            .single_line(&format!("SETROUTERPURPOSE {fingerprint} {purpose}"))
            .await?;
        match response.is_ok() {
            true => Ok(()),
            false => Err(Error::invalid_request(&response.code, response.message)),
        }
    }

    pub async fn drop_ownership(&self) -> Result<()> {
        let response = self.single_line("DROPOWNERSHIP").await?;
        match response.is_ok() {
            true => Ok(()),
            false => Err(Error::protocol(format!(
                "DROPOWNERSHIP returned unexpected response code: {}",
                response.code
            ))),
        }
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.tasks
            .lock()
            .unwrap()
            .drain(..)
            .for_each(|task| task.abort());
        self.shared.socket.abort();
    }
}

fn query_label(query: &str) -> String {
    query
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string()
}

fn parse_listener_addresses(query: &str, text: &str) -> Result<Vec<(String, String)>> {
    let mut line = ControlLine::new(text.trim());
    let mut addresses = Vec::new();
    while !line.is_empty() {
        if !line.is_next_quoted(true) {
            return Err(Error::protocol(format!(
                "'GETINFO {query}' responses are expected to be quoted: {text}"
            )));
        }
        let listener = line.pop(true, true)?;
        let Some((address, port)) = listener.rsplit_once(':') else {
            return Err(Error::protocol(format!(
                "'GETINFO {query}' had a listener without a colon: {listener}"
            )));
        };
        if address == "unix" {
            continue;
        }
        let address = address.trim_start_matches('[').trim_end_matches(']');
        addresses.push((address.to_string(), port.to_string()));
    }
    Ok(addresses)
}

pub(crate) async fn receive_with_timeout(
    receiver: &mut mpsc::UnboundedReceiver<Event>,
    timeout: Option<Duration>,
    started: Instant,
) -> Result<Event> {
    let Some(limit) = timeout else {
        return receiver.recv().await.ok_or(Error::SocketClosed);
    };
    let message = || format!("Reached our {:.1} second timeout", limit.as_secs_f64());
    let remaining = limit
        .checked_sub(started.elapsed())
        .ok_or_else(|| Error::Timeout(message()))?;
    match tokio::time::timeout(remaining, receiver.recv()).await {
        Ok(Some(event)) => Ok(event),
        Ok(None) => Err(Error::SocketClosed),
        Err(_) => Err(Error::Timeout(message())),
    }
}

pub(crate) fn is_valid_target_address(address: &str) -> bool {
    is_valid_ipv4_address(address) || is_valid_ipv6_address(address, false)
}
