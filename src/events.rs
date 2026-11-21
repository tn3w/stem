use std::collections::{HashMap, VecDeque};
use std::time::SystemTime;

use chrono::NaiveDateTime;

use crate::address::{is_valid_ipv4_address, is_valid_ipv6_address, parse_port};
use crate::descriptor::hidden_service::HiddenServiceDescriptor;
use crate::descriptor::router_status::RouterStatusEntryV3;
use crate::enumerations::string_enum;
use crate::enumerations::*;
use crate::error::{Error, Result};
use crate::formatting::{parse_iso_timestamp, parse_timestamp};
use crate::response::{ControlMessage, unescape_bytes};
use crate::validation::{
    is_valid_circuit_id, is_valid_connection_id, is_valid_fingerprint, is_valid_nickname,
    is_valid_stream_id,
};
use crate::version::Requirement;

string_enum!(EventType {
    AddrMap = "ADDRMAP",
    AuthDirNewDescs = "AUTHDIR_NEWDESCS",
    BuildTimeoutSet = "BUILDTIMEOUT_SET",
    Bw = "BW",
    CellStats = "CELL_STATS",
    Circ = "CIRC",
    CircBw = "CIRC_BW",
    CircMinor = "CIRC_MINOR",
    ConfChanged = "CONF_CHANGED",
    ConnBw = "CONN_BW",
    ClientsSeen = "CLIENTS_SEEN",
    Debug = "DEBUG",
    DescChanged = "DESCCHANGED",
    Err = "ERR",
    Guard = "GUARD",
    HsDesc = "HS_DESC",
    HsDescContent = "HS_DESC_CONTENT",
    Info = "INFO",
    NetworkLiveness = "NETWORK_LIVENESS",
    NewConsensus = "NEWCONSENSUS",
    NewDesc = "NEWDESC",
    Notice = "NOTICE",
    Ns = "NS",
    OrConn = "ORCONN",
    PtLog = "PT_LOG",
    PtStatus = "PT_STATUS",
    Signal = "SIGNAL",
    StatusClient = "STATUS_CLIENT",
    StatusGeneral = "STATUS_GENERAL",
    StatusServer = "STATUS_SERVER",
    Stream = "STREAM",
    StreamBw = "STREAM_BW",
    TbEmpty = "TB_EMPTY",
    TransportLaunched = "TRANSPORT_LAUNCHED",
    Warn = "WARN",
    MalformedEvents = "MALFORMED_EVENTS",
});

impl EventType {
    pub fn is_sendable(&self) -> bool {
        let text = self.as_str();
        *self != EventType::MalformedEvents
            && !text.is_empty()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    }

    pub fn version_added(&self) -> Option<Requirement> {
        Some(match self {
            Self::AuthDirNewDescs => Requirement::EventAuthdirNewdescs,
            Self::BuildTimeoutSet => Requirement::EventBuildtimeoutSet,
            Self::CellStats => Requirement::EventCellStats,
            Self::CircBw => Requirement::EventCircBw,
            Self::CircMinor => Requirement::EventCircMinor,
            Self::ClientsSeen => Requirement::EventClientsSeen,
            Self::ConfChanged => Requirement::EventConfChanged,
            Self::ConnBw => Requirement::EventConnBw,
            Self::DescChanged => Requirement::EventDescChanged,
            Self::Guard => Requirement::EventGuard,
            Self::HsDesc => Requirement::EventHsDesc,
            Self::HsDescContent => Requirement::EventHsDescContent,
            Self::NetworkLiveness => Requirement::EventNetworkLiveness,
            Self::NewConsensus => Requirement::EventNewConsensus,
            Self::Ns => Requirement::EventNs,
            Self::Signal => Requirement::EventSignal,
            Self::StatusClient | Self::StatusGeneral | Self::StatusServer => {
                Requirement::EventStatus
            }
            Self::StreamBw => Requirement::EventStreamBw,
            Self::TbEmpty => Requirement::EventTbEmpty,
            Self::TransportLaunched => Requirement::EventTransportLaunched,
            _ => return None,
        })
    }
}

pub type CircuitEntry = (Option<String>, Option<String>);

pub fn parse_circuit_entry(entry: &str) -> Result<CircuitEntry> {
    let (fingerprint, nickname) =
        if let Some((fingerprint, nickname)) = entry.split_once('=') {
            if nickname.contains('=') {
                return Err(Error::protocol(format!(
                    "Fingerprint in the circuit path is malformed ({entry})"
                )));
            }
            (Some(fingerprint), Some(nickname))
        } else if let Some((fingerprint, nickname)) = entry.split_once('~') {
            if nickname.contains('~') {
                return Err(Error::protocol(format!(
                    "Fingerprint in the circuit path is malformed ({entry})"
                )));
            }
            (Some(fingerprint), Some(nickname))
        } else if entry.starts_with('$') {
            (Some(entry), None)
        } else {
            (None, Some(entry))
        };
    if let Some(fingerprint) = fingerprint
        && !is_valid_fingerprint(fingerprint, true)
    {
        return Err(Error::protocol(format!(
            "Fingerprint in the circuit path is malformed ({fingerprint})"
        )));
    }
    if let Some(nickname) = nickname
        && !is_valid_nickname(nickname)
    {
        return Err(Error::protocol(format!(
            "Nickname in the circuit path is malformed ({nickname})"
        )));
    }
    Ok((
        fingerprint.map(|fingerprint| fingerprint[1..].to_string()),
        nickname.map(str::to_string),
    ))
}

pub fn parse_circuit_path(path: &str) -> Result<Vec<CircuitEntry>> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    path.split(',')
        .map(parse_circuit_entry)
        .collect::<Result<Vec<_>>>()
        .map_err(|error| Error::protocol(format!("{error}: {path}")))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quoting {
    Plain,
    Optional,
}

struct Arguments {
    text: String,
    positional: VecDeque<String>,
    keywords: HashMap<String, String>,
}

fn is_keyword_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn peel_quoted_keyword(content: &str) -> Option<(&str, &str, &str)> {
    let body = content.strip_suffix('"')?;
    let bytes = body.as_bytes();
    let mut search_end = bytes.len();
    while let Some(position) = body[..search_end].rfind("=\"") {
        let key_start = bytes[..position]
            .iter()
            .rposition(|byte| !is_keyword_character(*byte))
            .map_or(0, |index| index + 1);
        let has_space = key_start > 0 && bytes[key_start - 1] == b' ';
        if key_start < position && has_space {
            return Some((
                &body[..key_start - 1],
                &body[key_start..position],
                &body[position + 2..],
            ));
        }
        search_end = position;
    }
    None
}

fn peel_plain_keyword(content: &str) -> Option<(&str, &str, &str)> {
    let space = content.rfind(' ')?;
    let token = &content[space + 1..];
    let (key, value) = token.split_once('=')?;
    let is_key = !key.is_empty() && key.bytes().all(is_keyword_character);
    is_key.then_some((&content[..space], key, value))
}

impl Arguments {
    fn parse(message: &ControlMessage) -> Self {
        let text = message.to_string();
        let first_line = text.lines().next().unwrap_or("").to_string();
        let mut content = first_line.as_str();
        let mut keywords = HashMap::new();
        while let Some((rest, key, value)) =
            peel_quoted_keyword(content).or_else(|| peel_plain_keyword(content))
        {
            keywords.insert(key.to_string(), value.to_string());
            content = rest;
        }
        let positional = content
            .split_whitespace()
            .skip(1)
            .map(str::to_string)
            .collect();
        Self {
            text,
            positional,
            keywords,
        }
    }

    fn take(&mut self, name: &str, quoting: Quoting) -> Result<Option<String>> {
        let Some(first) = self.positional.pop_front() else {
            return Ok(None);
        };
        let is_quoted = match quoting {
            Quoting::Plain => false,
            Quoting::Optional => first.starts_with('"'),
        };
        if !is_quoted {
            return Ok(Some(first));
        }
        if !first.starts_with('"') {
            return Err(self.error(format!(
                "The {name} value should be quoted, but didn't have a starting quote"
            )));
        }
        let mut pieces = vec![first];
        loop {
            let Some(next) = self.positional.pop_front() else {
                return Err(self.error(format!(
                    "The {name} value should be quoted, but didn't have an ending quote"
                )));
            };
            let finished = next.ends_with('"');
            pieces.push(next);
            if finished {
                break;
            }
        }
        let joined = pieces.join(" ");
        Ok(Some(joined[1..joined.len() - 1].to_string()))
    }

    fn require(&mut self, name: &str, quoting: Quoting) -> Result<String> {
        self.take(name, quoting)?
            .ok_or_else(|| self.error(format!("Event is missing its {name}")))
    }

    fn error(&self, message: impl std::fmt::Display) -> Error {
        Error::protocol(format!("{message}: {}", self.text))
    }

    fn keyword(&self, name: &str) -> Option<String> {
        self.keywords.get(name).cloned()
    }

    fn number(&self, name: &str, label: &str) -> Result<Option<u64>> {
        self.keyword(name)
            .map(|value| self.parse_number(&value, label))
            .transpose()
    }

    fn parse_number(&self, value: &str, label: &str) -> Result<u64> {
        let is_digits =
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit());
        match is_digits.then(|| value.parse().ok()).flatten() {
            Some(number) => Ok(number),
            None => Err(self.error(format!(
                "{label} should be a positive numeric value, received: {value}"
            ))),
        }
    }

    fn iso_timestamp(&self, value: Option<String>) -> Result<Option<NaiveDateTime>> {
        value
            .map(|timestamp| {
                parse_iso_timestamp(&timestamp).map_err(|error| {
                    self.error(format!("Unable to parse timestamp ({error})"))
                })
            })
            .transpose()
    }
}

fn recognized<T: std::str::FromStr<Err = std::convert::Infallible>>(
    event_type: &str,
    attribute: &str,
    value: &str,
    is_recognized: impl Fn(&T) -> bool,
) -> T {
    let parsed: T = value.parse().unwrap_or_else(|never| match never {});
    if !is_recognized(&parsed) {
        log::info!(
            "{event_type} event had an unrecognized {attribute} ({value}). Maybe a new \
            addition to the control protocol?"
        );
    }
    parsed
}

macro_rules! typed {
    ($event_type:expr, $attribute:expr, $value:expr, $enum:ty) => {
        recognized::<$enum>($event_type, $attribute, $value, <$enum>::is_recognized)
    };
}

macro_rules! typed_option {
    ($event_type:expr, $attribute:expr, $value:expr, $enum:ty) => {
        $value
            .as_deref()
            .map(|text| typed!($event_type, $attribute, text, $enum))
    };
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AddrMapEvent {
    pub hostname: String,
    pub destination: Option<String>,
    pub expiry: Option<NaiveDateTime>,
    pub error: Option<String>,
    pub utc_expiry: Option<NaiveDateTime>,
    pub cached: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthDirNewDescEvent {
    pub action: String,
    pub message: String,
    pub descriptor: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BandwidthEvent {
    pub read: u64,
    pub written: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BuildTimeoutSetEvent {
    pub set_type: TimeoutSetType,
    pub total_times: Option<u64>,
    pub timeout: Option<u64>,
    pub xm: Option<u64>,
    pub alpha: Option<f64>,
    pub quantile: Option<f64>,
    pub timeout_rate: Option<f64>,
    pub close_timeout: Option<u64>,
    pub close_rate: Option<f64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CircuitEvent {
    pub id: String,
    pub status: CircStatus,
    pub path: Vec<CircuitEntry>,
    pub build_flags: Option<Vec<CircBuildFlag>>,
    pub purpose: Option<CircPurpose>,
    pub hs_state: Option<HiddenServiceState>,
    pub rend_query: Option<String>,
    pub created: Option<NaiveDateTime>,
    pub reason: Option<CircClosureReason>,
    pub remote_reason: Option<CircClosureReason>,
    pub socks_username: Option<String>,
    pub socks_password: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CircMinorEvent {
    pub id: String,
    pub event: CircEvent,
    pub path: Vec<CircuitEntry>,
    pub build_flags: Option<Vec<CircBuildFlag>>,
    pub purpose: Option<CircPurpose>,
    pub hs_state: Option<HiddenServiceState>,
    pub rend_query: Option<String>,
    pub created: Option<NaiveDateTime>,
    pub old_purpose: Option<CircPurpose>,
    pub old_hs_state: Option<HiddenServiceState>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ClientsSeenEvent {
    pub start_time: Option<NaiveDateTime>,
    pub locales: Option<HashMap<String, u64>>,
    pub ip_versions: Option<HashMap<String, u64>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConfChangedEvent {
    pub changed: HashMap<String, Vec<String>>,
    pub unset: Vec<String>,
    pub config: HashMap<String, Option<String>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GuardEvent {
    pub guard_type: GuardType,
    pub endpoint: String,
    pub endpoint_fingerprint: Option<String>,
    pub endpoint_nickname: Option<String>,
    pub status: GuardStatus,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HsDescEvent {
    pub action: HsDescAction,
    pub address: String,
    pub authentication: HsAuth,
    pub directory: String,
    pub directory_fingerprint: Option<String>,
    pub directory_nickname: Option<String>,
    pub descriptor_id: Option<String>,
    pub reason: Option<HsDescReason>,
    pub replica: Option<u64>,
    pub index: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HsDescContentEvent {
    pub address: Option<String>,
    pub descriptor_id: String,
    pub directory: String,
    pub directory_fingerprint: Option<String>,
    pub directory_nickname: Option<String>,
    pub descriptor: Option<HiddenServiceDescriptor>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LogEvent {
    pub runlevel: Runlevel,
    pub message: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkStatusEvent {
    pub desc: Vec<RouterStatusEntryV3>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkLivenessEvent {
    pub status: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NewConsensusEvent {
    pub consensus_content: String,
}

impl NewConsensusEvent {
    pub fn entries(&self, validate: bool) -> Result<Vec<RouterStatusEntryV3>> {
        RouterStatusEntryV3::parse_many(self.consensus_content.as_bytes(), validate)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NewDescEvent {
    pub relays: Vec<CircuitEntry>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OrConnEvent {
    pub endpoint: String,
    pub endpoint_fingerprint: Option<String>,
    pub endpoint_nickname: Option<String>,
    pub endpoint_address: Option<String>,
    pub endpoint_port: Option<u16>,
    pub status: OrStatus,
    pub reason: Option<OrClosureReason>,
    pub circ_count: Option<u64>,
    pub id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PtLogEvent {
    pub program: String,
    pub message: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PtStatusEvent {
    pub program: String,
    pub transport: String,
    pub message: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SignalEvent {
    pub signal: Signal,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StatusEvent {
    pub status_type: StatusType,
    pub runlevel: Runlevel,
    pub action: String,
    pub arguments: HashMap<String, String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamEvent {
    pub id: String,
    pub status: StreamStatus,
    pub circ_id: Option<String>,
    pub target: String,
    pub target_address: String,
    pub target_port: u16,
    pub reason: Option<StreamClosureReason>,
    pub remote_reason: Option<StreamClosureReason>,
    pub source: Option<StreamSource>,
    pub source_addr: Option<String>,
    pub source_address: Option<String>,
    pub source_port: Option<u16>,
    pub purpose: Option<StreamPurpose>,
    pub socks_username: Option<String>,
    pub socks_password: Option<String>,
    pub client_protocol: Option<String>,
    pub nym_epoch: Option<String>,
    pub session_group: Option<String>,
    pub iso_fields: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamBandwidthEvent {
    pub id: String,
    pub written: u64,
    pub read: u64,
    pub time: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TransportLaunchedEvent {
    pub transport_type: String,
    pub name: String,
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionBandwidthEvent {
    pub id: String,
    pub conn_type: ConnectionType,
    pub read: u64,
    pub written: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CircuitBandwidthEvent {
    pub id: String,
    pub read: u64,
    pub written: u64,
    pub delivered_read: Option<u64>,
    pub delivered_written: Option<u64>,
    pub overhead_read: Option<u64>,
    pub overhead_written: Option<u64>,
    pub time: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CellStatsEvent {
    pub id: Option<String>,
    pub inbound_queue: Option<String>,
    pub inbound_connection: Option<String>,
    pub inbound_added: Option<HashMap<String, u64>>,
    pub inbound_removed: Option<HashMap<String, u64>>,
    pub inbound_time: Option<HashMap<String, u64>>,
    pub outbound_queue: Option<String>,
    pub outbound_connection: Option<String>,
    pub outbound_added: Option<HashMap<String, u64>>,
    pub outbound_removed: Option<HashMap<String, u64>>,
    pub outbound_time: Option<HashMap<String, u64>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenBucketEmptyEvent {
    pub bucket: TokenBucket,
    pub id: Option<String>,
    pub read: u64,
    pub written: u64,
    pub last_refill: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
pub enum EventData {
    AddrMap(AddrMapEvent),
    AuthDirNewDescs(AuthDirNewDescEvent),
    Bandwidth(BandwidthEvent),
    BuildTimeoutSet(BuildTimeoutSetEvent),
    CellStats(CellStatsEvent),
    Circuit(CircuitEvent),
    CircuitBandwidth(CircuitBandwidthEvent),
    CircMinor(CircMinorEvent),
    ClientsSeen(ClientsSeenEvent),
    ConfChanged(ConfChangedEvent),
    ConnectionBandwidth(ConnectionBandwidthEvent),
    DescChanged,
    Guard(GuardEvent),
    HsDesc(HsDescEvent),
    HsDescContent(HsDescContentEvent),
    Log(LogEvent),
    NetworkLiveness(NetworkLivenessEvent),
    NetworkStatus(NetworkStatusEvent),
    NewConsensus(NewConsensusEvent),
    NewDesc(NewDescEvent),
    OrConn(OrConnEvent),
    PtLog(PtLogEvent),
    PtStatus(PtStatusEvent),
    Signal(SignalEvent),
    Status(StatusEvent),
    Stream(StreamEvent),
    StreamBandwidth(StreamBandwidthEvent),
    TokenBucketEmpty(TokenBucketEmptyEvent),
    TransportLaunched(TransportLaunchedEvent),
    Unrecognized,
    Malformed(String),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Event {
    pub event_type: String,
    pub data: EventData,
    pub positional_args: Vec<String>,
    pub keyword_args: HashMap<String, String>,
    #[serde(skip)]
    pub message: ControlMessage,
}

impl Event {
    pub fn arrived_at(&self) -> SystemTime {
        self.message.arrived_at
    }

    pub fn is_malformed(&self) -> bool {
        matches!(self.data, EventData::Malformed(_))
    }

    pub fn listener_type(&self) -> EventType {
        match self.is_malformed() {
            true => EventType::MalformedEvents,
            false => self.event_type.as_str().into(),
        }
    }

    pub fn malformed(message: ControlMessage, reason: String) -> Self {
        let event_type = message
            .to_string()
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        Self {
            event_type,
            data: EventData::Malformed(reason),
            positional_args: Vec::new(),
            keyword_args: HashMap::new(),
            message,
        }
    }

    pub fn parse(message: ControlMessage) -> Result<Self> {
        let text = message.to_string();
        let Some(event_type) = text.split_whitespace().next().map(str::to_string) else {
            return Err(Error::protocol(
                "Received a blank tor event. Events must at the very least have a type.",
            ));
        };
        let mut arguments = Arguments::parse(&message);
        let positional_args = arguments.positional.iter().cloned().collect();
        let keyword_args = arguments.keywords.clone();
        let data = parse_event_data(&event_type, &message, &mut arguments)?;
        Ok(Self {
            event_type,
            data,
            positional_args,
            keyword_args,
            message,
        })
    }

    pub fn from_content(content: &str) -> Result<Self> {
        Self::parse(ControlMessage::parse(content, true)?)
    }
}

fn parse_event_data(
    event_type: &str,
    message: &ControlMessage,
    arguments: &mut Arguments,
) -> Result<EventData> {
    Ok(match event_type {
        "ADDRMAP" => EventData::AddrMap(parse_addrmap(arguments)?),
        "AUTHDIR_NEWDESCS" => {
            EventData::AuthDirNewDescs(parse_authdir_newdescs(arguments)?)
        }
        "BW" => EventData::Bandwidth(parse_bandwidth(arguments)?),
        "BUILDTIMEOUT_SET" => {
            EventData::BuildTimeoutSet(parse_buildtimeout_set(arguments)?)
        }
        "CELL_STATS" => EventData::CellStats(parse_cell_stats(arguments)?),
        "CIRC" => EventData::Circuit(parse_circuit(arguments)?),
        "CIRC_BW" => EventData::CircuitBandwidth(parse_circuit_bandwidth(arguments)?),
        "CIRC_MINOR" => EventData::CircMinor(parse_circ_minor(arguments)?),
        "CLIENTS_SEEN" => EventData::ClientsSeen(parse_clients_seen(arguments)?),
        "CONF_CHANGED" => EventData::ConfChanged(parse_conf_changed(message)),
        "CONN_BW" => {
            EventData::ConnectionBandwidth(parse_connection_bandwidth(arguments)?)
        }
        "DESCCHANGED" => EventData::DescChanged,
        "DEBUG" | "INFO" | "NOTICE" | "WARN" | "ERR" => {
            EventData::Log(parse_log(event_type, message))
        }
        "GUARD" => EventData::Guard(parse_guard(arguments)?),
        "HS_DESC" => EventData::HsDesc(parse_hs_desc(arguments)?),
        "HS_DESC_CONTENT" => EventData::HsDescContent(parse_hs_desc_content(arguments)?),
        "NETWORK_LIVENESS" => EventData::NetworkLiveness(NetworkLivenessEvent {
            status: arguments.require("status", Quoting::Plain)?,
        }),
        "NEWCONSENSUS" => EventData::NewConsensus(parse_new_consensus(message)),
        "NEWDESC" => EventData::NewDesc(parse_new_desc(message)?),
        "NS" => EventData::NetworkStatus(parse_network_status(message)?),
        "ORCONN" => EventData::OrConn(parse_or_conn(arguments)?),
        "PT_LOG" => EventData::PtLog(parse_pt_log(message)?),
        "PT_STATUS" => EventData::PtStatus(parse_pt_status(message)?),
        "SIGNAL" => EventData::Signal(SignalEvent {
            signal: typed!(
                event_type,
                "signal",
                &arguments.require("signal", Quoting::Plain)?,
                Signal
            ),
        }),
        "STATUS_GENERAL" | "STATUS_CLIENT" | "STATUS_SERVER" => {
            EventData::Status(parse_status(event_type, arguments)?)
        }
        "STREAM" => EventData::Stream(parse_stream(arguments)?),
        "STREAM_BW" => EventData::StreamBandwidth(parse_stream_bandwidth(arguments)?),
        "TB_EMPTY" => EventData::TokenBucketEmpty(parse_token_bucket_empty(arguments)?),
        "TRANSPORT_LAUNCHED" => {
            EventData::TransportLaunched(parse_transport_launched(arguments)?)
        }
        _ => EventData::Unrecognized,
    })
}

fn parse_addrmap(arguments: &mut Arguments) -> Result<AddrMapEvent> {
    let hostname = arguments.require("hostname", Quoting::Plain)?;
    let destination = arguments.require("destination", Quoting::Plain)?;
    let expiry = arguments.take("expiry", Quoting::Optional)?;
    let expiry = match expiry.as_deref() {
        None | Some("NEVER") => None,
        Some(value) => Some(
            parse_timestamp(value)
                .map_err(|_| arguments.error("Unable to parse date in ADDRMAP event"))?,
        ),
    };
    let utc_expiry = arguments
        .keyword("EXPIRES")
        .map(|value| parse_timestamp(&value))
        .transpose()?;
    let cached = match arguments.keyword("CACHED").as_deref() {
        None => None,
        Some("YES") => Some(true),
        Some("NO") => Some(false),
        Some(_) => {
            return Err(arguments
                .error("An ADDRMAP event's CACHED mapping can only be 'YES' or 'NO'"));
        }
    };
    Ok(AddrMapEvent {
        hostname,
        destination: Some(destination).filter(|value| value != "<error>"),
        expiry,
        error: arguments.keyword("error"),
        utc_expiry,
        cached,
    })
}

fn parse_authdir_newdescs(arguments: &Arguments) -> Result<AuthDirNewDescEvent> {
    let lines: Vec<&str> = arguments.text.split('\n').collect();
    if lines.len() < 5 {
        return Err(Error::protocol(
            "AUTHDIR_NEWDESCS events must contain lines for at least the type, action, \
            message, descriptor, and terminating 'OK'",
        ));
    }
    if lines[lines.len() - 1] != "OK" {
        return Err(Error::protocol("AUTHDIR_NEWDESCS doesn't end with an 'OK'"));
    }
    Ok(AuthDirNewDescEvent {
        action: lines[1].to_string(),
        message: lines[2].to_string(),
        descriptor: lines[3..lines.len() - 1].join("\n"),
    })
}

fn parse_bandwidth(arguments: &mut Arguments) -> Result<BandwidthEvent> {
    let read = arguments.take("read", Quoting::Plain)?;
    let written = arguments.take("written", Quoting::Plain)?;
    let (Some(read), Some(written)) = (read, written) else {
        return Err(Error::protocol(
            "BW event is missing its read or written value",
        ));
    };
    let label = "A BW event's bytes sent and received";
    Ok(BandwidthEvent {
        read: arguments.parse_number(&read, label)?,
        written: arguments.parse_number(&written, label)?,
    })
}

fn parse_buildtimeout_set(arguments: &mut Arguments) -> Result<BuildTimeoutSetEvent> {
    let set_type = arguments.require("set_type", Quoting::Plain)?;
    let integer = |name: &str, label: &str| -> Result<Option<u64>> {
        arguments
            .keyword(name)
            .map(|value| {
                value.parse::<u64>().map_err(|_| {
                    arguments.error(format!(
                        "The {label} of a BUILDTIMEOUT_SET should be an integer"
                    ))
                })
            })
            .transpose()
    };
    let float = |name: &str, label: &str| -> Result<Option<f64>> {
        arguments
            .keyword(name)
            .map(|value| {
                value.parse::<f64>().map_err(|_| {
                    arguments.error(format!(
                        "The {label} of a BUILDTIMEOUT_SET should be a float"
                    ))
                })
            })
            .transpose()
    };
    Ok(BuildTimeoutSetEvent {
        total_times: integer("TOTAL_TIMES", "total_times")?,
        timeout: integer("TIMEOUT_MS", "timeout")?,
        xm: integer("XM", "xm")?,
        alpha: float("ALPHA", "alpha")?,
        quantile: float("CUTOFF_QUANTILE", "quantile")?,
        timeout_rate: float("TIMEOUT_RATE", "timeout_rate")?,
        close_timeout: integer("CLOSE_MS", "close_timeout")?,
        close_rate: float("CLOSE_RATE", "close_rate")?,
        set_type: typed!("BUILDTIMEOUT_SET", "set_type", &set_type, TimeoutSetType),
    })
}

fn parse_build_flags(
    arguments: &Arguments,
    event_type: &str,
) -> Option<Vec<CircBuildFlag>> {
    arguments.keyword("BUILD_FLAGS").map(|flags| {
        flags
            .split(',')
            .map(|flag| typed!(event_type, "build_flags", flag, CircBuildFlag))
            .collect()
    })
}

fn validated_circuit_id(arguments: &Arguments, id: String) -> Result<String> {
    match is_valid_circuit_id(&id) {
        true => Ok(id),
        false => Err(arguments.error(format!(
            "Circuit IDs must be one to sixteen alphanumeric characters, got '{id}'"
        ))),
    }
}

fn parse_circuit(arguments: &mut Arguments) -> Result<CircuitEvent> {
    let id = arguments.require("id", Quoting::Plain)?;
    let status = arguments.require("status", Quoting::Plain)?;
    let path = arguments.take("path", Quoting::Plain)?.unwrap_or_default();
    let created = arguments.iso_timestamp(arguments.keyword("TIME_CREATED"))?;
    Ok(CircuitEvent {
        id: validated_circuit_id(arguments, id)?,
        status: typed!("CIRC", "status", &status, CircStatus),
        path: parse_circuit_path(&path)?,
        build_flags: parse_build_flags(arguments, "CIRC"),
        purpose: typed_option!(
            "CIRC",
            "purpose",
            arguments.keyword("PURPOSE"),
            CircPurpose
        ),
        hs_state: typed_option!(
            "CIRC",
            "hs_state",
            arguments.keyword("HS_STATE"),
            HiddenServiceState
        ),
        rend_query: arguments.keyword("REND_QUERY"),
        created,
        reason: typed_option!(
            "CIRC",
            "reason",
            arguments.keyword("REASON"),
            CircClosureReason
        ),
        remote_reason: typed_option!(
            "CIRC",
            "remote_reason",
            arguments.keyword("REMOTE_REASON"),
            CircClosureReason
        ),
        socks_username: arguments.keyword("SOCKS_USERNAME"),
        socks_password: arguments.keyword("SOCKS_PASSWORD"),
    })
}

fn parse_circ_minor(arguments: &mut Arguments) -> Result<CircMinorEvent> {
    let id = arguments.require("id", Quoting::Plain)?;
    let event = arguments.require("event", Quoting::Plain)?;
    let path = arguments.take("path", Quoting::Plain)?.unwrap_or_default();
    let created = arguments.iso_timestamp(arguments.keyword("TIME_CREATED"))?;
    Ok(CircMinorEvent {
        id: validated_circuit_id(arguments, id)?,
        event: typed!("CIRC_MINOR", "event", &event, CircEvent),
        path: parse_circuit_path(&path)?,
        build_flags: parse_build_flags(arguments, "CIRC_MINOR"),
        purpose: typed_option!(
            "CIRC_MINOR",
            "purpose",
            arguments.keyword("PURPOSE"),
            CircPurpose
        ),
        hs_state: typed_option!(
            "CIRC_MINOR",
            "hs_state",
            arguments.keyword("HS_STATE"),
            HiddenServiceState
        ),
        rend_query: arguments.keyword("REND_QUERY"),
        created,
        old_purpose: typed_option!(
            "CIRC_MINOR",
            "old_purpose",
            arguments.keyword("OLD_PURPOSE"),
            CircPurpose
        ),
        old_hs_state: typed_option!(
            "CIRC_MINOR",
            "old_hs_state",
            arguments.keyword("OLD_HS_STATE"),
            HiddenServiceState
        ),
    })
}

fn parse_count_mapping(
    arguments: &Arguments,
    value: &str,
    kind: &str,
    require_locale: bool,
) -> Result<HashMap<String, u64>> {
    let mut counts = HashMap::new();
    for entry in value.split(',') {
        let Some((key, count)) = entry.split_once('=') else {
            return Err(arguments.error(format!(
                "The CLIENTS_SEEN's {kind} should be a comma separated listing of \
                '<key>=<count>' mappings"
            )));
        };
        if require_locale && key.chars().count() != 2 {
            return Err(arguments.error(format!(
                "Locales should be a two character code, got '{key}'"
            )));
        }
        let count = arguments.parse_number(count, &format!("{kind} count"))?;
        if counts.insert(key.to_string(), count).is_some() && require_locale {
            return Err(arguments
                .error(format!("CountrySummary had multiple mappings for '{key}'")));
        }
    }
    Ok(counts)
}

fn parse_clients_seen(arguments: &mut Arguments) -> Result<ClientsSeenEvent> {
    let start_time = arguments
        .keyword("TimeStarted")
        .map(|value| parse_timestamp(&value))
        .transpose()?;
    let locales = arguments
        .keyword("CountrySummary")
        .map(|value| parse_count_mapping(arguments, &value, "CountrySummary", true))
        .transpose()?;
    let ip_versions = arguments
        .keyword("IPVersions")
        .map(|value| parse_count_mapping(arguments, &value, "IPVersions", false))
        .transpose()?;
    Ok(ClientsSeenEvent {
        start_time,
        locales,
        ip_versions,
    })
}

fn parse_conf_changed(message: &ControlMessage) -> ConfChangedEvent {
    let text = message.to_string();
    let lines: Vec<&str> = text.lines().collect();
    let body = lines.get(1..lines.len().saturating_sub(1)).unwrap_or(&[]);
    let mut event = ConfChangedEvent {
        changed: HashMap::new(),
        unset: Vec::new(),
        config: HashMap::new(),
    };
    for line in body {
        match line.split_once('=') {
            Some((key, value)) => {
                event
                    .changed
                    .entry(key.to_string())
                    .or_default()
                    .push(value.to_string());
                event
                    .config
                    .insert(key.to_string(), Some(value.to_string()));
            }
            None => {
                event.unset.push(line.to_string());
                event.config.insert(line.to_string(), None);
            }
        }
    }
    event
}

fn parse_guard(arguments: &mut Arguments) -> Result<GuardEvent> {
    let guard_type = arguments.require("guard_type", Quoting::Plain)?;
    let endpoint = arguments.require("endpoint", Quoting::Plain)?;
    let status = arguments.require("status", Quoting::Plain)?;
    let (endpoint_fingerprint, endpoint_nickname) = parse_circuit_entry(&endpoint)
        .map_err(|_| arguments.error("GUARD's endpoint doesn't match a ServerSpec"))?;
    Ok(GuardEvent {
        guard_type: typed!("GUARD", "guard_type", &guard_type, GuardType),
        endpoint,
        endpoint_fingerprint,
        endpoint_nickname,
        status: typed!("GUARD", "status", &status, GuardStatus),
    })
}

fn parse_hs_desc(arguments: &mut Arguments) -> Result<HsDescEvent> {
    let action = arguments.require("action", Quoting::Plain)?;
    let address = arguments.require("address", Quoting::Plain)?;
    let authentication = arguments.require("authentication", Quoting::Plain)?;
    let directory = arguments.require("directory", Quoting::Plain)?;
    let descriptor_id = arguments.take("descriptor_id", Quoting::Plain)?;
    let (directory_fingerprint, directory_nickname) = match directory.as_str() {
        "UNKNOWN" => (None, None),
        _ => parse_circuit_entry(&directory).map_err(|_| {
            arguments.error("HS_DESC's directory doesn't match a ServerSpec")
        })?,
    };
    let replica = match arguments.keyword("REPLICA") {
        Some(value) => {
            Some(arguments.parse_number(&value, "HS_DESC event replica count")?)
        }
        None => None,
    };
    Ok(HsDescEvent {
        action: typed!("HS_DESC", "action", &action, HsDescAction),
        address,
        authentication: typed!("HS_DESC", "authentication", &authentication, HsAuth),
        directory,
        directory_fingerprint,
        directory_nickname,
        descriptor_id,
        reason: typed_option!(
            "HS_DESC",
            "reason",
            arguments.keyword("REASON"),
            HsDescReason
        ),
        replica,
        index: arguments.keyword("HSDIR_INDEX"),
    })
}

fn parse_hs_desc_content(arguments: &mut Arguments) -> Result<HsDescContentEvent> {
    let address = arguments.require("address", Quoting::Plain)?;
    let descriptor_id = arguments.require("descriptor_id", Quoting::Plain)?;
    let directory = arguments.require("directory", Quoting::Plain)?;
    let (directory_fingerprint, directory_nickname) = parse_circuit_entry(&directory)
        .map_err(|_| {
            arguments.error("HS_DESC_CONTENT's directory doesn't match a ServerSpec")
        })?;
    let lines: Vec<&str> = arguments.text.lines().collect();
    let content = lines
        .get(1..lines.len().saturating_sub(1))
        .unwrap_or(&[])
        .join("\n");
    let descriptor = match content.is_empty() {
        true => None,
        false => Some(HiddenServiceDescriptor::parse(content.as_bytes(), false)?),
    };
    Ok(HsDescContentEvent {
        address: Some(address).filter(|address| address != "UNKNOWN"),
        descriptor_id,
        directory,
        directory_fingerprint,
        directory_nickname,
        descriptor,
    })
}

fn parse_log(event_type: &str, message: &ControlMessage) -> LogEvent {
    let text = message.to_string();
    let mut body = text.get(event_type.len() + 1..).unwrap_or("").to_string();
    if let Some(stripped) = body.strip_suffix("\nOK") {
        body = stripped.to_string();
    }
    LogEvent {
        runlevel: typed!(event_type, "runlevel", event_type, Runlevel),
        message: body,
    }
}

fn body_between(message: &ControlMessage, event_type: &str) -> String {
    let text = message.to_string();
    let body = text
        .strip_prefix(event_type)
        .map(|rest| rest.strip_prefix('\n').unwrap_or(rest))
        .unwrap_or(&text);
    body.strip_suffix("\nOK").unwrap_or(body).to_string()
}

fn parse_network_status(message: &ControlMessage) -> Result<NetworkStatusEvent> {
    let content = body_between(message, "NS");
    Ok(NetworkStatusEvent {
        desc: RouterStatusEntryV3::parse_many(content.as_bytes(), false)?,
    })
}

fn parse_new_consensus(message: &ControlMessage) -> NewConsensusEvent {
    NewConsensusEvent {
        consensus_content: body_between(message, "NEWCONSENSUS"),
    }
}

fn parse_new_desc(message: &ControlMessage) -> Result<NewDescEvent> {
    let text = message.to_string();
    let relays = text
        .split_whitespace()
        .skip(1)
        .map(parse_circuit_entry)
        .collect::<Result<Vec<_>>>()?;
    Ok(NewDescEvent { relays })
}

fn parse_endpoint(
    arguments: &Arguments,
    label: &str,
    target: &str,
    allow_zero: bool,
) -> Result<(String, u16)> {
    let Some((address, port)) = target.rsplit_once(':') else {
        return Err(arguments.error(format!(
            "{label} location must be of the form 'address:port'"
        )));
    };
    let Some(port) = parse_port(port, allow_zero) else {
        return Err(arguments.error(format!("{label} location's port is invalid")));
    };
    Ok((address.to_string(), port))
}

fn parse_or_conn(arguments: &mut Arguments) -> Result<OrConnEvent> {
    let endpoint = arguments.require("endpoint", Quoting::Plain)?;
    let status = arguments.require("status", Quoting::Plain)?;
    let (mut fingerprint, mut nickname, mut address, mut port) = (None, None, None, None);
    match parse_circuit_entry(&endpoint) {
        Ok((parsed_fingerprint, parsed_nickname)) => {
            fingerprint = parsed_fingerprint;
            nickname = parsed_nickname;
        }
        Err(_) => {
            if !endpoint.contains(':') {
                return Err(arguments
                    .error("ORCONN endpoint is neither a relay nor 'address:port'"));
            }
            let (parsed_address, parsed_port) =
                parse_endpoint(arguments, "ORCONN's endpoint", &endpoint, false)?;
            address = Some(parsed_address);
            port = Some(parsed_port);
        }
    }
    let circ_count = match arguments.keyword("NCIRCS") {
        Some(value) => {
            Some(arguments.parse_number(&value, "ORCONN event circuit count")?)
        }
        None => None,
    };
    let id = arguments.keyword("ID");
    if id.as_deref().is_some_and(|id| !is_valid_connection_id(id)) {
        return Err(arguments
            .error("Connection IDs must be one to sixteen alphanumeric characters"));
    }
    Ok(OrConnEvent {
        endpoint,
        endpoint_fingerprint: fingerprint,
        endpoint_nickname: nickname,
        endpoint_address: address,
        endpoint_port: port,
        status: typed!("ORCONN", "status", &status, OrStatus),
        reason: typed_option!(
            "ORCONN",
            "reason",
            arguments.keyword("REASON"),
            OrClosureReason
        ),
        circ_count,
        id,
    })
}

fn parse_pt_log(message: &ControlMessage) -> Result<PtLogEvent> {
    let text = message.to_string();
    let rest = text.strip_prefix("PT_LOG").unwrap_or(&text).trim_start();
    let Some(rest) = rest.strip_prefix("PT=") else {
        return Err(Error::protocol(format!(
            "PT_LOG event is missing its PT: {text}"
        )));
    };
    let (program, log_message) = rest.split_once(' ').unwrap_or((rest, ""));
    Ok(PtLogEvent {
        program: program.to_string(),
        message: log_message.to_string(),
    })
}

fn parse_pt_status(message: &ControlMessage) -> Result<PtStatusEvent> {
    let text = message.to_string();
    let rest = text.strip_prefix("PT_STATUS").unwrap_or(&text).trim_start();
    let mut line = crate::response::ControlLine::new(rest);
    let missing = || {
        Error::protocol(format!(
            "PT_STATUS event is missing PT or TRANSPORT: {text}"
        ))
    };
    if !line.is_next_mapping(Some("PT"), false, false) {
        return Err(missing());
    }
    let (_, program) = line.pop_mapping(false, false)?;
    if !line.is_next_mapping(Some("TRANSPORT"), false, false) {
        return Err(missing());
    }
    let (_, transport) = line.pop_mapping(false, false)?;
    Ok(PtStatusEvent {
        program,
        transport,
        message: line.remainder().to_string(),
    })
}

fn parse_status(event_type: &str, arguments: &mut Arguments) -> Result<StatusEvent> {
    let runlevel = arguments.require("runlevel", Quoting::Plain)?;
    let action = arguments.require("action", Quoting::Plain)?;
    let status_type = match event_type {
        "STATUS_GENERAL" => StatusType::General,
        "STATUS_CLIENT" => StatusType::Client,
        _ => StatusType::Server,
    };
    Ok(StatusEvent {
        status_type,
        runlevel: typed!(event_type, "runlevel", &runlevel, Runlevel),
        action,
        arguments: arguments.keywords.clone(),
    })
}

fn optional_endpoint(
    arguments: &Arguments,
    label: &str,
    value: Option<&str>,
) -> Result<(Option<String>, Option<u16>)> {
    let Some(value) = value else {
        return Ok((None, None));
    };
    let (address, port) = parse_endpoint(arguments, label, value, true)?;
    Ok((Some(address), Some(port)))
}

fn parse_stream(arguments: &mut Arguments) -> Result<StreamEvent> {
    let id = arguments.require("id", Quoting::Plain)?;
    let status = arguments.require("status", Quoting::Plain)?;
    let circ_id = arguments.take("circ_id", Quoting::Plain)?;
    let Some(target) = arguments.take("target", Quoting::Plain)? else {
        return Err(arguments.error("STREAM event didn't have a target"));
    };
    let (target_address, target_port) =
        parse_endpoint(arguments, "Target", &target, true)?;
    let source_addr = arguments.keyword("SOURCE_ADDR");
    let (source_address, source_port) =
        optional_endpoint(arguments, "Source", source_addr.as_deref())?;
    Ok(StreamEvent {
        id,
        status: typed!("STREAM", "status", &status, StreamStatus),
        circ_id: circ_id.filter(|circ_id| circ_id != "0"),
        target,
        target_address,
        target_port,
        reason: typed_option!(
            "STREAM",
            "reason",
            arguments.keyword("REASON"),
            StreamClosureReason
        ),
        remote_reason: typed_option!(
            "STREAM",
            "remote_reason",
            arguments.keyword("REMOTE_REASON"),
            StreamClosureReason
        ),
        source: typed_option!(
            "STREAM",
            "source",
            arguments.keyword("SOURCE"),
            StreamSource
        ),
        source_addr,
        source_address,
        source_port,
        purpose: typed_option!(
            "STREAM",
            "purpose",
            arguments.keyword("PURPOSE"),
            StreamPurpose
        ),
        socks_username: arguments.keyword("SOCKS_USERNAME"),
        socks_password: arguments.keyword("SOCKS_PASSWORD"),
        client_protocol: arguments.keyword("CLIENT_PROTOCOL"),
        nym_epoch: arguments.keyword("NYM_EPOCH"),
        session_group: arguments.keyword("SESSION_GROUP"),
        iso_fields: arguments.keyword("ISO_FIELDS"),
    })
}

fn parse_stream_bandwidth(arguments: &mut Arguments) -> Result<StreamBandwidthEvent> {
    let id = arguments.require("id", Quoting::Plain)?;
    if !is_valid_stream_id(&id) {
        return Err(arguments.error(format!(
            "Stream IDs must be one to sixteen alphanumeric characters, got '{id}'"
        )));
    }
    let written = arguments.require("written", Quoting::Plain)?;
    let read = arguments.require("read", Quoting::Plain)?;
    let time = arguments.take("time", Quoting::Plain)?;
    let label = "A STREAM_BW event's bytes sent and received";
    Ok(StreamBandwidthEvent {
        id,
        written: arguments.parse_number(&written, label)?,
        read: arguments.parse_number(&read, label)?,
        time: arguments.iso_timestamp(time)?,
    })
}

fn parse_transport_launched(arguments: &mut Arguments) -> Result<TransportLaunchedEvent> {
    let transport_type = arguments.require("type", Quoting::Plain)?;
    let name = arguments.require("name", Quoting::Plain)?;
    let address = arguments.require("address", Quoting::Plain)?;
    let port = arguments.require("port", Quoting::Plain)?;
    if !matches!(transport_type.as_str(), "server" | "client") {
        return Err(
            arguments.error("Transport type should either be 'server' or 'client'")
        );
    }
    if !is_valid_ipv4_address(&address) && !is_valid_ipv6_address(&address, false) {
        return Err(
            arguments.error("Transport address isn't a valid IPv4 or IPv6 address")
        );
    }
    let Some(port) = parse_port(&port, false) else {
        return Err(arguments.error("Transport port is invalid"));
    };
    Ok(TransportLaunchedEvent {
        transport_type,
        name,
        address,
        port,
    })
}

fn required_keyword(arguments: &Arguments, name: &str, label: &str) -> Result<String> {
    arguments
        .keyword(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::protocol(format!("{label} event is missing its {name}")))
}

fn parse_connection_bandwidth(
    arguments: &mut Arguments,
) -> Result<ConnectionBandwidthEvent> {
    let id = required_keyword(arguments, "ID", "CONN_BW")?;
    let conn_type = required_keyword(arguments, "TYPE", "CONN_BW")?;
    let read = required_keyword(arguments, "READ", "CONN_BW")?;
    let written = required_keyword(arguments, "WRITTEN", "CONN_BW")?;
    if !is_valid_connection_id(&id) {
        return Err(arguments.error(format!(
            "Connection IDs must be one to sixteen alphanumeric characters, got '{id}'"
        )));
    }
    let label = "A CONN_BW event's bytes sent and received";
    Ok(ConnectionBandwidthEvent {
        id,
        conn_type: typed!("CONN_BW", "conn_type", &conn_type, ConnectionType),
        read: arguments.parse_number(&read, label)?,
        written: arguments.parse_number(&written, label)?,
    })
}

fn parse_circuit_bandwidth(arguments: &mut Arguments) -> Result<CircuitBandwidthEvent> {
    let id = required_keyword(arguments, "ID", "CIRC_BW")?;
    let read = required_keyword(arguments, "READ", "CIRC_BW")?;
    let written = required_keyword(arguments, "WRITTEN", "CIRC_BW")?;
    let id = validated_circuit_id(arguments, id)?;
    let time = arguments.iso_timestamp(arguments.keyword("TIME"))?;
    Ok(CircuitBandwidthEvent {
        id,
        read: arguments.parse_number(&read, "A CIRC_BW event's bytes received")?,
        written: arguments.parse_number(&written, "A CIRC_BW event's bytes sent")?,
        delivered_read: arguments.number(
            "DELIVERED_READ",
            "A CIRC_BW event's delivered bytes received",
        )?,
        delivered_written: arguments.number(
            "DELIVERED_WRITTEN",
            "A CIRC_BW event's delivered bytes sent",
        )?,
        overhead_read: arguments
            .number("OVERHEAD_READ", "A CIRC_BW event's overhead bytes received")?,
        overhead_written: arguments
            .number("OVERHEAD_WRITTEN", "A CIRC_BW event's overhead bytes sent")?,
        time,
    })
}

fn parse_cell_type_mapping(
    mapping: Option<String>,
) -> Result<Option<HashMap<String, u64>>> {
    let Some(mapping) = mapping else {
        return Ok(None);
    };
    let mut results = HashMap::new();
    for entry in mapping.split(',') {
        let Some((key, value)) = entry.rsplit_once(':') else {
            return Err(Error::protocol(format!(
                "Mappings are expected to be of the form 'key:value', got '{entry}': \
                {mapping}"
            )));
        };
        let is_key = !key.is_empty()
            && key.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
            });
        if !is_key {
            return Err(Error::protocol(format!(
                "Key had invalid characters, got '{key}': {mapping}"
            )));
        }
        let value = value.parse::<u64>().map_err(|_| {
            Error::protocol(format!(
                "Values should just be integers, got '{value}': {mapping}"
            ))
        })?;
        results.insert(key.to_string(), value);
    }
    Ok(Some(results))
}

fn parse_cell_stats(arguments: &mut Arguments) -> Result<CellStatsEvent> {
    let circuit_ids = ["ID", "InboundQueue", "OutboundQueue"];
    for name in circuit_ids {
        if arguments
            .keyword(name)
            .is_some_and(|value| !is_valid_circuit_id(&value))
        {
            return Err(arguments.error(format!(
                "{name} must be one to sixteen alphanumeric characters"
            )));
        }
    }
    for name in ["InboundConn", "OutboundConn"] {
        if arguments
            .keyword(name)
            .is_some_and(|value| !is_valid_connection_id(&value))
        {
            return Err(arguments.error(format!(
                "{name} must be one to sixteen alphanumeric characters"
            )));
        }
    }
    Ok(CellStatsEvent {
        id: arguments.keyword("ID"),
        inbound_queue: arguments.keyword("InboundQueue"),
        inbound_connection: arguments.keyword("InboundConn"),
        inbound_added: parse_cell_type_mapping(arguments.keyword("InboundAdded"))?,
        inbound_removed: parse_cell_type_mapping(arguments.keyword("InboundRemoved"))?,
        inbound_time: parse_cell_type_mapping(arguments.keyword("InboundTime"))?,
        outbound_queue: arguments.keyword("OutboundQueue"),
        outbound_connection: arguments.keyword("OutboundConn"),
        outbound_added: parse_cell_type_mapping(arguments.keyword("OutboundAdded"))?,
        outbound_removed: parse_cell_type_mapping(arguments.keyword("OutboundRemoved"))?,
        outbound_time: parse_cell_type_mapping(arguments.keyword("OutboundTime"))?,
    })
}

fn parse_token_bucket_empty(arguments: &mut Arguments) -> Result<TokenBucketEmptyEvent> {
    let bucket = arguments.require("bucket", Quoting::Plain)?;
    let id = arguments.keyword("ID");
    if id.as_deref().is_some_and(|id| !is_valid_connection_id(id)) {
        return Err(arguments
            .error("Connection IDs must be one to sixteen alphanumeric characters"));
    }
    let read = required_keyword(arguments, "READ", "TB_EMPTY")?;
    let written = required_keyword(arguments, "WRITTEN", "TB_EMPTY")?;
    let last = required_keyword(arguments, "LAST", "TB_EMPTY")?;
    Ok(TokenBucketEmptyEvent {
        bucket: typed!("TB_EMPTY", "bucket", &bucket, TokenBucket),
        id,
        read: arguments.parse_number(&read, "A TB_EMPTY's READ value")?,
        written: arguments.parse_number(&written, "A TB_EMPTY's WRITTEN value")?,
        last_refill: arguments.parse_number(&last, "A TB_EMPTY's LAST value")?,
    })
}

pub fn unescape_event_value(value: &str) -> Result<String> {
    Ok(String::from_utf8_lossy(&unescape_bytes(value)?).into_owned())
}
