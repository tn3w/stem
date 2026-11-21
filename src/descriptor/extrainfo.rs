use std::ops::Deref;

use chrono::NaiveDateTime;
use indexmap::IndexMap;
use rsa::RsaPrivateKey;

use crate::address::{is_valid_ipv4_address, is_valid_ipv6_address, parse_port};
use crate::descriptor::server::append_router_signature;
use crate::descriptor::{
    AttrValue, Attributes, DigestEncoding, DigestHash, Entries, History, LineCursor,
    ReadOptions, content_range, descriptor_components, descriptor_content, encode_digest,
    hash_bytes, key_block, lenient, lenient_option, mappings_for, parse_forty_hex,
    parse_history, parse_timestamp_and_interval, parse_timestamp_line,
    random_crypto_blob, random_date, random_fingerprint, random_nickname,
};
use crate::error::{Error, Result};
use crate::validation::{is_valid_fingerprint, is_valid_nickname};

const DIR_RESPONSES: [&str; 6] = [
    "ok",
    "not-enough-sigs",
    "unavailable",
    "not-found",
    "not-modified",
    "busy",
];
const DIR_STATS: [&str; 16] = [
    "complete", "timeout", "running", "min", "max", "q1", "q3", "md", "d1", "d2", "d3",
    "d4", "d6", "d7", "d8", "d9",
];
const REQUIRED_FIELDS: [&str; 3] = ["extra-info", "published", "router-signature"];
const SINGLE_FIELDS: [&str; 33] = [
    "read-history",
    "write-history",
    "geoip-db-digest",
    "geoip6-db-digest",
    "bridge-stats-end",
    "bridge-ips",
    "dirreq-stats-end",
    "dirreq-v2-ips",
    "dirreq-v3-ips",
    "dirreq-v2-reqs",
    "dirreq-v3-reqs",
    "dirreq-v2-share",
    "dirreq-v3-share",
    "dirreq-v2-resp",
    "dirreq-v3-resp",
    "dirreq-v2-direct-dl",
    "dirreq-v3-direct-dl",
    "dirreq-v2-tunneled-dl",
    "dirreq-v3-tunneled-dl",
    "dirreq-read-history",
    "dirreq-write-history",
    "entry-stats-end",
    "entry-ips",
    "cell-stats-end",
    "cell-processed-cells",
    "cell-queued-cells",
    "cell-time-in-queue",
    "cell-circuits-per-decile",
    "conn-bi-direct",
    "exit-stats-end",
    "exit-kibibytes-written",
    "exit-kibibytes-read",
    "exit-streams-opened",
];
const RECOGNIZED_KEYWORDS: [&str; 50] = [
    "extra-info",
    "geoip-db-digest",
    "geoip6-db-digest",
    "transport",
    "cell-circuits-per-decile",
    "dirreq-v2-resp",
    "dirreq-v3-resp",
    "dirreq-v2-direct-dl",
    "dirreq-v3-direct-dl",
    "dirreq-v2-tunneled-dl",
    "dirreq-v3-tunneled-dl",
    "dirreq-v2-share",
    "dirreq-v3-share",
    "cell-processed-cells",
    "cell-queued-cells",
    "cell-time-in-queue",
    "published",
    "geoip-start-time",
    "cell-stats-end",
    "entry-stats-end",
    "exit-stats-end",
    "bridge-stats-end",
    "dirreq-stats-end",
    "conn-bi-direct",
    "read-history",
    "write-history",
    "dirreq-read-history",
    "dirreq-write-history",
    "exit-kibibytes-written",
    "exit-kibibytes-read",
    "exit-streams-opened",
    "hidserv-stats-end",
    "hidserv-rend-relayed-cells",
    "hidserv-dir-onions-seen",
    "padding-counts",
    "dirreq-v2-ips",
    "dirreq-v3-ips",
    "dirreq-v2-reqs",
    "dirreq-v3-reqs",
    "geoip-client-origins",
    "entry-ips",
    "bridge-ips",
    "bridge-ip-versions",
    "bridge-ip-transports",
    "identity-ed25519",
    "router-sig-ed25519",
    "router-signature",
    "master-key-ed25519",
    "router-digest-sha256",
    "router-digest",
];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StatsPeriod {
    pub end: NaiveDateTime,
    pub interval: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Transport {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub args: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ConnBiDirect {
    pub end: NaiveDateTime,
    pub interval: u64,
    pub below: u64,
    pub read: u64,
    pub write: u64,
    pub both: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct DirCounts {
    pub recognized: IndexMap<String, u64>,
    pub unknown: IndexMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PortKey {
    Port(u16),
    Other,
}

impl serde::Serialize for PortKey {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Port(port) => serializer.collect_str(port),
            Self::Other => serializer.serialize_str("other"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
pub enum CountValue {
    Number(u64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HiddenServiceStat {
    pub value: Option<i64>,
    pub attributes: IndexMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct ExtraInfoDescriptor {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub unrecognized_lines: Vec<String>,
    pub nickname: Option<String>,
    pub fingerprint: Option<String>,
    pub published: Option<NaiveDateTime>,
    pub geoip_db_digest: Option<String>,
    pub geoip6_db_digest: Option<String>,
    pub transport: IndexMap<String, Transport>,
    pub conn_bi_direct: Option<ConnBiDirect>,
    pub read_history: Option<History>,
    pub write_history: Option<History>,
    pub dir_read_history: Option<History>,
    pub dir_write_history: Option<History>,
    pub cell_stats: Option<StatsPeriod>,
    pub cell_processed_cells: Option<Vec<f64>>,
    pub cell_queued_cells: Option<Vec<f64>>,
    pub cell_time_in_queue: Option<Vec<f64>>,
    pub cell_circuits_per_decile: Option<u64>,
    pub dir_stats: Option<StatsPeriod>,
    pub dir_v2_ips: Option<IndexMap<String, u64>>,
    pub dir_v3_ips: Option<IndexMap<String, u64>>,
    pub dir_v2_share: Option<f64>,
    pub dir_v3_share: Option<f64>,
    pub dir_v2_requests: Option<IndexMap<String, u64>>,
    pub dir_v3_requests: Option<IndexMap<String, u64>>,
    pub dir_v2_responses: Option<DirCounts>,
    pub dir_v3_responses: Option<DirCounts>,
    pub dir_v2_direct_dl: Option<DirCounts>,
    pub dir_v3_direct_dl: Option<DirCounts>,
    pub dir_v2_tunneled_dl: Option<DirCounts>,
    pub dir_v3_tunneled_dl: Option<DirCounts>,
    pub entry_stats: Option<StatsPeriod>,
    pub entry_ips: Option<IndexMap<String, u64>>,
    pub exit_stats: Option<StatsPeriod>,
    pub exit_kibibytes_written: Option<IndexMap<PortKey, u64>>,
    pub exit_kibibytes_read: Option<IndexMap<PortKey, u64>>,
    pub exit_streams_opened: Option<IndexMap<PortKey, u64>>,
    pub hs_stats_end: Option<NaiveDateTime>,
    pub hs_rend_cells: Option<HiddenServiceStat>,
    pub hs_dir_onions_seen: Option<HiddenServiceStat>,
    pub padding_counts: IndexMap<String, CountValue>,
    pub padding_counts_period: Option<StatsPeriod>,
    pub bridge_stats: Option<StatsPeriod>,
    pub bridge_ips: Option<IndexMap<String, u64>>,
    pub geoip_start_time: Option<NaiveDateTime>,
    pub geoip_client_origins: Option<IndexMap<String, u64>>,
    pub ip_versions: Option<IndexMap<String, u64>>,
    pub ip_transports: Option<IndexMap<String, u64>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RelayExtraInfoDescriptor {
    #[serde(flatten)]
    pub common: ExtraInfoDescriptor,
    pub ed25519_certificate: Option<String>,
    pub ed25519_signature: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BridgeExtraInfoDescriptor {
    #[serde(flatten)]
    pub common: ExtraInfoDescriptor,
    pub ed25519_certificate_hash: Option<String>,
    pub router_digest_sha256: Option<String>,
    digest: Option<String>,
}

impl Deref for RelayExtraInfoDescriptor {
    type Target = ExtraInfoDescriptor;

    fn deref(&self) -> &ExtraInfoDescriptor {
        &self.common
    }
}

impl Deref for BridgeExtraInfoDescriptor {
    type Target = ExtraInfoDescriptor;

    fn deref(&self) -> &ExtraInfoDescriptor {
        &self.common
    }
}

fn parse_unsigned_text(text: &str) -> Option<u64> {
    match !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) {
        true => text.parse().ok(),
        false => None,
    }
}

fn parse_period(keyword: &str, value: &str) -> Result<StatsPeriod> {
    let (end, interval, _) = parse_timestamp_and_interval(keyword, value)?;
    Ok(StatsPeriod { end, interval })
}

fn parse_extra_info_line(value: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(Error::parse(format!(
            "Extra-info line must have two values: extra-info {value}"
        )));
    }
    if !is_valid_nickname(parts[0]) {
        return Err(Error::parse(format!(
            "Extra-info line entry isn't a valid nickname: {}",
            parts[0]
        )));
    }
    if !is_valid_fingerprint(parts[1], false) {
        return Err(Error::parse(format!(
            "Tor relay fingerprints consist of forty hex digits: {}",
            parts[1]
        )));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

fn parse_transports(entries: &Entries) -> Result<IndexMap<String, Transport>> {
    let mut transports = IndexMap::new();
    for value in entries.values("transport") {
        if !value.contains(' ') {
            transports.insert(
                value.to_string(),
                Transport {
                    address: None,
                    port: None,
                    args: None,
                },
            );
            continue;
        }
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(Error::parse(format!(
                "Transport line is missing its address:port value: transport {value}"
            )));
        }
        let Some((address, port_text)) = parts[1].rsplit_once(':') else {
            return Err(Error::parse(format!(
                "Transport line's address:port entry is missing a colon: transport \
                {value}"
            )));
        };
        if !is_valid_ipv4_address(address) && !is_valid_ipv6_address(address, true) {
            return Err(Error::parse(format!(
                "Transport line has a malformed address: transport {value}"
            )));
        }
        let Some(port) = parse_port(port_text, false) else {
            return Err(Error::parse(format!(
                "Transport line has a malformed port: transport {value}"
            )));
        };
        transports.insert(
            parts[0].to_string(),
            Transport {
                address: Some(address.to_string()),
                port: Some(port),
                args: Some(parts[2..].iter().map(|arg| arg.to_string()).collect()),
            },
        );
    }
    Ok(transports)
}

fn parse_padding_counts(
    value: &str,
) -> Result<(StatsPeriod, IndexMap<String, CountValue>)> {
    let (end, interval, remainder) =
        parse_timestamp_and_interval("padding-counts", value)?;
    let mut counts = IndexMap::new();
    for (key, mapped) in mappings_for("padding-counts", &remainder, true, ' ')? {
        let count = match parse_unsigned_text(&mapped) {
            Some(number) => CountValue::Number(number),
            None => CountValue::Text(mapped),
        };
        counts.insert(key, count);
    }
    Ok((StatsPeriod { end, interval }, counts))
}

fn parse_dir_counts(keyword: &str, value: &str, is_response: bool) -> Result<DirCounts> {
    let recognized_set: &[&str] = if is_response {
        &DIR_RESPONSES
    } else {
        &DIR_STATS
    };
    let key_type = if is_response { "STATUS" } else { "STAT" };
    let mut counts = DirCounts::default();
    for (status, count) in mappings_for(keyword, value, false, ',')? {
        let Some(number) = parse_unsigned_text(&count) else {
            return Err(Error::parse(format!(
                "{keyword} lines should contain {key_type}=COUNT mappings: {keyword} \
                {value}"
            )));
        };
        match recognized_set.contains(&status.as_str()) {
            true => counts.recognized.insert(status, number),
            false => counts.unknown.insert(status, number),
        };
    }
    Ok(counts)
}

fn parse_dir_share(keyword: &str, value: &str) -> Result<f64> {
    let Some(percentage) = value.strip_suffix('%') else {
        return Err(Error::parse(format!(
            "{keyword} lines should be a percentage: {keyword} {value}"
        )));
    };
    let number: f64 = percentage.parse().map_err(|_| {
        Error::parse(format!(
            "{keyword} lines should be a percentage: {keyword} {value}"
        ))
    })?;
    match number < 0.0 {
        true => Err(Error::parse(format!(
            "Negative percentage value: {keyword} {value}"
        ))),
        false => Ok(number / 100.0),
    }
}

fn parse_cell_values(keyword: &str, value: &str) -> Result<Vec<f64>> {
    match value.is_empty() {
        true => Ok(Vec::new()),
        false => value
            .split(',')
            .map(|entry| entry.parse::<f64>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| {
                Error::parse(format!(
                    "Non-numeric entry in {keyword} listing: {keyword} {value}"
                ))
            }),
    }
}

fn parse_conn_bi_direct(value: &str) -> Result<ConnBiDirect> {
    let (end, interval, remainder) =
        parse_timestamp_and_interval("conn-bi-direct", value)?;
    let stats: Vec<Option<u64>> = remainder.split(',').map(parse_unsigned_text).collect();
    match stats.as_slice() {
        [Some(below), Some(read), Some(write), Some(both)] => Ok(ConnBiDirect {
            end,
            interval,
            below: *below,
            read: *read,
            write: *write,
            both: *both,
        }),
        _ => Err(Error::parse(format!(
            "conn-bi-direct line should end with four numeric values: conn-bi-direct \
            {value}"
        ))),
    }
}

fn parse_port_counts(keyword: &str, value: &str) -> Result<IndexMap<PortKey, u64>> {
    let mut mappings = IndexMap::new();
    for (port, stat) in mappings_for(keyword, value, false, ',')? {
        let key = match port.as_str() {
            "other" => Some(PortKey::Other),
            text => parse_port(text, false).map(PortKey::Port),
        };
        let (Some(key), Some(count)) = (key, parse_unsigned_text(&stat)) else {
            return Err(Error::parse(format!(
                "Entries in {keyword} line should only be PORT=N entries: {keyword} \
                {value}"
            )));
        };
        mappings.insert(key, count);
    }
    Ok(mappings)
}

fn parse_geoip_counts(keyword: &str, value: &str) -> Result<IndexMap<String, u64>> {
    let mut usage = IndexMap::new();
    for (locale, count) in mappings_for(keyword, value, false, ',')? {
        let is_locale = locale.chars().count() == 2
            && locale
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '?');
        let (true, Some(number)) = (is_locale, parse_unsigned_text(&count)) else {
            return Err(Error::parse(format!(
                "Entries in {keyword} line should only be CC=N entries: {keyword} {value}"
            )));
        };
        usage.insert(locale, number);
    }
    Ok(usage)
}

fn parse_named_counts(
    keyword: &str,
    label: &str,
    value: &str,
) -> Result<IndexMap<String, u64>> {
    let mut counts = IndexMap::new();
    for (name, count) in mappings_for(keyword, value, false, ',')? {
        let Some(number) = parse_unsigned_text(&count) else {
            return Err(Error::protocol(format!(
                "{label} count was non-numeric ({count}): {keyword} {value}"
            )));
        };
        counts.insert(name, number);
    }
    Ok(counts)
}

fn parse_hs_stats(keyword: &str, value: &str) -> Result<HiddenServiceStat> {
    if value.is_empty() {
        return Err(Error::parse(format!("'{keyword}' line was blank")));
    }
    let (stat_text, remainder) = value.split_once(' ').unwrap_or((value, ""));
    let stat: i64 = stat_text.parse().map_err(|_| {
        Error::parse(format!(
            "'{keyword}' stat was non-numeric ({stat_text}): {keyword} {value}"
        ))
    })?;
    let attributes = mappings_for(keyword, remainder, false, ' ')?
        .into_iter()
        .collect();
    Ok(HiddenServiceStat {
        value: Some(stat),
        attributes,
    })
}

fn check_constraints(
    entries: &Entries,
    required: &[&str],
    last_keyword: Option<&str>,
) -> Result<()> {
    for keyword in required {
        if !entries.contains(keyword) {
            return Err(Error::parse(format!(
                "Extra-info descriptor must have a '{keyword}' entry"
            )));
        }
    }
    for keyword in required.iter().chain(SINGLE_FIELDS.iter()) {
        if entries.get(keyword).is_some_and(|values| values.len() > 1) {
            return Err(Error::parse(format!(
                "The '{keyword}' entry can only appear once in an extra-info descriptor"
            )));
        }
    }
    if entries.first_key() != Some("extra-info") {
        return Err(Error::parse(
            "Extra-info descriptor must start with a 'extra-info' entry",
        ));
    }
    match last_keyword {
        Some(last) if entries.last_key() != Some(last) => Err(Error::parse(format!(
            "Descriptor must end with a '{last}' entry"
        ))),
        _ => Ok(()),
    }
}

fn parse_stats_end(keyword: &str, value: &str) -> Result<NaiveDateTime> {
    match value.contains(" (") {
        true => parse_timestamp_and_interval(keyword, value).map(|(end, _, _)| end),
        false => parse_timestamp_line(keyword, value),
    }
}

macro_rules! assign {
    ($validate:expr, $entries:expr, $keyword:expr, $target:expr, $parse:expr) => {
        if let Ok(value) = $entries.value($keyword) {
            $target = lenient_option($validate, $parse($keyword, value))?;
        }
    };
}

fn parse_common(
    content: &[u8],
    entries: &Entries,
    validate: bool,
    extra_keywords: &[&str],
) -> Result<ExtraInfoDescriptor> {
    let mut recognized: Vec<&str> = RECOGNIZED_KEYWORDS.to_vec();
    recognized.extend_from_slice(extra_keywords);
    let mut info = ExtraInfoDescriptor {
        raw_contents: content.to_vec(),
        unrecognized_lines: entries.unrecognized_lines(&recognized),
        ..Default::default()
    };
    if let Ok(value) = entries.value("extra-info")
        && let Some((nickname, fingerprint)) =
            lenient_option(validate, parse_extra_info_line(value))?
    {
        info.nickname = Some(nickname);
        info.fingerprint = Some(fingerprint);
    }
    assign!(
        validate,
        entries,
        "published",
        info.published,
        parse_timestamp_line
    );
    assign!(
        validate,
        entries,
        "geoip-start-time",
        info.geoip_start_time,
        parse_timestamp_line
    );
    assign!(
        validate,
        entries,
        "hidserv-stats-end",
        info.hs_stats_end,
        parse_stats_end
    );
    assign!(
        validate,
        entries,
        "geoip-db-digest",
        info.geoip_db_digest,
        parse_forty_hex
    );
    assign!(
        validate,
        entries,
        "geoip6-db-digest",
        info.geoip6_db_digest,
        parse_forty_hex
    );
    if entries.contains("transport") {
        info.transport = lenient(validate, parse_transports(entries))?;
    }
    if let Ok(value) = entries.value("conn-bi-direct") {
        info.conn_bi_direct = lenient_option(validate, parse_conn_bi_direct(value))?;
    }
    assign!(
        validate,
        entries,
        "read-history",
        info.read_history,
        parse_history
    );
    assign!(
        validate,
        entries,
        "write-history",
        info.write_history,
        parse_history
    );
    assign!(
        validate,
        entries,
        "dirreq-read-history",
        info.dir_read_history,
        parse_history
    );
    assign!(
        validate,
        entries,
        "dirreq-write-history",
        info.dir_write_history,
        parse_history
    );
    assign!(
        validate,
        entries,
        "cell-stats-end",
        info.cell_stats,
        parse_period
    );
    assign!(
        validate,
        entries,
        "entry-stats-end",
        info.entry_stats,
        parse_period
    );
    assign!(
        validate,
        entries,
        "exit-stats-end",
        info.exit_stats,
        parse_period
    );
    assign!(
        validate,
        entries,
        "bridge-stats-end",
        info.bridge_stats,
        parse_period
    );
    assign!(
        validate,
        entries,
        "dirreq-stats-end",
        info.dir_stats,
        parse_period
    );
    assign!(
        validate,
        entries,
        "cell-processed-cells",
        info.cell_processed_cells,
        parse_cell_values
    );
    assign!(
        validate,
        entries,
        "cell-queued-cells",
        info.cell_queued_cells,
        parse_cell_values
    );
    assign!(
        validate,
        entries,
        "cell-time-in-queue",
        info.cell_time_in_queue,
        parse_cell_values
    );
    if let Ok(value) = entries.value("cell-circuits-per-decile") {
        info.cell_circuits_per_decile = lenient_option(
            validate,
            crate::descriptor::parse_integer("cell-circuits-per-decile", value, false)
                .map(|number| number as u64),
        )?;
    }
    assign!(
        validate,
        entries,
        "dirreq-v2-share",
        info.dir_v2_share,
        parse_dir_share
    );
    assign!(
        validate,
        entries,
        "dirreq-v3-share",
        info.dir_v3_share,
        parse_dir_share
    );
    for (keyword, target, is_response) in [
        ("dirreq-v2-resp", &mut info.dir_v2_responses, true),
        ("dirreq-v3-resp", &mut info.dir_v3_responses, true),
        ("dirreq-v2-direct-dl", &mut info.dir_v2_direct_dl, false),
        ("dirreq-v3-direct-dl", &mut info.dir_v3_direct_dl, false),
        ("dirreq-v2-tunneled-dl", &mut info.dir_v2_tunneled_dl, false),
        ("dirreq-v3-tunneled-dl", &mut info.dir_v3_tunneled_dl, false),
    ] {
        if let Ok(value) = entries.value(keyword) {
            *target =
                lenient_option(validate, parse_dir_counts(keyword, value, is_response))?;
        }
    }
    for (keyword, target) in [
        ("exit-kibibytes-written", &mut info.exit_kibibytes_written),
        ("exit-kibibytes-read", &mut info.exit_kibibytes_read),
        ("exit-streams-opened", &mut info.exit_streams_opened),
    ] {
        if let Ok(value) = entries.value(keyword) {
            *target = lenient_option(validate, parse_port_counts(keyword, value))?;
        }
    }
    for (keyword, target) in [
        ("dirreq-v2-ips", &mut info.dir_v2_ips),
        ("dirreq-v3-ips", &mut info.dir_v3_ips),
        ("dirreq-v2-reqs", &mut info.dir_v2_requests),
        ("dirreq-v3-reqs", &mut info.dir_v3_requests),
        ("geoip-client-origins", &mut info.geoip_client_origins),
        ("entry-ips", &mut info.entry_ips),
        ("bridge-ips", &mut info.bridge_ips),
    ] {
        if let Ok(value) = entries.value(keyword) {
            *target = lenient_option(validate, parse_geoip_counts(keyword, value))?;
        }
    }
    for (keyword, target) in [
        ("hidserv-rend-relayed-cells", &mut info.hs_rend_cells),
        ("hidserv-dir-onions-seen", &mut info.hs_dir_onions_seen),
    ] {
        if let Ok(value) = entries.value(keyword) {
            *target = lenient_option(validate, parse_hs_stats(keyword, value))?;
        }
    }
    if let Ok(value) = entries.value("padding-counts")
        && let Some((period, counts)) =
            lenient_option(validate, parse_padding_counts(value))?
    {
        info.padding_counts_period = Some(period);
        info.padding_counts = counts;
    }
    if let Ok(value) = entries.value("bridge-ip-versions") {
        info.ip_versions = lenient_option(
            validate,
            parse_named_counts("bridge-ip-versions", "IP protocol", value),
        )?;
    }
    if let Ok(value) = entries.value("bridge-ip-transports") {
        info.ip_transports = lenient_option(
            validate,
            parse_named_counts("bridge-ip-transports", "Transport", value),
        )?;
    }
    Ok(info)
}

impl RelayExtraInfoDescriptor {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        let (entries, _) = descriptor_components(content, validate, &[], &[])?;
        if validate {
            check_constraints(&entries, &REQUIRED_FIELDS, Some("router-signature"))?;
        }
        let common = parse_common(content, &entries, validate, &[])?;
        let mut descriptor = Self {
            common,
            ed25519_certificate: None,
            ed25519_signature: None,
            signature: None,
        };
        if entries.contains("identity-ed25519") {
            descriptor.ed25519_certificate = lenient_option(
                validate,
                key_block(&entries, "identity-ed25519", "ED25519 CERT")
                    .map(|(_, block)| block),
            )?;
        }
        descriptor.ed25519_signature =
            entries.value("router-sig-ed25519").ok().map(str::to_string);
        if entries.contains("router-signature") {
            descriptor.signature = lenient_option(
                validate,
                key_block(&entries, "router-signature", "SIGNATURE")
                    .map(|(_, block)| block),
            )?;
        }
        Ok(descriptor)
    }

    pub fn parse_many(content: &[u8], validate: bool) -> Result<Vec<Self>> {
        split_extrainfo(content, false)
            .into_iter()
            .map(|text| Self::parse(&text, validate))
            .collect()
    }

    pub fn digest(&self, hash: DigestHash, encoding: DigestEncoding) -> Result<String> {
        let bytes = match hash {
            DigestHash::Sha1 => hash_bytes(
                hash,
                &content_range(&self.raw_contents, None, Some("\nrouter-signature\n"))?,
            ),
            DigestHash::Sha256 => hash_bytes(hash, &self.raw_contents),
        };
        Ok(encode_digest(&bytes, encoding))
    }

    pub fn content(
        attributes: &Attributes,
        exclude: &[&str],
        signing_key: Option<&RsaPrivateKey>,
    ) -> Result<Vec<u8>> {
        let header = [
            (
                "extra-info",
                AttrValue::Text(format!(
                    "{} {}",
                    random_nickname(),
                    random_fingerprint()
                )),
            ),
            ("published", AttrValue::Text(random_date())),
        ];
        let Some(private_key) = signing_key else {
            let footer = [(
                "router-signature",
                AttrValue::Text(random_crypto_blob(Some("SIGNATURE"))),
            )];
            return Ok(descriptor_content(attributes, exclude, &header, &footer));
        };
        if attributes.iter().any(|(key, _)| key == "router-signature") {
            return Err(Error::invalid_input(
                "Cannot sign the descriptor if a router-signature has been provided",
            ));
        }
        let mut content = descriptor_content(attributes, exclude, &header, &[]);
        content.extend_from_slice(b"\nrouter-signature\n");
        append_router_signature(content, private_key)
    }

    pub fn create(
        attributes: &Attributes,
        exclude: &[&str],
        validate: bool,
        signing_key: Option<&RsaPrivateKey>,
    ) -> Result<Self> {
        Self::parse(&Self::content(attributes, exclude, signing_key)?, validate)
    }
}

impl BridgeExtraInfoDescriptor {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        let (entries, _) = descriptor_components(content, validate, &[], &[])?;
        if validate {
            let required = ["router-digest", "extra-info", "published"];
            check_constraints(&entries, &required, None)?;
        }
        let common = parse_common(content, &entries, validate, &[])?;
        let digest = match entries.value("router-digest") {
            Ok(value) => {
                lenient_option(validate, parse_forty_hex("router-digest", value))?
            }
            Err(_) => None,
        };
        Ok(Self {
            common,
            ed25519_certificate_hash: entries
                .value("master-key-ed25519")
                .ok()
                .map(str::to_string),
            router_digest_sha256: entries
                .value("router-digest-sha256")
                .ok()
                .map(str::to_string),
            digest,
        })
    }

    pub fn parse_many(content: &[u8], validate: bool) -> Result<Vec<Self>> {
        split_extrainfo(content, true)
            .into_iter()
            .map(|text| Self::parse(&text, validate))
            .collect()
    }

    pub fn digest(&self, hash: DigestHash, encoding: DigestEncoding) -> Result<String> {
        match (hash, encoding) {
            (DigestHash::Sha1, DigestEncoding::Hex) => {
                Ok(self.digest.clone().unwrap_or_default())
            }
            (DigestHash::Sha256, DigestEncoding::Base64) => {
                Ok(self.router_digest_sha256.clone().unwrap_or_default())
            }
            _ => Err(Error::invalid_input(
                "Bridge extrainfo digests are only available as sha1/hex and \
                sha256/base64",
            )),
        }
    }

    pub fn content(attributes: &Attributes, exclude: &[&str]) -> Vec<u8> {
        descriptor_content(
            attributes,
            exclude,
            &[
                (
                    "extra-info",
                    AttrValue::Text(format!(
                        "ec2bridgereaac65a3 {}",
                        random_fingerprint()
                    )),
                ),
                ("published", AttrValue::Text(random_date())),
            ],
            &[("router-digest", AttrValue::Text(random_fingerprint()))],
        )
    }

    pub fn create(
        attributes: &Attributes,
        exclude: &[&str],
        validate: bool,
    ) -> Result<Self> {
        Self::parse(&Self::content(attributes, exclude), validate)
    }
}

fn split_extrainfo(content: &[u8], is_bridge: bool) -> Vec<Vec<u8>> {
    let mut cursor = LineCursor::new(content);
    let mut found = Vec::new();
    loop {
        let mut body = if is_bridge {
            cursor
                .read_until_keywords(
                    &["router-digest"],
                    ReadOptions {
                        inclusive: true,
                        ..Default::default()
                    },
                )
                .content
        } else {
            let mut body = cursor
                .read_until_keywords(&["router-signature"], ReadOptions::default())
                .content;
            body.extend(
                cursor
                    .read_until_keywords(
                        &["-----END"],
                        ReadOptions {
                            inclusive: true,
                            ..Default::default()
                        },
                    )
                    .content,
            );
            body
        };
        if body.is_empty() {
            break;
        }
        if body.starts_with(b"@type") {
            body = body
                .splitn(2, |byte| *byte == b'\n')
                .nth(1)
                .unwrap_or_default()
                .to_vec();
        }
        found.push(body);
    }
    found
}
