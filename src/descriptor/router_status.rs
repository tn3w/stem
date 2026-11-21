use std::net::Ipv4Addr;
use std::ops::Deref;

use chrono::NaiveDateTime;
use indexmap::IndexMap;

use crate::address::{is_valid_ipv4_address, is_valid_ipv6_address, parse_port};
use crate::descriptor::{
    AttrValue, Attributes, Entries, LineCursor, Protocols, ReadOptions, decode_base64,
    descriptor_components, descriptor_content, lenient, lenient_option,
    parse_protocol_line, random_date, random_ipv4_address, random_nickname,
    split_keyword_line,
};
use crate::error::{Error, Result};
use crate::exit_policy::MicroExitPolicy;
use crate::formatting::parse_timestamp;
use crate::validation::{is_valid_fingerprint, is_valid_nickname};
use crate::version::Version;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentContext {
    pub is_vote: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    V2,
    V3,
    MicroV3,
}

impl EntryKind {
    fn name(self, plural: bool) -> &'static str {
        match (self, plural) {
            (Self::V2, false) => "Router status entry (v2)",
            (Self::V2, true) => "Router status entries (v2)",
            (Self::V3, false) => "Router status entry (v3)",
            (Self::V3, true) => "Router status entries (v3)",
            (Self::MicroV3, false) => "Router status entry (micro v3)",
            (Self::MicroV3, true) => "Router status entries (micro v3)",
        }
    }

    fn required_fields(self) -> &'static [&'static str] {
        match self {
            Self::V2 => &["r"],
            Self::V3 => &["r", "s"],
            Self::MicroV3 => &["r", "s", "m"],
        }
    }

    fn single_fields(self) -> &'static [&'static str] {
        match self {
            Self::V2 => &["r", "s", "v"],
            Self::V3 => &["r", "s", "v", "w", "p", "pr"],
            Self::MicroV3 => &["r", "s", "v", "w", "m", "pr"],
        }
    }

    fn recognized_keywords(self) -> &'static [&'static str] {
        match self {
            Self::V2 => &["r", "s", "v"],
            Self::V3 => &["r", "s", "v", "a", "w", "p", "pr", "id", "m"],
            Self::MicroV3 => &["r", "s", "v", "a", "w", "m", "pr"],
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct RouterStatusEntryCommon {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub unrecognized_lines: Vec<String>,
    pub nickname: Option<String>,
    pub fingerprint: Option<String>,
    pub published: Option<NaiveDateTime>,
    pub address: Option<String>,
    pub or_port: Option<u16>,
    pub dir_port: Option<u16>,
    pub flags: Vec<String>,
    pub version_line: Option<String>,
    pub version: Option<Version>,
}

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct BandwidthLine {
    pub bandwidth: Option<u64>,
    pub measured: Option<u64>,
    pub is_unmeasured: bool,
    pub unrecognized_bandwidth_entries: Vec<String>,
}

pub type OrAddress = (String, u16, bool);

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RouterStatusEntryV2 {
    #[serde(flatten)]
    pub common: RouterStatusEntryCommon,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RouterStatusEntryV3 {
    #[serde(flatten)]
    pub common: RouterStatusEntryCommon,
    pub digest: Option<String>,
    pub or_addresses: Vec<OrAddress>,
    pub identifier_type: Option<String>,
    pub identifier: Option<String>,
    pub bandwidth: Option<u64>,
    pub measured: Option<u64>,
    pub is_unmeasured: bool,
    pub unrecognized_bandwidth_entries: Vec<String>,
    pub exit_policy: Option<MicroExitPolicy>,
    pub protocols: Protocols,
    pub microdescriptor_hashes: Vec<(Vec<u32>, IndexMap<String, String>)>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RouterStatusEntryMicroV3 {
    #[serde(flatten)]
    pub common: RouterStatusEntryCommon,
    pub or_addresses: Vec<OrAddress>,
    pub bandwidth: Option<u64>,
    pub measured: Option<u64>,
    pub is_unmeasured: bool,
    pub unrecognized_bandwidth_entries: Vec<String>,
    pub protocols: Protocols,
    pub microdescriptor_digest: Option<String>,
    pub digest: Option<String>,
}

macro_rules! deref_to_common {
    ($($entry:ty),+) => {
        $(impl Deref for $entry {
            type Target = RouterStatusEntryCommon;

            fn deref(&self) -> &RouterStatusEntryCommon {
                &self.common
            }
        })+
    };
}

deref_to_common!(
    RouterStatusEntryV2,
    RouterStatusEntryV3,
    RouterStatusEntryMicroV3
);

pub fn base64_to_hex(identity: &str, check_if_fingerprint: bool) -> Result<String> {
    let decoded = decode_base64(identity).map_err(|_| {
        Error::parse(format!("Unable to decode identity string '{identity}'"))
    })?;
    let fingerprint = hex::encode_upper(decoded);
    match !check_if_fingerprint || is_valid_fingerprint(&fingerprint, false) {
        true => Ok(fingerprint),
        false => Err(Error::parse(format!(
            "Decoded '{identity}' to be '{fingerprint}', which isn't a valid fingerprint"
        ))),
    }
}

struct RLine {
    nickname: String,
    fingerprint: String,
    digest: Option<String>,
    published: NaiveDateTime,
    address: String,
    or_port: u16,
    dir_port: Option<u16>,
}

fn parse_r_line(kind: EntryKind, entries: &Entries) -> Result<RLine> {
    let value = entries.value("r")?;
    let name = kind.name(false);
    let include_digest = kind != EntryKind::MicroV3;
    let mut parts: Vec<Option<&str>> = value.split(' ').map(Some).collect();
    if !include_digest {
        parts.insert(2.min(parts.len()), None);
    }
    if parts.len() < 8 {
        let count = if include_digest { "eight" } else { "seven" };
        return Err(Error::parse(format!(
            "{name} 'r' line must have {count} values: r {value}"
        )));
    }
    let field = |index: usize| parts[index].unwrap_or_default();
    if !is_valid_nickname(field(0)) {
        return Err(Error::parse(format!(
            "{name} nickname isn't valid: {}",
            field(0)
        )));
    }
    if !is_valid_ipv4_address(field(5)) {
        return Err(Error::parse(format!(
            "{name} address isn't a valid IPv4 address: {}",
            field(5)
        )));
    }
    let or_port = parse_port(field(6), false)
        .ok_or_else(|| Error::parse(format!("{name} ORPort is invalid: {}", field(6))))?;
    let dir_port = parse_port(field(7), true).ok_or_else(|| {
        Error::parse(format!("{name} DirPort is invalid: {}", field(7)))
    })?;
    let published =
        parse_timestamp(&format!("{} {}", field(3), field(4))).map_err(|_| {
            Error::parse(format!("Publication time time wasn't parsable: r {value}"))
        })?;
    Ok(RLine {
        nickname: field(0).to_string(),
        fingerprint: base64_to_hex(field(1), true)?,
        digest: match include_digest {
            true => Some(base64_to_hex(field(2), true)?),
            false => None,
        },
        published,
        address: field(5).to_string(),
        or_port,
        dir_port: Some(dir_port).filter(|port| *port != 0),
    })
}

pub fn parse_a_lines(name: &str, entries: &Entries) -> Result<Vec<OrAddress>> {
    let mut addresses = Vec::new();
    for value in entries.values("a") {
        let Some((address, port)) = value.rsplit_once(':') else {
            return Err(Error::parse(format!(
                "{name} 'a' line must be of the form '[address]:[ports]': a {value}"
            )));
        };
        if !is_valid_ipv4_address(address) && !is_valid_ipv6_address(address, true) {
            return Err(Error::parse(format!(
                "{name} 'a' line must start with an IPv6 address: a {value}"
            )));
        }
        let Some(port) = parse_port(port, false) else {
            return Err(Error::parse(format!(
                "{name} 'a' line had an invalid port ({port}): a {value}"
            )));
        };
        addresses.push((
            address
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
            port,
            is_valid_ipv6_address(address, true),
        ));
    }
    Ok(addresses)
}

fn parse_s_line(name: &str, entries: &Entries) -> Result<Vec<String>> {
    let value = entries.value("s")?;
    let flags: Vec<String> = match value.is_empty() {
        true => Vec::new(),
        false => value.split(' ').map(str::to_string).collect(),
    };
    for flag in &flags {
        if flags.iter().filter(|other| *other == flag).count() > 1 {
            return Err(Error::parse(format!(
                "{name} had duplicate flags: s {value}"
            )));
        }
        if flag.is_empty() {
            return Err(Error::parse(format!(
                "{name} had extra whitespace on its 's' line: s {value}"
            )));
        }
    }
    Ok(flags)
}

fn parse_v_line(name: &str, entries: &Entries) -> Result<(String, Option<Version>)> {
    let value = entries.value("v")?;
    let version = match value.strip_prefix("Tor ") {
        Some(text) => Some(Version::new(text).map_err(|error| {
            Error::parse(format!(
                "{name} has a malformed tor version ({error}): v {value}"
            ))
        })?),
        None => None,
    };
    Ok((value.to_string(), version))
}

fn parse_w_line(name: &str, entries: &Entries) -> Result<BandwidthLine> {
    let value = entries.value("w")?;
    if !value
        .split(' ')
        .next()
        .is_some_and(|first| first.starts_with("Bandwidth="))
    {
        return Err(Error::parse(format!(
            "{name} 'w' line needs to start with a 'Bandwidth=' entry: w {value}"
        )));
    }
    let mut line = BandwidthLine::default();
    for entry in value.split(' ') {
        let (key, mapped) = match entry.split_once('=') {
            Some((key, mapped)) => (key, Some(mapped)),
            None => (entry, None),
        };
        let number = |label: &str| -> Result<u64> {
            mapped
                .filter(|text| {
                    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
                })
                .and_then(|text| text.parse().ok())
                .ok_or_else(|| {
                    Error::parse(format!(
                        "{name} '{label}=' entry needs to have a numeric value: w {value}"
                    ))
                })
        };
        match key {
            "Bandwidth" => line.bandwidth = Some(number("Bandwidth")?),
            "Measured" => line.measured = Some(number("Measured")?),
            "Unmeasured" => {
                if mapped != Some("1") {
                    return Err(Error::parse(format!(
                        "{name} 'Unmeasured=' should only have the value of '1': w \
                        {value}"
                    )));
                }
                line.is_unmeasured = true;
            }
            _ => line.unrecognized_bandwidth_entries.push(entry.to_string()),
        }
    }
    Ok(line)
}

fn parse_p_line(name: &str, entries: &Entries) -> Result<MicroExitPolicy> {
    let value = entries.value("p")?;
    MicroExitPolicy::new(value).map_err(|error| {
        Error::parse(format!(
            "{name} exit policy is malformed ({error}): p {value}"
        ))
    })
}

fn parse_id_line(
    name: &str,
    entries: &Entries,
    document: Option<DocumentContext>,
) -> Result<(Option<String>, Option<String>)> {
    let value = entries.value("id")?;
    if value.is_empty() {
        return Ok((None, None));
    }
    if document.is_some_and(|context| !context.is_vote) {
        return Err(Error::parse(format!(
            "{name} 'id' line should only appear in votes: id {value}"
        )));
    }
    let parts: Vec<&str> = value.split_whitespace().collect();
    match parts.as_slice() {
        [kind, identifier, ..] => {
            Ok((Some(kind.to_string()), Some(identifier.to_string())))
        }
        _ => Err(Error::parse(format!(
            "'id' lines should contain both the key type and digest: id {value}"
        ))),
    }
}

type MicrodescriptorHashes = Vec<(Vec<u32>, IndexMap<String, String>)>;

fn parse_m_lines(
    name: &str,
    entries: &Entries,
    document: Option<DocumentContext>,
) -> Result<MicrodescriptorHashes> {
    let mut all_hashes = Vec::new();
    for value in entries.values("m") {
        if !document.is_some_and(|context| context.is_vote) {
            let status = if document.is_some() {
                "vote"
            } else {
                "<undefined document>"
            };
            return Err(Error::parse(format!(
                "{name} 'm' line should only appear in votes (appeared in a {status}): \
                m {value}"
            )));
        }
        let mut parts = value.split(' ');
        let methods = parts
            .next()
            .unwrap_or_default()
            .split(',')
            .map(|entry| entry.parse::<u32>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| {
                Error::parse(format!(
                    "{name} microdescriptor methods should be a series of comma \
                    separated integers: m {value}"
                ))
            })?;
        let mut hashes = IndexMap::new();
        for entry in parts {
            let Some((hash_name, digest)) = entry.split_once('=') else {
                return Err(Error::parse(format!(
                    "{name} can only have a series of 'algorithm=digest' mappings after \
                    the methods: m {value}"
                )));
            };
            hashes.insert(hash_name.to_string(), digest.to_string());
        }
        all_hashes.push((methods, hashes));
    }
    Ok(all_hashes)
}

fn check_constraints(kind: EntryKind, entries: &Entries, raw: &str) -> Result<()> {
    for keyword in kind.required_fields() {
        if !entries.contains(keyword) {
            return Err(Error::parse(format!(
                "{} must have a '{keyword}' line:\n{raw}",
                kind.name(true)
            )));
        }
    }
    for keyword in kind.single_fields() {
        let count = entries.get(keyword).map_or(0, <[_]>::len);
        if count > 1 {
            return Err(Error::parse(format!(
                "{} can only have a single '{keyword}' line, got {count}:\n{raw}",
                kind.name(true)
            )));
        }
    }
    match entries.first_key() {
        Some("r") => Ok(()),
        _ => Err(Error::parse(format!(
            "{} are expected to start with a 'r' line:\n{raw}",
            kind.name(true)
        ))),
    }
}

fn parse_common(
    kind: EntryKind,
    content: &[u8],
    entries: &Entries,
    validate: bool,
) -> Result<(RouterStatusEntryCommon, Option<String>)> {
    let name = kind.name(false);
    let mut common = RouterStatusEntryCommon {
        raw_contents: content.to_vec(),
        unrecognized_lines: entries.unrecognized_lines(kind.recognized_keywords()),
        ..Default::default()
    };
    let mut digest = None;
    if entries.contains("r")
        && let Some(line) = lenient_option(validate, parse_r_line(kind, entries))?
    {
        common.nickname = Some(line.nickname);
        common.fingerprint = Some(line.fingerprint);
        common.published = Some(line.published);
        common.address = Some(line.address);
        common.or_port = Some(line.or_port);
        common.dir_port = line.dir_port;
        digest = line.digest;
    }
    if entries.contains("s") {
        common.flags = lenient(validate, parse_s_line(name, entries))?;
    }
    if entries.contains("v")
        && let Some((line, version)) =
            lenient_option(validate, parse_v_line(name, entries))?
    {
        common.version_line = Some(line);
        common.version = version;
    }
    Ok((common, digest))
}

fn read_entries(content: &[u8], validate: bool, kind: EntryKind) -> Result<Entries> {
    let (entries, _) = descriptor_components(content, validate, &[], &[])?;
    if validate {
        check_constraints(kind, &entries, &String::from_utf8_lossy(content))?;
    }
    Ok(entries)
}

impl RouterStatusEntryV2 {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        let entries = read_entries(content, validate, EntryKind::V2)?;
        let (common, digest) = parse_common(EntryKind::V2, content, &entries, validate)?;
        Ok(Self { common, digest })
    }

    pub fn parse_many(content: &[u8], validate: bool) -> Result<Vec<Self>> {
        let mut cursor = LineCursor::new(content);
        parse_entry_section(&mut cursor, validate, &[], None, |bytes| {
            Self::parse(bytes, validate)
        })
    }

    pub fn content(attributes: &Attributes, exclude: &[&str]) -> Vec<u8> {
        let header = format!(
            "{} p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE {} {} 9001 0",
            random_nickname(),
            random_date(),
            random_ipv4_address()
        );
        descriptor_content(attributes, exclude, &[("r", AttrValue::Text(header))], &[])
    }

    pub fn create(
        attributes: &Attributes,
        exclude: &[&str],
        validate: bool,
    ) -> Result<Self> {
        Self::parse(&Self::content(attributes, exclude), validate)
    }
}

impl RouterStatusEntryV3 {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        Self::parse_with_document(content, validate, None)
    }

    pub fn parse_with_document(
        content: &[u8],
        validate: bool,
        document: Option<DocumentContext>,
    ) -> Result<Self> {
        let kind = EntryKind::V3;
        let name = kind.name(false);
        let entries = read_entries(content, validate, kind)?;
        let (common, digest) = parse_common(kind, content, &entries, validate)?;
        let mut entry = Self {
            common,
            digest,
            or_addresses: Vec::new(),
            identifier_type: None,
            identifier: None,
            bandwidth: None,
            measured: None,
            is_unmeasured: false,
            unrecognized_bandwidth_entries: Vec::new(),
            exit_policy: None,
            protocols: Protocols::new(),
            microdescriptor_hashes: Vec::new(),
        };
        if entries.contains("a") {
            entry.or_addresses = lenient(validate, parse_a_lines(name, &entries))?;
        }
        if entries.contains("id")
            && let Some((kind, identifier)) =
                lenient_option(validate, parse_id_line(name, &entries, document))?
        {
            entry.identifier_type = kind;
            entry.identifier = identifier;
        }
        if entries.contains("w")
            && let Some(line) = lenient_option(validate, parse_w_line(name, &entries))?
        {
            entry.bandwidth = line.bandwidth;
            entry.measured = line.measured;
            entry.is_unmeasured = line.is_unmeasured;
            entry.unrecognized_bandwidth_entries = line.unrecognized_bandwidth_entries;
        }
        if entries.contains("p") {
            entry.exit_policy = lenient_option(validate, parse_p_line(name, &entries))?;
        }
        if entries.contains("pr") {
            entry.protocols =
                lenient(validate, parse_protocol_line("pr", entries.value("pr")?))?;
        }
        if entries.contains("m") {
            entry.microdescriptor_hashes =
                lenient(validate, parse_m_lines(name, &entries, document))?;
        }
        Ok(entry)
    }

    pub fn parse_many(content: &[u8], validate: bool) -> Result<Vec<Self>> {
        let mut cursor = LineCursor::new(content);
        parse_entry_section(&mut cursor, validate, &[], None, |bytes| {
            Self::parse(bytes, validate)
        })
    }

    pub fn content(attributes: &Attributes, exclude: &[&str]) -> Vec<u8> {
        let header = format!(
            "{} p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE {} {} 9001 0",
            random_nickname(),
            random_date(),
            random_ipv4_address()
        );
        descriptor_content(
            attributes,
            exclude,
            &[
                ("r", AttrValue::Text(header)),
                (
                    "s",
                    AttrValue::Text("Fast Named Running Stable Valid".to_string()),
                ),
            ],
            &[],
        )
    }

    pub fn create(
        attributes: &Attributes,
        exclude: &[&str],
        validate: bool,
    ) -> Result<Self> {
        Self::parse(&Self::content(attributes, exclude), validate)
    }

    pub fn ipv4_address(&self) -> Option<Ipv4Addr> {
        self.common.address.as_deref()?.parse().ok()
    }
}

impl RouterStatusEntryMicroV3 {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        Self::parse_with_document(content, validate, None)
    }

    pub fn parse_with_document(
        content: &[u8],
        validate: bool,
        _document: Option<DocumentContext>,
    ) -> Result<Self> {
        let kind = EntryKind::MicroV3;
        let name = kind.name(false);
        let entries = read_entries(content, validate, kind)?;
        let (common, _) = parse_common(kind, content, &entries, validate)?;
        let mut entry = Self {
            common,
            or_addresses: Vec::new(),
            bandwidth: None,
            measured: None,
            is_unmeasured: false,
            unrecognized_bandwidth_entries: Vec::new(),
            protocols: Protocols::new(),
            microdescriptor_digest: None,
            digest: None,
        };
        if entries.contains("a") {
            entry.or_addresses = lenient(validate, parse_a_lines(name, &entries))?;
        }
        if entries.contains("w")
            && let Some(line) = lenient_option(validate, parse_w_line(name, &entries))?
        {
            entry.bandwidth = line.bandwidth;
            entry.measured = line.measured;
            entry.is_unmeasured = line.is_unmeasured;
            entry.unrecognized_bandwidth_entries = line.unrecognized_bandwidth_entries;
        }
        if entries.contains("pr") {
            entry.protocols =
                lenient(validate, parse_protocol_line("pr", entries.value("pr")?))?;
        }
        if entries.contains("m") {
            let value = entries.value("m")?;
            if let Some(digest) = lenient_option(validate, base64_to_hex(value, false))? {
                entry.microdescriptor_digest = Some(value.to_string());
                entry.digest = Some(digest);
            }
        }
        Ok(entry)
    }

    pub fn parse_many(content: &[u8], validate: bool) -> Result<Vec<Self>> {
        let mut cursor = LineCursor::new(content);
        parse_entry_section(&mut cursor, validate, &[], None, |bytes| {
            Self::parse(bytes, validate)
        })
    }

    pub fn content(attributes: &Attributes, exclude: &[&str]) -> Vec<u8> {
        let header = format!(
            "{} ARIJF2zbqirB9IwsW0mQznccWww {} {} 9001 9030",
            random_nickname(),
            random_date(),
            random_ipv4_address()
        );
        descriptor_content(
            attributes,
            exclude,
            &[
                ("r", AttrValue::Text(header)),
                (
                    "m",
                    AttrValue::Text(
                        "aiUklwBrua82obG5AsTX+iEpkjQA2+AQHxZ7GwMfY70".to_string(),
                    ),
                ),
                (
                    "s",
                    AttrValue::Text(
                        "Fast Guard HSDir Named Running Stable V2Dir Valid".to_string(),
                    ),
                ),
            ],
            &[],
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

pub fn parse_entry_section<T>(
    cursor: &mut LineCursor<'_>,
    _validate: bool,
    section_end_keywords: &[&str],
    end_position: Option<usize>,
    mut build: impl FnMut(&[u8]) -> Result<T>,
) -> Result<Vec<T>> {
    if !section_end_keywords.is_empty() {
        let start = cursor.tell();
        let first_keyword = cursor.read_line().and_then(|line| {
            let text = String::from_utf8_lossy(line).into_owned();
            split_keyword_line(text.trim_end_matches(['\n', '\r']))
                .map(|(keyword, _)| keyword.to_string())
        });
        cursor.seek(start);
        if first_keyword
            .is_some_and(|keyword| section_end_keywords.contains(&keyword.as_str()))
        {
            return Ok(Vec::new());
        }
    }
    let mut keywords = vec!["r"];
    keywords.extend_from_slice(section_end_keywords);
    let mut parsed = Vec::new();
    while end_position.is_none_or(|end| cursor.tell() < end) {
        let result = cursor.read_until_keywords(
            &keywords,
            ReadOptions {
                ignore_first: true,
                end_position,
                inclusive: false,
            },
        );
        if result.content.is_empty() {
            break;
        }
        parsed.push(build(&result.content)?);
        if result
            .ending_keyword
            .as_deref()
            .is_some_and(|keyword| section_end_keywords.contains(&keyword))
        {
            break;
        }
    }
    Ok(parsed)
}
