pub mod bandwidth_file;
pub mod certificate;
pub mod collector;
pub mod export;
pub mod extrainfo;
pub mod hidden_service;
pub mod microdescriptor;
pub mod network_status;
pub mod parsing;
pub mod reader;
pub mod remote;
pub mod router_status;
pub mod server;
pub mod tordnsel;

use std::collections::HashMap;
use std::io::Read;

use base64::Engine;
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use chrono::NaiveDateTime;
use indexmap::IndexMap;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::formatting::parse_timestamp;

pub const MAX_DECOMPRESSED_LENGTH: u64 = 1 << 29;
const MAX_PROTOCOL_VERSIONS: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestHash {
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestEncoding {
    Hex,
    Base64,
}

pub fn hash_bytes(hash: DigestHash, content: &[u8]) -> Vec<u8> {
    match hash {
        DigestHash::Sha1 => Sha1::digest(content).to_vec(),
        DigestHash::Sha256 => Sha256::digest(content).to_vec(),
    }
}

pub fn encode_digest(digest: &[u8], encoding: DigestEncoding) -> String {
    match encoding {
        DigestEncoding::Hex => hex::encode_upper(digest),
        DigestEncoding::Base64 => truncated_base64(digest),
    }
}

pub fn truncated_base64(content: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(content)
        .trim_end_matches('=')
        .to_string()
}

pub fn decode_base64(content: &str) -> Result<Vec<u8>> {
    let config = GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true);
    let engine = GeneralPurpose::new(&STANDARD, config);
    let cleaned: String = content.chars().filter(|c| !c.is_whitespace()).collect();
    engine
        .decode(cleaned.trim_end_matches('='))
        .map_err(|error| Error::parse(format!("Invalid base64 content ({error})")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Plaintext,
    Gzip,
    Bzip2,
    Lzma,
    Zstd,
}

impl Compression {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Plaintext => ".txt",
            Self::Gzip => ".gz",
            Self::Bzip2 => ".bz2",
            Self::Lzma => ".xz",
            Self::Zstd => ".zst",
        }
    }

    pub fn encoding(self) -> &'static str {
        match self {
            Self::Plaintext => "identity",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Lzma => "x-tor-lzma",
            Self::Zstd => "x-zstd",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Lzma => "lzma",
            Self::Zstd => "zstd",
        }
    }

    pub fn from_encoding(encoding: &str) -> Option<Self> {
        [
            Self::Plaintext,
            Self::Gzip,
            Self::Bzip2,
            Self::Lzma,
            Self::Zstd,
        ]
        .into_iter()
        .find(|candidate| candidate.encoding() == encoding.trim().to_lowercase())
        .or(match encoding.trim().to_lowercase().as_str() {
            "deflate" => Some(Self::Gzip),
            _ => None,
        })
    }

    pub fn decompress(self, content: &[u8]) -> Result<Vec<u8>> {
        let failure = |error: String| {
            Error::Io(std::io::Error::other(format!(
                "Failed to decompress as {}: {error}",
                self.name()
            )))
        };
        let mut output = Vec::new();
        match self {
            Self::Plaintext => return Ok(content.to_vec()),
            Self::Gzip => match content.starts_with(&[0x1f, 0x8b]) {
                true => flate2::read::MultiGzDecoder::new(content)
                    .take(MAX_DECOMPRESSED_LENGTH + 1)
                    .read_to_end(&mut output)
                    .map(|_| ())
                    .map_err(|error| failure(error.to_string()))?,
                false => flate2::read::ZlibDecoder::new(content)
                    .take(MAX_DECOMPRESSED_LENGTH + 1)
                    .read_to_end(&mut output)
                    .map(|_| ())
                    .map_err(|error| failure(error.to_string()))?,
            },
            Self::Bzip2 => {
                bzip2_rs::DecoderReader::new(content)
                    .take(MAX_DECOMPRESSED_LENGTH + 1)
                    .read_to_end(&mut output)
                    .map_err(|error| failure(error.to_string()))?;
            }
            Self::Lzma => {
                let mut reader = std::io::BufReader::new(content);
                let xz = lzma_rs::xz_decompress(&mut reader, &mut output);
                if xz.is_err() {
                    output.clear();
                    let mut reader = std::io::BufReader::new(content);
                    lzma_rs::lzma_decompress(&mut reader, &mut output)
                        .map_err(|error| failure(error.to_string()))?;
                }
            }
            Self::Zstd => {
                let mut decoder = ruzstd::decoding::StreamingDecoder::new(content)
                    .map_err(|error| failure(error.to_string()))?;
                (&mut decoder)
                    .take(MAX_DECOMPRESSED_LENGTH + 1)
                    .read_to_end(&mut output)
                    .map_err(|error| failure(error.to_string()))?;
            }
        }
        match output.len() as u64 > MAX_DECOMPRESSED_LENGTH {
            true => Err(failure(
                "decompressed content exceeded the size limit".to_string(),
            )),
            false => Ok(output),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub value: String,
    pub block_type: Option<String>,
    pub block_contents: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Entries {
    entries: IndexMap<String, Vec<Entry>>,
}

impl Entries {
    pub fn get(&self, keyword: &str) -> Option<&[Entry]> {
        self.entries.get(keyword).map(Vec::as_slice)
    }

    pub fn contains(&self, keyword: &str) -> bool {
        self.entries.contains_key(keyword)
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<Entry>)> {
        self.entries.iter()
    }

    pub fn first_key(&self) -> Option<&str> {
        self.entries.keys().next().map(String::as_str)
    }

    pub fn last_key(&self) -> Option<&str> {
        self.entries.keys().next_back().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entry(&self, keyword: &str) -> Result<&Entry> {
        self.get(keyword).and_then(<[Entry]>::first).ok_or_else(|| {
            Error::parse(format!("Descriptor must have a '{keyword}' entry"))
        })
    }

    pub fn value(&self, keyword: &str) -> Result<&str> {
        self.entry(keyword).map(|entry| entry.value.as_str())
    }

    pub fn values(&self, keyword: &str) -> Vec<&str> {
        self.get(keyword)
            .map(|entries| entries.iter().map(|entry| entry.value.as_str()).collect())
            .unwrap_or_default()
    }

    pub fn push(&mut self, keyword: &str, entry: Entry) {
        self.entries
            .entry(keyword.to_string())
            .or_default()
            .push(entry);
    }

    pub fn unrecognized_lines(&self, recognized: &[&str]) -> Vec<String> {
        let mut lines = Vec::new();
        for (keyword, entries) in &self.entries {
            if recognized.contains(&keyword.as_str()) {
                continue;
            }
            for entry in entries {
                let mut line = format!("{keyword} {}", entry.value);
                if let Some(block) = &entry.block_contents {
                    line.push('\n');
                    line.push_str(block);
                }
                lines.push(line);
            }
        }
        lines
    }
}

fn is_keyword_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '-'
}

pub fn split_keyword_line(line: &str) -> Option<(&str, &str)> {
    let keyword_end = line
        .find(|character: char| !is_keyword_character(character))
        .unwrap_or(line.len());
    if keyword_end == 0 {
        return None;
    }
    let (keyword, rest) = line.split_at(keyword_end);
    match rest.is_empty() {
        true => Some((keyword, "")),
        false => {
            let value = rest.trim_start_matches([' ', '\t']);
            (value.len() != rest.len()).then_some((keyword, value))
        }
    }
}

fn pgp_block_type(line: &str) -> Option<&str> {
    let inner = line.strip_prefix("-----BEGIN ")?.strip_suffix("-----")?;
    let is_type = !inner.is_empty()
        && inner.chars().all(|character| {
            is_keyword_character(character) || character == ' ' || character == '\t'
        });
    is_type.then_some(inner)
}

fn pseudo_pgp_block(
    remaining: &mut std::collections::VecDeque<&str>,
) -> Result<Option<(String, String)>> {
    let Some(block_type) = remaining.front().and_then(|line| pgp_block_type(line)) else {
        return Ok(None);
    };
    let block_type = block_type.to_string();
    let end_line = format!("-----END {block_type}-----");
    let mut block_lines: Vec<&str> = Vec::new();
    loop {
        let Some(line) = remaining.pop_front() else {
            return Err(Error::parse(format!(
                "Unterminated pgp style block (looking for '{end_line}'):\n{}",
                block_lines.join("\n")
            )));
        };
        block_lines.push(line);
        if line == end_line {
            return Ok(Some((block_type, block_lines.join("\n"))));
        }
    }
}

pub fn descriptor_components(
    raw_contents: &[u8],
    validate: bool,
    extra_keywords: &[&str],
    non_ascii_fields: &[&str],
) -> Result<(Entries, Vec<String>)> {
    let text = String::from_utf8_lossy(raw_contents);
    let mut entries = Entries::default();
    let mut extra_entries = Vec::new();
    let mut remaining: std::collections::VecDeque<&str> = text.split('\n').collect();
    while let Some(raw_line) = remaining.pop_front() {
        let line = raw_line.strip_prefix("opt ").unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        let Some((keyword, value)) = split_keyword_line(line) else {
            match validate {
                true => {
                    return Err(Error::parse(format!(
                        "Line contains invalid characters: {line}"
                    )));
                }
                false => continue,
            }
        };
        let block = match pseudo_pgp_block(&mut remaining) {
            Ok(block) => block,
            Err(error) if validate => return Err(error),
            Err(_) => continue,
        };
        if validate && !non_ascii_fields.contains(&keyword) && !value.is_ascii() {
            let replaced: String = value
                .chars()
                .map(|character| if character.is_ascii() { character } else { '?' })
                .collect();
            return Err(Error::parse(format!(
                "'{keyword}' line had non-ascii content: {replaced}"
            )));
        }
        if extra_keywords.contains(&keyword) {
            extra_entries.push(format!("{keyword} {value}"));
            continue;
        }
        let (block_type, block_contents) = match block {
            Some((kind, contents)) => (Some(kind), Some(contents)),
            None => (None, None),
        };
        entries.push(
            keyword,
            Entry {
                value: value.to_string(),
                block_type,
                block_contents,
            },
        );
    }
    Ok((entries, extra_entries))
}

pub fn lenient<T: Default>(validate: bool, result: Result<T>) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(error) if validate => Err(error),
        Err(_) => Ok(T::default()),
    }
}

pub fn lenient_option<T>(validate: bool, result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if validate => Err(error),
        Err(_) => Ok(None),
    }
}

pub fn bytes_for_block(content: &str) -> Result<Vec<u8>> {
    let lines: Vec<&str> = content.split('\n').collect();
    let body = match lines.len() {
        0..=2 => "".to_string(),
        count => lines[1..count - 1].concat(),
    };
    decode_base64(&body)
}

pub fn key_block(
    entries: &Entries,
    keyword: &str,
    expected_type: &str,
) -> Result<(String, String)> {
    let entry = entries.entry(keyword)?;
    match (&entry.block_contents, &entry.block_type) {
        (Some(contents), Some(block_type))
            if block_type == expected_type && !contents.is_empty() =>
        {
            Ok((entry.value.clone(), contents.clone()))
        }
        _ => Err(Error::parse(format!(
            "'{keyword}' should be followed by a {expected_type} block, but was a {}",
            entry.block_type.as_deref().unwrap_or("None")
        ))),
    }
}

pub fn parse_integer(keyword: &str, value: &str, allow_negative: bool) -> Result<i64> {
    let number: i64 = value.trim().parse().map_err(|_| {
        Error::parse(format!("{keyword} must have a numeric value: {value}"))
    })?;
    match number < 0 && !allow_negative {
        true => Err(Error::parse(format!(
            "{keyword} must have a positive value: {value}"
        ))),
        false => Ok(number),
    }
}

pub fn parse_unsigned(keyword: &str, value: &str) -> Result<u64> {
    let is_digits = !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit());
    match is_digits {
        true => value.parse().map_err(|_| {
            Error::parse(format!("{keyword} value is out of range: {value}"))
        }),
        false => Err(Error::parse(format!(
            "{keyword} must have a numeric value: {value}"
        ))),
    }
}

pub fn parse_timestamp_line(keyword: &str, value: &str) -> Result<NaiveDateTime> {
    parse_timestamp(value).map_err(|_| {
        Error::parse(format!(
            "Timestamp on {keyword} line wasn't parsable: {keyword} {value}"
        ))
    })
}

pub fn parse_forty_hex(keyword: &str, value: &str) -> Result<String> {
    match crate::validation::is_hex_digits(value, 40) {
        true => Ok(value.to_string()),
        false => Err(Error::parse(format!(
            "{keyword} line had an invalid value (should be 40 hex characters): \
            {keyword} {value}"
        ))),
    }
}

pub fn mappings_for(
    keyword: &str,
    value: &str,
    require_value: bool,
    divider: char,
) -> Result<Vec<(String, String)>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(divider)
        .map(|entry| {
            let Some((key, mapped)) = entry.split_once('=') else {
                return Err(Error::parse(format!(
                    "'{keyword}' should be a series of 'key=value' pairs but was: {value}"
                )));
            };
            match require_value && mapped.is_empty() {
                true => Err(Error::parse(format!(
                    "'{keyword}' line's {key} mapping had a blank value: {value}"
                ))),
                false => Ok((key.to_string(), mapped.to_string())),
            }
        })
        .collect()
}

pub type Protocols = IndexMap<String, Vec<u32>>;

pub fn serialize_optional_text<S: serde::Serializer>(
    bytes: &Option<Vec<u8>>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match bytes {
        Some(bytes) => serializer.serialize_str(&String::from_utf8_lossy(bytes)),
        None => serializer.serialize_none(),
    }
}

pub fn serialize_text_list<S: serde::Serializer>(
    lines: &[Vec<u8>],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    let texts: Vec<String> = lines
        .iter()
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect();
    serde::Serialize::serialize(&texts, serializer)
}

pub fn serialize_hex<S: serde::Serializer, B: AsRef<[u8]>>(
    bytes: &B,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(bytes))
}

pub fn serialize_optional_hex<S: serde::Serializer>(
    bytes: &Option<Vec<u8>>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match bytes {
        Some(bytes) => serializer.serialize_str(&hex::encode(bytes)),
        None => serializer.serialize_none(),
    }
}

pub fn parse_protocol_line(keyword: &str, value: &str) -> Result<Protocols> {
    let mut protocols = Protocols::new();
    for (name, versions) in mappings_for(keyword, value, false, ' ')? {
        if versions.is_empty() {
            continue;
        }
        let mut expanded = Vec::new();
        for entry in versions.split(',') {
            let (first, last) = entry.split_once('-').unwrap_or((entry, entry));
            let (Ok(first), Ok(last)) =
                (parse_protocol_number(first), parse_protocol_number(last))
            else {
                return Err(Error::parse(format!(
                    "Protocol values should be a number or number range, but was: \
                    {keyword} {value}"
                )));
            };
            if last >= first && last - first >= MAX_PROTOCOL_VERSIONS {
                return Err(Error::parse(format!(
                    "Protocol version range is too large: {keyword} {value}"
                )));
            }
            expanded.extend(first..=last);
        }
        protocols.insert(name, expanded);
    }
    Ok(protocols)
}

fn parse_protocol_number(entry: &str) -> std::result::Result<u32, ()> {
    match !entry.is_empty() && entry.bytes().all(|byte| byte.is_ascii_digit()) {
        true => entry.parse().map_err(|_| ()),
        false => Err(()),
    }
}

pub fn content_range(
    content: &[u8],
    start: Option<&str>,
    end: Option<&str>,
) -> Result<Vec<u8>> {
    let find = |needle: &str, from: usize| -> Result<usize> {
        content[from..]
            .windows(needle.len())
            .position(|window| window == needle.as_bytes())
            .map(|position| position + from)
            .ok_or_else(|| {
                Error::parse(format!(
                    "'{needle}' is not present within our descriptor content"
                ))
            })
    };
    let start_index = match start {
        Some(start) => find(start, 0)?,
        None => 0,
    };
    let end_index = match end {
        Some(end) => find(end, start_index)? + end.len(),
        None => content.len(),
    };
    Ok(content[start_index..end_index].to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeAnnotation {
    pub name: String,
    pub major_version: u32,
    pub minor_version: u32,
}

impl std::fmt::Display for TypeAnnotation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "@type {} {}.{}",
            self.name, self.major_version, self.minor_version
        )
    }
}

impl TypeAnnotation {
    pub fn parse(line: &str) -> Option<Self> {
        let rest = line.trim().strip_prefix("@type ")?;
        let (name, version) = rest.split_once(' ')?;
        let (major, minor) = version.split_once('.')?;
        Some(Self {
            name: name.to_string(),
            major_version: major.parse().ok()?,
            minor_version: minor.parse().ok()?,
        })
    }
}

pub struct LineCursor<'a> {
    content: &'a [u8],
    position: usize,
}

impl<'a> LineCursor<'a> {
    pub fn new(content: &'a [u8]) -> Self {
        Self {
            content,
            position: 0,
        }
    }

    pub fn tell(&self) -> usize {
        self.position
    }

    pub fn seek(&mut self, position: usize) {
        self.position = position.min(self.content.len());
    }

    pub fn is_finished(&self) -> bool {
        self.position >= self.content.len()
    }

    pub fn read_line(&mut self) -> Option<&'a [u8]> {
        if self.is_finished() {
            return None;
        }
        let rest = &self.content[self.position..];
        let length = rest
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(rest.len(), |index| index + 1);
        self.position += length;
        Some(&rest[..length])
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.content[self.position..]
    }

    pub fn read_until_keywords(
        &mut self,
        keywords: &[&str],
        options: ReadOptions,
    ) -> ReadResult {
        let mut content: Vec<u8> = Vec::new();
        let mut ending_keyword = None;
        if options.ignore_first
            && let Some(first) = self.read_line()
        {
            content.extend_from_slice(first);
        }
        loop {
            let last_position = self.position;
            if options.end_position.is_some_and(|end| last_position >= end) {
                break;
            }
            let Some(line) = self.read_line() else {
                break;
            };
            let text = String::from_utf8_lossy(line);
            let trimmed = text.trim_end_matches(['\n', '\r']);
            let keyword = split_keyword_line(trimmed)
                .map(|(keyword, _)| keyword)
                .filter(|keyword| keywords.contains(keyword));
            if let Some(keyword) = keyword {
                ending_keyword = Some(keyword.to_string());
                if options.inclusive {
                    content.extend_from_slice(line);
                } else {
                    self.position = last_position;
                }
                break;
            }
            content.extend_from_slice(line);
        }
        ReadResult {
            content,
            ending_keyword,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ReadOptions {
    pub inclusive: bool,
    pub ignore_first: bool,
    pub end_position: Option<usize>,
}

pub struct ReadResult {
    pub content: Vec<u8>,
    pub ending_keyword: Option<String>,
}

pub fn parse_key_value_counts(value: &str) -> HashMap<String, String> {
    value
        .split(' ')
        .filter_map(|entry| entry.split_once('='))
        .map(|(key, mapped)| (key.to_string(), mapped.to_string()))
        .collect()
}

#[derive(Debug, Clone)]
pub enum AttrValue {
    Remove,
    Text(String),
    Lines(Vec<String>),
}

pub type Attributes = Vec<(String, AttrValue)>;
pub type Template<'a> = &'a [(&'a str, AttrValue)];

pub fn attr(keyword: &str, value: &str) -> (String, AttrValue) {
    (keyword.to_string(), AttrValue::Text(value.to_string()))
}

fn render_line(keyword: &str, value: &AttrValue, lines: &mut Vec<String>) {
    match value {
        AttrValue::Remove => {}
        AttrValue::Lines(values) => {
            lines.extend(values.iter().map(|entry| format!("{keyword} {entry}")))
        }
        AttrValue::Text(text) if text.is_empty() => lines.push(keyword.to_string()),
        AttrValue::Text(text) if text.starts_with('\n') => {
            lines.push(format!("{keyword}{text}"))
        }
        AttrValue::Text(text) => lines.push(format!("{keyword} {text}")),
    }
}

pub fn descriptor_content(
    attributes: &Attributes,
    exclude: &[&str],
    header: Template<'_>,
    footer: Template<'_>,
) -> Vec<u8> {
    let mut remaining: Attributes = attributes.clone();
    let mut sections: [Vec<String>; 2] = [Vec::new(), Vec::new()];
    for (lines, template) in sections.iter_mut().zip([header, footer]) {
        for (keyword, default) in template {
            if exclude.contains(keyword) {
                continue;
            }
            let value = match remaining.iter().position(|(name, _)| name == keyword) {
                Some(index) => remaining.remove(index).1,
                None => default.clone(),
            };
            render_line(keyword, &value, lines);
        }
    }
    let mut extra = Vec::new();
    for (keyword, value) in &remaining {
        if let AttrValue::Text(text) = value {
            extra.push(format!("{keyword} {text}"));
        } else {
            render_line(keyword, value, &mut extra);
        }
    }
    let [header_lines, footer_lines] = sections;
    [header_lines, extra, footer_lines]
        .concat()
        .join("\n")
        .into_bytes()
}

pub fn random_nickname() -> String {
    let number: u64 = rand::random::<u64>() % 100_000_000_000_000;
    format!("Unnamed{number}").chars().take(19).collect()
}

pub fn random_fingerprint() -> String {
    hex::encode_upper(rand::random::<[u8; 20]>())
}

pub fn random_ipv4_address() -> String {
    let octets: [u8; 4] = rand::random();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

pub fn random_date() -> String {
    let random = |low: u32, high: u32| low + rand::random::<u32>() % (high - low + 1);
    format!(
        "{}-{:02}-{:02} {:02}:{:02}:{:02}",
        random(2000, 2015),
        random(1, 12),
        random(1, 20),
        random(0, 23),
        random(0, 59),
        random(0, 59)
    )
}

pub fn split_into_lines(content: &str, size: usize) -> Vec<String> {
    crate::formatting::split_by_length(content, size)
}

pub fn random_crypto_blob(block_type: Option<&str>) -> String {
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 140]>());
    let blob = split_into_lines(&encoded, 64).join("\n");
    match block_type {
        Some(kind) => format!("\n-----BEGIN {kind}-----\n{blob}\n-----END {kind}-----"),
        None => blob,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct History {
    pub end: NaiveDateTime,
    pub interval: u64,
    pub values: Vec<i64>,
}

pub fn parse_timestamp_and_interval(
    keyword: &str,
    content: &str,
) -> Result<(NaiveDateTime, u64, String)> {
    let malformed =
        || Error::parse(format!("Malformed {keyword} line: {keyword} {content}"));
    let mut search_end = content.len();
    let (timestamp, interval, remainder) = loop {
        let Some(open) = content[..search_end].rfind(" (") else {
            return Err(malformed());
        };
        let rest = &content[open + 2..];
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        let after = &rest[digits..];
        if digits > 0
            && let Some(tail) = after.strip_prefix(" s)")
            && (tail.is_empty() || tail.starts_with(' '))
        {
            break (
                &content[..open],
                &rest[..digits],
                tail.strip_prefix(' ').unwrap_or(""),
            );
        }
        search_end = open;
    };
    let interval = interval.parse::<u64>().map_err(|_| {
        Error::parse(format!(
            "{keyword} line's interval wasn't a number: {keyword} {content}"
        ))
    })?;
    let timestamp = parse_timestamp(timestamp).map_err(|_| {
        Error::parse(format!(
            "{keyword} line's timestamp wasn't parsable: {keyword} {content}"
        ))
    })?;
    Ok((timestamp, interval, remainder.to_string()))
}

pub fn parse_history(keyword: &str, value: &str) -> Result<History> {
    let (end, interval, remainder) = parse_timestamp_and_interval(keyword, value)?;
    let values = match remainder.is_empty() {
        true => Vec::new(),
        false => remainder
            .split(',')
            .map(|entry| entry.parse::<i64>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| {
                Error::parse(format!(
                    "{keyword} line has non-numeric values: {keyword} {value}"
                ))
            })?,
    };
    Ok(History {
        end,
        interval,
        values,
    })
}

pub fn parse_bytes_line(raw: &[u8], keyword: &str) -> Option<Vec<u8>> {
    raw.split(|byte| *byte == b'\n').find_map(|line| {
        let line = line.strip_prefix(b"opt ").unwrap_or(line);
        let rest = line.strip_prefix(keyword.as_bytes())?;
        match rest.first() {
            None => Some(Vec::new()),
            Some(b' ' | b'\t') => Some(rest.trim_ascii_start().to_vec()),
            _ => None,
        }
    })
}

pub use parsing::{Descriptor, DocumentHandler, ParsedFile, parse_bytes, parse_path};
