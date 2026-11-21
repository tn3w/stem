use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use std::time::SystemTime;

use crate::error::{Error, Result};

pub const MAX_LINE_LENGTH: usize = 1 << 20;
pub const MAX_MESSAGE_LENGTH: usize = 1 << 29;

#[derive(Clone, PartialEq, Eq)]
pub struct MessagePart {
    pub code: String,
    pub divider: char,
    pub content: Vec<u8>,
}

impl MessagePart {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.content).into_owned()
    }
}

impl fmt::Debug for MessagePart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessagePart")
            .field("code", &self.code)
            .field("divider", &self.divider)
            .field("content", &self.text())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ControlMessage {
    parts: Vec<MessagePart>,
    raw: Vec<u8>,
    pub arrived_at: SystemTime,
}

impl PartialEq for ControlMessage {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Eq for ControlMessage {}

impl ControlMessage {
    pub fn new(parts: Vec<MessagePart>, raw: Vec<u8>) -> Result<Self> {
        if parts.is_empty() {
            return Err(Error::invalid_input("ControlMessages can't be empty"));
        }
        Ok(Self {
            parts,
            raw,
            arrived_at: SystemTime::now(),
        })
    }

    pub fn parse(content: &str, normalize: bool) -> Result<Self> {
        let mut text = content.to_string();
        if normalize {
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text = text.replace("\r\n", "\n").replace('\n', "\r\n");
        }
        let mut builder = MessageBuilder::default();
        for line in text.as_bytes().split_inclusive(|byte| *byte == b'\n') {
            if let Some(message) = builder.push_line(line)? {
                return Ok(message);
            }
        }
        Err(Error::SocketClosed)
    }

    pub fn is_ok(&self) -> bool {
        self.parts.iter().any(|part| part.code == "250")
    }

    pub fn is_event(&self) -> bool {
        self.parts.last().is_some_and(|part| part.code == "650")
    }

    pub fn status_code(&self) -> &str {
        &self.parts[0].code
    }

    pub fn parts(&self) -> &[MessagePart] {
        &self.parts
    }

    pub fn content(&self) -> Vec<(String, char, String)> {
        self.parts
            .iter()
            .map(|part| (part.code.clone(), part.divider, part.text()))
            .collect()
    }

    pub fn raw_content(&self) -> String {
        String::from_utf8_lossy(&self.raw).into_owned()
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn len(&self) -> usize {
        self.parts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    pub fn lines(&self) -> Vec<ControlLine> {
        self.parts
            .iter()
            .map(|part| ControlLine::new(part.text()))
            .collect()
    }

    pub fn line(&self, index: usize) -> Option<ControlLine> {
        self.parts
            .get(index)
            .map(|part| ControlLine::new(part.text()))
    }
}

impl fmt::Display for ControlMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lines: Vec<String> = self.parts.iter().map(MessagePart::text).collect();
        formatter.write_str(&lines.join("\n"))
    }
}

#[derive(Default)]
pub struct MessageBuilder {
    parts: Vec<MessagePart>,
    raw: Vec<u8>,
    data_block: Option<MessagePart>,
}

impl MessageBuilder {
    pub fn push_line(&mut self, line: &[u8]) -> Result<Option<ControlMessage>> {
        if self.raw.len() + line.len() > MAX_MESSAGE_LENGTH {
            return Err(Error::protocol("Control message exceeded the size limit"));
        }
        self.raw.extend_from_slice(line);
        match self.data_block.take() {
            Some(block) => self.push_data_line(block, line),
            None => self.push_status_line(line),
        }
    }

    fn push_data_line(
        &mut self,
        mut block: MessagePart,
        line: &[u8],
    ) -> Result<Option<ControlMessage>> {
        let Some(line) = line.strip_suffix(b"\r\n") else {
            return Err(Error::protocol("All lines should end with CRLF"));
        };
        if line == b"." {
            self.parts.push(block);
            return Ok(None);
        }
        let line = line
            .strip_prefix(b".")
            .filter(|rest| rest.starts_with(b"."))
            .unwrap_or(line);
        block.content.push(b'\n');
        block.content.extend_from_slice(line);
        self.data_block = Some(block);
        Ok(None)
    }

    fn push_status_line(&mut self, line: &[u8]) -> Result<Option<ControlMessage>> {
        let has_prefix = line.len() >= 4
            && line[..3].iter().all(u8::is_ascii_digit)
            && matches!(line[3], b'-' | b'+' | b' ');
        if !has_prefix {
            return Err(Error::protocol(
                "Badly formatted reply line: beginning is malformed",
            ));
        }
        let Some(content) = line[4..].strip_suffix(b"\r\n") else {
            return Err(Error::protocol("All lines should end with CRLF"));
        };
        let part = MessagePart {
            code: String::from_utf8_lossy(&line[..3]).into_owned(),
            divider: char::from(line[3]),
            content: content.to_vec(),
        };
        match part.divider {
            '+' => self.data_block = Some(part),
            '-' => self.parts.push(part),
            _ => {
                self.parts.push(part);
                let parts = std::mem::take(&mut self.parts);
                let raw = std::mem::take(&mut self.raw);
                return ControlMessage::new(parts, raw).map(Some);
            }
        }
        Ok(None)
    }
}

pub fn format_for_sending(message: &str) -> String {
    let normalized = message.replace("\r\n", "\n");
    let Some((command, data)) = normalized.split_once('\n') else {
        return format!("{normalized}\r\n");
    };
    let stuffed: Vec<String> = data
        .split('\n')
        .map(|line| match line.starts_with('.') {
            true => format!(".{line}"),
            false => line.to_string(),
        })
        .collect();
    format!("+{command}\r\n{}\r\n.\r\n", stuffed.join("\r\n"))
}

#[derive(Debug, Clone)]
pub struct ControlLine {
    text: String,
    remainder: String,
}

impl Deref for ControlLine {
    type Target = str;

    fn deref(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for ControlLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

fn quote_span(line: &str, escaped: bool) -> Option<(usize, usize)> {
    let start = line.find('"')?;
    let mut characters = line[start + 1..].char_indices();
    while let Some((offset, character)) = characters.next() {
        match character {
            '\\' if escaped => {
                characters.next();
            }
            '"' => return Some((start, start + 1 + offset)),
            _ => {}
        }
    }
    None
}

fn mapping_key(line: &str) -> Option<&str> {
    let (key, _) = line.split_once('=')?;
    let is_key = !key.is_empty() && !key.contains(char::is_whitespace);
    is_key.then_some(key)
}

pub fn unescape_bytes(entry: &str) -> Result<Vec<u8>> {
    let bytes = entry.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        index += 1;
        if byte != b'\\' {
            decoded.push(byte);
            continue;
        }
        let Some(&escape) = bytes.get(index) else {
            return Err(Error::parse("Trailing \\ in string"));
        };
        index += 1;
        let simple = match escape {
            b'\\' | b'\'' | b'"' => Some(escape),
            b'a' => Some(7),
            b'b' => Some(8),
            b'f' => Some(12),
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            b'v' => Some(11),
            _ => None,
        };
        if let Some(value) = simple {
            decoded.push(value);
        } else if escape.is_ascii_digit() && escape < b'8' {
            let mut value = u32::from(escape - b'0');
            let mut digits = 1;
            while digits < 3
                && bytes.get(index).is_some_and(|d| (b'0'..=b'7').contains(d))
            {
                value = value * 8 + u32::from(bytes[index] - b'0');
                index += 1;
                digits += 1;
            }
            decoded.push((value & 0xff) as u8);
        } else if escape == b'x' {
            let hex = entry
                .get(index..index + 2)
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                .filter(|_| {
                    bytes[index].is_ascii_hexdigit()
                        && bytes[index + 1].is_ascii_hexdigit()
                })
                .ok_or_else(|| Error::parse("invalid \\x escape"))?;
            decoded.push(hex);
            index += 2;
        } else {
            decoded.extend_from_slice(&[b'\\', escape]);
        }
    }
    Ok(decoded)
}

pub fn escape_quoted(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if control.is_control() => {
                escaped.push_str(&format!("\\{:03o}", u32::from(control) & 0xff))
            }
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    escaped
}

impl ControlLine {
    pub fn new(value: impl Into<String>) -> Self {
        let text = value.into();
        Self {
            remainder: text.clone(),
            text,
        }
    }

    pub fn remainder(&self) -> &str {
        &self.remainder
    }

    pub fn is_empty(&self) -> bool {
        self.remainder.is_empty()
    }

    pub fn is_next_quoted(&self, escaped: bool) -> bool {
        quote_span(&self.remainder, escaped).is_some_and(|(start, _)| start == 0)
    }

    pub fn is_next_mapping(
        &self,
        key: Option<&str>,
        quoted: bool,
        escaped: bool,
    ) -> bool {
        let Some(found) = mapping_key(&self.remainder) else {
            return false;
        };
        if key.is_some_and(|expected| expected != found) {
            return false;
        }
        match quoted {
            true => quote_span(&self.remainder, escaped)
                .is_some_and(|(start, _)| start == found.len() + 1),
            false => true,
        }
    }

    pub fn peek_key(&self) -> Option<&str> {
        mapping_key(&self.remainder)
    }

    pub fn pop(&mut self, quoted: bool, escaped: bool) -> Result<String> {
        let bytes = self.pop_entry(quoted, escaped)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub fn pop_bytes(&mut self, quoted: bool, escaped: bool) -> Result<Vec<u8>> {
        self.pop_entry(quoted, escaped)
    }

    pub fn pop_mapping(
        &mut self,
        quoted: bool,
        escaped: bool,
    ) -> Result<(String, String)> {
        let (key, value) = self.pop_mapping_bytes(quoted, escaped)?;
        Ok((key, String::from_utf8_lossy(&value).into_owned()))
    }

    pub fn pop_mapping_bytes(
        &mut self,
        quoted: bool,
        escaped: bool,
    ) -> Result<(String, Vec<u8>)> {
        if self.is_empty() {
            return Err(Error::parse("no remaining content to parse"));
        }
        let Some(key) = mapping_key(&self.remainder).map(str::to_string) else {
            return Err(Error::parse(format!(
                "the next entry isn't a KEY=VALUE mapping: {}",
                self.remainder
            )));
        };
        let rest = self.remainder[key.len() + 1..].to_string();
        let original = std::mem::replace(&mut self.remainder, rest);
        match self.pop_entry(quoted, escaped) {
            Ok(value) => Ok((key, value)),
            Err(error) => {
                self.remainder = original;
                Err(error)
            }
        }
    }

    fn pop_entry(&mut self, quoted: bool, escaped: bool) -> Result<Vec<u8>> {
        if self.remainder.is_empty() {
            return Err(Error::parse("no remaining content to parse"));
        }
        let (entry, rest) = match quoted {
            true => match quote_span(&self.remainder, escaped) {
                Some((0, end)) => (&self.remainder[1..end], &self.remainder[end + 1..]),
                _ => {
                    return Err(Error::parse(format!(
                        "the next entry isn't a quoted value: {}",
                        self.remainder
                    )));
                }
            },
            false => self
                .remainder
                .split_once(' ')
                .unwrap_or((&self.remainder, "")),
        };
        let value = match escaped {
            true => unescape_bytes(entry)?,
            false => entry.as_bytes().to_vec(),
        };
        self.remainder = rest.trim_start().to_string();
        Ok(value)
    }
}

#[derive(Debug, Clone)]
pub struct SingleLineResponse {
    pub code: String,
    pub message: String,
    pub raw: ControlMessage,
}

impl SingleLineResponse {
    pub fn parse(message: ControlMessage) -> Result<Self> {
        match message.parts() {
            [] => Err(Error::protocol("Received empty response")),
            [part] => Ok(Self {
                code: part.code.clone(),
                message: part.text(),
                raw: message.clone(),
            }),
            _ => Err(Error::protocol("Received multi-line response")),
        }
    }

    pub fn is_ok(&self) -> bool {
        self.code == "250"
    }

    pub fn is_strictly_ok(&self) -> bool {
        self.code == "250" && self.message == "OK"
    }
}

#[derive(Debug, Clone, Default)]
pub struct GetInfoResponse {
    pub entries: HashMap<String, Vec<u8>>,
}

impl GetInfoResponse {
    pub fn parse(message: &ControlMessage) -> Result<Self> {
        let mut contents: Vec<&[u8]> = message
            .parts()
            .iter()
            .map(|part| part.content.as_slice())
            .collect();
        if !message.is_ok() || contents.pop() != Some(b"OK".as_slice()) {
            return Err(Self::failure(message));
        }
        let mut entries = HashMap::new();
        for content in contents {
            let Some(split) = content.iter().position(|byte| *byte == b'=') else {
                return Err(Error::protocol(format!(
                    "GETINFO replies should only contain parameter=value \
                    mappings:\n{message}"
                )));
            };
            let key = String::from_utf8_lossy(&content[..split]).into_owned();
            let mut value = &content[split + 1..];
            if value.contains(&b'\n') {
                value = value.strip_prefix(b"\n").ok_or_else(|| {
                    Error::protocol(format!(
                        "GETINFO response contained a multi-line value that didn't \
                        start with a newline:\n{message}"
                    ))
                })?;
            }
            entries.insert(key, value.to_vec());
        }
        Ok(Self { entries })
    }

    fn failure(message: &ControlMessage) -> Error {
        let mut unrecognized = Vec::new();
        let mut failure = None;
        for part in message.parts() {
            let text = part.text();
            if part.code != "250" {
                failure = Some((part.code.clone(), text.clone()));
            }
            let key = text
                .strip_prefix("Unrecognized key \"")
                .and_then(|rest| rest.strip_suffix('"'));
            if let (Some(key), "552") = (key, part.code.as_str()) {
                unrecognized.push(key.to_string());
            }
        }
        if !unrecognized.is_empty() {
            return Error::invalid_arguments(
                "552",
                format!(
                    "GETINFO request contained unrecognized keywords: {}\n",
                    unrecognized.join(", ")
                ),
                unrecognized,
            );
        }
        match failure {
            Some((code, text)) => Error::operation_failed(&code, text),
            None => Error::protocol(format!(
                "GETINFO response didn't have an OK status:\n{message}"
            )),
        }
    }

    pub fn assert_matches(&self, params: &[String]) -> Result<()> {
        let mut requested: Vec<&String> = params.iter().collect();
        let mut received: Vec<&String> = self.entries.keys().collect();
        requested.sort();
        received.sort();
        if requested == received {
            return Ok(());
        }
        Err(Error::protocol(format!(
            "GETINFO reply doesn't match the parameters that we requested. Queried '{}' \
            but got '{}'.",
            requested
                .iter()
                .map(|key| key.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            received
                .iter()
                .map(|key| key.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        )))
    }
}

#[derive(Debug, Clone, Default)]
pub struct GetConfResponse {
    pub entries: HashMap<String, Vec<String>>,
}

impl GetConfResponse {
    pub fn parse(message: &ControlMessage) -> Result<Self> {
        if message.content() == [("250".to_string(), ' ', "OK".to_string())] {
            return Ok(Self::default());
        }
        if !message.is_ok() {
            return Err(Self::failure(message));
        }
        let mut entries: HashMap<String, Vec<String>> = HashMap::new();
        for mut line in message.lines() {
            let (key, value) = if line.is_next_mapping(None, true, true) {
                let (key, value) = line.pop_mapping(true, true)?;
                (key, Some(value))
            } else if line.is_next_mapping(None, false, false) {
                let (key, value) = line.split_once('=').unwrap_or((&line, ""));
                (key.to_string(), Some(value.to_string()))
            } else {
                (line.pop(false, false)?, None)
            };
            let values = entries.entry(key).or_default();
            values.extend(value.filter(|value| !value.is_empty()));
        }
        Ok(Self { entries })
    }

    fn failure(message: &ControlMessage) -> Error {
        let unrecognized: Vec<String> = message
            .parts()
            .iter()
            .filter(|part| part.code == "552")
            .filter_map(|part| {
                let text = part.text();
                let key = text
                    .strip_prefix("Unrecognized configuration key \"")?
                    .strip_suffix('"')?;
                Some(key.to_string())
            })
            .collect();
        match unrecognized.is_empty() {
            true => Error::protocol(format!(
                "GETCONF response contained a non-OK status code:\n{message}"
            )),
            false => Error::invalid_arguments(
                "552",
                format!(
                    "GETCONF request contained unrecognized keywords: {}",
                    unrecognized.join(", ")
                ),
                unrecognized,
            ),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MapAddressResponse {
    pub entries: HashMap<String, String>,
}

impl MapAddressResponse {
    pub fn parse(message: &ControlMessage) -> Result<Self> {
        if !message.is_ok() {
            let part = &message.parts()[0];
            return Err(match part.code.as_str() {
                "512" => Error::invalid_request("512", part.text()),
                "451" => Error::operation_failed("451", part.text()),
                code => Error::protocol(format!(
                    "MAPADDRESS returned unexpected response code: {code}"
                )),
            });
        }
        let mut entries = HashMap::new();
        for part in message.parts().iter().filter(|part| part.code == "250") {
            let text = part.text();
            let (key, value) = text.split_once('=').ok_or_else(|| {
                Error::protocol(format!(
                    "MAPADDRESS returned '{text}', which isn't a mapping"
                ))
            })?;
            entries.insert(key.to_string(), value.to_string());
        }
        Ok(Self { entries })
    }
}

#[derive(Debug, Clone, Default)]
pub struct AddOnionResponse {
    pub service_id: Option<String>,
    pub private_key: Option<String>,
    pub private_key_type: Option<String>,
    pub client_auth: HashMap<String, String>,
    pub client_auth_v3: Vec<String>,
}

impl AddOnionResponse {
    pub fn parse(message: &ControlMessage) -> Result<Self> {
        if !message.is_ok() {
            return Err(Error::protocol(format!(
                "ADD_ONION response didn't have an OK status: {message}"
            )));
        }
        if !message.to_string().starts_with("ServiceID=") {
            return Err(Error::protocol(format!(
                "ADD_ONION response should start with the service id: {message}"
            )));
        }
        let mut response = Self::default();
        for line in message.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "ServiceID" => response.service_id = Some(value.to_string()),
                "PrivateKey" => {
                    let (kind, key) = value.split_once(':').ok_or_else(|| {
                        Error::protocol(format!(
                            "ADD_ONION PrivateKey lines should be of the form \
                            'PrivateKey=[type]:[key]: {message}"
                        ))
                    })?;
                    response.private_key_type = Some(kind.to_string());
                    response.private_key = Some(key.to_string());
                }
                "ClientAuth" => {
                    let (username, credential) =
                        value.split_once(':').ok_or_else(|| {
                            Error::protocol(format!(
                                "ADD_ONION ClientAuth lines should be of the form \
                            'ClientAuth=[username]:[credential]: {message}"
                            ))
                        })?;
                    response
                        .client_auth
                        .insert(username.to_string(), credential.to_string());
                }
                "ClientAuthV3" => response.client_auth_v3.push(value.to_string()),
                _ => {}
            }
        }
        Ok(response)
    }
}
