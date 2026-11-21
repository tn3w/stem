use std::ops::Deref;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use indexmap::IndexMap;
use regex::Regex;

use crate::address::{is_valid_ipv4_address, is_valid_ipv6_address, parse_port};
use crate::configuration::Config;
use crate::download::download;
use crate::error::{Error, Result};
use crate::validation::{is_valid_fingerprint, is_valid_nickname};

pub const GITLAB_AUTHORITY_URL: &str =
    "https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/app/config/auth_dirs.inc";
pub const GITLAB_FALLBACK_URL: &str = concat!(
    "https://gitlab.torproject.org/tpo/core/tor/-/raw/main/",
    "src/app/config/fallback_dirs.inc"
);
const EMBEDDED_AUTHORITIES: &str = include_str!("data/auth_dirs.inc");
const EMBEDDED_FALLBACKS: &str = include_str!("data/fallback_dirs.inc");
const FALLBACK_DIV: &str = "/* ===== */";
const FALLBACK_TYPE_FIELD: &str = "/* type=fallback */";

fn regex(pattern: &'static str, cell: &'static OnceLock<Regex>) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("directory patterns are valid"))
}

fn authority_name() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(r#""(\S+) orport=(\d+) .*""#, &CELL)
}

fn authority_v3ident() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(r#""v3ident=([\dA-F]{40}) ""#, &CELL)
}

fn authority_ipv6() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(r#""ipv6=\[([\da-f:]+)\]:(\d+) ""#, &CELL)
}

fn authority_address() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(r#""([\d\.]+):(\d+) ([\dA-F ]{40,49})","#, &CELL)
}

fn fallback_mapping() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(r"/\*\s+(\S+)=(\S*)\s+\*/", &CELL)
}

fn fallback_address() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(
        r#""([\d\.]+)(?::(\d+))? orport=(\d+) id=([\dA-F]{40}).*"#,
        &CELL,
    )
}

fn fallback_nickname() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(r"/\* nickname=(\S+) \*/", &CELL)
}

fn fallback_extrainfo() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(r"/\* extrainfo=([0-1]) \*/", &CELL)
}

fn fallback_ipv6() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(r#"" ipv6=\[([\da-f:]+)\]:(\d+)""#, &CELL)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    pub address: String,
    pub or_port: u16,
    pub dir_port: Option<u16>,
    pub fingerprint: String,
    pub nickname: Option<String>,
    pub orport_v6: Option<(String, u16)>,
}

impl Directory {
    pub fn new(
        address: &str,
        or_port: u16,
        dir_port: Option<u16>,
        fingerprint: &str,
        nickname: Option<&str>,
        orport_v6: Option<(&str, u16)>,
    ) -> Result<Self> {
        let identifier = match nickname {
            Some(name) => format!("{fingerprint} ({name})"),
            None => fingerprint.to_string(),
        };
        if !is_valid_ipv4_address(address) {
            return Err(Error::invalid_input(format!(
                "{identifier} has an invalid IPv4 address: {address}"
            )));
        }
        if or_port == 0 {
            return Err(Error::invalid_input(format!(
                "{identifier} has an invalid ORPort: {or_port}"
            )));
        }
        if dir_port == Some(0) {
            return Err(Error::invalid_input(format!(
                "{identifier} has an invalid DirPort: 0"
            )));
        }
        if !is_valid_fingerprint(fingerprint, false) {
            return Err(Error::invalid_input(format!(
                "{identifier} has an invalid fingerprint: {fingerprint}"
            )));
        }
        if let Some(name) = nickname.filter(|name| !is_valid_nickname(name)) {
            return Err(Error::invalid_input(format!(
                "{fingerprint} has an invalid nickname: {name}"
            )));
        }
        if let Some((v6_address, v6_port)) = orport_v6 {
            if !is_valid_ipv6_address(v6_address, false) {
                return Err(Error::invalid_input(format!(
                    "{identifier} has an invalid IPv6 address: {v6_address}"
                )));
            }
            if v6_port == 0 {
                return Err(Error::invalid_input(format!(
                    "{identifier} has an invalid IPv6 port: {v6_port}"
                )));
            }
        }
        Ok(Self {
            address: address.to_string(),
            or_port,
            dir_port,
            fingerprint: fingerprint.to_string(),
            nickname: nickname.map(str::to_string),
            orport_v6: orport_v6.map(|(address, port)| (address.to_string(), port)),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    pub directory: Directory,
    pub v3ident: Option<String>,
    pub is_bandwidth_authority: bool,
}

impl Deref for Authority {
    type Target = Directory;

    fn deref(&self) -> &Directory {
        &self.directory
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fallback {
    pub directory: Directory,
    pub has_extrainfo: bool,
    pub header: IndexMap<String, String>,
}

impl Deref for Fallback {
    type Target = Directory;

    fn deref(&self) -> &Directory {
        &self.directory
    }
}

fn pop_authority_section<'a>(
    lines: &mut std::collections::VecDeque<&'a str>,
) -> Vec<&'a str> {
    let mut section = Vec::new();
    if let Some(first) = lines.pop_front() {
        section.push(first);
        while let Some(next) = lines.front().filter(|line| line.starts_with(' ')) {
            section.push(next);
            lines.pop_front();
        }
    }
    section
}

fn pop_fallback_section<'a>(
    lines: &mut std::collections::VecDeque<&'a str>,
) -> Vec<&'a str> {
    let mut section = Vec::new();
    if let Some(mut line) = lines.pop_front() {
        while !lines.is_empty() && line != FALLBACK_DIV {
            if line.trim() != "," {
                section.push(line);
            }
            line = lines.pop_front().unwrap_or(FALLBACK_DIV);
        }
    }
    section
}

fn capture<'a>(lines: &[&'a str], matcher: &Regex) -> Option<regex::Captures<'a>> {
    lines.iter().rev().find_map(|line| matcher.captures(line))
}

fn port_text(text: &str, what: &str) -> Result<u16> {
    parse_port(text, false)
        .ok_or_else(|| Error::invalid_input(format!("{what} is invalid: {text}")))
}

impl Authority {
    pub fn new(
        address: &str,
        or_port: u16,
        dir_port: Option<u16>,
        fingerprint: &str,
        nickname: Option<&str>,
        orport_v6: Option<(&str, u16)>,
        v3ident: Option<&str>,
    ) -> Result<Self> {
        let directory =
            Directory::new(address, or_port, dir_port, fingerprint, nickname, orport_v6)?;
        if let Some(ident) = v3ident.filter(|ident| !is_valid_fingerprint(ident, false)) {
            let identifier = nickname.map_or(fingerprint.to_string(), |name| {
                format!("{fingerprint} ({name})")
            });
            return Err(Error::invalid_input(format!(
                "{identifier} has an invalid v3ident: {ident}"
            )));
        }
        Ok(Self {
            directory,
            v3ident: v3ident.map(str::to_string),
            is_bandwidth_authority: false,
        })
    }

    pub fn from_cache() -> Result<IndexMap<String, Authority>> {
        Self::parse_inc(EMBEDDED_AUTHORITIES)
    }

    pub async fn from_remote(timeout: Duration) -> Result<IndexMap<String, Authority>> {
        Self::from_url(GITLAB_AUTHORITY_URL, timeout).await
    }

    pub async fn from_url(
        url: &str,
        timeout: Duration,
    ) -> Result<IndexMap<String, Authority>> {
        let content = download(url, Some(timeout), 0).await.map_err(|error| {
            Error::DownloadFailed {
                url: url.to_string(),
                message: format!(
                    "Unable to download tor's directory authorities from {url}: {error}"
                ),
            }
        })?;
        let authorities = Self::parse_inc(&String::from_utf8_lossy(&content))?;
        match authorities.is_empty() {
            true => Err(Error::Io(std::io::Error::other(format!(
                "{url} didn't contain any directory authorities"
            )))),
            false => Ok(authorities),
        }
    }

    pub fn parse_inc(content: &str) -> Result<IndexMap<String, Authority>> {
        let mut lines: std::collections::VecDeque<&str> = content.lines().collect();
        let mut results = IndexMap::new();
        loop {
            let section = pop_authority_section(&mut lines);
            if section.is_empty() {
                break;
            }
            let (Some(name), Some(address)) = (
                capture(&section, authority_name()),
                capture(&section, authority_address()),
            ) else {
                return Err(Error::Io(std::io::Error::other(format!(
                    "Failed to parse mandatory data from:\n\n{}",
                    section.join("\n")
                ))));
            };
            let nickname = name[1].to_string();
            let fingerprint = address[3].replace(' ', "");
            let v6 = capture(&section, authority_ipv6());
            let ident = capture(&section, authority_v3ident());
            let dir_port = port_text(&address[2], "DirPort")?;
            let authority = Authority::new(
                &address[1],
                port_text(&name[2], "ORPort")?,
                Some(dir_port),
                &fingerprint,
                Some(&nickname),
                match &v6 {
                    Some(found) => Some((&found[1], port_text(&found[2], "IPv6 port")?)),
                    None => None,
                },
                ident.as_ref().map(|found| &found[1]),
            )
            .map_err(|error| Error::Io(std::io::Error::other(error.to_string())))?;
            results.insert(nickname, authority);
        }
        Ok(results)
    }
}

impl Fallback {
    pub fn new(
        directory: Directory,
        has_extrainfo: bool,
        header: IndexMap<String, String>,
    ) -> Self {
        Self {
            directory,
            has_extrainfo,
            header,
        }
    }

    pub fn from_cache(path: Option<&Path>) -> Result<IndexMap<String, Fallback>> {
        match path {
            None => Self::parse_inc(EMBEDDED_FALLBACKS),
            Some(path) => Self::from_config_cache(path),
        }
    }

    fn from_config_cache(path: &Path) -> Result<IndexMap<String, Fallback>> {
        let mut config = Config::new();
        config.load(path)?;
        let headers: IndexMap<String, String> = config
            .keys()
            .iter()
            .filter_map(|key| {
                let name = key.strip_prefix("header.")?;
                Some((name.to_string(), config.get_value(key)?.to_string()))
            })
            .collect();
        let fingerprints: indexmap::IndexSet<String> = config
            .keys()
            .iter()
            .filter_map(|key| key.split('.').next().map(str::to_string))
            .collect();
        let mut results = IndexMap::new();
        for fingerprint in fingerprints {
            if matches!(
                fingerprint.as_str(),
                "tor_commit" | "stem_commit" | "header"
            ) {
                continue;
            }
            let attribute = |name: &str| {
                config
                    .get_value(&format!("{fingerprint}.{name}"))
                    .map(str::to_string)
            };
            let missing = |name: &str| {
                Error::Io(std::io::Error::other(format!(
                    "'{fingerprint}.{name}' is missing from {}",
                    path.display()
                )))
            };
            let address = attribute("address")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| missing("address"))?;
            let or_port: u16 = attribute("or_port")
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| missing("or_port"))?;
            let dir_port = attribute("dir_port").and_then(|value| value.parse().ok());
            let nickname = attribute("nickname");
            let orport_v6 = match (
                attribute("orport6_address"),
                attribute("orport6_port").and_then(|port| port.parse::<u16>().ok()),
            ) {
                (Some(address), Some(port)) => Some((address, port)),
                _ => None,
            };
            results.insert(
                fingerprint.clone(),
                Fallback::new(
                    Directory::new(
                        &address,
                        or_port,
                        dir_port,
                        &fingerprint,
                        nickname.as_deref().filter(|name| !name.is_empty()),
                        orport_v6
                            .as_ref()
                            .map(|(address, port)| (address.as_str(), *port)),
                    )?,
                    attribute("has_extrainfo").as_deref() == Some("true"),
                    headers.clone(),
                ),
            );
        }
        Ok(results)
    }

    pub async fn from_remote(timeout: Duration) -> Result<IndexMap<String, Fallback>> {
        Self::from_url(GITLAB_FALLBACK_URL, timeout).await
    }

    pub async fn from_url(
        url: &str,
        timeout: Duration,
    ) -> Result<IndexMap<String, Fallback>> {
        let content = download(url, Some(timeout), 0).await.map_err(|error| {
            Error::DownloadFailed {
                url: url.to_string(),
                message: format!(
                    "Unable to download tor's fallback directories from {url}: {error}"
                ),
            }
        })?;
        Self::parse_inc(&String::from_utf8_lossy(&content))
    }

    pub fn parse_inc(content: &str) -> Result<IndexMap<String, Fallback>> {
        let malformed = |message: String| Error::Io(std::io::Error::other(message));
        let mut lines: std::collections::VecDeque<&str> = content.lines().collect();
        if lines.front().copied() != Some(FALLBACK_TYPE_FIELD) {
            return Err(malformed(format!(
                "{GITLAB_FALLBACK_URL} does not have a type field indicating it is \
                fallback directory metadata"
            )));
        }
        let mut header = IndexMap::new();
        while let Some(line) = lines.front().copied().filter(|line| *line != "//") {
            lines.pop_front();
            let Some(mapping) = fallback_mapping().captures(line) else {
                return Err(malformed(format!(
                    "Malformed fallback directory header line: {line}"
                )));
            };
            header.insert(mapping[1].to_string(), mapping[2].to_string());
        }
        let generated = lines
            .get(1)
            .is_some_and(|line| line.starts_with("// Generated on: "))
            && lines.front() == Some(&"//");
        if !generated {
            return Err(malformed(format!(
                "Malformed header: {}",
                lines.iter().take(2).copied().collect::<Vec<_>>().join("\n")
            )));
        }
        lines.pop_front();
        lines.pop_front();
        let mut results = IndexMap::new();
        loop {
            let section = pop_fallback_section(&mut lines);
            if section.is_empty() {
                break;
            }
            let Some(found) = capture(&section, fallback_address()) else {
                return Err(malformed(format!(
                    "Failed to parse mandatory data from:\n\n{}",
                    section.join("\n")
                )));
            };
            let dir_port = found
                .get(2)
                .map(|port| port_text(port.as_str(), "DirPort"))
                .transpose()?;
            let fingerprint = found[4].to_string();
            let nickname =
                capture(&section, fallback_nickname()).map(|name| name[1].to_string());
            let v6 = capture(&section, fallback_ipv6());
            let has_extrainfo = capture(&section, fallback_extrainfo())
                .is_some_and(|flag| &flag[1] == "1");
            let directory = Directory::new(
                &found[1],
                port_text(&found[3], "ORPort")?,
                dir_port,
                &fingerprint,
                nickname.as_deref(),
                match &v6 {
                    Some(address) => {
                        Some((&address[1], port_text(&address[2], "IPv6 port")?))
                    }
                    None => None,
                },
            )
            .map_err(|error| malformed(error.to_string()))?;
            let fallback = Fallback::new(directory, has_extrainfo, header.clone());
            results.insert(fingerprint, fallback);
        }
        Ok(results)
    }

    pub fn write_cache(
        fallbacks: &IndexMap<String, Fallback>,
        tor_commit: &str,
        stem_commit: &str,
        headers: &IndexMap<String, String>,
        path: &Path,
    ) -> Result<()> {
        let mut config = Config::new();
        config.set("tor_commit", tor_commit, true);
        config.set("stem_commit", stem_commit, true);
        for (key, value) in headers {
            config.set(&format!("header.{key}"), value, true);
        }
        let mut sorted: Vec<&Fallback> = fallbacks.values().collect();
        sorted.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
        for fallback in sorted {
            let fingerprint = &fallback.fingerprint;
            config.set(&format!("{fingerprint}.address"), &fallback.address, true);
            config.set(
                &format!("{fingerprint}.or_port"),
                &fallback.or_port.to_string(),
                true,
            );
            if let Some(port) = fallback.dir_port {
                config.set(&format!("{fingerprint}.dir_port"), &port.to_string(), true);
            }
            config.set(
                &format!("{fingerprint}.nickname"),
                fallback.nickname.as_deref().unwrap_or(""),
                true,
            );
            config.set(
                &format!("{fingerprint}.has_extrainfo"),
                if fallback.has_extrainfo {
                    "true"
                } else {
                    "false"
                },
                true,
            );
            if let Some((address, port)) = &fallback.orport_v6 {
                config.set(&format!("{fingerprint}.orport6_address"), address, true);
                config.set(
                    &format!("{fingerprint}.orport6_port"),
                    &port.to_string(),
                    true,
                );
            }
        }
        config.save(path)
    }
}

pub fn fallback_directory_differences(
    previous: &IndexMap<String, Fallback>,
    current: &IndexMap<String, Fallback>,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    for (fingerprint, directory) in current
        .iter()
        .filter(|(fingerprint, _)| !previous.contains_key(*fingerprint))
    {
        let v6 = directory
            .orport_v6
            .as_ref()
            .map_or("[none]".to_string(), |(address, port)| {
                format!("{address}:{port}")
            });
        lines.extend([
            format!("* Added {fingerprint} as a new fallback directory:"),
            format!("  address: {}", directory.address),
            format!("  or_port: {}", directory.or_port),
            format!(
                "  dir_port: {}",
                directory
                    .dir_port
                    .map_or("None".to_string(), |port| port.to_string())
            ),
            format!(
                "  nickname: {}",
                directory.nickname.as_deref().unwrap_or("None")
            ),
            format!("  has_extrainfo: {}", directory.has_extrainfo),
            format!("  orport_v6: {v6}"),
            String::new(),
        ]);
    }
    for fingerprint in previous
        .keys()
        .filter(|fingerprint| !current.contains_key(*fingerprint))
    {
        lines.push(format!("* Removed {fingerprint} as a fallback directory"));
    }
    for (fingerprint, new_directory) in current {
        let Some(old_directory) = previous.get(fingerprint) else {
            continue;
        };
        if old_directory == new_directory {
            continue;
        }
        let describe = |directory: &Directory, attribute: &str| match attribute {
            "address" => directory.address.clone(),
            "or_port" => directory.or_port.to_string(),
            "dir_port" => directory
                .dir_port
                .map_or("None".to_string(), |port| port.to_string()),
            "fingerprint" => directory.fingerprint.clone(),
            _ => directory
                .orport_v6
                .as_ref()
                .map_or("None".to_string(), |(address, port)| {
                    format!("('{address}', {port})")
                }),
        };
        for attribute in ["address", "or_port", "dir_port", "fingerprint", "orport_v6"] {
            let (old, new) = (
                describe(old_directory, attribute),
                describe(new_directory, attribute),
            );
            if old != new {
                lines.push(format!(
                    "* Changed the {attribute} of {fingerprint} from {old} to {new}"
                ));
            }
        }
    }
    lines.join("\n")
}
