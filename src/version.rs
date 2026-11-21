use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::process::Command;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub micro: u32,
    pub patch: Option<u32>,
    pub status: Option<String>,
    pub all_extra: Vec<String>,
    pub git_commit: Option<String>,
    version_string: String,
}

impl Version {
    pub fn new(version_string: &str) -> Result<Self> {
        let invalid = || {
            Error::parse(format!(
                "'{version_string}' isn't a properly formatted tor version"
            ))
        };
        let (numbers, suffix) = split_numbers(version_string);
        let parts = numbers
            .split('.')
            .map(
                |part| match part.bytes().all(|byte| byte.is_ascii_digit()) {
                    true => part.parse::<u32>().ok(),
                    false => None,
                },
            )
            .collect::<Option<Vec<u32>>>()
            .filter(|parts| (3..=4).contains(&parts.len()))
            .ok_or_else(invalid)?;
        let (status, all_extra) = parse_suffix(suffix).ok_or_else(invalid)?;
        let git_commit = all_extra.iter().find_map(|extra| {
            let commit = extra.strip_prefix("git-")?;
            let is_commit = commit.len() == 16
                && commit
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
            is_commit.then(|| commit.to_string())
        });
        Ok(Self {
            major: parts[0],
            minor: parts[1],
            micro: parts[2],
            patch: parts.get(3).copied(),
            status,
            all_extra,
            git_commit,
            version_string: version_string.to_string(),
        })
    }

    pub fn extra(&self) -> Option<&str> {
        self.all_extra.first().map(String::as_str)
    }

    pub fn meets(&self, requirement: Requirement) -> bool {
        requirement.is_met_by(self)
    }

    fn comparison_key(&self) -> (u32, u32, u32, u32, &str) {
        (
            self.major,
            self.minor,
            self.micro,
            self.patch.unwrap_or(0),
            self.status.as_deref().unwrap_or(""),
        )
    }
}

fn split_numbers(version: &str) -> (&str, &str) {
    let end = version
        .find(|character: char| !(character.is_ascii_digit() || character == '.'))
        .unwrap_or(version.len());
    version.split_at(end)
}

fn parse_suffix(suffix: &str) -> Option<(Option<String>, Vec<String>)> {
    let (status, mut remaining) = match suffix.strip_prefix('-') {
        Some(rest) => {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            (Some(rest[..end].to_string()), &rest[end..])
        }
        None => (None, suffix),
    };
    let mut extras = Vec::new();
    while !remaining.is_empty() {
        let rest = remaining.strip_prefix(' ')?;
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let token = &rest[..end];
        let extra = token.strip_prefix('(')?.strip_suffix(')')?;
        extras.push(extra.to_string());
        remaining = &rest[end..];
    }
    Some((status.filter(|status| !status.is_empty()), extras))
}

impl FromStr for Version {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        Self::new(text)
    }
}

impl serde::Serialize for Version {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.version_string)
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.comparison_key() == other.comparison_key()
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.comparison_key().cmp(&other.comparison_key())
    }
}

impl Hash for Version {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.comparison_key().hash(state);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Requirement {
    AuthSafecookie,
    DescriptorCompression,
    DormantMode,
    DropGuards,
    EventAuthdirNewdescs,
    EventBuildtimeoutSet,
    EventCircMinor,
    EventClientsSeen,
    EventConfChanged,
    EventDescChanged,
    EventGuard,
    EventHsDescContent,
    EventNs,
    EventNetworkLiveness,
    EventNewConsensus,
    EventSignal,
    EventStatus,
    EventStreamBw,
    EventTransportLaunched,
    EventConnBw,
    EventCircBw,
    EventCellStats,
    EventTbEmpty,
    EventHsDesc,
    ExtendCircuitPathOptional,
    FeatureExtendedEvents,
    FeatureVerboseNames,
    GetinfoConfigText,
    GetinfoGeoipAvailable,
    GetinfoMicrodescriptors,
    GetinfoUptime,
    HiddenServiceV3,
    HsFetch,
    HsFetchV3,
    HsPost,
    AddOnion,
    AddOnionBasicAuth,
    AddOnionNonAnonymous,
    AddOnionMaxStreams,
    LoadConf,
    MicrodescriptorIsDefault,
    SaveConfForce,
    TakeOwnership,
    TorrcControlSocket,
    TorrcPortForwarding,
    TorrcDisableDebuggerAttachment,
    TorrcViaStdin,
    OnionServiceAuthAdd,
}

fn parsed(version: &str) -> Version {
    Version::new(version).expect("requirement versions are literals")
}

impl Requirement {
    pub const ALL: [Requirement; 48] = [
        Self::AuthSafecookie,
        Self::DescriptorCompression,
        Self::DormantMode,
        Self::DropGuards,
        Self::EventAuthdirNewdescs,
        Self::EventBuildtimeoutSet,
        Self::EventCircMinor,
        Self::EventClientsSeen,
        Self::EventConfChanged,
        Self::EventDescChanged,
        Self::EventGuard,
        Self::EventHsDescContent,
        Self::EventNs,
        Self::EventNetworkLiveness,
        Self::EventNewConsensus,
        Self::EventSignal,
        Self::EventStatus,
        Self::EventStreamBw,
        Self::EventTransportLaunched,
        Self::EventConnBw,
        Self::EventCircBw,
        Self::EventCellStats,
        Self::EventTbEmpty,
        Self::EventHsDesc,
        Self::ExtendCircuitPathOptional,
        Self::FeatureExtendedEvents,
        Self::FeatureVerboseNames,
        Self::GetinfoConfigText,
        Self::GetinfoGeoipAvailable,
        Self::GetinfoMicrodescriptors,
        Self::GetinfoUptime,
        Self::HiddenServiceV3,
        Self::HsFetch,
        Self::HsFetchV3,
        Self::HsPost,
        Self::AddOnion,
        Self::AddOnionBasicAuth,
        Self::AddOnionNonAnonymous,
        Self::AddOnionMaxStreams,
        Self::LoadConf,
        Self::MicrodescriptorIsDefault,
        Self::SaveConfForce,
        Self::TakeOwnership,
        Self::TorrcControlSocket,
        Self::TorrcPortForwarding,
        Self::TorrcDisableDebuggerAttachment,
        Self::TorrcViaStdin,
        Self::OnionServiceAuthAdd,
    ];

    pub fn minimum(&self) -> Version {
        parsed(match self {
            Self::AuthSafecookie => "0.2.3.13",
            Self::DescriptorCompression => "0.3.1.1-alpha",
            Self::DormantMode => "0.4.0.1-alpha",
            Self::DropGuards => "0.2.5.1-alpha",
            Self::EventAuthdirNewdescs => "0.1.1.10-alpha",
            Self::EventBuildtimeoutSet => "0.2.2.7-alpha",
            Self::EventCircMinor => "0.2.3.11-alpha",
            Self::EventClientsSeen => "0.2.1.10-alpha",
            Self::EventConfChanged => "0.2.3.3-alpha",
            Self::EventDescChanged => "0.1.2.2-alpha",
            Self::EventGuard => "0.1.2.5-alpha",
            Self::EventHsDescContent => "0.2.7.1-alpha",
            Self::EventNs => "0.1.2.3-alpha",
            Self::EventNetworkLiveness => "0.2.7.2-alpha",
            Self::EventNewConsensus => "0.2.1.13-alpha",
            Self::EventSignal => "0.2.3.1-alpha",
            Self::EventStatus => "0.1.2.3-alpha",
            Self::EventStreamBw => "0.1.2.8-beta",
            Self::EventTransportLaunched => "0.2.5.0-alpha",
            Self::EventConnBw | Self::EventCircBw | Self::EventCellStats => {
                "0.2.5.2-alpha"
            }
            Self::EventTbEmpty | Self::EventHsDesc => "0.2.5.2-alpha",
            Self::ExtendCircuitPathOptional => "0.2.2.9",
            Self::FeatureExtendedEvents | Self::FeatureVerboseNames => "0.2.2.1-alpha",
            Self::GetinfoConfigText => "0.2.2.7-alpha",
            Self::GetinfoGeoipAvailable => "0.3.2.1-alpha",
            Self::GetinfoMicrodescriptors | Self::GetinfoUptime => "0.3.5.1-alpha",
            Self::HiddenServiceV3 => "0.3.3.1-alpha",
            Self::HsFetch | Self::HsPost => "0.2.7.1-alpha",
            Self::HsFetchV3 => "0.4.1.1-alpha",
            Self::AddOnion => "0.2.7.1-alpha",
            Self::AddOnionBasicAuth => "0.2.9.1-alpha",
            Self::AddOnionNonAnonymous => "0.2.9.3-alpha",
            Self::AddOnionMaxStreams => "0.2.7.2-alpha",
            Self::LoadConf => "0.2.1.1",
            Self::MicrodescriptorIsDefault => "0.2.3.3",
            Self::SaveConfForce => "0.3.1.1-alpha",
            Self::TakeOwnership => "0.2.2.28-beta",
            Self::TorrcControlSocket => "0.2.0.30",
            Self::TorrcPortForwarding => "0.2.3.1-alpha",
            Self::TorrcDisableDebuggerAttachment => "0.2.3.9",
            Self::TorrcViaStdin => "0.2.6.3-alpha",
            Self::OnionServiceAuthAdd => "0.4.6.1-alpha",
        })
    }

    pub fn is_met_by(&self, version: &Version) -> bool {
        match self {
            Self::AuthSafecookie => {
                let first_range = parsed("0.2.2.36")..parsed("0.2.3.0");
                first_range.contains(version) || *version >= parsed("0.2.3.13")
            }
            _ => *version >= self.minimum(),
        }
    }
}

impl fmt::Display for Requirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.minimum())
    }
}

pub fn get_system_tor_version(tor_command: &str) -> Result<Version> {
    get_system_tor_version_with_environment(tor_command, &[])
}

pub fn get_system_tor_version_with_environment(
    tor_command: &str,
    environment: &[(String, String)],
) -> Result<Version> {
    static CACHE: OnceLock<Mutex<HashMap<String, Version>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(version) = cache.lock().unwrap().get(tor_command) {
        return Ok(version.clone());
    }
    let output = Command::new(tor_command)
        .arg("--version")
        .envs(environment.iter().map(|(key, value)| (key, value)))
        .output()
        .map_err(
            |error| match std::path::Path::new(tor_command).is_absolute() {
                true => Error::Io(std::io::Error::new(
                    error.kind(),
                    format!(
                        "Unable to check tor's version. '{tor_command}' doesn't exist."
                    ),
                )),
                false => Error::Io(std::io::Error::new(
                    error.kind(),
                    format!(
                        "Unable to run '{tor_command} --version'. Maybe tor isn't in \
                    your PATH?"
                    ),
                )),
            },
        )?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Tor version ")?.strip_suffix('.'))
        .ok_or_else(|| {
            Error::Io(std::io::Error::other(format!(
                "'{tor_command} --version' didn't provide a parseable \
                version:\n\n{stdout}"
            )))
        })
        .and_then(Version::new)?;
    cache
        .lock()
        .unwrap()
        .insert(tor_command.to_string(), version.clone());
    Ok(version)
}
