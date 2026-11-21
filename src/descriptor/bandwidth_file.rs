use chrono::{DateTime, NaiveDateTime};
use indexmap::IndexMap;

use crate::descriptor::{AttrValue, Attributes, mappings_for};
use crate::error::{Error, Result};
use crate::formatting::parse_iso_timestamp;

const HEADER_DIV: &str = "=====";
const HEADER_DIV_ALT: &str = "====";

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct RelayFailures {
    pub no_measurement: Option<u64>,
    pub insuffient_period: Option<u64>,
    pub insufficient_measurements: Option<u64>,
    pub stale: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct RecentStats {
    pub consensus_count: Option<u64>,
    pub prioritized_relays: Option<u64>,
    pub prioritized_relay_lists: Option<u64>,
    pub measurement_attempts: Option<u64>,
    pub measurement_failures: Option<u64>,
    pub relay_failures: RelayFailures,
}

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct BandwidthFile {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub timestamp: Option<NaiveDateTime>,
    pub header: IndexMap<String, String>,
    pub measurements: IndexMap<String, IndexMap<String, String>>,
    pub version: Option<String>,
    pub software: Option<String>,
    pub software_version: Option<String>,
    pub earliest_bandwidth: Option<NaiveDateTime>,
    pub latest_bandwidth: Option<NaiveDateTime>,
    pub created_at: Option<NaiveDateTime>,
    pub generated_at: Option<NaiveDateTime>,
    pub consensus_size: Option<u64>,
    pub eligible_count: Option<u64>,
    pub eligible_percent: Option<u64>,
    pub min_count: Option<u64>,
    pub min_percent: Option<u64>,
    pub scanner_country: Option<String>,
    pub destinations_countries: Option<Vec<String>>,
    pub time_to_report_half_network: Option<u64>,
    pub recent_stats: RecentStats,
}

fn integer(value: Option<&String>) -> Option<u64> {
    value
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse().ok())
}

fn date(value: Option<&String>) -> Option<NaiveDateTime> {
    value.and_then(|text| parse_iso_timestamp(text).ok())
}

fn text_lines(content: &str) -> Vec<&str> {
    content.split('\n').collect()
}

fn take_entry(header: &mut Vec<(String, String)>, key: &str) -> Option<String> {
    let index = header.iter().position(|(name, _)| name == key)?;
    Some(header.remove(index).1)
}

impl BandwidthFile {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        let text = String::from_utf8_lossy(content).into_owned();
        let mut file = Self {
            raw_contents: content.to_vec(),
            ..Default::default()
        };
        let timestamp = file.parse_timestamp(&text);
        let header = file.parse_header(&text);
        let body = file.parse_body(&text);
        if validate {
            timestamp?;
            header?;
            body?;
        }
        Ok(file)
    }

    fn parse_timestamp(&mut self, text: &str) -> Result<()> {
        let first_line = text_lines(text).first().copied().unwrap_or_default().trim();
        match !first_line.is_empty()
            && first_line.bytes().all(|byte| byte.is_ascii_digit())
        {
            true => {
                self.timestamp = first_line
                    .parse::<i64>()
                    .ok()
                    .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
                    .map(|moment| moment.naive_utc());
                Ok(())
            }
            false => Err(Error::parse(format!(
                "First line should be a unix timestamp, but was '{first_line}'"
            ))),
        }
    }

    fn parse_header(&mut self, text: &str) -> Result<()> {
        let mut header = IndexMap::new();
        let mut version_index = None;
        let mut failure = None;
        for (index, line) in text_lines(text).iter().enumerate().skip(1) {
            let line = line.trim();
            if line.is_empty() || line == HEADER_DIV || line == HEADER_DIV_ALT {
                break;
            }
            if header.is_empty() && line.contains("node_id=") {
                break;
            }
            let Some((key, value)) = line.split_once('=') else {
                failure = Some(Error::parse(format!(
                    "Header expected to be key=value pairs, but had '{line}'"
                )));
                break;
            };
            if key == "version" {
                version_index = Some(index);
            }
            header.insert(key.to_string(), value.to_string());
        }
        self.assign_header(&header);
        self.header = header;
        if let Some(error) = failure {
            return Err(error);
        }
        match version_index {
            Some(index) if index != 1 => Err(Error::parse(
                "The 'version' header must be in the second position",
            )),
            _ => Ok(()),
        }
    }

    fn assign_header(&mut self, header: &IndexMap<String, String>) {
        let text = |key: &str| header.get(key).cloned();
        self.version = header
            .get("version")
            .cloned()
            .or_else(|| Some("1.0.0".to_string()));
        self.software = text("software");
        self.software_version = text("software_version");
        self.earliest_bandwidth = date(header.get("earliest_bandwidth"));
        self.latest_bandwidth = date(header.get("latest_bandwidth"));
        self.created_at = date(header.get("file_created"));
        self.generated_at = date(header.get("generator_started"));
        self.consensus_size = integer(header.get("number_consensus_relays"));
        self.eligible_count = integer(header.get("number_eligible_relays"));
        self.eligible_percent = integer(header.get("percent_eligible_relays"));
        self.min_count = integer(header.get("minimum_number_eligible_relays"));
        self.min_percent = integer(header.get("minimum_percent_eligible_relays"));
        self.scanner_country = text("scanner_country");
        self.destinations_countries = header.get("destinations_countries").map(|value| {
            value
                .split(',')
                .map(|country| country.trim().to_string())
                .collect()
        });
        self.time_to_report_half_network =
            integer(header.get("time_to_report_half_network"));
        self.recent_stats = RecentStats {
            consensus_count: integer(header.get("recent_consensus_count")),
            prioritized_relays: integer(header.get("recent_priority_relay_count")),
            prioritized_relay_lists: integer(header.get("recent_priority_list_count")),
            measurement_attempts: integer(header.get("recent_measurement_attempt_count")),
            measurement_failures: integer(header.get("recent_measurement_failure_count")),
            relay_failures: RelayFailures {
                no_measurement: integer(
                    header.get("recent_measurements_excluded_error_count"),
                ),
                insuffient_period: integer(
                    header.get("recent_measurements_excluded_near_count"),
                ),
                insufficient_measurements: integer(
                    header.get("recent_measurements_excluded_few_count"),
                ),
                stale: integer(header.get("recent_measurements_excluded_old_count")),
            },
        };
    }

    fn parse_body(&mut self, text: &str) -> Result<()> {
        let lines = text_lines(text);
        let skip = match self.version.as_deref() == Some("1.0.0") {
            true => 1,
            false => lines
                .iter()
                .position(|line| matches!(line.trim(), HEADER_DIV | HEADER_DIV_ALT))
                .map_or(lines.len(), |index| index + 1),
        };
        let mut measurements = IndexMap::new();
        let last_index = lines.len().saturating_sub(1);
        for (index, line) in lines.iter().enumerate().skip(skip) {
            let line = line.trim();
            if line.is_empty() && index == last_index {
                continue;
            }
            let attributes: IndexMap<String, String> =
                mappings_for("measurement", line, false, ' ')?
                    .into_iter()
                    .collect();
            let fingerprint = attributes
                .get("node_id")
                .map(|id| id.trim_start_matches('$').to_string())
                .unwrap_or_default();
            if fingerprint.is_empty() {
                return Err(Error::parse(format!(
                    "Every meaurement must include 'node_id': {line}"
                )));
            }
            if measurements.contains_key(&fingerprint) {
                return Err(Error::parse(format!(
                    "Relay {fingerprint} is listed multiple times. It should only be \
                    present once."
                )));
            }
            measurements.insert(fingerprint, attributes);
        }
        self.measurements = measurements;
        Ok(())
    }

    pub fn content(
        header: &Attributes,
        exclude: &[&str],
        measurements: &[String],
    ) -> Result<Vec<u8>> {
        let mut header: Vec<(String, String)> = header
            .iter()
            .filter_map(|(key, value)| match value {
                AttrValue::Text(text) => Some((key.clone(), text.clone())),
                _ => None,
            })
            .collect();
        let timestamp = take_entry(&mut header, "timestamp")
            .unwrap_or_else(|| chrono::Utc::now().timestamp().to_string());
        let version = header
            .iter()
            .find(|(name, _)| name == "version")
            .map_or("1.0.0".to_string(), |(_, value)| value.clone());
        let mut lines: Vec<String> = Vec::new();
        if !exclude.contains(&"timestamp") {
            lines.push(timestamp);
        }
        if version == "1.0.0" && !header.is_empty() {
            return Err(Error::invalid_input(
                "Headers require BandwidthFile version 1.1 or later",
            ));
        }
        if version != "1.0.0" {
            if !exclude.contains(&"version") {
                let value = take_entry(&mut header, "version").unwrap_or_default();
                lines.push(format!("version={value}"));
            } else {
                take_entry(&mut header, "version");
            }
            lines.extend(header.iter().map(|(key, value)| format!("{key}={value}")));
            lines.push(HEADER_DIV.to_string());
        }
        lines.extend(measurements.iter().cloned());
        Ok(lines.join("\n").into_bytes())
    }

    pub fn create(
        header: &Attributes,
        exclude: &[&str],
        measurements: &[String],
        validate: bool,
    ) -> Result<Self> {
        Self::parse(&Self::content(header, exclude, measurements)?, validate)
    }
}
