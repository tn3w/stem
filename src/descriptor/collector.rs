use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use chrono::{Datelike, NaiveDate, NaiveDateTime, TimeDelta};
use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::descriptor::Compression;
use crate::descriptor::parsing::{Descriptor, DocumentHandler, parse_compressed};
use crate::download::download;
use crate::error::{Error, Result};

pub const COLLECTOR_URL: &str = "https://collector.torproject.org/";
pub const REFRESH_INDEX_RATE: Duration = Duration::from_secs(3600);

const INDEX_TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M";
const PATH_TIMESTAMP_FORMAT: &str = "%Y-%m-%d-%H-%M-%S";

static YEAR_DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-(\d{4})-(\d{2})\.").expect("valid pattern"));
static SECOND_DATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})").expect("valid pattern")
});
static SHARED_COLLECTOR: LazyLock<CollecTor> = LazyLock::new(CollecTor::new);

#[derive(Debug, Deserialize)]
struct IndexDirectory {
    path: Option<String>,
    #[serde(default)]
    directories: Vec<IndexDirectory>,
    #[serde(default)]
    files: Vec<IndexFile>,
}

#[derive(Debug, Deserialize)]
struct IndexFile {
    path: String,
    #[serde(default)]
    types: Vec<String>,
    size: Option<u64>,
    sha256: Option<String>,
    first_published: Option<String>,
    last_published: Option<String>,
    last_modified: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorFile {
    pub path: String,
    pub types: Vec<String>,
    pub compression: Compression,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    pub last_modified: NaiveDateTime,
    pub start: Option<NaiveDateTime>,
    pub end: Option<NaiveDateTime>,
}

#[derive(Debug, Clone)]
pub struct CollectorRequest {
    pub start: Option<NaiveDateTime>,
    pub end: Option<NaiveDateTime>,
    pub cache_to: Option<PathBuf>,
    pub timeout: Option<Duration>,
    pub retries: u32,
    pub document_handler: DocumentHandler,
    pub validate: bool,
}

impl Default for CollectorRequest {
    fn default() -> Self {
        Self {
            start: None,
            end: None,
            cache_to: None,
            timeout: None,
            retries: 3,
            document_handler: DocumentHandler::Entries,
            validate: false,
        }
    }
}

fn validate_path(path: &str) -> Result<()> {
    let invalid =
        || Error::parse(format!("Unsafe path in the CollecTor index: {path:?}"));
    let allowed = |character: char| {
        character.is_ascii_alphanumeric() || "-_.+:".contains(character)
    };
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(invalid());
        }
        if !segment.chars().all(allowed) {
            return Err(invalid());
        }
    }
    Ok(())
}

fn parse_index_timestamp(value: &str) -> Result<NaiveDateTime> {
    NaiveDateTime::parse_from_str(value, INDEX_TIMESTAMP_FORMAT)
        .map_err(|_| Error::parse(format!("Invalid CollecTor timestamp: {value:?}")))
}

fn guess_compression(path: &str) -> Compression {
    [Compression::Lzma, Compression::Bzip2, Compression::Gzip]
        .into_iter()
        .find(|compression| path.ends_with(compression.extension()))
        .unwrap_or(Compression::Plaintext)
}

fn guess_time_range(path: &str) -> (Option<NaiveDateTime>, Option<NaiveDateTime>) {
    if let Some(captures) = YEAR_DATE.captures(path) {
        let year = captures[1].parse().ok();
        let month = captures[2].parse().ok();
        let start = year
            .zip(month)
            .and_then(|(year, month)| NaiveDate::from_ymd_opt(year, month, 1));
        let Some(start) = start else {
            return (None, None);
        };
        let next = match start.month() {
            12 => NaiveDate::from_ymd_opt(start.year() + 1, 1, 1),
            month => NaiveDate::from_ymd_opt(start.year(), month + 1, 1),
        };
        let midnight = |date: NaiveDate| date.and_hms_opt(0, 0, 0);
        return (midnight(start), next.and_then(midnight));
    }
    let start = SECOND_DATE.captures(path).and_then(|captures| {
        NaiveDateTime::parse_from_str(&captures[1], PATH_TIMESTAMP_FORMAT).ok()
    });
    match start {
        Some(start) => (Some(start), Some(start + TimeDelta::seconds(3600))),
        None => (None, None),
    }
}

fn hash_matches(expected_base64: &str, content: &[u8]) -> bool {
    let Ok(expected) = base64::engine::general_purpose::STANDARD.decode(expected_base64)
    else {
        return false;
    };
    let actual = Sha256::digest(content);
    expected.as_slice().ct_eq(actual.as_slice()).into()
}

impl CollectorFile {
    fn from_index(path: String, entry: IndexFile) -> Result<Self> {
        validate_path(&path)?;
        let last_modified = parse_index_timestamp(&entry.last_modified)?;
        let (start, end) = match (&entry.first_published, &entry.last_published) {
            (Some(first), Some(last)) if !first.is_empty() && !last.is_empty() => (
                Some(parse_index_timestamp(first)?),
                Some(parse_index_timestamp(last)?),
            ),
            _ => guess_time_range(&path),
        };
        Ok(Self {
            compression: guess_compression(&path),
            path,
            types: entry
                .types
                .into_iter()
                .map(|kind| match kind.strip_prefix("@type ") {
                    Some(bare) => bare.to_string(),
                    None => kind,
                })
                .collect(),
            size: entry.size,
            sha256: entry.sha256,
            last_modified,
            start,
            end,
        })
    }

    pub fn file_name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    fn descriptor_type(&self, requested: Option<&str>) -> Result<String> {
        if let Some(requested) = requested {
            return Ok(requested.to_string());
        }
        let mut base_types: Vec<&str> = self
            .types
            .iter()
            .filter_map(|descriptor_type| descriptor_type.split(' ').next())
            .collect();
        base_types.dedup();
        match (self.types.first(), base_types.len()) {
            (None, _) => Err(Error::invalid_input(
                "Unable to determine this file's descriptor type",
            )),
            (Some(first), 1) => Ok(first.clone()),
            _ => Err(Error::invalid_input(format!(
                "Unable to disambiguate file's descriptor type from among {}",
                self.types.join(", ")
            ))),
        }
    }

    pub async fn fetch(
        &self,
        base_url: &str,
        timeout: Option<Duration>,
        retries: u32,
    ) -> Result<Vec<u8>> {
        let content =
            download(&format!("{base_url}{}", self.path), timeout, retries).await?;
        let Some(expected) = &self.sha256 else {
            return Err(Error::DownloadFailed {
                url: self.path.clone(),
                message: "the CollecTor index provides no checksum".to_string(),
            });
        };
        match hash_matches(expected, &content) {
            true => Ok(content),
            false => Err(Error::DownloadFailed {
                url: self.path.clone(),
                message: "content mismatches the checksum in the CollecTor index"
                    .to_string(),
            }),
        }
    }

    pub async fn download_to(
        &self,
        base_url: &str,
        directory: &Path,
        timeout: Option<Duration>,
        retries: u32,
        overwrite: bool,
    ) -> Result<PathBuf> {
        let path = directory.join(self.file_name());
        std::fs::create_dir_all(directory)?;
        if let Some(prior) = read_regular_file(&path)? {
            let matches = self
                .sha256
                .as_deref()
                .is_some_and(|expected| hash_matches(expected, &prior));
            if matches {
                return Ok(path);
            }
            if !overwrite {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "{} already exists but mismatches CollecTor's checksum",
                        path.display()
                    ),
                )));
            }
        }
        let content = self.fetch(base_url, timeout, retries).await?;
        std::fs::write(&path, content)?;
        Ok(path)
    }

    pub async fn read(
        &self,
        base_url: &str,
        descriptor_type: Option<&str>,
        request: &CollectorRequest,
    ) -> Result<Vec<Descriptor>> {
        let descriptor_type = self.descriptor_type(descriptor_type)?;
        let raw = match &request.cache_to {
            Some(directory) => {
                let path = self
                    .download_to(
                        base_url,
                        directory,
                        request.timeout,
                        request.retries,
                        false,
                    )
                    .await?;
                std::fs::read(path)?
            }
            None => {
                self.fetch(base_url, request.timeout, request.retries)
                    .await?
            }
        };
        let parsed = parse_compressed(
            raw,
            None,
            None,
            request.validate,
            request.document_handler,
        )?;
        Ok(parsed
            .into_iter()
            .map(|file| file.descriptor)
            .filter(|descriptor| {
                descriptor_type.starts_with(&descriptor.type_annotation().name)
            })
            .filter(|descriptor| in_range(descriptor, request))
            .collect())
    }
}

fn read_regular_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(metadata) if !metadata.is_file() => Err(Error::invalid_input(format!(
            "{} exists but is not a regular file",
            path.display()
        ))),
        Ok(_) => Ok(Some(std::fs::read(path)?)),
    }
}

fn in_range(descriptor: &Descriptor, request: &CollectorRequest) -> bool {
    let Some(published) = descriptor.published() else {
        return true;
    };
    let before_start = request.start.is_some_and(|start| published < start);
    let after_end = request.end.is_some_and(|end| published > end);
    !before_start && !after_end
}

fn flatten_index(
    directory: IndexDirectory,
    path: &[String],
) -> Result<Vec<CollectorFile>> {
    let mut files = Vec::new();
    for entry in directory.files {
        let full_path = [path, std::slice::from_ref(&entry.path)].concat().join("/");
        files.push(CollectorFile::from_index(full_path, entry)?);
    }
    for child in directory.directories {
        let Some(name) = child.path.clone() else {
            continue;
        };
        let child_path = [path, &[name]].concat();
        files.extend(flatten_index(child, &child_path)?);
    }
    Ok(files)
}

pub fn parse_index(content: &[u8]) -> Result<Vec<CollectorFile>> {
    let root: IndexDirectory = serde_json::from_slice(content)
        .map_err(|error| Error::parse(format!("Invalid CollecTor index: {error}")))?;
    let mut files = flatten_index(root, &[])?;
    files.sort_by_key(|file| (file.start.is_none(), file.start));
    Ok(files)
}

struct CachedIndex {
    files: Vec<CollectorFile>,
    fetched_at: Instant,
}

pub struct CollecTor {
    base_url: String,
    retries: u32,
    timeout: Option<Duration>,
    cached: Mutex<Option<CachedIndex>>,
}

impl Default for CollecTor {
    fn default() -> Self {
        Self::new()
    }
}

impl CollecTor {
    pub fn new() -> Self {
        Self::with_url(COLLECTOR_URL)
    }

    pub fn with_url(base_url: &str) -> Self {
        let base_url = match base_url.ends_with('/') {
            true => base_url.to_string(),
            false => format!("{base_url}/"),
        };
        Self {
            base_url,
            retries: 2,
            timeout: None,
            cached: Mutex::new(None),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    pub fn shared() -> &'static CollecTor {
        &SHARED_COLLECTOR
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn fresh_files(&self) -> Option<Vec<CollectorFile>> {
        let cached = self
            .cached
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        cached
            .as_ref()
            .filter(|index| index.fetched_at.elapsed() < REFRESH_INDEX_RATE)
            .map(|index| index.files.clone())
    }

    pub async fn all_files(&self) -> Result<Vec<CollectorFile>> {
        if let Some(files) = self.fresh_files() {
            return Ok(files);
        }
        let compression = Compression::Lzma;
        let url = format!(
            "{}index/index.json{}",
            self.base_url,
            compression.extension()
        );
        let compressed = download(&url, self.timeout, self.retries).await?;
        let files = parse_index(&compression.decompress(&compressed)?)?;
        let mut cached = self
            .cached
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *cached = Some(CachedIndex {
            files: files.clone(),
            fetched_at: Instant::now(),
        });
        Ok(files)
    }

    pub async fn files(
        &self,
        descriptor_type: Option<&str>,
        start: Option<NaiveDateTime>,
        end: Option<NaiveDateTime>,
    ) -> Result<Vec<CollectorFile>> {
        Ok(self
            .all_files()
            .await?
            .into_iter()
            .filter(|file| {
                start.is_none_or(|start| file.end.is_some_and(|end| end >= start))
            })
            .filter(|file| {
                end.is_none_or(|end| file.start.is_some_and(|start| start <= end))
            })
            .filter(|file| {
                descriptor_type.is_none_or(|wanted| {
                    file.types
                        .iter()
                        .any(|candidate| candidate.starts_with(wanted))
                })
            })
            .collect())
    }

    async fn collect(
        &self,
        descriptor_type: &str,
        request: &CollectorRequest,
    ) -> Result<Vec<Descriptor>> {
        let mut descriptors = Vec::new();
        for file in self
            .files(Some(descriptor_type), request.start, request.end)
            .await?
        {
            descriptors.extend(
                file.read(&self.base_url, Some(descriptor_type), request)
                    .await?,
            );
        }
        Ok(descriptors)
    }

    pub async fn get_server_descriptors(
        &self,
        request: &CollectorRequest,
        bridge: bool,
    ) -> Result<Vec<Descriptor>> {
        match bridge {
            true => self.collect("bridge-server-descriptor", request).await,
            false => self.collect("server-descriptor", request).await,
        }
    }

    pub async fn get_extrainfo_descriptors(
        &self,
        request: &CollectorRequest,
        bridge: bool,
    ) -> Result<Vec<Descriptor>> {
        match bridge {
            true => self.collect("bridge-extra-info", request).await,
            false => self.collect("extra-info", request).await,
        }
    }

    pub async fn get_microdescriptors(
        &self,
        request: &CollectorRequest,
    ) -> Result<Vec<Descriptor>> {
        self.collect("microdescriptor", request).await
    }

    pub async fn get_consensus(
        &self,
        request: &CollectorRequest,
        version: u32,
        microdescriptor: bool,
        bridge: bool,
    ) -> Result<Vec<Descriptor>> {
        let descriptor_type = match (version, microdescriptor, bridge) {
            (_, _, true) => "bridge-network-status",
            (3, false, false) => "network-status-consensus-3",
            (3, true, false) => "network-status-microdesc-consensus-3",
            (2, false, false) => "network-status-2",
            (_, true, false) => {
                return Err(Error::invalid_input(format!(
                    "Only v3 microdescriptors are available (not version {version})"
                )));
            }
            _ => {
                return Err(Error::invalid_input(format!(
                    "Only v2 and v3 router status entries are available (not version \
                    {version})"
                )));
            }
        };
        self.collect(descriptor_type, request).await
    }

    pub async fn get_key_certificates(
        &self,
        request: &CollectorRequest,
    ) -> Result<Vec<Descriptor>> {
        self.collect("dir-key-certificate-3", request).await
    }

    pub async fn get_bandwidth_files(
        &self,
        request: &CollectorRequest,
    ) -> Result<Vec<Descriptor>> {
        self.collect("bandwidth-file", request).await
    }

    pub async fn get_exit_lists(
        &self,
        request: &CollectorRequest,
    ) -> Result<Vec<Descriptor>> {
        self.collect("tordnsel", request).await
    }
}
