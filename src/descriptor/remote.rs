use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::address::{DirPort, OrPort};
use crate::client::relay::Relay;
use crate::descriptor::network_status::{DetachedSignature, KeyCertificate};
use crate::descriptor::{Compression, Descriptor, DocumentHandler, parse_bytes};
use crate::directory::{Authority, Directory};
use crate::download::{USER_AGENT, download_with_headers};
use crate::enumerations::Flag;
use crate::error::{Error, Result};
use crate::validation::is_valid_fingerprint;

pub const MAX_FINGERPRINTS: usize = 96;
pub const MAX_MICRODESCRIPTOR_HASHES: usize = 90;
pub const DETACHED_SIGNATURE_TYPE: &str = "detached-signature";
const DIR_PORT_BLACKLIST: [&str; 2] = ["tor26", "Serge"];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RemoteEndpoint {
    Or(OrPort),
    Dir(DirPort),
}

impl RemoteEndpoint {
    pub fn dir(address: &str, port: u16) -> Result<Self> {
        Ok(Self::Dir(DirPort::new(address, port)?))
    }
}

#[derive(Debug, Clone)]
pub struct Query {
    pub resource: String,
    pub descriptor_type: String,
    pub endpoints: Vec<RemoteEndpoint>,
    pub compression: Vec<Compression>,
    pub retries: u32,
    pub fall_back_to_authority: bool,
    pub timeout: Option<Duration>,
    pub validate: bool,
    pub document_handler: DocumentHandler,
}

#[derive(Debug, Clone)]
pub struct QueryResult {
    pub content: Vec<u8>,
    pub reply_headers: std::collections::HashMap<String, String>,
    pub download_url: Option<String>,
    pub runtime: Duration,
}

fn guess_descriptor_type(resource: &str) -> Result<String> {
    let last_segment = resource.rsplit('/').next().unwrap_or_default();
    let guessed = if resource.starts_with("/tor/server/") {
        Some("server-descriptor 1.0")
    } else if resource.starts_with("/tor/extra/") {
        Some("extra-info 1.0")
    } else if resource.starts_with("/tor/micro/") {
        Some("microdescriptor 1.0")
    } else if resource.starts_with("/tor/keys/") {
        Some("dir-key-certificate-3 1.0")
    } else if resource.starts_with("/tor/status-vote/") {
        if resource.ends_with("/consensus") || resource.ends_with("/authority") {
            Some("network-status-consensus-3 1.0")
        } else if resource.ends_with("/consensus-microdesc") {
            Some("network-status-microdesc-consensus-3 1.0")
        } else if resource.ends_with("/consensus-signatures") {
            Some("detached-signature 1.0")
        } else if is_valid_fingerprint(last_segment, false) {
            Some("network-status-consensus-3 1.0")
        } else if resource.ends_with("/bandwidth") {
            Some("bandwidth-file 1.0")
        } else {
            None
        }
    } else {
        None
    };
    guessed.map(str::to_string).ok_or_else(|| {
        Error::invalid_input(format!(
            "Unable to determine the descriptor type for '{resource}'"
        ))
    })
}

fn pick<T>(items: &[T]) -> Result<&T> {
    match items.is_empty() {
        true => Err(Error::invalid_input(
            "There are no endpoints to download from",
        )),
        false => Ok(&items[(rand::random::<u64>() % items.len() as u64) as usize]),
    }
}

fn http_header_value(
    headers: &std::collections::HashMap<String, String>,
    name: &str,
) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

fn decompress(data: &[u8], encoding: Option<&str>) -> Result<Vec<u8>> {
    let encoding = encoding.unwrap_or("identity");
    match Compression::from_encoding(encoding) {
        Some(compression) => compression.decompress(data),
        None => Err(Error::invalid_input(format!(
            "'{encoding}' isn't a recognized type of encoding"
        ))),
    }
}

impl Query {
    pub fn new(resource: &str) -> Result<Self> {
        if !resource.starts_with('/') {
            return Err(Error::invalid_input(format!(
                "Resources should start with a '/': {resource}"
            )));
        }
        let (resource, compression) = match resource.strip_suffix(".z") {
            Some(stripped) => (stripped.to_string(), vec![Compression::Gzip]),
            None => (resource.to_string(), vec![Compression::Gzip]),
        };
        Ok(Self {
            descriptor_type: guess_descriptor_type(&resource)?,
            resource,
            endpoints: Vec::new(),
            compression,
            retries: 2,
            fall_back_to_authority: false,
            timeout: None,
            validate: false,
            document_handler: DocumentHandler::Entries,
        })
    }

    pub fn with_endpoints(mut self, endpoints: Vec<RemoteEndpoint>) -> Self {
        self.endpoints = endpoints;
        self
    }

    pub fn with_compression(mut self, compression: Vec<Compression>) -> Self {
        self.compression = match compression.is_empty() {
            true => vec![Compression::Plaintext],
            false => compression,
        };
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    pub fn with_validation(mut self, validate: bool) -> Self {
        self.validate = validate;
        self
    }

    pub fn with_document_handler(mut self, handler: DocumentHandler) -> Self {
        self.document_handler = handler;
        self
    }

    pub fn with_descriptor_type(mut self, descriptor_type: &str) -> Self {
        self.descriptor_type = descriptor_type.to_string();
        self
    }

    pub fn falling_back_to_authority(mut self) -> Self {
        self.fall_back_to_authority = true;
        self
    }

    fn pick_endpoint(&self, use_authority: bool) -> Result<RemoteEndpoint> {
        if use_authority || self.endpoints.is_empty() {
            let authorities: Vec<Authority> = Authority::from_cache()?
                .into_values()
                .filter(|authority| {
                    authority
                        .nickname
                        .as_deref()
                        .is_none_or(|name| !DIR_PORT_BLACKLIST.contains(&name))
                })
                .filter(|authority| authority.dir_port.is_some())
                .collect();
            let picked = pick(&authorities)?;
            return RemoteEndpoint::dir(&picked.address, picked.dir_port.unwrap_or(80));
        }
        pick(&self.endpoints).cloned()
    }

    async fn download_once(
        &self,
        endpoint: &RemoteEndpoint,
        timeout: Option<Duration>,
    ) -> Result<QueryResult> {
        let started = Instant::now();
        let accept_encoding = self
            .compression
            .iter()
            .map(|compression| compression.encoding())
            .collect::<Vec<_>>()
            .join(", ");
        match endpoint {
            RemoteEndpoint::Or(orport) => {
                let link_protocols: Vec<u32> =
                    orport.link_protocols.clone().unwrap_or_else(|| vec![3]);
                let relay =
                    Relay::connect(orport.address(), orport.port(), &link_protocols)
                        .await?;
                let mut circuit = relay.create_circuit().await?;
                let request = format!(
                    "GET {} HTTP/1.0\r\nAccept-Encoding: \
                    {accept_encoding}\r\nUser-Agent: {USER_AGENT}\r\n\r\n",
                    self.resource
                );
                let response = circuit.directory(request.as_bytes(), 1).await;
                let _ = circuit.close().await;
                relay.close().await;
                let (headers, body) = split_http_response(&response?)?;
                let content = decompress(
                    &body,
                    http_header_value(&headers, "Content-Encoding").as_deref(),
                )?;
                Ok(QueryResult {
                    content,
                    reply_headers: headers,
                    download_url: None,
                    runtime: started.elapsed(),
                })
            }
            RemoteEndpoint::Dir(dirport) => {
                let host = match dirport.address() {
                    IpAddr::V4(address) => address.to_string(),
                    IpAddr::V6(address) => format!("[{address}]"),
                };
                let url = format!(
                    "http://{host}:{}/{}",
                    dirport.port(),
                    self.resource.trim_start_matches('/')
                );
                let (body, headers) = download_with_headers(
                    &url,
                    &[
                        ("Accept-Encoding", &accept_encoding),
                        ("User-Agent", USER_AGENT),
                    ],
                    timeout,
                    0,
                )
                .await?;
                let content = decompress(
                    &body,
                    http_header_value(&headers, "content-encoding").as_deref(),
                )?;
                Ok(QueryResult {
                    content,
                    reply_headers: headers,
                    download_url: Some(url),
                    runtime: started.elapsed(),
                })
            }
        }
    }

    pub async fn download(&self) -> Result<QueryResult> {
        let started = Instant::now();
        let mut retries = self.retries;
        let mut timeout = self.timeout;
        loop {
            let endpoint =
                self.pick_endpoint(retries == 0 && self.fall_back_to_authority)?;
            match self.download_once(&endpoint, timeout).await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    if let Some(limit) = timeout {
                        timeout = Some(limit.saturating_sub(started.elapsed()));
                    }
                    let exhausted =
                        retries == 0 || timeout.is_some_and(|limit| limit.is_zero());
                    log::debug!(
                        "Unable to download descriptors ({retries} retries remaining): \
                        {error}"
                    );
                    if exhausted {
                        return Err(error);
                    }
                    retries -= 1;
                }
            }
        }
    }

    pub async fn run(&self) -> Result<Vec<Descriptor>> {
        let result = self.download().await?;
        self.parse(&result.content)
    }

    pub fn parse(&self, content: &[u8]) -> Result<Vec<Descriptor>> {
        if self.descriptor_type.starts_with(DETACHED_SIGNATURE_TYPE) {
            return Ok(DetachedSignature::parse_many(content, self.validate)?
                .into_iter()
                .map(|signature| Descriptor::DetachedSignature(Box::new(signature)))
                .collect());
        }
        parse_bytes(
            content,
            Some(&self.descriptor_type),
            self.validate,
            self.document_handler,
            None,
        )
    }
}

fn split_http_response(
    response: &[u8],
) -> Result<(std::collections::HashMap<String, String>, Vec<u8>)> {
    let first_end = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| Error::protocol("The directory response had no status line"))?;
    let first_line = String::from_utf8_lossy(&response[..first_end]).into_owned();
    let rest = &response[first_end + 2..];
    let header_end = rest
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            Error::protocol("The directory response had no header terminator")
        })?;
    if !first_line.starts_with("HTTP/1.0 2") && !first_line.starts_with("HTTP/1.1 2") {
        return Err(Error::protocol(format!(
            "Response should begin with HTTP success, but was '{first_line}'"
        )));
    }
    let mut headers = std::collections::HashMap::new();
    for line in String::from_utf8_lossy(&rest[..header_end]).lines() {
        let Some((key, value)) = line.split_once(": ") else {
            return Err(Error::protocol(format!("'{line}' is not a HTTP header")));
        };
        headers.insert(key.to_string(), value.to_string());
    }
    Ok((headers, rest[header_end + 4..].to_vec()))
}

#[derive(Debug, Clone, Default)]
pub struct DescriptorDownloader {
    endpoints: Vec<RemoteEndpoint>,
    pub default_timeout: Option<Duration>,
    pub default_validate: bool,
}

impl DescriptorDownloader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_endpoints(&mut self, endpoints: Vec<RemoteEndpoint>) {
        self.endpoints = endpoints;
    }

    pub async fn use_directory_mirrors(&mut self) -> Result<()> {
        let mut endpoints: indexmap::IndexSet<(String, u16)> = Authority::from_cache()?
            .values()
            .filter(|authority| {
                authority
                    .nickname
                    .as_deref()
                    .is_none_or(|name| !DIR_PORT_BLACKLIST.contains(&name))
            })
            .filter_map(|authority| {
                Some((authority.address.clone(), authority.dir_port?))
            })
            .collect();
        let query = self
            .get_consensus(None, false)
            .with_document_handler(DocumentHandler::Document);
        for descriptor in query.run().await? {
            if let Descriptor::NetworkStatusV3(document) = descriptor {
                for entry in document.routers.values() {
                    let common = entry.common();
                    if common
                        .flags
                        .iter()
                        .any(|flag| *flag == Flag::V2Dir.as_str())
                        && let (Some(address), Some(port)) =
                            (&common.address, common.dir_port)
                    {
                        endpoints.insert((address.clone(), port));
                    }
                }
            }
        }
        self.endpoints = endpoints
            .into_iter()
            .map(|(address, port)| RemoteEndpoint::dir(&address, port))
            .collect::<Result<_>>()?;
        Ok(())
    }

    pub fn query(&self, resource: &str) -> Result<Query> {
        let mut query = Query::new(resource)?.with_endpoints(self.endpoints.clone());
        query.timeout = self.default_timeout;
        query.validate = self.default_validate;
        Ok(query)
    }

    fn fixed(&self, resource: &str) -> Query {
        self.query(resource).expect("fixed resources are valid")
    }

    pub fn their_server_descriptor(&self) -> Query {
        self.fixed("/tor/server/authority")
    }

    pub fn get_server_descriptors(&self, fingerprints: &[&str]) -> Result<Query> {
        self.by_fingerprints("/tor/server", fingerprints)
    }

    pub fn get_extrainfo_descriptors(&self, fingerprints: &[&str]) -> Result<Query> {
        self.by_fingerprints("/tor/extra", fingerprints)
    }

    fn by_fingerprints(&self, prefix: &str, fingerprints: &[&str]) -> Result<Query> {
        if fingerprints.len() > MAX_FINGERPRINTS {
            return Err(Error::invalid_input(format!(
                "Unable to request more than {MAX_FINGERPRINTS} descriptors at a time \
                by their fingerprints"
            )));
        }
        for fingerprint in fingerprints {
            if !is_valid_fingerprint(fingerprint, false) {
                return Err(Error::invalid_input(format!(
                    "'{fingerprint}' isn't a valid fingerprint"
                )));
            }
        }
        match fingerprints.is_empty() {
            true => self.query(&format!("{prefix}/all")),
            false => self.query(&format!("{prefix}/fp/{}", fingerprints.join("+"))),
        }
    }

    pub fn get_microdescriptors(&self, hashes: &[&str]) -> Result<Query> {
        if hashes.len() > MAX_MICRODESCRIPTOR_HASHES {
            return Err(Error::invalid_input(format!(
                "Unable to request more than {MAX_MICRODESCRIPTOR_HASHES} \
                microdescriptors at a time by their hashes"
            )));
        }
        for hash in hashes {
            let is_safe = !hash.is_empty()
                && hash.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
                });
            if !is_safe {
                return Err(Error::invalid_input(format!(
                    "'{hash}' isn't a valid microdescriptor hash"
                )));
            }
        }
        self.query(&format!("/tor/micro/d/{}", hashes.join("-")))
    }

    pub fn get_consensus(
        &self,
        authority_v3ident: Option<&str>,
        microdescriptor: bool,
    ) -> Query {
        let mut resource = match microdescriptor {
            true => "/tor/status-vote/current/consensus-microdesc".to_string(),
            false => "/tor/status-vote/current/consensus".to_string(),
        };
        if let Some(ident) =
            authority_v3ident.filter(|ident| is_valid_fingerprint(ident, false))
        {
            resource.push_str(&format!("/{ident}"));
        }
        self.fixed(&resource)
    }

    pub async fn get_consensus_validated(
        &self,
        authority_v3ident: Option<&str>,
        microdescriptor: bool,
    ) -> Result<Vec<Descriptor>> {
        let query = self
            .get_consensus(authority_v3ident, microdescriptor)
            .with_validation(true);
        let query = query.with_document_handler(DocumentHandler::Document);
        let descriptors = query.run().await?;
        let certificates = self.get_key_certificates(&[])?.run().await?;
        let key_certificates: Vec<KeyCertificate> = certificates
            .into_iter()
            .filter_map(|descriptor| match descriptor {
                Descriptor::KeyCertificate(certificate) => Some(*certificate),
                _ => None,
            })
            .collect();
        for descriptor in &descriptors {
            if let Descriptor::NetworkStatusV3(document) = descriptor {
                document.validate_signatures(&key_certificates)?;
            }
        }
        Ok(descriptors)
    }

    pub fn get_vote(&self, authority: &Directory) -> Result<Query> {
        let endpoint =
            RemoteEndpoint::dir(&authority.address, authority.dir_port.unwrap_or(80))?;
        Ok(self
            .fixed("/tor/status-vote/current/authority")
            .with_endpoints(vec![endpoint]))
    }

    pub fn get_key_certificates(&self, authority_v3idents: &[&str]) -> Result<Query> {
        if authority_v3idents.len() > MAX_FINGERPRINTS {
            return Err(Error::invalid_input(format!(
                "Unable to request more than {MAX_FINGERPRINTS} key certificates at a \
                time by their identity fingerprints"
            )));
        }
        match authority_v3idents.is_empty() {
            true => self.query("/tor/keys/all"),
            false => {
                self.query(&format!("/tor/keys/fp/{}", authority_v3idents.join("+")))
            }
        }
    }

    pub fn get_bandwidth_file(&self) -> Query {
        self.fixed("/tor/status-vote/next/bandwidth")
    }

    pub fn get_detached_signatures(&self) -> Query {
        self.fixed("/tor/status-vote/next/consensus-signatures")
    }
}

pub fn get_authorities() -> Result<indexmap::IndexMap<String, Authority>> {
    Authority::from_cache()
}
