use std::io::Read;
use std::path::{Path, PathBuf};

use crate::descriptor::bandwidth_file::BandwidthFile;
use crate::descriptor::extrainfo::{BridgeExtraInfoDescriptor, RelayExtraInfoDescriptor};
use crate::descriptor::hidden_service::{
    HiddenServiceDescriptorV2, HiddenServiceDescriptorV3,
};
use crate::descriptor::microdescriptor::Microdescriptor;
use crate::descriptor::network_status::{
    BridgeNetworkStatusDocument, DetachedSignature, KeyCertificate,
    NetworkStatusDocumentV2, NetworkStatusDocumentV3, RouterEntry,
};
use crate::descriptor::router_status::RouterStatusEntryV2;
use crate::descriptor::server::{BridgeServerDescriptor, RelayServerDescriptor};
use crate::descriptor::tordnsel::TorDnsel;
use crate::descriptor::{Compression, TypeAnnotation};
use crate::error::{Error, Result};
use crate::process_inspection::is_tarfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentHandler {
    Entries,
    Document,
    BareDocument,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum Descriptor {
    RelayServer(Box<RelayServerDescriptor>),
    BridgeServer(Box<BridgeServerDescriptor>),
    RelayExtraInfo(Box<RelayExtraInfoDescriptor>),
    BridgeExtraInfo(Box<BridgeExtraInfoDescriptor>),
    Microdescriptor(Box<Microdescriptor>),
    RouterStatusEntryV2(Box<RouterStatusEntryV2>),
    RouterEntry(Box<RouterEntry>),
    NetworkStatusV2(Box<NetworkStatusDocumentV2>),
    NetworkStatusV3(Box<NetworkStatusDocumentV3>),
    BridgeNetworkStatus(Box<BridgeNetworkStatusDocument>),
    KeyCertificate(Box<KeyCertificate>),
    DetachedSignature(Box<DetachedSignature>),
    TorDnsel(Box<TorDnsel>),
    HiddenServiceV2(Box<HiddenServiceDescriptorV2>),
    HiddenServiceV3(Box<HiddenServiceDescriptorV3>),
    BandwidthFile(Box<BandwidthFile>),
}

impl Descriptor {
    pub fn type_annotation(&self) -> TypeAnnotation {
        let name = match self {
            Self::RelayServer(_) => "server-descriptor",
            Self::BridgeServer(_) => "bridge-server-descriptor",
            Self::RelayExtraInfo(_) => "extra-info",
            Self::BridgeExtraInfo(_) => "bridge-extra-info",
            Self::Microdescriptor(_) => "microdescriptor",
            Self::RouterStatusEntryV2(_) => "network-status-consensus-2",
            Self::RouterEntry(entry) => match **entry {
                RouterEntry::Full(_) => "network-status-consensus-3",
                RouterEntry::Micro(_) => "network-status-microdesc-consensus-3",
            },
            Self::NetworkStatusV2(_) => "network-status-2",
            Self::NetworkStatusV3(document) => {
                match (document.is_microdescriptor, document.is_vote) {
                    (true, _) => "network-status-microdesc-consensus-3",
                    (false, true) => "network-status-vote-3",
                    (false, false) => "network-status-consensus-3",
                }
            }
            Self::BridgeNetworkStatus(_) => "bridge-network-status",
            Self::KeyCertificate(_) => "dir-key-certificate-3",
            Self::DetachedSignature(_) => "detached-signature-3",
            Self::TorDnsel(_) => "tordnsel",
            Self::HiddenServiceV2(_) => "hidden-service-descriptor",
            Self::HiddenServiceV3(_) => "hidden-service-descriptor-3",
            Self::BandwidthFile(_) => "bandwidth-file",
        };
        TypeAnnotation {
            name: name.to_string(),
            major_version: 1,
            minor_version: 0,
        }
    }

    pub fn published(&self) -> Option<chrono::NaiveDateTime> {
        match self {
            Self::RelayServer(descriptor) => descriptor.published,
            Self::BridgeServer(descriptor) => descriptor.published,
            Self::RelayExtraInfo(descriptor) => descriptor.published,
            Self::BridgeExtraInfo(descriptor) => descriptor.published,
            Self::RouterEntry(entry) => entry.common().published,
            Self::RouterStatusEntryV2(entry) => entry.published,
            Self::NetworkStatusV2(document) => document.published,
            Self::NetworkStatusV3(document) => document.published,
            Self::BridgeNetworkStatus(document) => document.published,
            Self::HiddenServiceV2(descriptor) => descriptor.published,
            Self::TorDnsel(descriptor) => descriptor.published,
            Self::KeyCertificate(certificate) => certificate.published,
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedFile {
    pub descriptor: Descriptor,
    pub path: Option<PathBuf>,
    pub archive_path: Option<String>,
}

fn parse_type(descriptor_type: &str) -> Result<(String, u32, u32)> {
    let invalid = || {
        Error::invalid_input(
            "The descriptor_type must be of the form '<type> \
            <major_version>.<minor_version>'",
        )
    };
    let (name, version) = descriptor_type.split_once(' ').ok_or_else(invalid)?;
    let (major, minor) = version.split_once('.').ok_or_else(invalid)?;
    Ok((
        name.to_string(),
        major.parse().map_err(|_| invalid())?,
        minor.parse().map_err(|_| invalid())?,
    ))
}

fn boxed<T, U>(items: Vec<T>, wrap: impl Fn(Box<T>) -> U) -> Vec<U> {
    items.into_iter().map(|item| wrap(Box::new(item))).collect()
}

fn parse_metrics(
    name: &str,
    major: u32,
    minor: u32,
    content: &[u8],
    validate: bool,
    handler: DocumentHandler,
) -> Result<Vec<Descriptor>> {
    if major != 1 {
        return Err(Error::invalid_input(format!(
            "Unrecognized metrics descriptor format. type: '{name}', version: \
            '{major}.{minor}'"
        )));
    }
    Ok(match name {
        "server-descriptor" => boxed(
            RelayServerDescriptor::parse_many(content, validate)?,
            Descriptor::RelayServer,
        ),
        "bridge-server-descriptor" => boxed(
            BridgeServerDescriptor::parse_many(content, validate)?,
            Descriptor::BridgeServer,
        ),
        "extra-info" => boxed(
            RelayExtraInfoDescriptor::parse_many(content, validate)?,
            Descriptor::RelayExtraInfo,
        ),
        "bridge-extra-info" => boxed(
            BridgeExtraInfoDescriptor::parse_many(content, validate)?,
            Descriptor::BridgeExtraInfo,
        ),
        "microdescriptor" => boxed(
            Microdescriptor::parse_many(content, validate)?,
            Descriptor::Microdescriptor,
        ),
        "network-status-2" => match handler {
            DocumentHandler::Entries => {
                let document = NetworkStatusDocumentV2::parse(content, validate)?;
                document
                    .routers
                    .into_values()
                    .map(|entry| Descriptor::RouterStatusEntryV2(Box::new(entry)))
                    .collect()
            }
            _ => vec![Descriptor::NetworkStatusV2(Box::new(
                NetworkStatusDocumentV2::parse(content, validate)?,
            ))],
        },
        "dir-key-certificate-3" => boxed(
            KeyCertificate::parse_many(content, validate)?,
            Descriptor::KeyCertificate,
        ),
        "network-status-consensus-3" | "network-status-vote-3" => {
            parse_v3_documents(content, validate, handler, false)?
        }
        "network-status-microdesc-consensus-3" => {
            parse_v3_documents(content, validate, handler, true)?
        }
        "bridge-network-status" => match handler {
            DocumentHandler::Entries => {
                BridgeNetworkStatusDocument::parse(content, validate)?
                    .routers
                    .into_values()
                    .map(|entry| Descriptor::RouterStatusEntryV2(Box::new(entry)))
                    .collect()
            }
            _ => vec![Descriptor::BridgeNetworkStatus(Box::new(
                BridgeNetworkStatusDocument::parse(content, validate)?,
            ))],
        },
        "detached-signature-3" => vec![Descriptor::DetachedSignature(Box::new(
            DetachedSignature::parse(content, validate)?,
        ))],
        "tordnsel" => boxed(
            TorDnsel::parse_many(content, validate)?,
            Descriptor::TorDnsel,
        ),
        "hidden-service-descriptor" => boxed(
            HiddenServiceDescriptorV2::parse_many(content, validate)?,
            Descriptor::HiddenServiceV2,
        ),
        "hidden-service-descriptor-3" => boxed(
            HiddenServiceDescriptorV3::parse_many(content, validate)?,
            Descriptor::HiddenServiceV3,
        ),
        "bandwidth-file" => vec![Descriptor::BandwidthFile(Box::new(
            BandwidthFile::parse(content, validate)?,
        ))],
        other => {
            return Err(Error::invalid_input(format!(
                "Unrecognized metrics descriptor format. type: '{other}', version: \
                '{major}.{minor}'"
            )));
        }
    })
}

fn parse_v3_documents(
    content: &[u8],
    validate: bool,
    handler: DocumentHandler,
    is_microdescriptor: bool,
) -> Result<Vec<Descriptor>> {
    match handler {
        DocumentHandler::Document => {
            let document = NetworkStatusDocumentV3::parse(content, validate)?;
            Ok(vec![Descriptor::NetworkStatusV3(Box::new(document))])
        }
        DocumentHandler::BareDocument => {
            let split = bare_document_content(content);
            let document = NetworkStatusDocumentV3::parse(&split, validate)?;
            Ok(vec![Descriptor::NetworkStatusV3(Box::new(document))])
        }
        DocumentHandler::Entries => Ok(NetworkStatusDocumentV3::parse_routers(
            content,
            validate,
            is_microdescriptor,
        )?
        .into_iter()
        .map(|entry| Descriptor::RouterEntry(Box::new(entry)))
        .collect()),
    }
}

fn bare_document_content(content: &[u8]) -> Vec<u8> {
    let mut cursor = crate::descriptor::LineCursor::new(content);
    let mut header = cursor
        .read_until_keywords(
            &["r", "directory-footer", "directory-signature"],
            Default::default(),
        )
        .content;
    if header.starts_with(b"@type") {
        header = header
            .splitn(2, |byte| *byte == b'\n')
            .nth(1)
            .unwrap_or_default()
            .to_vec();
    }
    cursor.read_until_keywords(
        &["directory-footer", "directory-signature"],
        Default::default(),
    );
    [header.as_slice(), cursor.remaining()].concat()
}

pub fn parse_bytes(
    content: &[u8],
    descriptor_type: Option<&str>,
    validate: bool,
    handler: DocumentHandler,
    file_name: Option<&str>,
) -> Result<Vec<Descriptor>> {
    let first_end = content
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(content.len(), |index| index + 1);
    let first_line = String::from_utf8_lossy(&content[..first_end])
        .trim()
        .to_string();
    let annotation = TypeAnnotation::parse(&first_line);
    let body = match annotation {
        Some(_) => &content[first_end..],
        None => content,
    };
    if let Some(descriptor_type) = descriptor_type {
        let (name, major, minor) = parse_type(descriptor_type)?;
        return parse_metrics(&name, major, minor, body, validate, handler);
    }
    if let Some(annotation) = annotation {
        return parse_metrics(
            &annotation.name,
            annotation.major_version,
            annotation.minor_version,
            body,
            validate,
            handler,
        );
    }
    let name = file_name.unwrap_or("<undefined>");
    match name {
        "cached-descriptors" | "cached-descriptors.new" => Ok(boxed(
            RelayServerDescriptor::parse_many(content, validate)?,
            Descriptor::RelayServer,
        )),
        "cached-extrainfo" | "cached-extrainfo.new" => Ok(boxed(
            RelayExtraInfoDescriptor::parse_many(content, validate)?,
            Descriptor::RelayExtraInfo,
        )),
        "cached-microdescs" | "cached-microdescs.new" => Ok(boxed(
            Microdescriptor::parse_many(content, validate)?,
            Descriptor::Microdescriptor,
        )),
        "cached-consensus" => parse_v3_documents(content, validate, handler, false),
        "cached-microdesc-consensus" => {
            parse_v3_documents(content, validate, handler, true)
        }
        _ => Err(Error::invalid_input(format!(
            "Unable to determine the descriptor's type. filename: '{name}', first line: \
            '{first_line}'"
        ))),
    }
}

fn decompress_archive(content: Vec<u8>) -> Result<Vec<u8>> {
    let compression = match content.as_slice() {
        [0x1f, 0x8b, ..] => Compression::Gzip,
        [b'B', b'Z', b'h', ..] => Compression::Bzip2,
        [0xfd, b'7', b'z', b'X', b'Z', 0x00, ..] => Compression::Lzma,
        [0x28, 0xb5, 0x2f, 0xfd, ..] => Compression::Zstd,
        _ => return Ok(content),
    };
    compression.decompress(&content)
}

pub fn parse_path(
    path: &Path,
    descriptor_type: Option<&str>,
    validate: bool,
    handler: DocumentHandler,
) -> Result<Vec<ParsedFile>> {
    let raw = std::fs::read(path)?;
    parse_compressed(raw, Some(path), descriptor_type, validate, handler)
}

pub fn parse_compressed(
    raw: Vec<u8>,
    path: Option<&Path>,
    descriptor_type: Option<&str>,
    validate: bool,
    handler: DocumentHandler,
) -> Result<Vec<ParsedFile>> {
    let content = decompress_archive(raw)?;
    let absolute = path
        .map(|path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()));
    let is_archive = is_tarfile_bytes(&content) || path.is_some_and(is_tarfile);
    if !is_archive {
        let file_name = path
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str());
        return Ok(
            parse_bytes(&content, descriptor_type, validate, handler, file_name)?
                .into_iter()
                .map(|descriptor| ParsedFile {
                    descriptor,
                    path: absolute.clone(),
                    archive_path: None,
                })
                .collect(),
        );
    }
    let mut results = Vec::new();
    let mut archive = tar::Archive::new(content.as_slice());
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() || entry.size() == 0 {
            continue;
        }
        let archive_path = entry.path()?.to_string_lossy().into_owned();
        let mut body = Vec::new();
        entry
            .by_ref()
            .take(crate::descriptor::MAX_DECOMPRESSED_LENGTH)
            .read_to_end(&mut body)?;
        let name = archive_path.rsplit('/').next();
        for descriptor in parse_bytes(&body, descriptor_type, validate, handler, name)? {
            results.push(ParsedFile {
                descriptor,
                path: absolute.clone(),
                archive_path: Some(archive_path.clone()),
            });
        }
    }
    Ok(results)
}

fn is_tarfile_bytes(content: &[u8]) -> bool {
    content.len() >= 512 && &content[257..262] == b"ustar"
}
