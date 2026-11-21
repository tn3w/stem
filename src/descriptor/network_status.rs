use std::cmp::Ordering;

use chrono::{NaiveDateTime, Utc};
use indexmap::IndexMap;
use sha1::{Digest, Sha1};

use crate::address::{is_valid_ipv4_address, parse_port};
use crate::descriptor::router_status::{
    DocumentContext, RouterStatusEntryCommon, RouterStatusEntryMicroV3,
    RouterStatusEntryV2, RouterStatusEntryV3, parse_entry_section,
};
use crate::descriptor::server::digest_for_signature;
use crate::descriptor::{
    AttrValue, Attributes, DigestEncoding, DigestHash, Entries, LineCursor, Protocols,
    ReadOptions, attr, content_range, descriptor_components, descriptor_content,
    encode_digest, hash_bytes, key_block, lenient, lenient_option, mappings_for,
    parse_forty_hex, parse_protocol_line, parse_timestamp_line, random_crypto_blob,
    random_date, random_fingerprint, random_ipv4_address, random_nickname,
};
use crate::error::{Error, Result};
use crate::formatting::parse_timestamp;
use crate::validation::{is_valid_fingerprint, is_valid_nickname};
use crate::version::Version;

const AUTH_START: &str = "dir-source";
const ROUTERS_START: &str = "r";
const FOOTER_START: &str = "directory-footer";
const V2_FOOTER_START: &str = "directory-signature";

const NETWORK_STATUS_V2_FIELDS: [(&str, bool); 10] = [
    ("network-status-version", true),
    ("dir-source", true),
    ("fingerprint", true),
    ("contact", true),
    ("dir-signing-key", true),
    ("client-versions", false),
    ("server-versions", false),
    ("published", true),
    ("dir-options", false),
    ("directory-signature", true),
];

struct HeaderField(&'static str, bool, bool, bool);

const HEADER_FIELDS: [HeaderField; 25] = [
    HeaderField("network-status-version", true, true, true),
    HeaderField("vote-status", true, true, true),
    HeaderField("consensus-methods", true, false, false),
    HeaderField("consensus-method", false, true, false),
    HeaderField("published", true, false, true),
    HeaderField("valid-after", true, true, true),
    HeaderField("fresh-until", true, true, true),
    HeaderField("valid-until", true, true, true),
    HeaderField("voting-delay", true, true, true),
    HeaderField("client-versions", true, true, false),
    HeaderField("server-versions", true, true, false),
    HeaderField("package", true, true, false),
    HeaderField("known-flags", true, true, true),
    HeaderField("flag-thresholds", true, false, false),
    HeaderField("shared-rand-participate", true, false, false),
    HeaderField("shared-rand-commit", true, false, false),
    HeaderField("shared-rand-previous-value", true, true, false),
    HeaderField("shared-rand-current-value", true, true, false),
    HeaderField("bandwidth-file-headers", true, false, false),
    HeaderField("bandwidth-file-digest", true, false, false),
    HeaderField("recommended-client-protocols", true, true, false),
    HeaderField("recommended-relay-protocols", true, true, false),
    HeaderField("required-client-protocols", true, true, false),
    HeaderField("required-relay-protocols", true, true, false),
    HeaderField("params", true, true, false),
];

const FOOTER_FIELDS: [HeaderField; 3] = [
    HeaderField("directory-footer", true, true, false),
    HeaderField("bandwidth-weights", false, true, false),
    HeaderField("directory-signature", true, true, true),
];

const KEY_CERTIFICATE_PARAMS: [(&str, bool); 9] = [
    ("dir-key-certificate-version", true),
    ("dir-address", false),
    ("fingerprint", true),
    ("dir-identity-key", true),
    ("dir-key-published", true),
    ("dir-key-expires", true),
    ("dir-signing-key", true),
    ("dir-key-crosscert", false),
    ("dir-key-certification", true),
];

const DETACHED_SIGNATURE_PARAMS: [(&str, bool, bool); 7] = [
    ("consensus-digest", true, false),
    ("valid-after", true, false),
    ("fresh-until", true, false),
    ("valid-until", true, false),
    ("additional-digest", false, true),
    ("additional-signature", false, true),
    ("directory-signature", false, true),
];

const DEFAULT_PARAMS: [(&str, i64); 24] = [
    ("bwweightscale", 10000),
    ("cbtdisabled", 0),
    ("cbtnummodes", 3),
    ("cbtrecentcount", 20),
    ("cbtmaxtimeouts", 18),
    ("cbtmincircs", 100),
    ("cbtquantile", 80),
    ("cbtclosequantile", 95),
    ("cbttestfreq", 60),
    ("cbtmintimeout", 2000),
    ("cbtinitialtimeout", 60000),
    ("cbtlearntimeout", 180),
    ("cbtmaxopencircs", 10),
    ("UseOptimisticData", 1),
    ("Support022HiddenServices", 1),
    ("usecreatefast", 1),
    ("max-consensuses-age-to-cache-for-diff", 72),
    ("try-diff-for-consensus-newer-than", 72),
    ("onion-key-rotation-days", 28),
    ("onion-key-grace-period-days", 7),
    ("hs_service_max_rdv_failures", 2),
    ("circ_max_cell_queue_size", 50000),
    ("circpad_max_circ_queued_cells", 1000),
    ("HiddenServiceEnableIntroDoSDefense", 0),
];

const MIN_PARAM: i64 = -2147483648;
const MAX_PARAM: i64 = 2147483647;

fn param_range(key: &str) -> (i64, i64) {
    match key {
        "circwindow" => (100, 1000),
        "CircuitPriorityHalflifeMsec" | "perconnbwrate" | "perconnbwburst" => {
            (-1, MAX_PARAM)
        }
        "refuseunknownexits"
        | "cbtdisabled"
        | "UseOptimisticData"
        | "Support022HiddenServices"
        | "usecreatefast"
        | "UseNTorHandshake"
        | "AllowNonearlyExtend"
        | "HiddenServiceEnableIntroDoSDefense" => (0, 1),
        "bwweightscale" | "cbttestfreq" | "AuthDirNumSRVAgreements" => (1, MAX_PARAM),
        "cbtnummodes" => (1, 20),
        "cbtrecentcount" => (3, 1000),
        "cbtmaxtimeouts" => (3, 10000),
        "cbtmincircs" => (1, 10000),
        "cbtquantile" => (10, 99),
        "cbtclosequantile" => (MIN_PARAM, 99),
        "cbtmintimeout" => (500, MAX_PARAM),
        "cbtlearntimeout" => (10, 60000),
        "cbtmaxopencircs" => (0, 14),
        "FastFlagMinThreshold" => (4, MAX_PARAM),
        "NumDirectoryGuards" => (0, 10),
        "NumEntryGuards" => (1, 10),
        "GuardLifetime" => (2592000, 157766400),
        "NumNTorsPerTAP" => (1, 100000),
        "max-consensuses-age-to-cache-for-diff" | "try-diff-for-consensus-newer-than" => {
            (0, 8192)
        }
        "onion-key-rotation-days" | "onion-key-grace-period-days" => (1, 90),
        "hs_service_max_rdv_failures" => (1, 10),
        "circ_max_cell_queue_size" => (1000, 4294967295),
        "circpad_max_circ_queued_cells" => (0, 50000),
        _ => (MIN_PARAM, MAX_PARAM),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PackageVersion {
    pub name: String,
    pub version: String,
    pub url: String,
    pub digests: IndexMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SharedRandomnessCommitment {
    pub version: u32,
    pub algorithm: String,
    pub identity: String,
    pub commit: String,
    pub reveal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DocumentDigest {
    pub flavor: String,
    pub algorithm: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DocumentSignature {
    pub method: String,
    pub identity: String,
    pub key_digest: String,
    pub signature: String,
    pub flavor: Option<String>,
}

impl DocumentSignature {
    pub fn new(
        method: &str,
        identity: &str,
        key_digest: &str,
        signature: &str,
        flavor: Option<&str>,
        validate: bool,
    ) -> Result<Self> {
        if validate {
            if !is_valid_fingerprint(identity, false) {
                return Err(Error::parse(format!(
                    "Malformed fingerprint ({identity}) in the document signature"
                )));
            }
            if !is_valid_fingerprint(key_digest, false) {
                return Err(Error::parse(format!(
                    "Malformed key digest ({key_digest}) in the document signature"
                )));
            }
        }
        Ok(Self {
            method: method.to_string(),
            identity: identity.to_string(),
            key_digest: key_digest.to_string(),
            signature: signature.to_string(),
            flavor: flavor.map(str::to_string),
        })
    }
}

impl PartialOrd for DocumentSignature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            (
                &self.method,
                &self.identity,
                &self.key_digest,
                &self.signature,
                &self.flavor,
            )
                .cmp(&(
                    &other.method,
                    &other.identity,
                    &other.key_digest,
                    &other.signature,
                    &other.flavor,
                )),
        )
    }
}

fn parse_version_line(entries: &Entries, keyword: &str, expected: u32) -> Result<u32> {
    let value = entries.value(keyword)?;
    let version: u32 = value
        .parse()
        .ok()
        .filter(|_| value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| {
            Error::parse(format!(
                "Document has a non-numeric version: {keyword} {value}"
            ))
        })?;
    match version == expected {
        true => Ok(version),
        false => Err(Error::parse(format!(
            "Expected a version {expected} document, but got version '{value}' instead"
        ))),
    }
}

fn parse_int_mappings(
    keyword: &str,
    value: &str,
    validate: bool,
) -> Result<IndexMap<String, i64>> {
    let mut results = IndexMap::new();
    let mut seen: Vec<String> = Vec::new();
    let template = |reason: &str| {
        format!(
            "Unable to parse network status document's '{keyword}' line ({reason}): \
            {value}'"
        )
    };
    for (key, mapped) in mappings_for(keyword, value, false, ' ')? {
        if validate && seen.iter().any(|prior| *prior > key) {
            return Err(Error::parse(template(
                "parameters must be sorted by their key",
            )));
        }
        if mapped.starts_with('+') {
            return Err(Error::parse(template(&format!(
                "'{mapped}' is a non-numeric value"
            ))));
        }
        let number = mapped.parse::<i64>().map_err(|_| {
            Error::parse(template(&format!("'{mapped}' is a non-numeric value")))
        })?;
        seen.push(key.clone());
        results.insert(key, number);
    }
    Ok(results)
}

fn unsigned(text: &str) -> Option<u32> {
    match !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) {
        true => text.parse().ok(),
        false => None,
    }
}

fn parse_packages(entries: &Entries) -> Result<Vec<PackageVersion>> {
    let mut packages = Vec::new();
    for value in entries.values("package") {
        let parts: Vec<&str> = value.splitn(4, ' ').collect();
        if parts.len() < 3 {
            return Err(Error::parse(format!(
                "'package' must at least have a 'PackageName Version URL': {value}"
            )));
        }
        let digests = match parts.get(3) {
            Some(rest) => mappings_for("package", rest, false, ' ')?
                .into_iter()
                .collect(),
            None => IndexMap::new(),
        };
        packages.push(PackageVersion {
            name: parts[0].to_string(),
            version: parts[1].to_string(),
            url: parts[2].to_string(),
            digests,
        });
    }
    Ok(packages)
}

fn parse_shared_rand_commits(
    entries: &Entries,
) -> Result<Vec<SharedRandomnessCommitment>> {
    let mut commitments = Vec::new();
    for value in entries.values("shared-rand-commit") {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(Error::parse(format!(
                "'shared-rand-commit' must at least have a 'Version AlgName Identity \
                Commit': {value}"
            )));
        }
        let version = unsigned(parts[0]).ok_or_else(|| {
            Error::parse(format!(
                "The version on our 'shared-rand-commit' line wasn't an integer: {value}"
            ))
        })?;
        commitments.push(SharedRandomnessCommitment {
            version,
            algorithm: parts[1].to_string(),
            identity: parts[2].to_string(),
            commit: parts[3].to_string(),
            reveal: parts.get(4).map(|reveal| reveal.to_string()),
        });
    }
    Ok(commitments)
}

fn parse_shared_rand_value(entries: &Entries, keyword: &str) -> Result<(u32, String)> {
    let value = entries.value(keyword)?;
    let parts: Vec<&str> = value.split(' ').collect();
    match parts.as_slice() {
        [count, text] if unsigned(count).is_some() => {
            Ok((unsigned(count).unwrap_or(0), text.to_string()))
        }
        _ => Err(Error::parse(format!(
            "A network status document's '{keyword}' line must be a pair of values, the \
            first an integer but was '{value}'"
        ))),
    }
}

fn parse_signatures(entries: &Entries, keyword: &str) -> Result<Vec<DocumentSignature>> {
    let mut signatures = Vec::new();
    for entry in entries.get(keyword).unwrap_or_default() {
        let spaces = entry.value.matches(' ').count();
        if !(1..=2).contains(&spaces) {
            return Err(Error::parse(format!(
                "Authority signatures in a network status document are expected to be \
                of the form 'directory-signature [METHOD] FINGERPRINT KEY_DIGEST', \
                received: {}",
                entry.value
            )));
        }
        let (Some(block), Some("SIGNATURE")) =
            (&entry.block_contents, entry.block_type.as_deref())
        else {
            return Err(Error::parse(format!(
                "'directory-signature' should be followed by a SIGNATURE block, but was \
                a {}",
                entry.block_type.as_deref().unwrap_or("None")
            )));
        };
        let parts: Vec<&str> = entry.value.splitn(3, ' ').collect();
        let (method, fingerprint, key_digest) = match parts.as_slice() {
            [fingerprint, key_digest] => ("sha1", *fingerprint, *key_digest),
            [method, fingerprint, key_digest] => (*method, *fingerprint, *key_digest),
            _ => unreachable!("one or two spaces were checked"),
        };
        signatures.push(DocumentSignature::new(
            method,
            fingerprint,
            key_digest,
            block,
            None,
            true,
        )?);
    }
    Ok(signatures)
}

fn parse_flag_thresholds(entries: &Entries) -> Result<IndexMap<String, f64>> {
    let value = entries.value("flag-thresholds")?.trim();
    let mut thresholds = IndexMap::new();
    let invalid = || {
        Error::parse(format!(
            "Network status document's 'flag-thresholds' line is expected to have float \
            values, got: flag-thresholds {value}"
        ))
    };
    for (key, mapped) in mappings_for("flag-thresholds", value, false, ' ')? {
        let number = match mapped.strip_suffix('%') {
            Some(percentage) => percentage.parse::<f64>().map_err(|_| invalid())? / 100.0,
            None => mapped.parse::<f64>().map_err(|_| invalid())?,
        };
        thresholds.insert(key, number);
    }
    Ok(thresholds)
}

fn parse_versions(entries: &Entries, keyword: &str) -> Result<Vec<Version>> {
    let value = entries.value(keyword)?;
    value
        .split(',')
        .map(|entry| {
            Version::new(entry).map_err(|_| {
                Error::parse(format!(
                    "Network status document's '{keyword}' line had '{entry}', which \
                    isn't a parsable tor version: {keyword} {value}"
                ))
            })
        })
        .collect()
}

fn check_missing_and_disallowed(
    is_vote: bool,
    entries: &Entries,
    fields: &[HeaderField],
) -> Result<()> {
    let is_consensus = !is_vote;
    let (mut missing, mut disallowed) = (Vec::new(), Vec::new());
    for HeaderField(field, in_votes, in_consensus, mandatory) in fields {
        let applies = (is_consensus && *in_consensus) || (is_vote && *in_votes);
        if *mandatory && applies {
            if !entries.contains(field) {
                missing.push(*field);
            }
        } else if ((is_consensus && !in_consensus) || (is_vote && !in_votes))
            && entries.contains(field)
        {
            disallowed.push(*field);
        }
    }
    if !missing.is_empty() {
        return Err(Error::parse(format!(
            "Network status document is missing mandatory field: {}",
            missing.join(", ")
        )));
    }
    match disallowed.is_empty() {
        true => Ok(()),
        false => Err(Error::parse(format!(
            "Network status document has fields that shouldn't appear in this document \
            type or version: {}",
            disallowed.join(", ")
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum RouterEntry {
    Full(RouterStatusEntryV3),
    Micro(RouterStatusEntryMicroV3),
}

impl RouterEntry {
    pub fn common(&self) -> &RouterStatusEntryCommon {
        match self {
            Self::Full(entry) => &entry.common,
            Self::Micro(entry) => &entry.common,
        }
    }

    pub fn bandwidth(&self) -> Option<u64> {
        match self {
            Self::Full(entry) => entry.bandwidth,
            Self::Micro(entry) => entry.bandwidth,
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct KeyCertificate {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub unrecognized_lines: Vec<String>,
    pub version: Option<u32>,
    pub address: Option<String>,
    pub dir_port: Option<u16>,
    pub fingerprint: Option<String>,
    pub identity_key: Option<String>,
    pub published: Option<NaiveDateTime>,
    pub expires: Option<NaiveDateTime>,
    pub signing_key: Option<String>,
    pub crosscert: Option<String>,
    pub certification: Option<String>,
}

impl KeyCertificate {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        let (entries, _) = descriptor_components(content, validate, &[], &[])?;
        let raw = String::from_utf8_lossy(content);
        if validate {
            if entries.first_key() != Some("dir-key-certificate-version") {
                return Err(Error::parse(format!(
                    "Key certificates must start with a 'dir-key-certificate-version' \
                    line:\n{raw}"
                )));
            }
            if entries.last_key() != Some("dir-key-certification") {
                return Err(Error::parse(format!(
                    "Key certificates must end with a 'dir-key-certification' \
                    line:\n{raw}"
                )));
            }
            for (keyword, mandatory) in KEY_CERTIFICATE_PARAMS {
                if mandatory && !entries.contains(keyword) {
                    return Err(Error::parse(format!(
                        "Key certificates must have a '{keyword}' line:\n{raw}"
                    )));
                }
                let count = entries.get(keyword).map_or(0, <[_]>::len);
                if count > 1 {
                    return Err(Error::parse(format!(
                        "Key certificates can only have a single '{keyword}' line, got \
                        {count}:\n{raw}"
                    )));
                }
            }
        }
        let recognized: Vec<&str> = KEY_CERTIFICATE_PARAMS
            .iter()
            .map(|(keyword, _)| *keyword)
            .collect();
        let mut certificate = Self {
            raw_contents: content.to_vec(),
            unrecognized_lines: entries.unrecognized_lines(&recognized),
            version: None,
            address: None,
            dir_port: None,
            fingerprint: None,
            identity_key: None,
            published: None,
            expires: None,
            signing_key: None,
            crosscert: None,
            certification: None,
        };
        if entries.contains("dir-key-certificate-version") {
            certificate.version = lenient_option(
                validate,
                parse_version_line(&entries, "dir-key-certificate-version", 3),
            )?;
        }
        if let Ok(value) = entries.value("dir-address") {
            let parsed = value
                .rsplit_once(':')
                .ok_or_else(|| {
                    Error::parse(format!(
                        "Key certificate's 'dir-address' is expected to be of the form \
                        ADDRESS:PORT: dir-address {value}"
                    ))
                })
                .and_then(|(address, port)| {
                    match (is_valid_ipv4_address(address), parse_port(port, false)) {
                        (true, Some(port)) => Ok((address.to_string(), port)),
                        (false, _) => Err(Error::parse(format!(
                            "Key certificate's address isn't a valid IPv4 address: \
                        dir-address {value}"
                        ))),
                        _ => Err(Error::parse(format!(
                            "Key certificate's dirport is \
                        invalid: dir-address {value}"
                        ))),
                    }
                });
            if let Some((address, port)) = lenient_option(validate, parsed)? {
                certificate.address = Some(address);
                certificate.dir_port = Some(port);
            }
        }
        if let Ok(value) = entries.value("fingerprint") {
            certificate.fingerprint =
                lenient_option(validate, parse_forty_hex("fingerprint", value))?;
        }
        for (keyword, kind, target) in [
            (
                "dir-identity-key",
                "RSA PUBLIC KEY",
                &mut certificate.identity_key,
            ),
            (
                "dir-signing-key",
                "RSA PUBLIC KEY",
                &mut certificate.signing_key,
            ),
            (
                "dir-key-crosscert",
                "ID SIGNATURE",
                &mut certificate.crosscert,
            ),
            (
                "dir-key-certification",
                "SIGNATURE",
                &mut certificate.certification,
            ),
        ] {
            if entries.contains(keyword) {
                *target = lenient_option(
                    validate,
                    key_block(&entries, keyword, kind).map(|(_, block)| block),
                )?;
            }
        }
        for (keyword, target) in [
            ("dir-key-published", &mut certificate.published),
            ("dir-key-expires", &mut certificate.expires),
        ] {
            if let Ok(value) = entries.value(keyword) {
                *target = lenient_option(validate, parse_timestamp_line(keyword, value))?;
            }
        }
        Ok(certificate)
    }

    pub fn parse_many(content: &[u8], validate: bool) -> Result<Vec<Self>> {
        let mut cursor = LineCursor::new(content);
        let mut certificates = Vec::new();
        loop {
            let mut body = cursor
                .read_until_keywords(&["dir-key-certification"], ReadOptions::default())
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
            if body.is_empty() {
                break;
            }
            certificates.push(Self::parse(&body, validate)?);
        }
        Ok(certificates)
    }

    pub fn content(attributes: &Attributes, exclude: &[&str]) -> Vec<u8> {
        descriptor_content(
            attributes,
            exclude,
            &[
                (
                    "dir-key-certificate-version",
                    AttrValue::Text("3".to_string()),
                ),
                ("fingerprint", AttrValue::Text(random_fingerprint())),
                ("dir-key-published", AttrValue::Text(random_date())),
                ("dir-key-expires", AttrValue::Text(random_date())),
                (
                    "dir-identity-key",
                    AttrValue::Text(random_crypto_blob(Some("RSA PUBLIC KEY"))),
                ),
                (
                    "dir-signing-key",
                    AttrValue::Text(random_crypto_blob(Some("RSA PUBLIC KEY"))),
                ),
            ],
            &[(
                "dir-key-certification",
                AttrValue::Text(random_crypto_blob(Some("SIGNATURE"))),
            )],
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

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct DirectoryAuthority {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub unrecognized_lines: Vec<String>,
    pub nickname: Option<String>,
    pub v3ident: Option<String>,
    pub fingerprint: Option<String>,
    pub hostname: Option<String>,
    pub address: Option<String>,
    pub dir_port: Option<u16>,
    pub or_port: Option<u16>,
    pub is_legacy: bool,
    pub contact: Option<String>,
    pub vote_digest: Option<String>,
    pub legacy_dir_key: Option<String>,
    pub is_shared_randomness_participate: bool,
    pub shared_randomness_commitments: Vec<SharedRandomnessCommitment>,
    pub shared_randomness_previous_reveal_count: Option<u32>,
    pub shared_randomness_previous_value: Option<String>,
    pub shared_randomness_current_reveal_count: Option<u32>,
    pub shared_randomness_current_value: Option<String>,
    pub key_certificate: Option<KeyCertificate>,
}

struct DirSource {
    nickname: String,
    v3ident: String,
    hostname: String,
    address: String,
    dir_port: Option<u16>,
    or_port: u16,
}

fn parse_dirauth_source(entries: &Entries) -> Result<DirSource> {
    let value = entries.value("dir-source")?;
    let parts: Vec<&str> = value.split(' ').collect();
    if parts.len() < 6 {
        return Err(Error::parse(format!(
            "Authority entry's 'dir-source' line must have six values: dir-source {value}"
        )));
    }
    if !is_valid_nickname(parts[0].trim_end_matches(['-', 'l', 'e', 'g', 'a', 'c', 'y']))
    {
        return Err(Error::parse(format!(
            "Authority's nickname is invalid: {}",
            parts[0]
        )));
    }
    if !is_valid_fingerprint(parts[1], false) {
        return Err(Error::parse(format!(
            "Authority's v3ident is invalid: {}",
            parts[1]
        )));
    }
    if parts[2].is_empty() {
        return Err(Error::parse(format!(
            "Authority's hostname can't be blank: dir-source {value}"
        )));
    }
    if !is_valid_ipv4_address(parts[3]) {
        return Err(Error::parse(format!(
            "Authority's address isn't a valid IPv4 address: {}",
            parts[3]
        )));
    }
    let dir_port = parse_port(parts[4], true).ok_or_else(|| {
        Error::parse(format!("Authority's DirPort is invalid: {}", parts[4]))
    })?;
    let or_port = parse_port(parts[5], false).ok_or_else(|| {
        Error::parse(format!("Authority's ORPort is invalid: {}", parts[5]))
    })?;
    Ok(DirSource {
        nickname: parts[0].to_string(),
        v3ident: parts[1].to_string(),
        hostname: parts[2].to_string(),
        address: parts[3].to_string(),
        dir_port: Some(dir_port).filter(|port| *port != 0),
        or_port,
    })
}

impl DirectoryAuthority {
    pub fn parse(content: &[u8], validate: bool, is_vote: bool) -> Result<Self> {
        let text = String::from_utf8_lossy(content).into_owned();
        let (key_certificate, authority_content) =
            match text.find("\ndir-key-certificate-version") {
                Some(split) => (
                    Some(KeyCertificate::parse(
                        &text.as_bytes()[split + 1..],
                        validate,
                    )?),
                    text[..split + 1].to_string(),
                ),
                None => (None, text.clone()),
            };
        let (entries, _) =
            descriptor_components(authority_content.as_bytes(), validate, &[], &[])?;
        if validate {
            Self::check_constraints(
                &entries,
                &authority_content,
                is_vote,
                key_certificate.is_some(),
            )?;
        }
        let recognized = [
            "dir-source",
            "contact",
            "legacy-dir-key",
            "vote-digest",
            "shared-rand-participate",
            "shared-rand-commit",
            "shared-rand-previous-value",
            "shared-rand-current-value",
        ];
        let mut authority = Self {
            raw_contents: content.to_vec(),
            unrecognized_lines: entries.unrecognized_lines(&recognized),
            nickname: None,
            v3ident: None,
            fingerprint: None,
            hostname: None,
            address: None,
            dir_port: None,
            or_port: None,
            is_legacy: false,
            contact: None,
            vote_digest: None,
            legacy_dir_key: None,
            is_shared_randomness_participate: entries.contains("shared-rand-participate"),
            shared_randomness_commitments: Vec::new(),
            shared_randomness_previous_reveal_count: None,
            shared_randomness_previous_value: None,
            shared_randomness_current_reveal_count: None,
            shared_randomness_current_value: None,
            key_certificate,
        };
        if entries.contains("dir-source")
            && let Some(source) =
                lenient_option(validate, parse_dirauth_source(&entries))?
        {
            authority.is_legacy = source.nickname.ends_with("-legacy");
            authority.nickname = Some(source.nickname);
            authority.fingerprint = Some(source.v3ident.clone());
            authority.v3ident = Some(source.v3ident);
            authority.hostname = Some(source.hostname);
            authority.address = Some(source.address);
            authority.dir_port = source.dir_port;
            authority.or_port = Some(source.or_port);
        }
        authority.contact = entries.value("contact").ok().map(str::to_string);
        if let Ok(value) = entries.value("legacy-dir-key") {
            authority.legacy_dir_key =
                lenient_option(validate, parse_forty_hex("legacy-dir-key", value))?;
        }
        if let Ok(value) = entries.value("vote-digest") {
            authority.vote_digest =
                lenient_option(validate, parse_forty_hex("vote-digest", value))?;
        }
        if entries.contains("shared-rand-commit") {
            authority.shared_randomness_commitments =
                lenient(validate, parse_shared_rand_commits(&entries))?;
        }
        if entries.contains("shared-rand-previous-value")
            && let Some((count, value)) = lenient_option(
                validate,
                parse_shared_rand_value(&entries, "shared-rand-previous-value"),
            )?
        {
            authority.shared_randomness_previous_reveal_count = Some(count);
            authority.shared_randomness_previous_value = Some(value);
        }
        if entries.contains("shared-rand-current-value")
            && let Some((count, value)) = lenient_option(
                validate,
                parse_shared_rand_value(&entries, "shared-rand-current-value"),
            )?
        {
            authority.shared_randomness_current_reveal_count = Some(count);
            authority.shared_randomness_current_value = Some(value);
        }
        Ok(authority)
    }

    fn check_constraints(
        entries: &Entries,
        content: &str,
        is_vote: bool,
        has_certificate: bool,
    ) -> Result<()> {
        if entries.first_key() != Some("dir-source") {
            return Err(Error::parse(format!(
                "Authority entries are expected to start with a 'dir-source' \
                line:\n{content}"
            )));
        }
        let is_legacy = entries
            .get("dir-source")
            .and_then(|values| values.first())
            .is_some_and(|entry| {
                entry
                    .value
                    .split_whitespace()
                    .next()
                    .is_some_and(|name| name.ends_with("-legacy"))
            });
        let mut required = vec!["dir-source"];
        let mut excluded: Vec<&str> = Vec::new();
        if !is_legacy {
            required.push("contact");
        }
        if is_vote {
            if !has_certificate {
                return Err(Error::parse(format!(
                    "Authority votes must have a key certificate:\n{content}"
                )));
            }
            excluded.push("vote-digest");
        } else {
            if has_certificate {
                return Err(Error::parse(format!(
                    "Authority consensus entries shouldn't have a key \
                    certificate:\n{content}"
                )));
            }
            if !is_legacy {
                required.push("vote-digest");
            }
            excluded.push("legacy-dir-key");
        }
        for keyword in required {
            if !entries.contains(keyword) {
                return Err(Error::parse(format!(
                    "Authority entries must have a '{keyword}' line:\n{content}"
                )));
            }
        }
        for keyword in entries.keys() {
            if excluded.contains(&keyword.as_str()) {
                let label = if is_vote {
                    "votes"
                } else {
                    "consensus entries"
                };
                return Err(Error::parse(format!(
                    "Authority {label} shouldn't have a '{keyword}' line:\n{content}"
                )));
            }
        }
        for keyword in ["dir-source", "contact", "legacy-dir-key", "vote-digest"] {
            let count = entries.get(keyword).map_or(0, <[_]>::len);
            if count > 1 {
                return Err(Error::parse(format!(
                    "Authority entries can only have a single '{keyword}' line, got \
                    {count}:\n{content}"
                )));
            }
        }
        Ok(())
    }

    pub fn content(attributes: &Attributes, exclude: &[&str], is_vote: bool) -> Vec<u8> {
        let mut attributes = attributes.clone();
        let excludes_digest = exclude.contains(&"vote-digest");
        if !is_vote
            && !attributes.iter().any(|(key, _)| key == "vote-digest")
            && !excludes_digest
        {
            attributes.push(attr("vote-digest", &random_fingerprint()));
        }
        let mut content = descriptor_content(
            &attributes,
            exclude,
            &[
                (
                    "dir-source",
                    AttrValue::Text(format!(
                        "{} {} no.place.com {} 9030 9090",
                        random_nickname(),
                        random_fingerprint(),
                        random_ipv4_address()
                    )),
                ),
                ("contact", AttrValue::Text("Mike Perry <email>".to_string())),
            ],
            &[],
        );
        if is_vote {
            content.push(b'\n');
            content.extend(KeyCertificate::content(&Vec::new(), &[]));
        }
        content
    }

    pub fn create(
        attributes: &Attributes,
        exclude: &[&str],
        validate: bool,
        is_vote: bool,
    ) -> Result<Self> {
        Self::parse(
            &Self::content(attributes, exclude, is_vote),
            validate,
            is_vote,
        )
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct NetworkStatusDocumentV3 {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub unrecognized_lines: Vec<String>,
    pub version: Option<u32>,
    pub version_flavor: String,
    pub is_consensus: bool,
    pub is_vote: bool,
    pub is_microdescriptor: bool,
    pub consensus_methods: Vec<u32>,
    pub published: Option<NaiveDateTime>,
    pub consensus_method: Option<u32>,
    pub valid_after: Option<NaiveDateTime>,
    pub fresh_until: Option<NaiveDateTime>,
    pub valid_until: Option<NaiveDateTime>,
    pub vote_delay: Option<u32>,
    pub dist_delay: Option<u32>,
    pub client_versions: Vec<Version>,
    pub server_versions: Vec<Version>,
    pub packages: Vec<PackageVersion>,
    pub known_flags: Vec<String>,
    pub flag_thresholds: IndexMap<String, f64>,
    pub recommended_client_protocols: Protocols,
    pub recommended_relay_protocols: Protocols,
    pub required_client_protocols: Protocols,
    pub required_relay_protocols: Protocols,
    pub params: IndexMap<String, i64>,
    pub shared_randomness_previous_reveal_count: Option<u32>,
    pub shared_randomness_previous_value: Option<String>,
    pub shared_randomness_current_reveal_count: Option<u32>,
    pub shared_randomness_current_value: Option<String>,
    pub is_shared_randomness_participate: bool,
    pub shared_randomness_commitments: Vec<SharedRandomnessCommitment>,
    pub bandwidth_file_headers: IndexMap<String, String>,
    pub bandwidth_file_digest: IndexMap<String, String>,
    pub signatures: Vec<DocumentSignature>,
    pub bandwidth_weights: IndexMap<String, i64>,
    pub directory_authorities: Vec<DirectoryAuthority>,
    pub routers: IndexMap<String, RouterEntry>,
}

const HEADER_KEYWORDS: [&str; 24] = [
    "network-status-version",
    "vote-status",
    "consensus-methods",
    "consensus-method",
    "published",
    "valid-after",
    "fresh-until",
    "valid-until",
    "voting-delay",
    "client-versions",
    "server-versions",
    "package",
    "known-flags",
    "flag-thresholds",
    "recommended-client-protocols",
    "recommended-relay-protocols",
    "required-client-protocols",
    "required-relay-protocols",
    "params",
    "shared-rand-previous-value",
    "shared-rand-current-value",
    "bandwidth-file-headers",
    "bandwidth-file-digest",
    "shared-rand-commit",
];

impl NetworkStatusDocumentV3 {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        Self::parse_with_options(content, validate, true)
    }

    pub fn parse_with_options(
        content: &[u8],
        validate: bool,
        default_params: bool,
    ) -> Result<Self> {
        let mut cursor = LineCursor::new(content);
        let header_bytes = cursor
            .read_until_keywords(
                &[AUTH_START, ROUTERS_START, FOOTER_START],
                ReadOptions::default(),
            )
            .content;
        let (header_entries, _) =
            descriptor_components(&header_bytes, validate, &[], &[])?;
        let mut document = Self::empty(content);
        document.parse_header(&header_entries, validate, default_params)?;
        let is_vote = document.is_vote;
        let authority_section = parse_entry_section_for(
            &mut cursor,
            AUTH_START,
            &[ROUTERS_START, FOOTER_START, V2_FOOTER_START],
            |bytes| DirectoryAuthority::parse(bytes, validate, is_vote),
        )?;
        document.directory_authorities = authority_section;
        if validate && document.is_vote && document.directory_authorities.len() != 1 {
            return Err(Error::parse(format!(
                "Votes should only have an authority entry for the one that issued it, \
                got {}",
                document.directory_authorities.len()
            )));
        }
        let context = DocumentContext { is_vote };
        let is_micro = document.is_microdescriptor;
        let routers = parse_entry_section(
            &mut cursor,
            validate,
            &[FOOTER_START, V2_FOOTER_START],
            None,
            |bytes| match is_micro {
                true => RouterStatusEntryMicroV3::parse_with_document(
                    bytes,
                    validate,
                    Some(context),
                )
                .map(RouterEntry::Micro),
                false => RouterStatusEntryV3::parse_with_document(
                    bytes,
                    validate,
                    Some(context),
                )
                .map(RouterEntry::Full),
            },
        )?;
        for entry in routers {
            if let Some(fingerprint) = entry.common().fingerprint.clone() {
                document.routers.insert(fingerprint, entry);
            }
        }
        document.parse_footer(cursor.remaining(), validate)?;
        Ok(document)
    }

    fn empty(content: &[u8]) -> Self {
        Self {
            raw_contents: content.to_vec(),
            unrecognized_lines: Vec::new(),
            version: None,
            version_flavor: "ns".to_string(),
            is_consensus: true,
            is_vote: false,
            is_microdescriptor: false,
            consensus_methods: Vec::new(),
            published: None,
            consensus_method: None,
            valid_after: None,
            fresh_until: None,
            valid_until: None,
            vote_delay: None,
            dist_delay: None,
            client_versions: Vec::new(),
            server_versions: Vec::new(),
            packages: Vec::new(),
            known_flags: Vec::new(),
            flag_thresholds: IndexMap::new(),
            recommended_client_protocols: Protocols::new(),
            recommended_relay_protocols: Protocols::new(),
            required_client_protocols: Protocols::new(),
            required_relay_protocols: Protocols::new(),
            params: IndexMap::new(),
            shared_randomness_previous_reveal_count: None,
            shared_randomness_previous_value: None,
            shared_randomness_current_reveal_count: None,
            shared_randomness_current_value: None,
            is_shared_randomness_participate: false,
            shared_randomness_commitments: Vec::new(),
            bandwidth_file_headers: IndexMap::new(),
            bandwidth_file_digest: IndexMap::new(),
            signatures: Vec::new(),
            bandwidth_weights: IndexMap::new(),
            directory_authorities: Vec::new(),
            routers: IndexMap::new(),
        }
    }

    fn parse_header(
        &mut self,
        entries: &Entries,
        validate: bool,
        default_params: bool,
    ) -> Result<()> {
        if validate {
            for (keyword, values) in entries.iter() {
                let is_header_field = HEADER_FIELDS
                    .iter()
                    .any(|HeaderField(name, ..)| name == keyword);
                if values.len() > 1
                    && is_header_field
                    && keyword != "package"
                    && keyword != "shared-rand-commit"
                {
                    return Err(Error::parse(format!(
                        "Network status documents can only have a single '{keyword}' \
                        line, got {}",
                        values.len()
                    )));
                }
            }
        }
        if default_params {
            self.params = DEFAULT_PARAMS
                .iter()
                .map(|(key, value)| (key.to_string(), *value))
                .collect();
        }
        self.unrecognized_lines
            .extend(entries.unrecognized_lines(&HEADER_KEYWORDS));
        if let Ok(value) = entries.value("network-status-version") {
            let parsed = (|| -> Result<(u32, String)> {
                let (version, flavor) = value.split_once(' ').unwrap_or((value, "ns"));
                let number = unsigned(version).ok_or_else(|| {
                    Error::parse(format!(
                        "Network status document has a non-numeric \
                        version: network-status-version {value}"
                    ))
                })?;
                match number == 3 {
                    true => Ok((number, flavor.to_string())),
                    false => Err(Error::parse(format!(
                        "Expected a version 3 network status document, got version \
                        '{number}' instead"
                    ))),
                }
            })();
            if let Some((version, flavor)) = lenient_option(validate, parsed)? {
                self.version = Some(version);
                self.is_microdescriptor = flavor == "microdesc";
                self.version_flavor = flavor;
            }
        }
        if let Ok(value) = entries.value("vote-status") {
            match value {
                "consensus" => (self.is_consensus, self.is_vote) = (true, false),
                "vote" => (self.is_consensus, self.is_vote) = (false, true),
                _ => {
                    lenient::<()>(
                        validate,
                        Err(Error::parse(format!(
                            "A network status document's vote-status line can only be \
                            'consensus' or 'vote', got '{value}' instead"
                        ))),
                    )?;
                }
            }
        }
        if let Ok(value) = entries.value("consensus-methods") {
            let methods: Result<Vec<u32>> = value
                .split(' ')
                .map(|entry| {
                    unsigned(entry).ok_or_else(|| {
                        Error::parse(format!(
                            "A network status document's consensus-methods must be a \
                            list of integer values, but was '{value}'"
                        ))
                    })
                })
                .collect();
            if let Some(methods) = lenient_option(validate, methods)? {
                self.consensus_methods = methods;
            }
        }
        if let Ok(value) = entries.value("consensus-method") {
            let parsed = unsigned(value).ok_or_else(|| {
                Error::parse(format!(
                    "A network status document's consensus-method must \
                    be an integer, but was '{value}'"
                ))
            });
            self.consensus_method = lenient_option(validate, parsed)?;
        }
        for (keyword, target) in [
            ("published", &mut self.published),
            ("valid-after", &mut self.valid_after),
            ("fresh-until", &mut self.fresh_until),
            ("valid-until", &mut self.valid_until),
        ] {
            if let Ok(value) = entries.value(keyword) {
                *target = lenient_option(validate, parse_timestamp_line(keyword, value))?;
            }
        }
        if let Ok(value) = entries.value("voting-delay") {
            let parts: Vec<&str> = value.split(' ').collect();
            match parts.as_slice() {
                [vote, dist] if unsigned(vote).is_some() && unsigned(dist).is_some() => {
                    self.vote_delay = unsigned(vote);
                    self.dist_delay = unsigned(dist);
                }
                _ => {
                    lenient::<()>(
                        validate,
                        Err(Error::parse(format!(
                            "A network status document's 'voting-delay' line must be a \
                            pair of integer values, but was '{value}'"
                        ))),
                    )?;
                }
            }
        }
        if entries.contains("client-versions") {
            self.client_versions =
                lenient(validate, parse_versions(entries, "client-versions"))?;
        }
        if entries.contains("server-versions") {
            self.server_versions =
                lenient(validate, parse_versions(entries, "server-versions"))?;
        }
        if entries.contains("package") {
            self.packages = lenient(validate, parse_packages(entries))?;
        }
        if let Ok(value) = entries.value("known-flags") {
            self.known_flags = value
                .split(' ')
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect();
        }
        if entries.contains("flag-thresholds") {
            self.flag_thresholds = lenient(validate, parse_flag_thresholds(entries))?;
        }
        for (keyword, target) in [
            (
                "recommended-client-protocols",
                &mut self.recommended_client_protocols,
            ),
            (
                "recommended-relay-protocols",
                &mut self.recommended_relay_protocols,
            ),
            (
                "required-client-protocols",
                &mut self.required_client_protocols,
            ),
            (
                "required-relay-protocols",
                &mut self.required_relay_protocols,
            ),
        ] {
            if let Ok(value) = entries.value(keyword) {
                *target = lenient(validate, parse_protocol_line(keyword, value))?;
            }
        }
        if let Ok(value) = entries.value("params")
            && !value.is_empty()
        {
            let parsed = parse_int_mappings("params", value, true).and_then(|params| {
                self.check_params_constraints(&params).map(|()| params)
            });
            if let Some(params) = lenient_option(validate, parsed)? {
                self.params = params;
            }
        }
        for (keyword, count_target, value_target) in [
            (
                "shared-rand-previous-value",
                &mut self.shared_randomness_previous_reveal_count,
                &mut self.shared_randomness_previous_value,
            ),
            (
                "shared-rand-current-value",
                &mut self.shared_randomness_current_reveal_count,
                &mut self.shared_randomness_current_value,
            ),
        ] {
            if entries.contains(keyword)
                && let Some((count, value)) =
                    lenient_option(validate, parse_shared_rand_value(entries, keyword))?
            {
                *count_target = Some(count);
                *value_target = Some(value);
            }
        }
        self.is_shared_randomness_participate =
            entries.contains("shared-rand-participate");
        if entries.contains("shared-rand-commit") {
            self.shared_randomness_commitments =
                lenient(validate, parse_shared_rand_commits(entries))?;
        }
        for (keyword, target) in [
            ("bandwidth-file-headers", &mut self.bandwidth_file_headers),
            ("bandwidth-file-digest", &mut self.bandwidth_file_digest),
        ] {
            if let Ok(value) = entries.value(keyword) {
                *target = lenient::<Vec<(String, String)>>(
                    validate,
                    mappings_for(keyword, value, false, ' '),
                )?
                .into_iter()
                .collect();
            }
        }
        if validate {
            if !self.meets_consensus_method(7) && entries.contains("params") {
                return Err(Error::parse(
                    "A network status document's 'params' line should only appear in \
                    consensus-method 7 or later",
                ));
            }
            check_missing_and_disallowed(self.is_vote, entries, &HEADER_FIELDS)?;
            if self.is_consensus && self.consensus_method.is_none() {
                self.consensus_method = Some(1);
            } else if self.is_vote && self.consensus_methods.is_empty() {
                self.consensus_methods = vec![1];
            }
        }
        Ok(())
    }

    fn parse_footer(&mut self, content: &[u8], validate: bool) -> Result<()> {
        let (entries, _) = descriptor_components(content, validate, &[], &[])?;
        self.unrecognized_lines.extend(entries.unrecognized_lines(&[
            "directory-footer",
            "bandwidth-weights",
            "directory-signature",
        ]));
        if validate {
            for (keyword, values) in entries.iter() {
                let is_footer_field = FOOTER_FIELDS
                    .iter()
                    .any(|HeaderField(name, ..)| name == keyword);
                if values.len() > 1
                    && is_footer_field
                    && !(keyword == "directory-signature" && self.is_consensus)
                {
                    return Err(Error::parse(format!(
                        "Network status documents can only have a single '{keyword}' \
                        line, got {}",
                        values.len()
                    )));
                }
            }
        }
        if let Ok(value) = entries.value("directory-footer")
            && !value.is_empty()
        {
            lenient::<()>(
                validate,
                Err(Error::parse(format!(
                    "A network status document's 'directory-footer' line shouldn't have \
                    any content, got 'directory-footer {value}'"
                ))),
            )?;
        }
        if let Ok(value) = entries.value("bandwidth-weights") {
            self.bandwidth_weights = lenient(
                validate,
                parse_int_mappings("bandwidth-weights", value, true),
            )?;
        }
        if entries.contains("directory-signature") {
            self.signatures =
                lenient(validate, parse_signatures(&entries, "directory-signature"))?;
        }
        if validate && !entries.is_empty() {
            match (self.meets_consensus_method(9), entries.first_key()) {
                (true, Some("directory-footer"))
                | (false, Some("directory-signature")) => {}
                (true, _) => {
                    return Err(Error::parse(
                        "Network status document's footer should start with a \
                        'directory-footer' line in consensus-method 9 or later",
                    ));
                }
                (false, _) => {
                    return Err(Error::parse(
                        "Network status document's footer should start with a \
                        'directory-signature' line prior to consensus-method 9",
                    ));
                }
            }
            check_missing_and_disallowed(self.is_vote, &entries, &FOOTER_FIELDS)?;
        }
        Ok(())
    }

    fn check_params_constraints(&self, params: &IndexMap<String, i64>) -> Result<()> {
        for (key, value) in params {
            let (mut minimum, maximum) = param_range(key);
            match key.as_str() {
                "cbtclosequantile" => {
                    minimum = params.get("cbtquantile").copied().unwrap_or(minimum)
                }
                "cbtinitialtimeout" => {
                    minimum = params.get("cbtmintimeout").copied().unwrap_or(minimum)
                }
                _ => {}
            }
            if *value < minimum || *value > maximum {
                return Err(Error::parse(format!(
                    "'{key}' value on the params line must be in the range of {minimum} \
                    - {maximum}, was {value}"
                )));
            }
        }
        Ok(())
    }

    pub fn meets_consensus_method(&self, method: u32) -> bool {
        match (self.consensus_method, self.consensus_methods.is_empty()) {
            (Some(current), _) => current >= method,
            (None, false) => self
                .consensus_methods
                .iter()
                .any(|candidate| *candidate >= method),
            (None, true) => false,
        }
    }

    pub fn is_valid(&self) -> bool {
        let now = Utc::now().naive_utc();
        match (self.valid_after, self.valid_until) {
            (Some(after), Some(until)) => after < now && now < until,
            _ => false,
        }
    }

    pub fn is_fresh(&self) -> bool {
        let now = Utc::now().naive_utc();
        match (self.valid_after, self.fresh_until) {
            (Some(after), Some(fresh)) => after < now && now < fresh,
            _ => false,
        }
    }

    pub fn digest(&self, hash: DigestHash, encoding: DigestEncoding) -> Result<String> {
        let content =
            content_range(&self.raw_contents, None, Some("\ndirectory-signature "))?;
        Ok(encode_digest(&hash_bytes(hash, &content), encoding))
    }

    pub fn validate_signatures(&self, key_certificates: &[KeyCertificate]) -> Result<()> {
        let signed = content_range(
            &self.raw_contents,
            Some("network-status-version"),
            Some("directory-signature "),
        )?;
        let local = Sha1::digest(&signed).to_vec();
        let required = self.signatures.len() as f64 / 2.0;
        let (mut valid, mut total) = (0usize, 0usize);
        for signature in &self.signatures {
            let Some(certificate) = key_certificates.iter().find(|certificate| {
                certificate.fingerprint.as_deref() == Some(signature.identity.as_str())
            }) else {
                continue;
            };
            let Some(signing_key) = &certificate.signing_key else {
                continue;
            };
            total += 1;
            if digest_for_signature(signing_key, &signature.signature)
                .is_ok_and(|digest| digest == local)
            {
                valid += 1;
            }
        }
        match (valid as f64) < required {
            true => Err(Error::parse(format!(
                "Network Status Document has {valid} valid signatures out of {total} \
                total, needed {required}"
            ))),
            false => Ok(()),
        }
    }

    pub fn parse_routers(
        content: &[u8],
        validate: bool,
        is_microdescriptor: bool,
    ) -> Result<Vec<RouterEntry>> {
        let split = split_document(content);
        let header_content: Vec<u8> =
            [split.header.as_slice(), split.footer.as_slice()].concat();
        let document = Self::parse_bare(&header_content, validate)?;
        let context = DocumentContext {
            is_vote: document.is_vote,
        };
        let mut cursor = LineCursor::new(content);
        cursor.seek(split.routers_start);
        parse_entry_section(
            &mut cursor,
            validate,
            &[],
            Some(split.routers_end),
            |bytes| match is_microdescriptor {
                true => RouterStatusEntryMicroV3::parse_with_document(
                    bytes,
                    validate,
                    Some(context),
                )
                .map(RouterEntry::Micro),
                false => RouterStatusEntryV3::parse_with_document(
                    bytes,
                    validate,
                    Some(context),
                )
                .map(RouterEntry::Full),
            },
        )
    }

    pub fn parse_bare(content: &[u8], validate: bool) -> Result<Self> {
        Self::parse(content, validate)
    }

    pub fn content(
        attributes: &Attributes,
        exclude: &[&str],
        authorities: Option<&[DirectoryAuthority]>,
        routers: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut attributes = attributes.clone();
        let is_vote = attributes.iter().any(|(key, value)| {
            key == "vote-status"
                && matches!(value, AttrValue::Text(text) if text == "vote")
        });
        let defaults: Vec<(&str, String)> = match is_vote {
            true => vec![
                ("consensus-methods", "1 9".to_string()),
                ("published", random_date()),
            ],
            false => vec![("consensus-method", "9".to_string())],
        };
        for (key, value) in defaults {
            if !exclude.contains(&key) && !attributes.iter().any(|(name, _)| name == key)
            {
                attributes.push((key.to_string(), AttrValue::Text(value)));
            }
        }
        let generated_authority;
        let authorities = match (authorities, is_vote) {
            (Some(authorities), _) => authorities,
            (None, true) => {
                generated_authority =
                    DirectoryAuthority::create(&Vec::new(), &[], true, true).ok();
                generated_authority.as_slice()
            }
            (None, false) => &[],
        };
        let mut content = descriptor_content(
            &attributes,
            exclude,
            &[
                ("network-status-version", AttrValue::Text("3".to_string())),
                ("vote-status", AttrValue::Text("consensus".to_string())),
                ("consensus-methods", AttrValue::Remove),
                ("consensus-method", AttrValue::Remove),
                ("published", AttrValue::Remove),
                ("valid-after", AttrValue::Text(random_date())),
                ("fresh-until", AttrValue::Text(random_date())),
                ("valid-until", AttrValue::Text(random_date())),
                ("voting-delay", AttrValue::Text("300 300".to_string())),
                ("client-versions", AttrValue::Remove),
                ("server-versions", AttrValue::Remove),
                ("package", AttrValue::Remove),
                (
                    "known-flags",
                    AttrValue::Text(
                        "Authority BadExit Exit Fast Guard HSDir Named \
                        Running Stable Unnamed V2Dir Valid"
                            .to_string(),
                    ),
                ),
                ("params", AttrValue::Remove),
            ],
            &[
                ("directory-footer", AttrValue::Text(String::new())),
                ("bandwidth-weights", AttrValue::Remove),
                (
                    "directory-signature",
                    AttrValue::Text(format!(
                        "{} {}{}",
                        random_fingerprint(),
                        random_fingerprint(),
                        random_crypto_blob(Some("SIGNATURE"))
                    )),
                ),
            ],
        );
        let find_footer = |content: &Vec<u8>| -> usize {
            let search = |needle: &[u8]| {
                content
                    .windows(needle.len())
                    .position(|window| window == needle)
            };
            match search(b"\ndirectory-footer")
                .or_else(|| search(b"\ndirectory-signature"))
            {
                Some(position) => position + 1,
                None => content.len() + 1,
            }
        };
        for section in [
            authorities
                .iter()
                .map(|authority| authority.raw_contents.clone())
                .collect::<Vec<_>>(),
            routers.to_vec(),
        ] {
            if section.is_empty() {
                continue;
            }
            let mut footer_div = find_footer(&content);
            if footer_div > content.len() {
                content.push(b'\n');
                footer_div = content.len();
            }
            let mut block = section.join(&b'\n');
            block.push(b'\n');
            content.splice(footer_div..footer_div, block);
        }
        content
    }

    pub fn create(
        attributes: &Attributes,
        exclude: &[&str],
        validate: bool,
        authorities: Option<&[DirectoryAuthority]>,
        routers: &[Vec<u8>],
    ) -> Result<Self> {
        Self::parse(
            &Self::content(attributes, exclude, authorities, routers),
            validate,
        )
    }
}

fn parse_entry_section_for<T>(
    cursor: &mut LineCursor<'_>,
    entry_keyword: &str,
    section_end_keywords: &[&str],
    mut build: impl FnMut(&[u8]) -> Result<T>,
) -> Result<Vec<T>> {
    let start = cursor.tell();
    let first_keyword = cursor.read_line().and_then(|line| {
        let text = String::from_utf8_lossy(line).into_owned();
        crate::descriptor::split_keyword_line(text.trim_end_matches(['\n', '\r']))
            .map(|(keyword, _)| keyword.to_string())
    });
    cursor.seek(start);
    if first_keyword
        .is_some_and(|keyword| section_end_keywords.contains(&keyword.as_str()))
    {
        return Ok(Vec::new());
    }
    let mut keywords = vec![entry_keyword];
    keywords.extend_from_slice(section_end_keywords);
    let mut parsed = Vec::new();
    loop {
        let result = cursor.read_until_keywords(
            &keywords,
            ReadOptions {
                ignore_first: true,
                ..Default::default()
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

struct SplitDocument {
    header: Vec<u8>,
    footer: Vec<u8>,
    routers_start: usize,
    routers_end: usize,
}

fn split_document(content: &[u8]) -> SplitDocument {
    let mut cursor = LineCursor::new(content);
    let mut header = cursor
        .read_until_keywords(
            &[ROUTERS_START, FOOTER_START, V2_FOOTER_START],
            ReadOptions::default(),
        )
        .content;
    if header.starts_with(b"@type") {
        header = header
            .splitn(2, |byte| *byte == b'\n')
            .nth(1)
            .unwrap_or_default()
            .to_vec();
    }
    let routers_start = cursor.tell();
    cursor.read_until_keywords(&[FOOTER_START, V2_FOOTER_START], ReadOptions::default());
    let routers_end = cursor.tell();
    SplitDocument {
        header,
        footer: cursor.remaining().to_vec(),
        routers_start,
        routers_end,
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct DetachedSignature {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub unrecognized_lines: Vec<String>,
    pub consensus_digest: Option<String>,
    pub valid_after: Option<NaiveDateTime>,
    pub fresh_until: Option<NaiveDateTime>,
    pub valid_until: Option<NaiveDateTime>,
    pub additional_digests: Vec<DocumentDigest>,
    pub additional_signatures: Vec<DocumentSignature>,
    pub signatures: Vec<DocumentSignature>,
}

impl DetachedSignature {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        let (entries, _) = descriptor_components(content, validate, &[], &[])?;
        let raw = String::from_utf8_lossy(content);
        if validate {
            if entries.first_key() != Some("consensus-digest") {
                return Err(Error::parse(format!(
                    "Detached signatures must start with a 'consensus-digest' \
                    line:\n{raw}"
                )));
            }
            for (keyword, mandatory, multiple) in DETACHED_SIGNATURE_PARAMS {
                if mandatory && !entries.contains(keyword) {
                    return Err(Error::parse(format!(
                        "Detached signatures must have a '{keyword}' line:\n{raw}"
                    )));
                }
                let count = entries.get(keyword).map_or(0, <[_]>::len);
                if !multiple && count > 1 {
                    return Err(Error::parse(format!(
                        "Detached signatures can only have a single '{keyword}' line, \
                        got {count}:\n{raw}"
                    )));
                }
            }
        }
        let recognized: Vec<&str> = DETACHED_SIGNATURE_PARAMS
            .iter()
            .map(|(keyword, _, _)| *keyword)
            .collect();
        let mut signature = Self {
            raw_contents: content.to_vec(),
            unrecognized_lines: entries.unrecognized_lines(&recognized),
            consensus_digest: None,
            valid_after: None,
            fresh_until: None,
            valid_until: None,
            additional_digests: Vec::new(),
            additional_signatures: Vec::new(),
            signatures: Vec::new(),
        };
        signature.consensus_digest =
            entries.value("consensus-digest").ok().map(str::to_string);
        for (keyword, target) in [
            ("valid-after", &mut signature.valid_after),
            ("fresh-until", &mut signature.fresh_until),
            ("valid-until", &mut signature.valid_until),
        ] {
            if let Ok(value) = entries.value(keyword) {
                *target = lenient_option(validate, parse_timestamp_line(keyword, value))?;
            }
        }
        if entries.contains("additional-digest") {
            let parsed: Result<Vec<DocumentDigest>> = entries
                .values("additional-digest")
                .into_iter()
                .map(|value| {
                    let parts: Vec<&str> = value.split(' ').collect();
                    match parts.as_slice() {
                        [flavor, algorithm, digest, ..] => Ok(DocumentDigest {
                            flavor: flavor.to_string(),
                            algorithm: algorithm.to_string(),
                            digest: digest.to_string(),
                        }),
                        _ => Err(Error::parse(format!(
                            "additional-digest lines should be of the form \
                            'additional-digest [flavor] [algname] [digest]' but was: \
                            {value}"
                        ))),
                    }
                })
                .collect();
            signature.additional_digests = lenient(validate, parsed)?;
        }
        if entries.contains("additional-signature") {
            signature.additional_signatures =
                lenient(validate, Self::parse_additional_signatures(&entries))?;
        }
        if entries.contains("directory-signature") {
            signature.signatures =
                lenient(validate, parse_signatures(&entries, "directory-signature"))?;
        }
        Ok(signature)
    }

    fn parse_additional_signatures(entries: &Entries) -> Result<Vec<DocumentSignature>> {
        let mut signatures = Vec::new();
        for entry in entries.get("additional-signature").unwrap_or_default() {
            let parts: Vec<&str> = entry.value.split(' ').collect();
            if parts.len() < 4 {
                return Err(Error::parse(format!(
                    "additional-signature lines should be of the form \
                    'additional-signature [flavor] [algname] [identity] \
                    [signing_key_digest]' but was: {}",
                    entry.value
                )));
            }
            let (Some(block), Some("SIGNATURE")) =
                (&entry.block_contents, entry.block_type.as_deref())
            else {
                return Err(Error::parse(format!(
                    "'additional-signature' should be followed by a SIGNATURE block, \
                    but was a {}",
                    entry.block_type.as_deref().unwrap_or("None")
                )));
            };
            signatures.push(DocumentSignature::new(
                parts[1],
                parts[2],
                parts[3],
                block,
                Some(parts[0]),
                true,
            )?);
        }
        Ok(signatures)
    }

    pub fn content(attributes: &Attributes, exclude: &[&str]) -> Vec<u8> {
        descriptor_content(
            attributes,
            exclude,
            &[
                (
                    "consensus-digest",
                    AttrValue::Text(
                        "6D3CC0EFA408F228410A4A8145E1B0BB0670E442".to_string(),
                    ),
                ),
                ("valid-after", AttrValue::Text(random_date())),
                ("fresh-until", AttrValue::Text(random_date())),
                ("valid-until", AttrValue::Text(random_date())),
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

    pub fn parse_many(content: &[u8], validate: bool) -> Result<Vec<Self>> {
        let mut cursor = LineCursor::new(content);
        let mut signatures = Vec::new();
        loop {
            let body = cursor
                .read_until_keywords(
                    &["consensus-digest"],
                    ReadOptions {
                        ignore_first: true,
                        ..Default::default()
                    },
                )
                .content;
            if body.is_empty() {
                break;
            }
            signatures.push(Self::parse(&body, validate)?);
        }
        Ok(signatures)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct NetworkStatusDocumentV2 {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub unrecognized_lines: Vec<String>,
    pub version: Option<u32>,
    pub hostname: Option<String>,
    pub address: Option<String>,
    pub dir_port: Option<u16>,
    pub fingerprint: Option<String>,
    pub contact: Option<String>,
    pub signing_key: Option<String>,
    pub client_versions: Vec<String>,
    pub server_versions: Vec<String>,
    pub published: Option<NaiveDateTime>,
    pub options: Vec<String>,
    pub signing_authority: Option<String>,
    pub signature: Option<String>,
    pub routers: IndexMap<String, RouterStatusEntryV2>,
}

impl NetworkStatusDocumentV2 {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        let mut cursor = LineCursor::new(content);
        let mut document_content = cursor
            .read_until_keywords(
                &[ROUTERS_START, V2_FOOTER_START],
                ReadOptions::default(),
            )
            .content;
        let routers = parse_entry_section(
            &mut cursor,
            validate,
            &[V2_FOOTER_START],
            None,
            |bytes| RouterStatusEntryV2::parse(bytes, validate),
        )?;
        document_content.push(b'\n');
        document_content.extend_from_slice(cursor.remaining());
        let (entries, _) = descriptor_components(&document_content, validate, &[], &[])?;
        if validate {
            Self::check_constraints(&entries, content)?;
        }
        let recognized: Vec<&str> = NETWORK_STATUS_V2_FIELDS
            .iter()
            .map(|(keyword, _)| *keyword)
            .collect();
        let mut document = Self {
            raw_contents: content.to_vec(),
            unrecognized_lines: entries.unrecognized_lines(&recognized),
            version: None,
            hostname: None,
            address: None,
            dir_port: None,
            fingerprint: None,
            contact: entries.value("contact").ok().map(str::to_string),
            signing_key: None,
            client_versions: Vec::new(),
            server_versions: Vec::new(),
            published: None,
            options: Vec::new(),
            signing_authority: None,
            signature: None,
            routers: routers
                .into_iter()
                .filter_map(|entry| Some((entry.fingerprint.clone()?, entry)))
                .collect(),
        };
        if entries.contains("network-status-version") {
            document.version = lenient_option(
                validate,
                parse_version_line(&entries, "network-status-version", 2),
            )?;
        }
        if let Ok(value) = entries.value("dir-source") {
            let parsed = (|| -> Result<(String, String, Option<u16>)> {
                let parts: Vec<&str> = value.split_whitespace().collect();
                if parts.len() < 3 {
                    return Err(Error::parse(format!(
                        "The 'dir-source' line of a v2 network status document must \
                        have three values: dir-source {value}"
                    )));
                }
                if !is_valid_ipv4_address(parts[1]) {
                    return Err(Error::parse(format!(
                        "Authority's address isn't a valid IPv4 address: {}",
                        parts[1]
                    )));
                }
                let port = parse_port(parts[2], true).ok_or_else(|| {
                    Error::parse(format!("Authority's DirPort is invalid: {}", parts[2]))
                })?;
                Ok((
                    parts[0].to_string(),
                    parts[1].to_string(),
                    Some(port).filter(|port| *port != 0),
                ))
            })();
            if let Some((hostname, address, dir_port)) = lenient_option(validate, parsed)?
            {
                document.hostname = Some(hostname);
                document.address = Some(address);
                document.dir_port = dir_port;
            }
        }
        if let Ok(value) = entries.value("fingerprint") {
            document.fingerprint =
                lenient_option(validate, parse_forty_hex("fingerprint", value))?;
        }
        if entries.contains("dir-signing-key") {
            document.signing_key = lenient_option(
                validate,
                key_block(&entries, "dir-signing-key", "RSA PUBLIC KEY")
                    .map(|(_, block)| block),
            )?;
        }
        if let Ok(value) = entries.value("client-versions") {
            document.client_versions = value.split(',').map(str::to_string).collect();
        }
        if let Ok(value) = entries.value("server-versions") {
            document.server_versions = value.split(',').map(str::to_string).collect();
        }
        if let Ok(value) = entries.value("published") {
            document.published =
                lenient_option(validate, parse_timestamp_line("published", value))?;
        }
        if let Ok(value) = entries.value("dir-options") {
            document.options = value.split_whitespace().map(str::to_string).collect();
        }
        if entries.contains("directory-signature")
            && let Some((authority, block)) = lenient_option(
                validate,
                key_block(&entries, "directory-signature", "SIGNATURE"),
            )?
        {
            document.signing_authority = Some(authority);
            document.signature = Some(block);
        }
        if validate
            && document.options.iter().any(|option| option == "Versions")
            && !(entries.contains("client-versions")
                && entries.contains("server-versions"))
        {
            return Err(Error::parse(format!(
                "Version 2 network status documents must have a 'client-versions' and \
                'server-versions' when 'Versions' is listed among its dir-options:\n{}",
                String::from_utf8_lossy(content)
            )));
        }
        Ok(document)
    }

    fn check_constraints(entries: &Entries, content: &[u8]) -> Result<()> {
        let raw = String::from_utf8_lossy(content);
        for (keyword, mandatory) in NETWORK_STATUS_V2_FIELDS {
            if mandatory && !entries.contains(keyword) {
                return Err(Error::parse(format!(
                    "Network status document (v2) must have a '{keyword}' line:\n{raw}"
                )));
            }
            let count = entries.get(keyword).map_or(0, <[_]>::len);
            if count > 1 {
                return Err(Error::parse(format!(
                    "Network status document (v2) can only have a single '{keyword}' \
                    line, got {count}:\n{raw}"
                )));
            }
        }
        match entries.first_key() {
            Some("network-status-version") => Ok(()),
            _ => Err(Error::parse(format!(
                "Network status document (v2) are expected to start with a \
                'network-status-version' line:\n{raw}"
            ))),
        }
    }

    pub fn content(attributes: &Attributes, exclude: &[&str]) -> Vec<u8> {
        descriptor_content(
            attributes,
            exclude,
            &[
                ("network-status-version", AttrValue::Text("2".to_string())),
                (
                    "dir-source",
                    AttrValue::Text(format!(
                        "{} {} 80",
                        random_ipv4_address(),
                        random_ipv4_address()
                    )),
                ),
                ("fingerprint", AttrValue::Text(random_fingerprint())),
                (
                    "contact",
                    AttrValue::Text("arma at mit dot edu".to_string()),
                ),
                ("published", AttrValue::Text(random_date())),
                (
                    "dir-signing-key",
                    AttrValue::Text(random_crypto_blob(Some("RSA PUBLIC KEY"))),
                ),
            ],
            &[(
                "directory-signature",
                AttrValue::Text(format!(
                    "moria2{}",
                    random_crypto_blob(Some("SIGNATURE"))
                )),
            )],
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

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BridgeNetworkStatusDocument {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub published: Option<NaiveDateTime>,
    pub routers: IndexMap<String, RouterStatusEntryV2>,
}

impl BridgeNetworkStatusDocument {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        let mut cursor = LineCursor::new(content);
        let first = cursor
            .read_line()
            .map(|line| String::from_utf8_lossy(line).into_owned())
            .unwrap_or_default();
        let mut published = None;
        match first.strip_prefix("published ") {
            Some(rest) => {
                let rest = rest.trim();
                match parse_timestamp(rest) {
                    Ok(timestamp) => published = Some(timestamp),
                    Err(_) if validate => {
                        return Err(Error::parse(format!(
                            "Bridge network status document's 'published' time wasn't \
                            parsable: {rest}"
                        )));
                    }
                    Err(_) => {}
                }
            }
            None if validate => {
                return Err(Error::parse(format!(
                    "Bridge network status documents must start with a 'published' \
                    line:\n{}",
                    String::from_utf8_lossy(content)
                )));
            }
            None => {}
        }
        let routers = parse_entry_section(&mut cursor, validate, &[], None, |bytes| {
            RouterStatusEntryV2::parse(bytes, validate)
        })?;
        Ok(Self {
            raw_contents: content.to_vec(),
            published,
            routers: routers
                .into_iter()
                .filter_map(|entry| Some((entry.fingerprint.clone()?, entry)))
                .collect(),
        })
    }
}
