use std::collections::BTreeSet;
use std::ops::Deref;

use chrono::NaiveDateTime;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha1::{Digest, Sha1};

use crate::address::{is_valid_ipv4_address, is_valid_ipv6_address, parse_port};
use crate::descriptor::certificate::{Ed25519Certificate, SIG_PREFIX_SERVER_DESC};
use crate::descriptor::router_status::RouterStatusEntryV3;
use crate::descriptor::{
    AttrValue, Attributes, DigestEncoding, DigestHash, Entries, History, LineCursor,
    Protocols, ReadOptions, attr, bytes_for_block, content_range, decode_base64,
    descriptor_components, descriptor_content, encode_digest, hash_bytes, key_block,
    lenient, lenient_option, parse_bytes_line, parse_forty_hex, parse_history,
    parse_integer, parse_protocol_line, parse_timestamp_line, random_crypto_blob,
    random_date, random_ipv4_address, random_nickname, truncated_base64,
};
use crate::error::{Error, Result};
use crate::exit_policy::{ExitPolicy, MicroExitPolicy};
use crate::validation::{is_hex_digits, is_valid_fingerprint, is_valid_nickname};
use crate::version::Version;

const REQUIRED_FIELDS: [&str; 6] = [
    "router",
    "bandwidth",
    "published",
    "onion-key",
    "signing-key",
    "router-signature",
];

const SINGLE_FIELDS: [&str; 23] = [
    "identity-ed25519",
    "master-key-ed25519",
    "platform",
    "fingerprint",
    "hibernating",
    "uptime",
    "contact",
    "read-history",
    "write-history",
    "eventdns",
    "bridge-distribution-request",
    "family",
    "caches-extra-info",
    "extra-info-digest",
    "hidden-service-dir",
    "protocols",
    "allow-single-hop-exits",
    "tunnelled-dir-server",
    "proto",
    "onion-key-crosscert",
    "ntor-onion-key",
    "ntor-onion-key-crosscert",
    "router-sig-ed25519",
];

const COMMON_KEYWORDS: [&str; 23] = [
    "router",
    "bandwidth",
    "platform",
    "published",
    "fingerprint",
    "contact",
    "hibernating",
    "extra-info-digest",
    "hidden-service-dir",
    "uptime",
    "protocols",
    "ntor-onion-key",
    "or-address",
    "read-history",
    "write-history",
    "ipv6-policy",
    "allow-single-hop-exits",
    "tunnelled-dir-server",
    "proto",
    "caches-extra-info",
    "bridge-distribution-request",
    "family",
    "eventdns",
];

const RELAY_KEYWORDS: [&str; 8] = [
    "identity-ed25519",
    "master-key-ed25519",
    "router-sig-ed25519",
    "onion-key",
    "onion-key-crosscert",
    "ntor-onion-key-crosscert",
    "signing-key",
    "router-signature",
];

const BRIDGE_KEYWORDS: [&str; 3] = [
    "master-key-ed25519",
    "router-digest-sha256",
    "router-digest",
];

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ServerDescriptor {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub unrecognized_lines: Vec<String>,
    pub annotation_lines: Vec<String>,
    pub nickname: Option<String>,
    pub fingerprint: Option<String>,
    #[serde(serialize_with = "crate::descriptor::serialize_optional_text")]
    pub contact: Option<Vec<u8>>,
    pub published: Option<NaiveDateTime>,
    pub exit_policy: ExitPolicy,
    pub address: Option<String>,
    pub or_port: Option<u16>,
    pub socks_port: Option<u16>,
    pub dir_port: Option<u16>,
    #[serde(serialize_with = "crate::descriptor::serialize_optional_text")]
    pub platform: Option<Vec<u8>>,
    pub tor_version: Option<Version>,
    pub operating_system: Option<String>,
    pub uptime: Option<i64>,
    pub exit_policy_v6: MicroExitPolicy,
    pub bridge_distribution: String,
    pub family: BTreeSet<String>,
    pub average_bandwidth: Option<u64>,
    pub burst_bandwidth: Option<u64>,
    pub observed_bandwidth: Option<u64>,
    pub link_protocols: Option<Vec<String>>,
    pub circuit_protocols: Option<Vec<String>>,
    pub is_hidden_service_dir: bool,
    pub hibernating: bool,
    pub allow_single_hop_exits: bool,
    pub allow_tunneled_dir_requests: bool,
    pub protocols: Protocols,
    pub extra_info_cache: bool,
    pub extra_info_digest: Option<String>,
    pub extra_info_sha256_digest: Option<String>,
    pub eventdns: Option<bool>,
    pub ntor_onion_key: Option<String>,
    pub or_addresses: Vec<(String, u16, bool)>,
    pub read_history: Option<History>,
    pub write_history: Option<History>,
    pub hidden_service_dir: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RelayServerDescriptor {
    #[serde(flatten)]
    pub common: ServerDescriptor,
    pub certificate: Option<Ed25519Certificate>,
    pub ed25519_certificate: Option<String>,
    pub ed25519_master_key: Option<String>,
    pub ed25519_signature: Option<String>,
    pub onion_key: Option<String>,
    pub onion_key_crosscert: Option<String>,
    pub ntor_onion_key_crosscert: Option<String>,
    pub ntor_onion_key_crosscert_sign: Option<String>,
    pub signing_key: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BridgeServerDescriptor {
    #[serde(flatten)]
    pub common: ServerDescriptor,
    pub ed25519_certificate_hash: Option<String>,
    pub router_digest_sha256: Option<String>,
    digest: Option<String>,
}

impl Deref for RelayServerDescriptor {
    type Target = ServerDescriptor;

    fn deref(&self) -> &ServerDescriptor {
        &self.common
    }
}

impl Deref for BridgeServerDescriptor {
    type Target = ServerDescriptor;

    fn deref(&self) -> &ServerDescriptor {
        &self.common
    }
}

struct RouterLine {
    nickname: String,
    address: String,
    or_port: u16,
    socks_port: Option<u16>,
    dir_port: Option<u16>,
}

fn parse_router_line(entries: &Entries) -> Result<RouterLine> {
    let value = entries.value("router")?;
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 5 {
        return Err(Error::parse(format!(
            "Router line must have five values: router {value}"
        )));
    }
    if !is_valid_nickname(parts[0]) {
        return Err(Error::parse(format!(
            "Router line entry isn't a valid nickname: {}",
            parts[0]
        )));
    }
    if !is_valid_ipv4_address(parts[1]) {
        return Err(Error::parse(format!(
            "Router line entry isn't a valid IPv4 address: {}",
            parts[1]
        )));
    }
    let port = |index: usize, label: &str| {
        parse_port(parts[index], true).ok_or_else(|| {
            Error::parse(format!(
                "Router line's {label} is invalid: {}",
                parts[index]
            ))
        })
    };
    let (or_port, socks_port, dir_port) = (
        port(2, "ORPort")?,
        port(3, "SocksPort")?,
        port(4, "DirPort")?,
    );
    Ok(RouterLine {
        nickname: parts[0].to_string(),
        address: parts[1].to_string(),
        or_port,
        socks_port: Some(socks_port).filter(|port| *port != 0),
        dir_port: Some(dir_port).filter(|port| *port != 0),
    })
}

fn parse_bandwidth_line(entries: &Entries) -> Result<(u64, u64, u64)> {
    let value = entries.value("bandwidth")?;
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(Error::parse(format!(
            "Bandwidth line must have three values: bandwidth {value}"
        )));
    }
    let number = |index: usize, label: &str| -> Result<u64> {
        let text = parts[index];
        match !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) {
            true => text.parse().map_err(|_| {
                Error::parse(format!("Bandwidth line's {label} isn't numeric: {text}"))
            }),
            false => Err(Error::parse(format!(
                "Bandwidth line's {label} isn't numeric: {text}"
            ))),
        }
    };
    Ok((
        number(0, "average rate")?,
        number(1, "burst rate")?,
        number(2, "observed rate")?,
    ))
}

fn parse_platform(value: &str) -> Option<(String, String)> {
    let rest = value
        .strip_prefix("node-")
        .unwrap_or(value)
        .strip_prefix("Tor ")?;
    let version_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let version = &rest[..version_end];
    let after = &rest[version_end..];
    let split = after.rfind(" on ")?;
    Some((version.to_string(), after[split + 4..].to_string()))
}

fn parse_fingerprint_line(value: &str) -> Result<String> {
    if value.split(' ').any(|group| group.len() != 4) {
        return Err(Error::parse(format!(
            "Fingerprint line should have groupings of four hex digits: {value}"
        )));
    }
    let fingerprint = value.replace(' ', "");
    match is_valid_fingerprint(&fingerprint, false) {
        true => Ok(fingerprint),
        false => Err(Error::parse(format!(
            "Tor relay fingerprints consist of forty hex digits: {value}"
        ))),
    }
}

fn parse_extra_info_digest(value: &str) -> Result<(String, Option<String>)> {
    let parts: Vec<&str> = value.split(' ').collect();
    match is_hex_digits(parts[0], 40) {
        true => Ok((
            parts[0].to_string(),
            parts.get(1).map(|digest| digest.to_string()),
        )),
        false => Err(Error::parse(format!(
            "extra-info-digest should be 40 hex characters: {}",
            parts[0]
        ))),
    }
}

fn parse_protocols_line(value: &str) -> Result<(Vec<String>, Vec<String>)> {
    let invalid = || {
        Error::parse(format!(
            "Protocols line did not match the expected pattern: protocols {value}"
        ))
    };
    let rest = value.strip_prefix("Link ").ok_or_else(invalid)?;
    let split = rest.find(" Circuit ").ok_or_else(invalid)?;
    let link = rest[..split].split(' ').map(str::to_string).collect();
    let circuit = rest[split + 9..].split(' ').map(str::to_string).collect();
    Ok((link, circuit))
}

fn parse_or_addresses(entries: &Entries) -> Result<Vec<(String, u16, bool)>> {
    let mut addresses = Vec::new();
    for entry in entries.values("or-address") {
        let Some((address, port)) = entry.rsplit_once(':') else {
            return Err(Error::parse(format!(
                "or-address line missing a colon: or-address {entry}"
            )));
        };
        let is_ipv6 = is_valid_ipv6_address(address, true);
        if !is_valid_ipv4_address(address) && !is_ipv6 {
            return Err(Error::parse(format!(
                "or-address line has a malformed address: or-address {entry}"
            )));
        }
        let Some(port) = parse_port(port, false) else {
            return Err(Error::parse(format!(
                "or-address line has a malformed port: or-address {entry}"
            )));
        };
        addresses.push((
            address
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
            port,
            is_ipv6,
        ));
    }
    Ok(addresses)
}

fn required_fields(is_bridge: bool) -> Vec<&'static str> {
    match is_bridge {
        false => REQUIRED_FIELDS.to_vec(),
        true => {
            let mut fields = vec!["router-digest"];
            fields.extend(REQUIRED_FIELDS.iter().filter(|field| {
                !matches!(**field, "onion-key" | "signing-key" | "router-signature")
            }));
            fields
        }
    }
}

fn check_constraints(
    entries: &Entries,
    is_bridge: bool,
    has_exit_policy: bool,
    has_ed25519: bool,
) -> Result<()> {
    let required = required_fields(is_bridge);
    for keyword in &required {
        if !entries.contains(keyword) {
            return Err(Error::parse(format!(
                "Descriptor must have a '{keyword}' entry"
            )));
        }
    }
    for keyword in required.iter().chain(SINGLE_FIELDS.iter()) {
        if entries.get(keyword).is_some_and(|values| values.len() > 1) {
            return Err(Error::parse(format!(
                "The '{keyword}' entry can only appear once in a descriptor"
            )));
        }
    }
    if entries.first_key() != Some("router") {
        return Err(Error::parse("Descriptor must start with a 'router' entry"));
    }
    if !is_bridge && entries.last_key() != Some("router-signature") {
        return Err(Error::parse(
            "Descriptor must end with a 'router-signature' entry",
        ));
    }
    if has_ed25519 {
        if !entries.contains("router-sig-ed25519") {
            return Err(Error::parse(
                "Descriptor must have router-sig-ed25519 entry to accompany \
                identity-ed25519",
            ));
        }
        let keys: Vec<&String> = entries.keys().collect();
        let tail = &keys[keys.len().saturating_sub(2)..];
        if !tail.iter().any(|key| key.as_str() == "router-sig-ed25519") {
            return Err(Error::parse(
                "Descriptor must have 'router-sig-ed25519' as the next-to-last entry",
            ));
        }
    }
    match has_exit_policy {
        true => Ok(()),
        false => Err(Error::parse(
            "Descriptor must have at least one 'accept' or 'reject' entry",
        )),
    }
}

fn parse_common(
    content: &[u8],
    entries: &Entries,
    policy_lines: &[String],
    annotation_lines: Vec<String>,
    validate: bool,
    is_bridge: bool,
) -> Result<ServerDescriptor> {
    let mut common = ServerDescriptor {
        raw_contents: content.to_vec(),
        unrecognized_lines: Vec::new(),
        annotation_lines,
        nickname: None,
        fingerprint: None,
        contact: None,
        published: None,
        exit_policy: ExitPolicy::new::<&str>(&[])?,
        address: None,
        or_port: None,
        socks_port: None,
        dir_port: None,
        platform: None,
        tor_version: None,
        operating_system: None,
        uptime: None,
        exit_policy_v6: MicroExitPolicy::new("reject 1-65535")?,
        bridge_distribution: "any".to_string(),
        family: BTreeSet::new(),
        average_bandwidth: None,
        burst_bandwidth: None,
        observed_bandwidth: None,
        link_protocols: None,
        circuit_protocols: None,
        is_hidden_service_dir: false,
        hibernating: false,
        allow_single_hop_exits: false,
        allow_tunneled_dir_requests: false,
        protocols: Protocols::new(),
        extra_info_cache: false,
        extra_info_digest: None,
        extra_info_sha256_digest: None,
        eventdns: None,
        ntor_onion_key: None,
        or_addresses: Vec::new(),
        read_history: None,
        write_history: None,
        hidden_service_dir: vec!["2".to_string()],
    };
    let mut recognized: Vec<&str> = COMMON_KEYWORDS.to_vec();
    recognized.extend(match is_bridge {
        true => BRIDGE_KEYWORDS.as_slice(),
        false => RELAY_KEYWORDS.as_slice(),
    });
    common.unrecognized_lines = entries.unrecognized_lines(&recognized);
    if entries.contains("router")
        && let Some(line) = lenient_option(validate, parse_router_line(entries))?
    {
        common.nickname = Some(line.nickname);
        common.address = Some(line.address);
        common.or_port = Some(line.or_port);
        common.socks_port = line.socks_port;
        common.dir_port = line.dir_port;
    }
    if entries.contains("bandwidth")
        && let Some((average, burst, observed)) =
            lenient_option(validate, parse_bandwidth_line(entries))?
    {
        common.average_bandwidth = Some(average);
        common.burst_bandwidth = Some(burst);
        common.observed_bandwidth = Some(observed);
    }
    common.platform = parse_bytes_line(content, "platform");
    if let Ok(value) = entries.value("platform")
        && let Some((version, operating_system)) = parse_platform(value)
    {
        common.tor_version = Version::new(&version).ok();
        common.operating_system = Some(operating_system);
    }
    if let Ok(value) = entries.value("published") {
        common.published =
            lenient_option(validate, parse_timestamp_line("published", value))?;
    }
    if let Ok(value) = entries.value("fingerprint") {
        common.fingerprint = lenient_option(validate, parse_fingerprint_line(value))?;
    }
    common.contact = parse_bytes_line(content, "contact");
    if let Ok(value) = entries.value("hibernating") {
        match value {
            "0" | "1" => common.hibernating = value == "1",
            _ => {
                lenient::<()>(
                    validate,
                    Err(Error::parse(format!(
                        "Hibernating line had an invalid value, must be zero or one: \
                        {value}"
                    ))),
                )?;
            }
        }
    }
    if let Ok(value) = entries.value("extra-info-digest")
        && let Some((digest, sha256)) =
            lenient_option(validate, parse_extra_info_digest(value))?
    {
        common.extra_info_digest = Some(digest);
        common.extra_info_sha256_digest = sha256;
    }
    common.is_hidden_service_dir = entries.contains("hidden-service-dir");
    if let Ok(value) = entries.value("uptime") {
        common.uptime = lenient_option(validate, parse_integer("uptime", value, true))?;
    }
    if let Ok(value) = entries.value("protocols")
        && let Some((link, circuit)) =
            lenient_option(validate, parse_protocols_line(value))?
    {
        common.link_protocols = Some(link);
        common.circuit_protocols = Some(circuit);
    }
    if let Ok(value) = entries.value("ntor-onion-key") {
        common.ntor_onion_key = Some(value.to_string());
    }
    if entries.contains("or-address") {
        common.or_addresses = lenient(validate, parse_or_addresses(entries))?;
    }
    for (keyword, target) in [
        ("read-history", &mut common.read_history),
        ("write-history", &mut common.write_history),
    ] {
        if let Ok(value) = entries.value(keyword) {
            *target = lenient_option(validate, parse_history(keyword, value))?;
        }
    }
    if let Ok(value) = entries.value("ipv6-policy")
        && let Some(policy) = lenient_option(validate, MicroExitPolicy::new(value))?
    {
        common.exit_policy_v6 = policy;
    }
    common.allow_single_hop_exits = entries.contains("allow-single-hop-exits");
    common.allow_tunneled_dir_requests = entries.contains("tunnelled-dir-server");
    if let Ok(value) = entries.value("proto") {
        common.protocols = lenient(validate, parse_protocol_line("proto", value))?;
    }
    common.extra_info_cache = entries.contains("caches-extra-info");
    if let Ok(value) = entries.value("bridge-distribution-request") {
        common.bridge_distribution = value.to_string();
    }
    if let Ok(value) = entries.value("family") {
        common.family = value.split(' ').map(str::to_string).collect();
    }
    if let Ok(value) = entries.value("eventdns") {
        common.eventdns = Some(value == "1");
    }
    common.exit_policy = match policy_lines.first().map(String::as_str) {
        Some("reject *:*") => ExitPolicy::new(&["reject *:*"])?,
        _ => match ExitPolicy::new(policy_lines) {
            Ok(policy) => policy,
            Err(error) if validate => return Err(error),
            Err(_) => ExitPolicy::from_rules(
                policy_lines
                    .iter()
                    .filter_map(|line| {
                        crate::exit_policy::ExitPolicyRule::new(line.trim()).ok()
                    })
                    .collect(),
                true,
            ),
        },
    };
    if validate
        && let (Some(uptime), Some(version)) = (common.uptime, &common.tor_version)
        && uptime < 0
        && *version >= Version::new("0.1.2.7")?
    {
        return Err(Error::parse(format!(
            "Descriptor for version '{version}' had a negative uptime value: {uptime}"
        )));
    }
    Ok(common)
}

pub fn parse_annotations(raw: &[u8]) -> Vec<String> {
    raw.split(|byte| *byte == b'\n')
        .map(|line| String::from_utf8_lossy(line.trim_ascii()).into_owned())
        .filter(|line| !line.is_empty())
        .collect()
}

pub fn annotation_map(lines: &[String]) -> indexmap::IndexMap<String, Option<String>> {
    lines
        .iter()
        .map(|line| match line.split_once(' ') {
            Some((key, value)) => (key.to_string(), Some(value.to_string())),
            None => (line.clone(), None),
        })
        .collect()
}

fn rsa_public_key(block: &str) -> Result<RsaPublicKey> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    let der = bytes_for_block(block)?;
    RsaPublicKey::from_pkcs1_der(&der)
        .map_err(|error| Error::parse(format!("Invalid RSA public key: {error}")))
}

pub fn digest_for_signature(
    signing_key_block: &str,
    signature_block: &str,
) -> Result<Vec<u8>> {
    let key = rsa_public_key(signing_key_block)?;
    if key.n().bits() > 4096 {
        return Err(Error::parse(
            "RSA keys larger than 4096 bits aren't supported",
        ));
    }
    let signature = bytes_for_block(signature_block)?;
    let modulus_length = key.size();
    if signature.len() != modulus_length {
        return Err(Error::parse("Verification failed, malformed data"));
    }
    let decrypted = BigUint::from_bytes_be(&signature).modpow(key.e(), key.n());
    let mut block = decrypted.to_bytes_be();
    if block.len() > modulus_length {
        return Err(Error::parse("Verification failed, malformed data"));
    }
    block.splice(0..0, vec![0u8; modulus_length - block.len()]);
    if block[..2] != [0x00, 0x01] {
        return Err(Error::parse("Verification failed, identifier missing"));
    }
    let separator = block[2..]
        .iter()
        .position(|byte| *byte != 0xff)
        .map(|offset| offset + 2)
        .ok_or_else(|| Error::parse("Verification failed, seperator not found"))?;
    if block[separator] != 0x00 || separator < 10 {
        return Err(Error::parse("Verification failed, seperator not found"));
    }
    Ok(block[separator + 1..].to_vec())
}

impl RelayServerDescriptor {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        Self::parse_with_options(content, validate, Vec::new(), false)
    }

    pub fn parse_with_options(
        content: &[u8],
        validate: bool,
        annotations: Vec<String>,
        skip_crypto_validation: bool,
    ) -> Result<Self> {
        let (entries, policy_lines) = descriptor_components(
            content,
            validate,
            &["accept", "reject"],
            &["contact", "platform"],
        )?;
        let common = parse_common(
            content,
            &entries,
            &policy_lines,
            annotations,
            validate,
            false,
        )?;
        if validate {
            check_constraints(
                &entries,
                false,
                !common.exit_policy.is_empty(),
                entries.contains("identity-ed25519"),
            )?;
        }
        let mut descriptor = Self {
            common,
            certificate: None,
            ed25519_certificate: None,
            ed25519_master_key: None,
            ed25519_signature: None,
            onion_key: None,
            onion_key_crosscert: None,
            ntor_onion_key_crosscert: None,
            ntor_onion_key_crosscert_sign: None,
            signing_key: None,
            signature: None,
        };
        if entries.contains("identity-ed25519")
            && let Some((_, block)) = lenient_option(
                validate,
                key_block(&entries, "identity-ed25519", "ED25519 CERT"),
            )?
        {
            descriptor.certificate =
                lenient_option(validate, Ed25519Certificate::from_base64(&block))?;
            descriptor.ed25519_certificate = Some(block);
        }
        if let Ok(value) = entries.value("master-key-ed25519") {
            descriptor.ed25519_master_key = Some(value.to_string());
        }
        if let Ok(value) = entries.value("router-sig-ed25519") {
            descriptor.ed25519_signature = Some(value.to_string());
        }
        for (keyword, kind, target) in [
            ("onion-key", "RSA PUBLIC KEY", &mut descriptor.onion_key),
            (
                "onion-key-crosscert",
                "CROSSCERT",
                &mut descriptor.onion_key_crosscert,
            ),
            ("signing-key", "RSA PUBLIC KEY", &mut descriptor.signing_key),
            ("router-signature", "SIGNATURE", &mut descriptor.signature),
        ] {
            if entries.contains(keyword) {
                *target = lenient_option(
                    validate,
                    key_block(&entries, keyword, kind).map(|(_, block)| block),
                )?;
            }
        }
        if entries.contains("ntor-onion-key-crosscert")
            && let Some((sign, block)) = lenient_option(
                validate,
                key_block(&entries, "ntor-onion-key-crosscert", "ED25519 CERT"),
            )?
        {
            descriptor.ntor_onion_key_crosscert = Some(block);
            descriptor.ntor_onion_key_crosscert_sign = Some(sign);
        }
        if validate {
            descriptor.check_relay_constraints()?;
            descriptor.validate_signatures(skip_crypto_validation)?;
        }
        Ok(descriptor)
    }

    fn check_relay_constraints(&self) -> Result<()> {
        if self.ed25519_certificate.is_some() {
            if self.onion_key_crosscert.is_none() {
                return Err(Error::parse(
                    "Descriptor must have a 'onion-key-crosscert' when identity-ed25519 \
                    is present",
                ));
            }
            if self.ed25519_signature.is_none() {
                return Err(Error::parse(
                    "Descriptor must have a 'router-sig-ed25519' when identity-ed25519 \
                    is present",
                ));
            }
        }
        Ok(())
    }

    fn validate_signatures(&self, skip_crypto_validation: bool) -> Result<()> {
        if let (Some(fingerprint), Some(signing_key)) =
            (&self.common.fingerprint, &self.signing_key)
        {
            let key_hash = hex::encode(Sha1::digest(bytes_for_block(signing_key)?));
            if key_hash != fingerprint.to_lowercase() {
                return Err(Error::parse(format!(
                    "Fingerprint does not match the hash of our signing key \
                    (fingerprint: {}, signing key hash: {key_hash})",
                    fingerprint.to_lowercase()
                )));
            }
        }
        if !skip_crypto_validation {
            self.validate_rsa_signatures()?;
        }
        if let Some(certificate) = &self.certificate {
            self.validate_ed25519(certificate)?;
        }
        Ok(())
    }

    fn validate_rsa_signatures(&self) -> Result<()> {
        let (Some(signing_key), Some(signature)) = (&self.signing_key, &self.signature)
        else {
            return Ok(());
        };
        let signed = digest_for_signature(signing_key, signature)?;
        let local = self.digest_bytes(DigestHash::Sha1)?;
        if signed != local {
            return Err(Error::parse(format!(
                "Decrypted digest does not match local digest (calculated: {}, local: \
                {})",
                hex::encode_upper(&signed),
                hex::encode_upper(&local)
            )));
        }
        if let (Some(crosscert), Some(onion_key)) =
            (&self.onion_key_crosscert, &self.onion_key)
        {
            let crosscert_digest = digest_for_signature(onion_key, crosscert)?;
            let expected = self.onion_key_crosscert_digest()?;
            if crosscert_digest != expected {
                return Err(Error::parse(format!(
                    "Decrypted onion-key-crosscert digest does not match local digest \
                    (calculated: {}, local: {})",
                    hex::encode_upper(&crosscert_digest),
                    hex::encode_upper(&expected)
                )));
            }
        }
        Ok(())
    }

    fn onion_key_crosscert_digest(&self) -> Result<Vec<u8>> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or_else(|| Error::parse("Descriptor lacks a signing-key"))?;
        let master = self
            .ed25519_master_key
            .as_ref()
            .ok_or_else(|| Error::parse("Descriptor lacks a master-key-ed25519"))?;
        let mut data = Sha1::digest(bytes_for_block(signing_key)?).to_vec();
        data.extend(decode_base64(master)?);
        Ok(data)
    }

    fn validate_ed25519(&self, certificate: &Ed25519Certificate) -> Result<()> {
        let prefix_end = "router-sig-ed25519 ";
        let signed = content_range(&self.common.raw_contents, None, Some(prefix_end))?;
        let signed_content =
            sha2::Sha256::digest([SIG_PREFIX_SERVER_DESC, &signed].concat());
        let signature = decode_base64(
            self.ed25519_signature
                .as_deref()
                .ok_or_else(|| Error::parse("Descriptor lacks a router-sig-ed25519"))?,
        )?;
        let master_key = match &self.ed25519_master_key {
            Some(master) => decode_base64(master)?,
            None => certificate
                .signing_key()
                .map(<[u8]>::to_vec)
                .ok_or_else(|| {
                    Error::parse("Server descriptor missing an ed25519 signing key")
                })?,
        };
        certificate.verify_certificate_signature(&master_key)?;
        certificate.verify_signature(&signed_content, &signature)
    }

    pub fn digest_bytes(&self, hash: DigestHash) -> Result<Vec<u8>> {
        let content = content_range(
            &self.common.raw_contents,
            Some("router"),
            Some("\nrouter-signature\n"),
        )?;
        Ok(hash_bytes(hash, &content))
    }

    pub fn digest(&self, hash: DigestHash, encoding: DigestEncoding) -> Result<String> {
        Ok(encode_digest(&self.digest_bytes(hash)?, encoding))
    }

    pub fn parse_many(content: &[u8], validate: bool) -> Result<Vec<Self>> {
        let mut descriptors = Vec::new();
        for (annotations, text) in split_server_descriptors(content, false, validate)? {
            descriptors.push(Self::parse_with_options(
                &text,
                validate,
                annotations,
                false,
            )?);
        }
        Ok(descriptors)
    }

    pub fn make_router_status_entry(&self) -> Result<RouterStatusEntryV3> {
        let fingerprint = self.common.fingerprint.as_ref().ok_or_else(|| {
            Error::invalid_input(
                "Server descriptor lacks a fingerprint. This is an \
                optional field, but required to make a router status entry.",
            )
        })?;
        let published = self.common.published.ok_or_else(|| {
            Error::invalid_input("Server descriptor lacks a published time")
        })?;
        let digest = self.digest_bytes(DigestHash::Sha1)?;
        let nickname = self.common.nickname.clone().unwrap_or_default();
        let r_line = [
            nickname,
            truncated_base64(
                &hex::decode(fingerprint)
                    .map_err(|error| Error::parse(error.to_string()))?,
            ),
            truncated_base64(&digest),
            published.format("%Y-%m-%d %H:%M:%S").to_string(),
            self.common.address.clone().unwrap_or_default(),
            self.common.or_port.unwrap_or(0).to_string(),
            self.common.dir_port.unwrap_or(0).to_string(),
        ]
        .join(" ");
        let mut attributes: Attributes = vec![
            attr("r", &r_line),
            attr(
                "w",
                &format!("Bandwidth={}", self.common.average_bandwidth.unwrap_or(0)),
            ),
            attr("p", &self.common.exit_policy.summary().replace(", ", ",")),
        ];
        if let Some(version) = &self.common.tor_version {
            attributes.push(attr("v", &format!("Tor {version}")));
        }
        if !self.common.or_addresses.is_empty() {
            attributes.push((
                "a".to_string(),
                AttrValue::Lines(
                    self.common
                        .or_addresses
                        .iter()
                        .map(|(address, port, _)| format!("{address}:{port}"))
                        .collect(),
                ),
            ));
        }
        if let Some(certificate) = &self.certificate {
            attributes.push(attr(
                "id",
                &format!("ed25519 {}", truncated_base64(&certificate.key)),
            ));
        }
        RouterStatusEntryV3::create(&attributes, &[], true)
    }

    pub fn content(
        attributes: &Attributes,
        exclude: &[&str],
        signing_key: Option<&RsaPrivateKey>,
        exit_policy: Option<&ExitPolicy>,
    ) -> Result<Vec<u8>> {
        let default_policy = ExitPolicy::new(&["reject *:*"])?;
        let policy = exit_policy.unwrap_or(&default_policy);
        let mut header: Vec<(String, AttrValue)> = vec![
            attr(
                "router",
                &format!("{} {} 9001 0 0", random_nickname(), random_ipv4_address()),
            ),
            attr("published", &random_date()),
            attr("bandwidth", "153600 256000 104590"),
        ];
        for rule in policy.iter() {
            let line = rule.to_string();
            let (keyword, value) = line.split_once(' ').unwrap_or((&line, ""));
            header.push((keyword.to_string(), AttrValue::Text(value.to_string())));
        }
        header.push(attr(
            "onion-key",
            &random_crypto_blob(Some("RSA PUBLIC KEY")),
        ));
        header.push(attr(
            "signing-key",
            &random_crypto_blob(Some("RSA PUBLIC KEY")),
        ));
        let borrowed: Vec<(&str, AttrValue)> = header
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect();
        let Some(private_key) = signing_key else {
            let footer = [
                ("router-sig-ed25519", AttrValue::Remove),
                (
                    "router-signature",
                    AttrValue::Text(random_crypto_blob(Some("SIGNATURE"))),
                ),
            ];
            return Ok(descriptor_content(attributes, exclude, &borrowed, &footer));
        };
        if attributes
            .iter()
            .any(|(key, _)| key == "signing-key" || key == "router-signature")
        {
            return Err(Error::invalid_input(
                "Cannot sign the descriptor if a signing-key or router-signature has \
                been provided",
            ));
        }
        let public_block = signing_key_block(private_key)?;
        let mut attributes = attributes.clone();
        if !attributes.iter().any(|(key, _)| key == "fingerprint") {
            let fingerprint =
                hex::encode_upper(Sha1::digest(bytes_for_block(&public_block)?));
            let grouped = crate::formatting::split_by_length(&fingerprint, 4).join(" ");
            attributes.push(attr("fingerprint", &grouped));
        }
        attributes.push((
            "signing-key".to_string(),
            AttrValue::Text(format!("\n{public_block}")),
        ));
        let mut content = descriptor_content(&attributes, exclude, &borrowed, &[]);
        content.extend_from_slice(b"\nrouter-signature\n");
        append_router_signature(content, private_key)
    }

    pub fn create(
        attributes: &Attributes,
        exclude: &[&str],
        validate: bool,
        signing_key: Option<&RsaPrivateKey>,
        exit_policy: Option<&ExitPolicy>,
    ) -> Result<Self> {
        let content = Self::content(attributes, exclude, signing_key, exit_policy)?;
        Self::parse_with_options(&content, validate, Vec::new(), signing_key.is_none())
    }
}

pub fn create_signing_key() -> Result<RsaPrivateKey> {
    RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).map_err(|error| {
        Error::invalid_input(format!("Unable to generate a signing key: {error}"))
    })
}

pub fn signing_key_block(private_key: &RsaPrivateKey) -> Result<String> {
    use rsa::pkcs1::EncodeRsaPublicKey;
    let der = private_key
        .to_public_key()
        .to_pkcs1_der()
        .map_err(|error| Error::invalid_input(error.to_string()))?;
    let encoded = base64_standard(der.as_bytes());
    Ok(format!(
        "-----BEGIN RSA PUBLIC KEY-----\n{}\n-----END RSA PUBLIC KEY-----",
        crate::formatting::split_by_length(&encoded, 64).join("\n")
    ))
}

fn base64_standard(content: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(content)
}

pub fn append_router_signature(
    mut content: Vec<u8>,
    private_key: &RsaPrivateKey,
) -> Result<Vec<u8>> {
    let digest = Sha1::digest(&content);
    let signature = private_key
        .sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest)
        .map_err(|error| {
            Error::invalid_input(format!("Unable to sign the descriptor: {error}"))
        })?;
    let encoded = base64_standard(&signature);
    content.extend_from_slice(b"-----BEGIN SIGNATURE-----\n");
    content.extend_from_slice(
        crate::formatting::split_by_length(&encoded, 64)
            .join("\n")
            .as_bytes(),
    );
    content.extend_from_slice(b"\n-----END SIGNATURE-----\n");
    Ok(content)
}

impl BridgeServerDescriptor {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        Self::parse_with_annotations(content, validate, Vec::new())
    }

    pub fn parse_with_annotations(
        content: &[u8],
        validate: bool,
        annotations: Vec<String>,
    ) -> Result<Self> {
        let (entries, policy_lines) = descriptor_components(
            content,
            validate,
            &["accept", "reject"],
            &["contact", "platform"],
        )?;
        let common = parse_common(
            content,
            &entries,
            &policy_lines,
            annotations,
            validate,
            true,
        )?;
        if validate {
            check_constraints(&entries, true, !common.exit_policy.is_empty(), false)?;
        }
        let digest = match entries.value("router-digest") {
            Ok(value) => {
                lenient_option(validate, parse_forty_hex("router-digest", value))?
            }
            Err(_) => None,
        };
        Ok(Self {
            common,
            ed25519_certificate_hash: entries
                .value("master-key-ed25519")
                .ok()
                .map(str::to_string),
            router_digest_sha256: entries
                .value("router-digest-sha256")
                .ok()
                .map(str::to_string),
            digest,
        })
    }

    pub fn parse_many(content: &[u8], validate: bool) -> Result<Vec<Self>> {
        let mut descriptors = Vec::new();
        for (annotations, text) in split_server_descriptors(content, true, validate)? {
            descriptors.push(Self::parse_with_annotations(&text, validate, annotations)?);
        }
        Ok(descriptors)
    }

    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }

    pub fn is_scrubbed(&self) -> bool {
        self.scrubbing_issues().is_empty()
    }

    pub fn scrubbing_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();
        let address = self.common.address.clone().unwrap_or_default();
        if !address.starts_with("10.") {
            issues.push(format!(
                "Router line's address should be scrubbed to be '10.x.x.x': {address}"
            ));
        }
        if let Some(contact) = &self.common.contact {
            let text = String::from_utf8_lossy(contact);
            if text != "somebody" {
                issues.push(format!(
                    "Contact line should be scrubbed to be 'somebody', \
                    but instead had '{text}'"
                ));
            }
        }
        for (address, _, is_ipv6) in &self.common.or_addresses {
            if !is_ipv6 && !address.starts_with("10.") {
                issues.push(format!(
                    "or-address line's address should be scrubbed to be \
                    '10.x.x.x': {address}"
                ));
            } else if *is_ipv6 && !address.starts_with("fd9f:2e19:3bcf::") {
                issues.push(format!(
                    "or-address line's address should be scrubbed to be \
                    'fd9f:2e19:3bcf::xx:xxxx': {address}"
                ));
            }
        }
        for line in &self.common.unrecognized_lines {
            for (prefix, label) in [
                ("onion-key ", "onion-key"),
                ("signing-key ", "signing-key"),
                ("router-signature ", "signature"),
            ] {
                if line.starts_with(prefix) {
                    issues.push(format!(
                        "Bridge descriptors should have their {label} scrubbed: {line}"
                    ));
                }
            }
        }
        issues
    }

    pub fn content(attributes: &Attributes, exclude: &[&str]) -> Vec<u8> {
        descriptor_content(
            attributes,
            exclude,
            &[
                (
                    "router",
                    AttrValue::Text(format!(
                        "{} {} 9001 0 0",
                        random_nickname(),
                        random_ipv4_address()
                    )),
                ),
                (
                    "router-digest",
                    AttrValue::Text(
                        "006FD96BA35E7785A6A3B8B75FE2E2435A13BDB4".to_string(),
                    ),
                ),
                ("published", AttrValue::Text(random_date())),
                (
                    "bandwidth",
                    AttrValue::Text("409600 819200 5120".to_string()),
                ),
                ("reject", AttrValue::Text("*:*".to_string())),
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

fn split_server_descriptors(
    content: &[u8],
    is_bridge: bool,
    validate: bool,
) -> Result<Vec<(Vec<String>, Vec<u8>)>> {
    let mut cursor = LineCursor::new(content);
    let mut found = Vec::new();
    loop {
        let annotations = cursor.read_until_keywords(&["router"], ReadOptions::default());
        let annotation_lines = parse_annotations(&annotations.content);
        let mut body = if is_bridge {
            cursor
                .read_until_keywords(
                    &["router-digest"],
                    ReadOptions {
                        inclusive: true,
                        ..Default::default()
                    },
                )
                .content
        } else {
            let mut body = cursor
                .read_until_keywords(&["router-signature"], ReadOptions::default())
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
            body
        };
        if body.is_empty() {
            if validate && !annotation_lines.is_empty() {
                return Err(Error::parse(format!(
                    "Content conform to being a server descriptor:\n{}",
                    annotation_lines.join("\n")
                )));
            }
            break;
        }
        if body.starts_with(b"@type") {
            body = body
                .splitn(2, |byte| *byte == b'\n')
                .nth(1)
                .unwrap_or_default()
                .to_vec();
        }
        found.push((annotation_lines, body));
    }
    Ok(found)
}
