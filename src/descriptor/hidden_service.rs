use std::net::{Ipv4Addr, Ipv6Addr};

use aes::{Aes128, Aes256};
use base64::Engine;
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use sha1::Sha1;
use sha2::{Digest, Sha512};
use sha3::Sha3_256;
use shake::Shake256;
use shake::digest::{ExtendableOutput, Update, XofReader};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::address::{is_valid_ipv4_address, parse_port};
use crate::client::datatypes::{CertType, LinkSpecifier, Reader};
use crate::descriptor::certificate::{
    Ed25519Certificate, Ed25519Extension, SIG_PREFIX_HS_V3,
};
use crate::descriptor::server::digest_for_signature;
use crate::descriptor::{
    AttrValue, Attributes, Entries, LineCursor, ReadOptions, attr, bytes_for_block,
    content_range, decode_base64, descriptor_components, descriptor_content, key_block,
    lenient, lenient_option, parse_integer, parse_timestamp_line, random_crypto_blob,
    random_date, split_into_lines,
};
use crate::error::{Error, Result};
use crate::validation::is_valid_hidden_service_address;

const REQUIRED_V2_FIELDS: [&str; 7] = [
    "rendezvous-service-descriptor",
    "version",
    "permanent-key",
    "secret-id-part",
    "publication-time",
    "protocol-versions",
    "signature",
];
const REQUIRED_V3_FIELDS: [&str; 6] = [
    "hs-descriptor",
    "descriptor-lifetime",
    "descriptor-signing-key-cert",
    "revision-counter",
    "superencrypted",
    "signature",
];
const SINGLE_INTRODUCTION_POINT_FIELDS: [&str; 5] = [
    "introduction-point",
    "ip-address",
    "onion-port",
    "onion-key",
    "service-key",
];
const BASIC_AUTH: u8 = 1;
const STEALTH_AUTH: u8 = 2;
const CHECKSUM_CONSTANT: &[u8] = b".onion checksum";
const BLIND_STRING: &[u8] = b"Derive temporary signing key\0";
const BASEPOINT_STRING: &[u8] = concat!(
    "(15112221349535400772501151409588531511454012693041857206046113283949847762202, ",
    "46316835694926478169428394003475163141307993866256225615783033603165251855960)"
)
.as_bytes();
const PERIOD_ROTATION_MINUTES: i64 = 12 * 60;
pub const DEFAULT_TIME_PERIOD_LENGTH: u64 = 1440;
const SALT_LENGTH: usize = 16;
const MAC_LENGTH: usize = 32;
const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 16;
const PLAINTEXT_PADDING_MULTIPLE: usize = 10000;
const MESSAGE_START: &str = "-----BEGIN MESSAGE-----\n";
const MESSAGE_END: &str = "\n-----END MESSAGE-----";

type Aes256Ctr = Ctr128BE<Aes256>;
type Aes128Ctr = Ctr128BE<Aes128>;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct DecryptionFailure(pub String);

impl From<DecryptionFailure> for Error {
    fn from(failure: DecryptionFailure) -> Self {
        Error::Parse(failure.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IntroductionPoints {
    pub identifier: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub onion_key: Option<String>,
    pub service_key: Option<String>,
    pub intro_authentication: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IntroductionPointV3 {
    pub link_specifiers: Vec<LinkSpecifier>,
    pub onion_key_raw: Option<String>,
    pub auth_key_cert: Ed25519Certificate,
    pub enc_key_raw: Option<String>,
    pub enc_key_cert: Ed25519Certificate,
    pub legacy_key_raw: Option<String>,
    pub legacy_key_cert: Option<String>,
}

fn standard_base64(content: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(content)
}

fn certificate_block(entries: &Entries, keyword: &str) -> Result<Ed25519Certificate> {
    let entry = entries.entry(keyword)?;
    let (Some(contents), Some("ED25519 CERT")) =
        (&entry.block_contents, entry.block_type.as_deref())
    else {
        return Err(Error::parse(format!(
            "Expected {keyword} to have an ed25519 certificate, but was {}",
            entry.block_type.as_deref().unwrap_or("None")
        )));
    };
    Ed25519Certificate::from_base64(contents)
}

fn ntor_key(line: &str) -> Option<String> {
    line.strip_prefix("ntor ").map(str::to_string)
}

impl IntroductionPointV3 {
    pub fn parse(content: &[u8]) -> Result<Self> {
        let (entries, _) = descriptor_components(content, false, &[], &[])?;
        let link_specifiers =
            Self::parse_link_specifiers(entries.value("introduction-point")?)?;
        let legacy = |keyword: &str| {
            entries
                .get(keyword)
                .and_then(|values| values.first())
                .and_then(|entry| entry.block_contents.clone())
        };
        Ok(Self {
            link_specifiers,
            onion_key_raw: ntor_key(entries.value("onion-key")?),
            auth_key_cert: certificate_block(&entries, "auth-key")?,
            enc_key_raw: ntor_key(entries.value("enc-key")?),
            enc_key_cert: certificate_block(&entries, "enc-key-cert")?,
            legacy_key_raw: legacy("legacy-key"),
            legacy_key_cert: legacy("legacy-key-cert"),
        })
    }

    fn parse_link_specifiers(content: &str) -> Result<Vec<LinkSpecifier>> {
        let decoded = decode_base64(content).map_err(|error| {
            Error::parse(format!(
                "Unable to base64 decode introduction point ({error}): {content}"
            ))
        })?;
        let mut reader = Reader::new(&decoded);
        let count = reader.u8()?;
        let mut specifiers = Vec::new();
        for _ in 0..count {
            specifiers.push(LinkSpecifier::pop(&mut reader)?);
        }
        match reader.remaining() {
            0 => Ok(specifiers),
            _ => Err(Error::parse(format!(
                "Introduction point had excessive data ({content})"
            ))),
        }
    }

    pub fn create_for_address(
        address: &str,
        port: u16,
        expiration: Option<NaiveDateTime>,
    ) -> Result<Self> {
        if port == 0 {
            return Err(Error::invalid_input(format!("'{port}' is an invalid port")));
        }
        let specifier = if let Ok(parsed) = address.parse::<Ipv4Addr>() {
            LinkSpecifier::Ipv4 {
                address: parsed,
                port,
            }
        } else if let Ok(parsed) = address.parse::<Ipv6Addr>() {
            LinkSpecifier::Ipv6 {
                address: parsed,
                port,
            }
        } else {
            return Err(Error::invalid_input(format!(
                "'{address}' is not a valid IPv4 or IPv6 address"
            )));
        };
        Self::create_for_link_specifiers(vec![specifier], expiration)
    }

    pub fn create_for_link_specifiers(
        link_specifiers: Vec<LinkSpecifier>,
        expiration: Option<NaiveDateTime>,
    ) -> Result<Self> {
        let expiration =
            expiration.unwrap_or_else(|| Utc::now().naive_utc() + Duration::hours(54));
        let onion_key = standard_base64(
            PublicKey::from(&StaticSecret::from(rand::random::<[u8; 32]>())).as_bytes(),
        );
        let enc_key = standard_base64(
            PublicKey::from(&StaticSecret::from(rand::random::<[u8; 32]>())).as_bytes(),
        );
        let auth_secret = SigningKey::from_bytes(&rand::random());
        let signing_key = SigningKey::from_bytes(&rand::random());
        let auth_key = auth_secret.verifying_key().to_bytes();
        let extensions = vec![Ed25519Extension::signing_key_extension(
            signing_key.verifying_key().to_bytes(),
        )];
        let auth_key_cert = Ed25519Certificate::new(
            CertType::HsV3IntroAuth,
            Some(expiration),
            Some(1),
            auth_key,
            extensions.clone(),
            None,
            Some(&signing_key),
        )?;
        let enc_key_cert = Ed25519Certificate::new(
            CertType::HsV3NtorEnc,
            Some(expiration),
            Some(1),
            auth_key,
            extensions,
            None,
            Some(&signing_key),
        )?;
        Ok(Self {
            link_specifiers,
            onion_key_raw: Some(onion_key),
            auth_key_cert,
            enc_key_raw: Some(enc_key),
            enc_key_cert,
            legacy_key_raw: None,
            legacy_key_cert: None,
        })
    }

    pub fn encode(&self) -> Result<String> {
        let mut specifiers = vec![self.link_specifiers.len() as u8];
        self.link_specifiers
            .iter()
            .for_each(|link| specifiers.extend_from_slice(&link.pack()));
        let mut lines = vec![format!(
            "introduction-point {}",
            standard_base64(&specifiers)
        )];
        lines.push(format!(
            "onion-key ntor {}",
            self.onion_key_raw.clone().unwrap_or_default()
        ));
        lines.push(format!("auth-key\n{}", self.auth_key_cert.to_base64(true)?));
        if let Some(key) = &self.enc_key_raw {
            lines.push(format!("enc-key ntor {key}"));
        }
        lines.push(format!(
            "enc-key-cert\n{}",
            self.enc_key_cert.to_base64(true)?
        ));
        if let Some(key) = &self.legacy_key_raw {
            lines.push(format!("legacy-key\n{key}"));
        }
        if let Some(cert) = &self.legacy_key_cert {
            lines.push(format!("legacy-key-cert\n{cert}"));
        }
        Ok(lines.join("\n"))
    }

    fn x25519_bytes(value: &Option<String>) -> Result<Option<[u8; 32]>> {
        value
            .as_ref()
            .map(|encoded| {
                decode_base64(encoded)?
                    .try_into()
                    .map_err(|_| Error::parse("x25519 keys are 32 bytes"))
            })
            .transpose()
    }

    pub fn onion_key(&self) -> Result<Option<PublicKey>> {
        Ok(Self::x25519_bytes(&self.onion_key_raw)?.map(PublicKey::from))
    }

    pub fn enc_key(&self) -> Result<Option<PublicKey>> {
        Ok(Self::x25519_bytes(&self.enc_key_raw)?.map(PublicKey::from))
    }

    pub fn auth_key(&self) -> &[u8; 32] {
        &self.auth_key_cert.key
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuthorizedClient {
    pub id: String,
    pub iv: String,
    pub cookie: String,
}

impl AuthorizedClient {
    pub fn random() -> Self {
        let encode = |bytes: &[u8]| crate::descriptor::truncated_base64(bytes);
        Self {
            id: encode(&rand::random::<[u8; 8]>()),
            iv: encode(&rand::random::<[u8; 16]>()),
            cookie: encode(&rand::random::<[u8; 16]>()),
        }
    }
}

fn layer_cipher(
    constant: &[u8],
    revision_counter: u64,
    subcredential: &[u8],
    secret_data: &[u8],
    salt: &[u8],
) -> (Aes256Ctr, Vec<u8>) {
    let mut hasher = Shake256::default();
    hasher.update(secret_data);
    hasher.update(subcredential);
    hasher.update(&revision_counter.to_be_bytes());
    hasher.update(salt);
    hasher.update(constant);
    let mut keys = [0u8; KEY_LENGTH + IV_LENGTH + MAC_LENGTH];
    hasher.finalize_xof().read(&mut keys);
    let cipher = Aes256Ctr::new_from_slices(
        &keys[..KEY_LENGTH],
        &keys[KEY_LENGTH..KEY_LENGTH + IV_LENGTH],
    )
    .expect("derived key sizes are fixed");
    let mac_key = &keys[KEY_LENGTH + IV_LENGTH..];
    let mut mac_prefix = (mac_key.len() as u64).to_be_bytes().to_vec();
    mac_prefix.extend_from_slice(mac_key);
    mac_prefix.extend_from_slice(&(salt.len() as u64).to_be_bytes());
    mac_prefix.extend_from_slice(salt);
    (cipher, mac_prefix)
}

fn layer_mac(mac_prefix: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    sha3::Digest::update(&mut hasher, mac_prefix);
    sha3::Digest::update(&mut hasher, ciphertext);
    sha3::Digest::finalize(hasher).to_vec()
}

fn decrypt_layer(
    encrypted_block: &str,
    constant: &[u8],
    revision_counter: u64,
    subcredential: &[u8],
    secret_data: &[u8],
) -> Result<Vec<u8>> {
    let body = match encrypted_block.starts_with(MESSAGE_START)
        && encrypted_block.ends_with(MESSAGE_END)
    {
        true => {
            &encrypted_block
                [MESSAGE_START.len()..encrypted_block.len() - MESSAGE_END.len()]
        }
        false => encrypted_block,
    };
    let encrypted = decode_base64(body)
        .map_err(|_| Error::parse("Unable to decode encrypted block as base64"))?;
    if encrypted.len() < SALT_LENGTH + MAC_LENGTH {
        return Err(Error::parse(format!(
            "Encrypted block malformed (only {} bytes)",
            encrypted.len()
        )));
    }
    let salt = &encrypted[..SALT_LENGTH];
    let ciphertext = &encrypted[SALT_LENGTH..encrypted.len() - MAC_LENGTH];
    let expected_mac = &encrypted[encrypted.len() - MAC_LENGTH..];
    let (mut cipher, mac_prefix) =
        layer_cipher(constant, revision_counter, subcredential, secret_data, salt);
    let actual_mac = layer_mac(&mac_prefix, ciphertext);
    if !bool::from(actual_mac.as_slice().ct_eq(expected_mac)) {
        return Err(Error::parse(format!(
            "Malformed mac (expected {}, but was {})",
            hex::encode(expected_mac),
            hex::encode(&actual_mac)
        )));
    }
    let mut plaintext = ciphertext.to_vec();
    cipher.apply_keystream(&mut plaintext);
    Ok(plaintext)
}

fn encrypt_layer(
    plaintext: &[u8],
    constant: &[u8],
    revision_counter: u64,
    subcredential: &[u8],
    secret_data: &[u8],
) -> String {
    let salt: [u8; SALT_LENGTH] = rand::random();
    let padded_length = plaintext.len().div_ceil(PLAINTEXT_PADDING_MULTIPLE).max(1)
        * PLAINTEXT_PADDING_MULTIPLE;
    let mut ciphertext = plaintext.to_vec();
    ciphertext.resize(padded_length, 0);
    let (mut cipher, mac_prefix) = layer_cipher(
        constant,
        revision_counter,
        subcredential,
        secret_data,
        &salt,
    );
    cipher.apply_keystream(&mut ciphertext);
    let mac = layer_mac(&mac_prefix, &ciphertext);
    let encoded = standard_base64(&[salt.as_slice(), &ciphertext, &mac].concat());
    format!(
        "{MESSAGE_START}{}{MESSAGE_END}",
        split_into_lines(&encoded, 64).join("\n")
    )
}

fn trim_padding(mut plaintext: Vec<u8>) -> Vec<u8> {
    while plaintext.last() == Some(&0) {
        plaintext.pop();
    }
    plaintext
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct HiddenServiceDescriptorV2 {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub unrecognized_lines: Vec<String>,
    pub descriptor_id: Option<String>,
    pub version: Option<u32>,
    pub permanent_key: Option<String>,
    pub secret_id_part: Option<String>,
    pub published: Option<NaiveDateTime>,
    pub protocol_versions: Vec<u32>,
    pub introduction_points_encoded: Option<String>,
    #[serde(serialize_with = "crate::descriptor::serialize_optional_text")]
    pub introduction_points_content: Option<Vec<u8>>,
    pub signature: Option<String>,
}

impl HiddenServiceDescriptorV2 {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        Self::parse_with_options(content, validate, false)
    }

    pub fn parse_with_options(
        content: &[u8],
        validate: bool,
        skip_crypto_validation: bool,
    ) -> Result<Self> {
        let (entries, _) =
            descriptor_components(content, validate, &[], &["introduction-points"])?;
        if validate {
            for keyword in REQUIRED_V2_FIELDS {
                match entries.get(keyword) {
                    None => {
                        return Err(Error::parse(format!(
                            "Hidden service descriptor must have a '{keyword}' entry"
                        )));
                    }
                    Some(values) if values.len() > 1 => {
                        return Err(Error::parse(format!(
                            "The '{keyword}' entry can only appear once in a hidden \
                            service descriptor"
                        )));
                    }
                    Some(_) => {}
                }
            }
            if entries.first_key() != Some("rendezvous-service-descriptor") {
                return Err(Error::parse(
                    "Hidden service descriptor must start with a \
                    'rendezvous-service-descriptor' entry",
                ));
            }
            if entries.last_key() != Some("signature") {
                return Err(Error::parse(
                    "Hidden service descriptor must end with a 'signature' entry",
                ));
            }
        }
        let mut descriptor = Self {
            raw_contents: content.to_vec(),
            unrecognized_lines: entries.unrecognized_lines(&REQUIRED_V2_FIELDS_PLUS),
            descriptor_id: entries
                .value("rendezvous-service-descriptor")
                .ok()
                .map(str::to_string),
            version: None,
            permanent_key: None,
            secret_id_part: entries.value("secret-id-part").ok().map(str::to_string),
            published: None,
            protocol_versions: Vec::new(),
            introduction_points_encoded: None,
            introduction_points_content: None,
            signature: None,
        };
        if let Ok(value) = entries.value("version") {
            descriptor.version = lenient_option(
                validate,
                parse_integer("version", value, false).map(|v| v as u32),
            )?;
        }
        if entries.contains("permanent-key") {
            descriptor.permanent_key = lenient_option(
                validate,
                key_block(&entries, "permanent-key", "RSA PUBLIC KEY")
                    .map(|(_, block)| block),
            )?;
        }
        if let Ok(value) = entries.value("publication-time") {
            descriptor.published = lenient_option(
                validate,
                parse_timestamp_line("publication-time", value),
            )?;
        }
        if let Ok(value) = entries.value("protocol-versions") {
            let parsed: Result<Vec<u32>> = value
                .split(',')
                .map(|entry| match entry.parse::<u32>() {
                    Ok(version) if version > 0 => Ok(version),
                    Ok(_) => Err(Error::parse(format!(
                        "protocol-versions must be \
                        positive integers: {value}"
                    ))),
                    Err(_) => Err(Error::parse(format!(
                        "protocol-versions line has non-numeric versoins: \
                        protocol-versions {value}"
                    ))),
                })
                .collect();
            descriptor.protocol_versions = lenient(validate, parsed)?;
        }
        if entries.contains("introduction-points") {
            let parsed = key_block(&entries, "introduction-points", "MESSAGE").and_then(
                |(_, block)| bytes_for_block(&block).map(|bytes| (block, bytes)),
            );
            if let Some((block, bytes)) = lenient_option(validate, parsed)? {
                descriptor.introduction_points_encoded = Some(block);
                descriptor.introduction_points_content = Some(bytes);
            }
        }
        if entries.contains("signature") {
            descriptor.signature = lenient_option(
                validate,
                key_block(&entries, "signature", "SIGNATURE").map(|(_, block)| block),
            )?;
        }
        if validate && !skip_crypto_validation {
            descriptor.validate_signature()?;
        }
        Ok(descriptor)
    }

    fn validate_signature(&self) -> Result<()> {
        let (Some(key), Some(signature)) = (&self.permanent_key, &self.signature) else {
            return Ok(());
        };
        let signed = digest_for_signature(key, signature)?;
        let digest_content = content_range(
            &self.raw_contents,
            Some("rendezvous-service-descriptor "),
            Some("\nsignature\n"),
        )?;
        let local = Sha1::digest(digest_content).to_vec();
        match signed == local {
            true => Ok(()),
            false => Err(Error::parse(format!(
                "Decrypted digest does not match local digest (calculated: {}, local: \
                {})",
                hex::encode_upper(signed),
                hex::encode_upper(local)
            ))),
        }
    }

    pub fn parse_many(content: &[u8], validate: bool) -> Result<Vec<Self>> {
        let mut cursor = LineCursor::new(content);
        let mut descriptors = Vec::new();
        loop {
            let mut body = cursor
                .read_until_keywords(
                    &["signature"],
                    ReadOptions {
                        inclusive: true,
                        ..Default::default()
                    },
                )
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
            if body.starts_with(b"@type") {
                body = body
                    .splitn(2, |byte| *byte == b'\n')
                    .nth(1)
                    .unwrap_or_default()
                    .to_vec();
            }
            descriptors.push(Self::parse(&body, validate)?);
        }
        Ok(descriptors)
    }

    pub fn introduction_points(
        &self,
        authentication_cookie: Option<&str>,
    ) -> Result<Vec<IntroductionPoints>> {
        let Some(content) = self
            .introduction_points_content
            .as_ref()
            .filter(|content| !content.is_empty())
        else {
            return Ok(Vec::new());
        };
        let decrypted = match authentication_cookie {
            Some(cookie) => {
                let cookie = decode_base64(cookie).map_err(|error| {
                    DecryptionFailure(format!(
                        "authentication_cookie must be a base64 encoded string ({error})"
                    ))
                })?;
                let plaintext = match content.first().copied() {
                    Some(BASIC_AUTH) => Self::decrypt_basic_auth(content, &cookie)?,
                    Some(STEALTH_AUTH) => Self::decrypt_stealth_auth(content, &cookie)?,
                    other => {
                        return Err(DecryptionFailure(format!(
                            "Unrecognized authentication type '{}', currently we only \
                            support basic auth ({BASIC_AUTH}) and stealth auth \
                            ({STEALTH_AUTH})",
                            other.unwrap_or(0)
                        ))
                        .into());
                    }
                };
                if !plaintext.starts_with(b"introduction-point ") {
                    return Err(DecryptionFailure(
                        "Unable to decrypt the introduction-points, maybe this is the \
                        wrong key?"
                            .to_string(),
                    )
                    .into());
                }
                plaintext
            }
            None if content.starts_with(b"introduction-point ") => content.clone(),
            None => {
                return Err(DecryptionFailure(
                    "introduction-points content is encrypted, you need to provide its \
                    authentication_cookie"
                        .to_string(),
                )
                .into());
            }
        };
        Self::parse_introduction_points(&decrypted)
    }

    fn decrypt_basic_auth(content: &[u8], cookie: &[u8]) -> Result<Vec<u8>> {
        let blocks = usize::from(*content.get(1).ok_or_else(|| {
            DecryptionFailure("Basic auth content is truncated".to_string())
        })?);
        let entries_length = blocks * 16 * 20;
        let entries = content.get(2..2 + entries_length).ok_or_else(|| {
            DecryptionFailure("Basic auth content is truncated".to_string())
        })?;
        let iv = content
            .get(2 + entries_length..2 + entries_length + 16)
            .ok_or_else(|| {
                DecryptionFailure("Basic auth content is truncated".to_string())
            })?;
        let encrypted = &content[2 + entries_length + 16..];
        let mut hasher = Sha1::new();
        sha1::Digest::update(&mut hasher, cookie);
        sha1::Digest::update(&mut hasher, iv);
        let client_id = sha1::Digest::finalize(hasher);
        for entry in entries.as_chunks::<20>().0 {
            if entry[..4] != client_id[..4] {
                continue;
            }
            let mut session_key = entry[4..20].to_vec();
            let mut key_cipher =
                Aes128Ctr::new_from_slices(cookie, &[0u8; 16]).map_err(|_| {
                    DecryptionFailure(
                        "The authentication cookie must be 16 bytes".to_string(),
                    )
                })?;
            key_cipher.apply_keystream(&mut session_key);
            let mut decrypted = encrypted.to_vec();
            let mut cipher = Aes128Ctr::new_from_slices(&session_key, iv)
                .map_err(|_| DecryptionFailure("Invalid session key".to_string()))?;
            cipher.apply_keystream(&mut decrypted);
            if decrypted.starts_with(b"introduction-point ") {
                return Ok(decrypted);
            }
        }
        Ok(content.to_vec())
    }

    fn decrypt_stealth_auth(content: &[u8], cookie: &[u8]) -> Result<Vec<u8>> {
        let (iv, encrypted) = (
            content.get(1..17).ok_or_else(|| {
                DecryptionFailure("Stealth auth content is truncated".to_string())
            })?,
            &content[17..],
        );
        let mut decrypted = encrypted.to_vec();
        let mut cipher = Aes128Ctr::new_from_slices(cookie, iv).map_err(|_| {
            DecryptionFailure("The authentication cookie must be 16 bytes".to_string())
        })?;
        cipher.apply_keystream(&mut decrypted);
        Ok(decrypted)
    }

    fn parse_introduction_points(content: &[u8]) -> Result<Vec<IntroductionPoints>> {
        let mut cursor = LineCursor::new(content);
        let mut points = Vec::new();
        loop {
            let block = cursor
                .read_until_keywords(
                    &["introduction-point"],
                    ReadOptions {
                        ignore_first: true,
                        ..Default::default()
                    },
                )
                .content;
            if block.is_empty() {
                break;
            }
            let (entries, _) = descriptor_components(&block, false, &[], &[])?;
            let mut point = IntroductionPoints {
                identifier: None,
                address: None,
                port: None,
                onion_key: None,
                service_key: None,
                intro_authentication: Vec::new(),
            };
            for (keyword, values) in entries.iter() {
                if SINGLE_INTRODUCTION_POINT_FIELDS.contains(&keyword.as_str())
                    && values.len() > 1
                {
                    return Err(Error::parse(format!(
                        "'{keyword}' can only appear once in an introduction-point \
                        block, but appeared {} times",
                        values.len()
                    )));
                }
                let first = &values[0];
                match keyword.as_str() {
                    "introduction-point" => point.identifier = Some(first.value.clone()),
                    "ip-address" => {
                        if !is_valid_ipv4_address(&first.value) {
                            return Err(Error::parse(format!(
                                "'{}' is an invalid IPv4 address",
                                first.value
                            )));
                        }
                        point.address = Some(first.value.clone());
                    }
                    "onion-port" => {
                        point.port =
                            Some(parse_port(&first.value, false).ok_or_else(|| {
                                Error::parse(format!(
                                    "'{}' is an invalid port",
                                    first.value
                                ))
                            })?);
                    }
                    "onion-key" => point.onion_key = first.block_contents.clone(),
                    "service-key" => point.service_key = first.block_contents.clone(),
                    "intro-authentication" => {
                        for entry in values {
                            let parts: Vec<&str> = entry.value.split(' ').collect();
                            if parts.len() < 2 {
                                return Err(Error::parse(format!(
                                    "We expected 'intro-authentication [auth_type] \
                                    [auth_data]', but had '{}'",
                                    entry.value
                                )));
                            }
                            point
                                .intro_authentication
                                .push((parts[0].to_string(), parts[1].to_string()));
                        }
                    }
                    _ => {}
                }
            }
            points.push(point);
        }
        Ok(points)
    }

    pub fn content(attributes: &Attributes, exclude: &[&str]) -> Vec<u8> {
        descriptor_content(
            attributes,
            exclude,
            &[
                (
                    "rendezvous-service-descriptor",
                    AttrValue::Text("y3olqqblqw2gbh6phimfuiroechjjafa".to_string()),
                ),
                ("version", AttrValue::Text("2".to_string())),
                (
                    "permanent-key",
                    AttrValue::Text(random_crypto_blob(Some("RSA PUBLIC KEY"))),
                ),
                (
                    "secret-id-part",
                    AttrValue::Text("e24kgecavwsznj7gpbktqsiwgvngsf4e".to_string()),
                ),
                ("publication-time", AttrValue::Text(random_date())),
                ("protocol-versions", AttrValue::Text("2,3".to_string())),
                (
                    "introduction-points",
                    AttrValue::Text(
                        "\n-----BEGIN MESSAGE-----\n-----END MESSAGE-----".to_string(),
                    ),
                ),
            ],
            &[(
                "signature",
                AttrValue::Text(random_crypto_blob(Some("SIGNATURE"))),
            )],
        )
    }

    pub fn create(
        attributes: &Attributes,
        exclude: &[&str],
        validate: bool,
    ) -> Result<Self> {
        Self::parse_with_options(&Self::content(attributes, exclude), validate, true)
    }
}

const REQUIRED_V2_FIELDS_PLUS: [&str; 8] = [
    "rendezvous-service-descriptor",
    "version",
    "permanent-key",
    "secret-id-part",
    "publication-time",
    "protocol-versions",
    "introduction-points",
    "signature",
];

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct HiddenServiceDescriptorV3 {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub unrecognized_lines: Vec<String>,
    pub version: Option<u32>,
    pub lifetime: Option<u32>,
    pub signing_cert: Option<Ed25519Certificate>,
    pub revision_counter: Option<u64>,
    pub superencrypted: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct OuterLayer {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub auth_type: Option<String>,
    pub ephemeral_key: Option<String>,
    pub clients: indexmap::IndexMap<String, AuthorizedClient>,
    pub encrypted: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct InnerLayer {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub formats: Vec<u32>,
    pub intro_auth: Vec<String>,
    pub is_single_service: bool,
    pub introduction_points: Vec<IntroductionPointV3>,
}

pub fn address_from_identity_key(key: &[u8; 32], suffix: bool) -> String {
    let mut hasher = Sha3_256::new();
    sha3::Digest::update(&mut hasher, CHECKSUM_CONSTANT);
    sha3::Digest::update(&mut hasher, key);
    sha3::Digest::update(&mut hasher, [3u8]);
    let checksum = sha3::Digest::finalize(hasher);
    let mut payload = key.to_vec();
    payload.extend_from_slice(&checksum[..2]);
    payload.push(3);
    let address = BASE32_NOPAD.encode(&payload).to_lowercase();
    match suffix {
        true => format!("{address}.onion"),
        false => address,
    }
}

pub fn identity_key_from_address(onion_address: &str) -> Result<[u8; 32]> {
    let address = onion_address
        .strip_suffix(".onion")
        .unwrap_or(onion_address);
    if !is_valid_hidden_service_address(address, &[3]) {
        return Err(Error::invalid_input(format!(
            "'{address}.onion' isn't a valid hidden service v3 address"
        )));
    }
    let decoded = BASE32_NOPAD
        .decode(address.to_uppercase().as_bytes())
        .map_err(|error| Error::invalid_input(error.to_string()))?;
    let (public_key, tail) = decoded.split_at(32);
    let mut hasher = Sha3_256::new();
    sha3::Digest::update(&mut hasher, CHECKSUM_CONSTANT);
    sha3::Digest::update(&mut hasher, public_key);
    sha3::Digest::update(&mut hasher, &tail[2..3]);
    let checksum = sha3::Digest::finalize(hasher);
    if tail[..2] != checksum[..2] {
        return Err(Error::invalid_input(format!(
            "Bad checksum (expected {} but was {})",
            hex::encode(&tail[..2]),
            hex::encode(&checksum[..2])
        )));
    }
    Ok(public_key.try_into().expect("32 bytes"))
}

pub fn subcredential(identity_key: &[u8], blinded_key: &[u8]) -> Vec<u8> {
    let mut credential = Sha3_256::new();
    sha3::Digest::update(&mut credential, b"credential");
    sha3::Digest::update(&mut credential, identity_key);
    let credential = sha3::Digest::finalize(credential);
    let mut hasher = Sha3_256::new();
    sha3::Digest::update(&mut hasher, b"subcredential");
    sha3::Digest::update(&mut hasher, credential);
    sha3::Digest::update(&mut hasher, blinded_key);
    sha3::Digest::finalize(hasher).to_vec()
}

pub struct LayerSecrets<'a> {
    pub subcredential: &'a [u8],
    pub blinded_key: &'a [u8],
    pub descriptor_cookie: &'a [u8],
}

impl OuterLayer {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        let trimmed = trim_padding(content.to_vec());
        let (entries, _) = descriptor_components(&trimmed, validate, &[], &[])?;
        let mut layer = Self {
            raw_contents: trimmed,
            auth_type: entries.value("desc-auth-type").ok().map(str::to_string),
            ephemeral_key: entries
                .value("desc-auth-ephemeral-key")
                .ok()
                .map(str::to_string),
            clients: indexmap::IndexMap::new(),
            encrypted: None,
        };
        if entries.contains("auth-client") {
            let parsed: Result<Vec<AuthorizedClient>> = entries
                .values("auth-client")
                .into_iter()
                .map(|value| {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    match parts.as_slice() {
                        [id, iv, cookie, ..] => Ok(AuthorizedClient {
                            id: id.to_string(),
                            iv: iv.to_string(),
                            cookie: cookie.to_string(),
                        }),
                        _ => Err(Error::parse(format!(
                            "auth-client should have a client-id, iv, and cookie: \
                            auth-client {value}"
                        ))),
                    }
                })
                .collect();
            layer.clients = lenient(validate, parsed)?
                .into_iter()
                .map(|client| (client.id.clone(), client))
                .collect();
        }
        if entries.contains("encrypted") {
            layer.encrypted = lenient_option(
                validate,
                key_block(&entries, "encrypted", "MESSAGE").map(|(_, block)| block),
            )?;
        }
        Ok(layer)
    }

    fn decrypt(
        encrypted: &str,
        revision_counter: u64,
        subcredential: &[u8],
        blinded_key: &[u8],
    ) -> Result<Self> {
        let plaintext = decrypt_layer(
            encrypted,
            b"hsdir-superencrypted-data",
            revision_counter,
            subcredential,
            blinded_key,
        )?;
        Self::parse(&plaintext, false)
    }

    pub fn descriptor_cookie_for_client(
        &self,
        subcredential: &[u8],
        client_private_key: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let ephemeral = self.ephemeral_key.as_ref().ok_or_else(|| {
            Error::parse("The outer layer has no desc-auth-ephemeral-key")
        })?;
        let ephemeral: [u8; 32] = decode_base64(ephemeral)?.try_into().map_err(|_| {
            Error::parse("desc-auth-ephemeral-key must be an x25519 public key")
        })?;
        let secret = StaticSecret::from(*client_private_key);
        let shared = secret.diffie_hellman(&PublicKey::from(ephemeral));
        let mut hasher = Shake256::default();
        hasher.update(subcredential);
        hasher.update(shared.as_bytes());
        let mut keys = [0u8; 40];
        hasher.finalize_xof().read(&mut keys);
        let client_id = crate::descriptor::truncated_base64(&keys[..8]);
        let client = self.clients.get(&client_id).ok_or_else(|| {
            DecryptionFailure(
                "None of the auth-client entries are for this client key".to_string(),
            )
        })?;
        let iv = decode_base64(&client.iv)?;
        let mut cookie = decode_base64(&client.cookie)?;
        let mut cipher = Aes256Ctr::new_from_slices(&keys[8..], &iv)
            .map_err(|_| Error::parse("auth-client has a malformed iv"))?;
        cipher.apply_keystream(&mut cookie);
        Ok(cookie)
    }

    pub fn content(
        attributes: &Attributes,
        exclude: &[&str],
        inner_layer: &InnerLayer,
        revision_counter: u64,
        authorized_clients: Option<&[AuthorizedClient]>,
        secrets: &LayerSecrets,
    ) -> Result<Vec<u8>> {
        if authorized_clients.is_some()
            && attributes.iter().any(|(key, _)| key == "auth-client")
        {
            return Err(Error::invalid_input(
                "Authorized clients cannot be specified through both attr and \
                authorized_clients",
            ));
        }
        let generated: Vec<AuthorizedClient> = match authorized_clients {
            Some(clients) => clients.to_vec(),
            None if attributes.iter().any(|(key, _)| key == "auth-client") => Vec::new(),
            None => (0..16).map(|_| AuthorizedClient::random()).collect(),
        };
        let ephemeral = PublicKey::from(&StaticSecret::from(rand::random::<[u8; 32]>()));
        let mut header: Vec<(String, AttrValue)> = vec![
            attr("desc-auth-type", "x25519"),
            attr(
                "desc-auth-ephemeral-key",
                &standard_base64(ephemeral.as_bytes()),
            ),
        ];
        for client in &generated {
            header.push(attr(
                "auth-client",
                &format!("{} {} {}", client.id, client.iv, client.cookie),
            ));
        }
        let borrowed: Vec<(&str, AttrValue)> = header
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect();
        let secret_data = [secrets.blinded_key, secrets.descriptor_cookie].concat();
        let encrypted =
            inner_layer.encrypt(revision_counter, secrets.subcredential, &secret_data);
        Ok(descriptor_content(
            attributes,
            exclude,
            &borrowed,
            &[("encrypted", AttrValue::Text(format!("\n{encrypted}")))],
        ))
    }
}

impl InnerLayer {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        let trimmed = trim_padding(content.to_vec());
        let split = trimmed
            .windows(b"\nintroduction-point ".len())
            .position(|window| window == b"\nintroduction-point ");
        let (head, unparsed_points) = match split {
            Some(position) => (&trimmed[..position], Some(&trimmed[position + 1..])),
            None => (trimmed.as_slice(), None),
        };
        let (entries, _) = descriptor_components(head, validate, &[], &[])?;
        let mut layer = Self {
            raw_contents: trimmed.clone(),
            formats: Vec::new(),
            intro_auth: Vec::new(),
            is_single_service: entries.contains("single-onion-service"),
            introduction_points: Vec::new(),
        };
        if let Ok(value) = entries.value("create2-formats") {
            let parsed: Result<Vec<u32>> = value
                .split(' ')
                .map(|entry| {
                    entry
                        .parse::<u32>()
                        .ok()
                        .filter(|_| entry.bytes().all(|b| b.is_ascii_digit()))
                        .ok_or_else(|| {
                            Error::parse(format!(
                                "create2-formats should only contain \
                            integers, but was '{value}'"
                            ))
                        })
                })
                .collect();
            layer.formats = lenient(validate, parsed)?;
        }
        if let Ok(value) = entries.value("intro-auth-required") {
            layer.intro_auth = value.split(' ').map(str::to_string).collect();
        }
        if let Some(mut remaining) = unparsed_points {
            let mut points = Vec::new();
            while !remaining.is_empty() {
                let search = &remaining[10.min(remaining.len())..];
                let next = search
                    .windows(b"\nintroduction-point ".len())
                    .position(|window| window == b"\nintroduction-point ")
                    .map(|position| position + 10.min(remaining.len()));
                let (chunk, rest) = match next {
                    Some(position) => {
                        (&remaining[..position], &remaining[position + 1..])
                    }
                    None => (remaining, &remaining[remaining.len()..]),
                };
                points.push(IntroductionPointV3::parse(chunk));
                remaining = rest;
            }
            layer.introduction_points =
                match points.into_iter().collect::<Result<Vec<_>>>() {
                    Ok(points) => points,
                    Err(error) if validate => return Err(error),
                    Err(_) => Vec::new(),
                };
        }
        Ok(layer)
    }

    fn decrypt(
        outer: &OuterLayer,
        revision_counter: u64,
        subcredential: &[u8],
        blinded_key: &[u8],
        descriptor_cookie: &[u8],
    ) -> Result<Self> {
        let encrypted = outer
            .encrypted
            .as_ref()
            .ok_or_else(|| Error::parse("The outer layer has no encrypted block"))?;
        let secret_data = [blinded_key, descriptor_cookie].concat();
        let plaintext = decrypt_layer(
            encrypted,
            b"hsdir-encrypted-data",
            revision_counter,
            subcredential,
            &secret_data,
        )?;
        Self::parse(&plaintext, true)
    }

    fn encrypt(
        &self,
        revision_counter: u64,
        subcredential: &[u8],
        secret_data: &[u8],
    ) -> String {
        encrypt_layer(
            &self.raw_contents,
            b"hsdir-encrypted-data",
            revision_counter,
            subcredential,
            secret_data,
        )
    }

    pub fn content(
        attributes: &Attributes,
        exclude: &[&str],
        introduction_points: &[IntroductionPointV3],
    ) -> Result<Vec<u8>> {
        let mut content = descriptor_content(
            attributes,
            exclude,
            &[("create2-formats", AttrValue::Text("2".to_string()))],
            &[],
        );
        content.push(b'\n');
        if !introduction_points.is_empty() {
            let encoded: Result<Vec<String>> = introduction_points
                .iter()
                .map(IntroductionPointV3::encode)
                .collect();
            content.extend_from_slice(encoded?.join("\n").as_bytes());
            content.push(b'\n');
        }
        Ok(content)
    }

    pub fn create(
        attributes: &Attributes,
        exclude: &[&str],
        validate: bool,
        introduction_points: &[IntroductionPointV3],
    ) -> Result<Self> {
        Self::parse(
            &Self::content(attributes, exclude, introduction_points)?,
            validate,
        )
    }
}

pub fn blinded_public_key(
    identity_key: &[u8; 32],
    blinding_nonce: &[u8; 32],
) -> Result<[u8; 32]> {
    let point = CompressedEdwardsY(*identity_key)
        .decompress()
        .ok_or_else(|| {
            Error::invalid_input("The identity key isn't a valid ed25519 point")
        })?;
    Ok(point.mul_clamped(*blinding_nonce).compress().to_bytes())
}

pub fn time_period_number(time: DateTime<Utc>, period_length: u64) -> Result<u64> {
    if period_length == 0 {
        return Err(Error::invalid_input(
            "Time periods can't be zero minutes long",
        ));
    }
    let minutes = (time.timestamp() / 60 - PERIOD_ROTATION_MINUTES).max(0);
    Ok(minutes.unsigned_abs() / period_length)
}

pub fn blinding_nonce(
    identity_key: &[u8; 32],
    period_number: u64,
    period_length: u64,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    sha3::Digest::update(&mut hasher, BLIND_STRING);
    sha3::Digest::update(&mut hasher, identity_key);
    sha3::Digest::update(&mut hasher, BASEPOINT_STRING);
    sha3::Digest::update(&mut hasher, b"key-blind");
    sha3::Digest::update(&mut hasher, period_number.to_be_bytes());
    sha3::Digest::update(&mut hasher, period_length.to_be_bytes());
    sha3::Digest::finalize(hasher).into()
}

pub fn blinded_key_for_period(
    identity_key: &[u8; 32],
    period_number: u64,
    period_length: u64,
) -> Result<[u8; 32]> {
    let nonce = blinding_nonce(identity_key, period_number, period_length);
    blinded_public_key(identity_key, &nonce)
}

fn clamp(bytes: [u8; 32]) -> [u8; 32] {
    let mut clamped = bytes;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    clamped
}

pub fn blinded_sign(
    message: &[u8],
    identity_key: &SigningKey,
    blinded_key: &[u8; 32],
    blinding_nonce: &[u8; 32],
) -> Vec<u8> {
    let hashed = Sha512::digest(identity_key.to_bytes());
    let secret =
        Scalar::from_bytes_mod_order(clamp(hashed[..32].try_into().expect("32 bytes")));
    let multiplier = Scalar::from_bytes_mod_order(clamp(*blinding_nonce));
    let blinded_secret = secret * multiplier;
    let mut derive = b"Derive temporary signing key hash input".to_vec();
    derive.extend_from_slice(&hashed[32..]);
    let blinded_prefix = Sha512::digest(&derive);
    let mut prefixed = blinded_prefix[..32].to_vec();
    prefixed.extend_from_slice(message);
    let random = Scalar::from_bytes_mod_order_wide(&Sha512::digest(&prefixed).into());
    let commitment: EdwardsPoint = ED25519_BASEPOINT_POINT * random;
    let commitment_bytes = commitment.compress().to_bytes();
    let mut challenge_input = commitment_bytes.to_vec();
    challenge_input.extend_from_slice(blinded_key);
    challenge_input.extend_from_slice(message);
    let challenge =
        Scalar::from_bytes_mod_order_wide(&Sha512::digest(&challenge_input).into());
    let response = random + challenge * blinded_secret;
    [commitment_bytes.as_slice(), response.as_bytes().as_slice()].concat()
}

#[derive(Default)]
pub struct HiddenServiceV3Options {
    pub inner_layer: Option<InnerLayer>,
    pub identity_key: Option<SigningKey>,
    pub signing_key: Option<SigningKey>,
    pub signing_cert: Option<Ed25519Certificate>,
    pub revision_counter: Option<u64>,
    pub blinding_nonce: Option<[u8; 32]>,
    pub authorized_clients: Option<Vec<AuthorizedClient>>,
    pub descriptor_cookie: Option<Vec<u8>>,
}

impl HiddenServiceDescriptorV3 {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        let (entries, _) = descriptor_components(content, validate, &[], &[])?;
        if validate {
            for keyword in REQUIRED_V3_FIELDS {
                match entries.get(keyword) {
                    None => {
                        return Err(Error::parse(format!(
                            "Hidden service descriptor must have a '{keyword}' entry"
                        )));
                    }
                    Some(values) if values.len() > 1 => {
                        return Err(Error::parse(format!(
                            "The '{keyword}' entry can only appear once in a hidden \
                            service descriptor"
                        )));
                    }
                    Some(_) => {}
                }
            }
            if entries.first_key() != Some("hs-descriptor") {
                return Err(Error::parse(
                    "Hidden service descriptor must start with a 'hs-descriptor' entry",
                ));
            }
            if entries.last_key() != Some("signature") {
                return Err(Error::parse(
                    "Hidden service descriptor must end with a 'signature' entry",
                ));
            }
        }
        let mut descriptor = Self {
            raw_contents: content.to_vec(),
            unrecognized_lines: entries.unrecognized_lines(&REQUIRED_V3_FIELDS),
            version: None,
            lifetime: None,
            signing_cert: None,
            revision_counter: None,
            superencrypted: None,
            signature: entries.value("signature").ok().map(str::to_string),
        };
        for (keyword, target) in [
            ("hs-descriptor", &mut descriptor.version),
            ("descriptor-lifetime", &mut descriptor.lifetime),
        ] {
            if let Ok(value) = entries.value(keyword) {
                *target = lenient_option(
                    validate,
                    parse_integer(keyword, value, false).map(|number| number as u32),
                )?;
            }
        }
        if entries.contains("descriptor-signing-key-cert") {
            descriptor.signing_cert = lenient_option(
                validate,
                certificate_block(&entries, "descriptor-signing-key-cert"),
            )?;
        }
        if let Ok(value) = entries.value("revision-counter") {
            descriptor.revision_counter = lenient_option(
                validate,
                parse_integer("revision-counter", value, false)
                    .map(|number| number as u64),
            )?;
        }
        if entries.contains("superencrypted") {
            descriptor.superencrypted = lenient_option(
                validate,
                key_block(&entries, "superencrypted", "MESSAGE").map(|(_, block)| block),
            )?;
        }
        if validate && let Some(certificate) = descriptor.signing_cert.clone() {
            descriptor.validate_signature(&certificate)?;
        }
        Ok(descriptor)
    }

    fn validate_signature(&self, certificate: &Ed25519Certificate) -> Result<()> {
        let signed = content_range(&self.raw_contents, None, Some("signature "))?;
        let signed_without_marker = &signed[..signed.len() - "signature ".len()];
        let message = [SIG_PREFIX_HS_V3, signed_without_marker].concat();
        let signature = decode_base64(self.signature.as_deref().ok_or_else(|| {
            Error::parse("Malformed descriptor missing signature line")
        })?)?;
        certificate.verify_signature(&message, &signature)
    }

    pub fn verify_signing_certificate(&self) -> Result<()> {
        let certificate = self
            .signing_cert
            .as_ref()
            .ok_or_else(|| Error::parse("No signing certificate is present"))?;
        let blinded_key = certificate
            .signing_key()
            .ok_or_else(|| Error::parse("No signing key is present"))?;
        certificate.verify_certificate_signature(blinded_key)
    }

    pub fn verify_blinded_key(
        &self,
        onion_address: &str,
        time: DateTime<Utc>,
        period_length: u64,
    ) -> Result<()> {
        let blinded_key = self
            .signing_cert
            .as_ref()
            .and_then(Ed25519Certificate::signing_key)
            .ok_or_else(|| Error::parse("No signing key is present"))?;
        let identity_key = identity_key_from_address(onion_address)?;
        let current = time_period_number(time, period_length)?;
        for period_number in [current.saturating_sub(1), current, current + 1] {
            let expected =
                blinded_key_for_period(&identity_key, period_number, period_length)?;
            if expected.as_slice() == blinded_key {
                return Ok(());
            }
        }
        Err(Error::parse(
            "The blinded key doesn't belong to the address' current time period",
        ))
    }

    pub fn decrypt(&self, onion_address: &str) -> Result<InnerLayer> {
        self.decrypt_with_cookie_source(onion_address, None)
    }

    pub fn decrypt_with_client_auth(
        &self,
        onion_address: &str,
        client_private_key: &[u8; 32],
    ) -> Result<InnerLayer> {
        self.decrypt_with_cookie_source(onion_address, Some(client_private_key))
    }

    fn decrypt_with_cookie_source(
        &self,
        onion_address: &str,
        client_key: Option<&[u8; 32]>,
    ) -> Result<InnerLayer> {
        let blinded_key = self
            .signing_cert
            .as_ref()
            .and_then(Ed25519Certificate::signing_key)
            .ok_or_else(|| Error::invalid_input("No signing key is present"))?;
        let identity_public_key = identity_key_from_address(onion_address)?;
        let credential = subcredential(&identity_public_key, blinded_key);
        let revision_counter = self
            .revision_counter
            .ok_or_else(|| Error::parse("Descriptor lacks a revision-counter"))?;
        let superencrypted = self
            .superencrypted
            .as_ref()
            .ok_or_else(|| Error::parse("Descriptor lacks a superencrypted block"))?;
        let outer = OuterLayer::decrypt(
            superencrypted,
            revision_counter,
            &credential,
            blinded_key,
        )?;
        let cookie = match client_key {
            Some(key) => outer.descriptor_cookie_for_client(&credential, key)?,
            None => Vec::new(),
        };
        InnerLayer::decrypt(&outer, revision_counter, &credential, blinded_key, &cookie)
    }

    pub fn content(
        attributes: &Attributes,
        exclude: &[&str],
        options: HiddenServiceV3Options,
    ) -> Result<Vec<u8>> {
        let nonce = options.blinding_nonce;
        let inner_layer = match options.inner_layer {
            Some(layer) => layer,
            None => InnerLayer::create(&Vec::new(), exclude, true, &[])?,
        };
        let identity_key = options
            .identity_key
            .unwrap_or_else(|| SigningKey::from_bytes(&rand::random()));
        let signing_key = options
            .signing_key
            .unwrap_or_else(|| SigningKey::from_bytes(&rand::random()));
        let revision_counter = options
            .revision_counter
            .unwrap_or_else(|| Utc::now().timestamp() as u64);
        let identity_public = identity_key.verifying_key().to_bytes();
        let blinded_key = match &nonce {
            Some(nonce) => blinded_public_key(&identity_public, nonce)?,
            None => [b'a'; 32],
        };
        let credential = subcredential(&identity_public, &blinded_key);
        let mut attributes = attributes.clone();
        let custom_signature = attributes
            .iter()
            .position(|(key, _)| key == "signature")
            .map(|index| attributes.remove(index).1);
        let cookie = options.descriptor_cookie.unwrap_or_default();
        let outer_content = OuterLayer::content(
            &attributes,
            exclude,
            &inner_layer,
            revision_counter,
            options.authorized_clients.as_deref(),
            &LayerSecrets {
                subcredential: &credential,
                blinded_key: &blinded_key,
                descriptor_cookie: &cookie,
            },
        );
        let outer_content =
            match attributes.iter().any(|(key, _)| key == "superencrypted") {
                true => Vec::new(),
                false => outer_content?,
            };
        let signing_cert = match options.signing_cert {
            Some(cert) => cert,
            None => {
                let extensions =
                    vec![Ed25519Extension::signing_key_extension(blinded_key)];
                let mut cert = Ed25519Certificate::new(
                    CertType::HsV3DescSigning,
                    None,
                    None,
                    signing_key.verifying_key().to_bytes(),
                    extensions,
                    None,
                    None,
                )?;
                cert.signature = Some(match &nonce {
                    Some(nonce) => {
                        blinded_sign(&cert.pack()?, &identity_key, &blinded_key, nonce)
                    }
                    None => vec![b'b'; 64],
                });
                cert
            }
        };
        let superencrypted = encrypt_layer(
            &outer_content,
            b"hsdir-superencrypted-data",
            revision_counter,
            &credential,
            &blinded_key,
        );
        let mut content = descriptor_content(
            &attributes,
            exclude,
            &[
                ("hs-descriptor", AttrValue::Text("3".to_string())),
                ("descriptor-lifetime", AttrValue::Text("180".to_string())),
                (
                    "descriptor-signing-key-cert",
                    AttrValue::Text(format!("\n{}", signing_cert.to_base64(true)?)),
                ),
                (
                    "revision-counter",
                    AttrValue::Text(revision_counter.to_string()),
                ),
                (
                    "superencrypted",
                    AttrValue::Text(format!("\n{superencrypted}")),
                ),
            ],
            &[],
        );
        content.push(b'\n');
        match custom_signature {
            Some(AttrValue::Text(text)) => {
                content.extend_from_slice(format!("signature {text}").as_bytes())
            }
            Some(_) => {}
            None if exclude.contains(&"signature") => {}
            None => {
                let message = [SIG_PREFIX_HS_V3, &content].concat();
                let signature = signing_key.sign(&message).to_bytes();
                content.extend_from_slice(
                    format!(
                        "signature {}",
                        crate::descriptor::truncated_base64(&signature)
                    )
                    .as_bytes(),
                );
            }
        }
        Ok(content)
    }

    pub fn create(
        attributes: &Attributes,
        exclude: &[&str],
        validate: bool,
        options: HiddenServiceV3Options,
    ) -> Result<Self> {
        Self::parse(&Self::content(attributes, exclude, options)?, validate)
    }

    pub fn parse_many(content: &[u8], validate: bool) -> Result<Vec<Self>> {
        let mut cursor = LineCursor::new(content);
        let mut descriptors = Vec::new();
        loop {
            let mut body = cursor
                .read_until_keywords(
                    &["signature"],
                    ReadOptions {
                        inclusive: true,
                        ..Default::default()
                    },
                )
                .content;
            if body.is_empty() {
                break;
            }
            if body.starts_with(b"@type") {
                body = body
                    .splitn(2, |byte| *byte == b'\n')
                    .nth(1)
                    .unwrap_or_default()
                    .to_vec();
            }
            descriptors.push(Self::parse(&body, validate)?);
        }
        Ok(descriptors)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum HiddenServiceDescriptor {
    V2(Box<HiddenServiceDescriptorV2>),
    V3(Box<HiddenServiceDescriptorV3>),
}

impl HiddenServiceDescriptor {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        let trimmed = content.trim_ascii_start();
        match trimmed.starts_with(b"hs-descriptor ") {
            true => Ok(Self::V3(Box::new(HiddenServiceDescriptorV3::parse(
                content, validate,
            )?))),
            false => Ok(Self::V2(Box::new(HiddenServiceDescriptorV2::parse(
                content, validate,
            )?))),
        }
    }

    pub fn raw_contents(&self) -> &[u8] {
        match self {
            Self::V2(descriptor) => &descriptor.raw_contents,
            Self::V3(descriptor) => &descriptor.raw_contents,
        }
    }
}
