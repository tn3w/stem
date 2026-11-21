use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::client::datatypes::{CertType, Reader};
use crate::descriptor::{decode_base64, split_into_lines};
use crate::error::{Error, Result};

pub const ED25519_KEY_LENGTH: usize = 32;
pub const ED25519_HEADER_LENGTH: usize = 40;
pub const ED25519_SIGNATURE_LENGTH: usize = 64;
pub const SIG_PREFIX_SERVER_DESC: &[u8] = b"Tor router descriptor signature v1";
pub const SIG_PREFIX_HS_V3: &[u8] = b"Tor onion service descriptor sig v3";
const DEFAULT_EXPIRATION_HOURS: i64 = 54;
const HAS_SIGNING_KEY: u8 = 4;
const PEM_START: &str = "-----BEGIN ED25519 CERT-----\n";
const PEM_END: &str = "\n-----END ED25519 CERT-----";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ExtensionFlag {
    AffectsValidation,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Ed25519Extension {
    #[serde(rename = "type")]
    pub extension_type: u8,
    pub flags: Vec<ExtensionFlag>,
    pub flag_int: u8,
    #[serde(serialize_with = "crate::descriptor::serialize_hex")]
    pub data: Vec<u8>,
}

fn whole_hours(moment: NaiveDateTime) -> NaiveDateTime {
    let seconds = moment.and_utc().timestamp() / 3600 * 3600;
    DateTime::from_timestamp(seconds, 0).map_or(moment, |floored| floored.naive_utc())
}

impl Ed25519Extension {
    pub fn new(extension_type: u8, flag_int: u8, data: Vec<u8>) -> Result<Self> {
        let mut flags = Vec::new();
        let mut remaining = flag_int;
        if remaining % 2 == 1 {
            flags.push(ExtensionFlag::AffectsValidation);
            remaining -= 1;
        }
        if remaining != 0 {
            flags.push(ExtensionFlag::Unknown);
        }
        if extension_type == HAS_SIGNING_KEY && data.len() != 32 {
            return Err(Error::parse(format!(
                "Ed25519 HAS_SIGNING_KEY extension must be 32 bytes, but was {}.",
                data.len()
            )));
        }
        Ok(Self {
            extension_type,
            flags,
            flag_int,
            data,
        })
    }

    pub fn signing_key_extension(key: [u8; 32]) -> Self {
        Self {
            extension_type: HAS_SIGNING_KEY,
            flags: Vec::new(),
            flag_int: 0,
            data: key.to_vec(),
        }
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut packed = (self.data.len() as u16).to_be_bytes().to_vec();
        packed.push(self.extension_type);
        packed.push(self.flag_int);
        packed.extend_from_slice(&self.data);
        packed
    }

    fn pop(reader: &mut Reader<'_>) -> Result<Self> {
        if reader.remaining() < 4 {
            return Err(Error::parse("Ed25519 extension is missing header fields"));
        }
        let size = usize::from(reader.u16()?);
        let extension_type = reader.u8()?;
        let flags = reader.u8()?;
        if reader.remaining() < size {
            return Err(Error::parse(format!(
                "Ed25519 extension is truncated. It should have {size} bytes of data \
                but there's only {}.",
                reader.remaining()
            )));
        }
        Self::new(extension_type, flags, reader.take(size)?.to_vec())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Ed25519Certificate {
    pub version: u8,
    pub cert_type: CertType,
    pub expiration: NaiveDateTime,
    pub key_type: u8,
    #[serde(serialize_with = "crate::descriptor::serialize_hex")]
    pub key: [u8; 32],
    pub extensions: Vec<Ed25519Extension>,
    #[serde(serialize_with = "crate::descriptor::serialize_optional_hex")]
    pub signature: Option<Vec<u8>>,
    pub encoded: Option<String>,
}

impl PartialEq for Ed25519Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.cert_type == other.cert_type
            && self.expiration == other.expiration
            && self.key_type == other.key_type
            && self.key == other.key
            && self.extensions == other.extensions
            && self.signature == other.signature
    }
}

impl Eq for Ed25519Certificate {}

impl Ed25519Certificate {
    pub fn new(
        cert_type: CertType,
        expiration: Option<NaiveDateTime>,
        key_type: Option<u8>,
        key: [u8; 32],
        extensions: Vec<Ed25519Extension>,
        signature: Option<Vec<u8>>,
        signing_key: Option<&SigningKey>,
    ) -> Result<Self> {
        match cert_type {
            CertType::Link | CertType::Identity | CertType::Authenticate => {
                return Err(Error::parse(format!(
                    "Ed25519 certificate cannot have a type of {}. This is reserved for \
                    CERTS cells.",
                    cert_type.value()
                )));
            }
            CertType::Ed25519Identity => {
                return Err(Error::parse(
                    "Ed25519 certificate cannot have a type of 7. This is reserved for \
                    RSA identity cross-certification.",
                ));
            }
            CertType::Unknown(value) => {
                return Err(Error::parse(format!(
                    "Ed25519 certificate type {value} is unrecognized"
                )));
            }
            _ => {}
        }
        let mut certificate = Self {
            version: 1,
            cert_type,
            expiration: whole_hours(expiration.unwrap_or_else(|| {
                Utc::now().naive_utc() + Duration::hours(DEFAULT_EXPIRATION_HOURS)
            })),
            key_type: key_type.unwrap_or(1),
            key,
            extensions,
            signature,
            encoded: None,
        };
        if let Some(signing_key) = signing_key {
            let calculated = signing_key.sign(&certificate.pack()?).to_bytes().to_vec();
            if certificate
                .signature
                .as_ref()
                .is_some_and(|given| *given != calculated)
            {
                return Err(Error::parse(
                    "Signature calculated from its key mismatches the one provided",
                ));
            }
            certificate.signature = Some(calculated);
        }
        Ok(certificate)
    }

    pub fn from_base64(content: &str) -> Result<Self> {
        let body = match content.starts_with(PEM_START) && content.ends_with(PEM_END) {
            true => &content[PEM_START.len()..content.len() - PEM_END.len()],
            false => content,
        };
        let decoded = decode_base64(body).map_err(|error| {
            Error::parse(format!(
                "Ed25519 certificate wasn't properly base64 encoded ({error}):\n{body}"
            ))
        })?;
        if decoded.is_empty() {
            return Err(Error::parse(format!(
                "Ed25519 certificate wasn't properly base64 encoded (empty):\n{body}"
            )));
        }
        let mut certificate = Self::unpack(&decoded)?;
        certificate.encoded = Some(body.to_string());
        Ok(certificate)
    }

    pub fn parse(content: &str) -> Result<Self> {
        Self::from_base64(content)
    }

    pub fn unpack(content: &[u8]) -> Result<Self> {
        let version = *content
            .first()
            .ok_or_else(|| Error::parse("Ed25519 certificate is empty"))?;
        if version != 1 {
            return Err(Error::parse(format!(
                "Ed25519 certificate is version {version}. Parser presently only \
                supports version 1."
            )));
        }
        let minimum = ED25519_HEADER_LENGTH + ED25519_SIGNATURE_LENGTH;
        if content.len() < minimum {
            return Err(Error::parse(format!(
                "Ed25519 certificate was {} bytes, but should be at least {minimum}",
                content.len()
            )));
        }
        let (header, signature) =
            content.split_at(content.len() - ED25519_SIGNATURE_LENGTH);
        let mut reader = Reader::new(header);
        reader.u8()?;
        let cert_type = CertType::from_value(reader.u8()?);
        let expiration_hours = reader.u32()?;
        let key_type = reader.u8()?;
        let key: [u8; 32] = reader
            .take(ED25519_KEY_LENGTH)?
            .try_into()
            .expect("32 bytes");
        let extension_count = reader.u8()?;
        let mut extensions = Vec::new();
        for _ in 0..extension_count {
            extensions.push(Ed25519Extension::pop(&mut reader)?);
        }
        if reader.remaining() > 0 {
            return Err(Error::parse(format!(
                "Ed25519 certificate had {} bytes of unused extension data",
                reader.remaining()
            )));
        }
        let expiration = DateTime::from_timestamp(i64::from(expiration_hours) * 3600, 0)
            .ok_or_else(|| {
                Error::parse("Ed25519 certificate expiration is out of range")
            })?
            .naive_utc();
        let mut certificate = Self::new(
            cert_type,
            Some(expiration),
            Some(key_type),
            key,
            extensions,
            Some(signature.to_vec()),
            None,
        )?;
        certificate.version = version;
        Ok(certificate)
    }

    pub fn pack(&self) -> Result<Vec<u8>> {
        let hours = u32::try_from(self.expiration.and_utc().timestamp() / 3600).map_err(
            |_| Error::invalid_input("Certificate expiration is out of range"),
        )?;
        let mut packed = vec![self.version, self.cert_type.value()];
        packed.extend_from_slice(&hours.to_be_bytes());
        packed.push(self.key_type);
        packed.extend_from_slice(&self.key);
        packed.push(
            u8::try_from(self.extensions.len())
                .map_err(|_| Error::invalid_input("Too many certificate extensions"))?,
        );
        for extension in &self.extensions {
            packed.extend_from_slice(&extension.pack());
        }
        if let Some(signature) = &self.signature {
            packed.extend_from_slice(signature);
        }
        Ok(packed)
    }

    pub fn to_base64(&self, pem: bool) -> Result<String> {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(self.pack()?);
        let body = split_into_lines(&encoded, 64).join("\n");
        Ok(match pem {
            true => format!("{PEM_START}{body}{PEM_END}"),
            false => body,
        })
    }

    pub fn is_expired(&self) -> bool {
        Utc::now().naive_utc() > self.expiration
    }

    pub fn signing_key(&self) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|extension| extension.extension_type == HAS_SIGNING_KEY)
            .map(|extension| extension.data.as_slice())
    }

    pub fn verify_signature(
        &self,
        signed_content: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        verify_ed25519(&self.key, signed_content, signature).map_err(|_| {
            Error::parse(
                "Descriptor Ed25519 certificate signature invalid (signature \
                forged or corrupt)",
            )
        })
    }

    pub fn verify_certificate_signature(&self, signing_key: &[u8]) -> Result<()> {
        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| Error::parse("Ed25519 certificate has no signature"))?;
        let packed = self.pack()?;
        verify_ed25519(
            signing_key,
            &packed[..packed.len() - ED25519_SIGNATURE_LENGTH],
            signature,
        )
        .map_err(|_| {
            Error::parse(
                "Ed25519KeyCertificate signing key is invalid (signature forged or \
                    corrupt)",
            )
        })
    }
}

impl std::fmt::Display for Ed25519Certificate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_base64(true) {
            Ok(text) => formatter.write_str(&text),
            Err(_) => Err(std::fmt::Error),
        }
    }
}

pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| Error::parse("Ed25519 public keys are 32 bytes"))?;
    let signature_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| Error::parse("Ed25519 signatures are 64 bytes"))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| Error::parse(error.to_string()))?;
    key.verify_strict(message, &Signature::from_bytes(&signature_bytes))
        .map_err(|error| Error::parse(error.to_string()))
}
