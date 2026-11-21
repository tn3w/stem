use chrono::{DateTime, Duration, NaiveDateTime, TimeZone, Utc};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::client::datatypes::{CertType, Certificate};
use crate::descriptor::certificate::Ed25519Certificate;
use crate::error::{Error, Result};

const IDENTITY_KEY_BITS: usize = 1024;
const CLOCK_SKEW_HOURS: i64 = 24;
const CROSS_CERTIFICATE_PREFIX: &[u8] = b"Tor TLS RSA/Ed25519 cross-certificate";
const SHA256_WITH_RSA: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 1, 11];
const SHA1_WITH_RSA: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 1, 5];
const SHA256_DIGEST_INFO: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x01, 0x05, 0x00, 0x04, 0x20,
];
const SHA1_DIGEST_INFO: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
    0x14,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayIdentity {
    pub fingerprint: String,
    pub ed25519: Option<[u8; 32]>,
}

struct Element<'a> {
    tag: u8,
    content: &'a [u8],
    raw: &'a [u8],
}

fn malformed(reason: &str) -> Error {
    Error::protocol(format!("Malformed relay certificate: {reason}"))
}

fn read_element(input: &[u8]) -> Result<(Element<'_>, &[u8])> {
    let [tag, first_length, rest @ ..] = input else {
        return Err(malformed("truncated header"));
    };
    let (length, header_size) = match first_length {
        0..=127 => (usize::from(*first_length), 2),
        _ => {
            let size = usize::from(first_length & 0x7f);
            let digits = rest.get(..size).filter(|_| (1..=4).contains(&size));
            let digits = digits.ok_or_else(|| malformed("unsupported length"))?;
            let length = digits
                .iter()
                .fold(0, |sum, byte| sum << 8 | usize::from(*byte));
            (length, 2 + size)
        }
    };
    let end = header_size + length;
    if input.len() < end {
        return Err(malformed("truncated content"));
    }
    let element = Element {
        tag: *tag,
        content: &input[header_size..end],
        raw: &input[..end],
    };
    Ok((element, &input[end..]))
}

fn read_expected<'a>(input: &'a [u8], tag: u8) -> Result<(Element<'a>, &'a [u8])> {
    let (element, rest) = read_element(input)?;
    match element.tag == tag {
        true => Ok((element, rest)),
        false => Err(malformed("unexpected structure")),
    }
}

fn parse_time(element: &Element<'_>) -> Result<DateTime<Utc>> {
    let text = std::str::from_utf8(element.content)
        .map_err(|_| malformed("time isn't text"))?
        .strip_suffix('Z')
        .ok_or_else(|| malformed("time isn't UTC"))?;
    let (format, digits) = match element.tag {
        0x17 => ("%y%m%d%H%M%S", text),
        0x18 => ("%Y%m%d%H%M%S", text),
        _ => return Err(malformed("unknown time type")),
    };
    let parsed = NaiveDateTime::parse_from_str(digits, format)
        .map_err(|_| malformed("unparseable time"))?;
    Ok(Utc.from_utc_datetime(&parsed))
}

struct X509 {
    signed: Vec<u8>,
    signature_algorithm: Vec<u8>,
    signature: Vec<u8>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    public_key_info: Vec<u8>,
}

impl X509 {
    fn parse(der: &[u8]) -> Result<Self> {
        let (certificate, trailing) = read_expected(der, 0x30)?;
        if !trailing.is_empty() {
            return Err(malformed("trailing data"));
        }
        let (tbs, rest) = read_expected(certificate.content, 0x30)?;
        let (algorithm, rest) = read_expected(rest, 0x30)?;
        let (signature, _) = read_expected(rest, 0x03)?;
        let (oid, _) = read_expected(algorithm.content, 0x06)?;
        let after_version = match tbs.content.first() {
            Some(0xa0) => read_element(tbs.content)?.1,
            _ => tbs.content,
        };
        let (_, rest) = read_expected(after_version, 0x02)?;
        let (_, rest) = read_expected(rest, 0x30)?;
        let (_, rest) = read_expected(rest, 0x30)?;
        let (validity, rest) = read_expected(rest, 0x30)?;
        let (_, rest) = read_expected(rest, 0x30)?;
        let (public_key_info, _) = read_expected(rest, 0x30)?;
        let (not_before, after_start) = read_element(validity.content)?;
        let (not_after, _) = read_element(after_start)?;
        Ok(Self {
            signed: tbs.raw.to_vec(),
            signature_algorithm: oid.content.to_vec(),
            signature: signature.content.get(1..).unwrap_or_default().to_vec(),
            not_before: parse_time(&not_before)?,
            not_after: parse_time(&not_after)?,
            public_key_info: public_key_info.raw.to_vec(),
        })
    }

    fn public_key(&self) -> Result<RsaPublicKey> {
        RsaPublicKey::from_public_key_der(&self.public_key_info)
            .map_err(|_| malformed("key isn't RSA"))
    }

    fn check_validity(&self, now: DateTime<Utc>) -> Result<()> {
        let skew = Duration::hours(CLOCK_SKEW_HOURS);
        match self.not_before - skew <= now && now <= self.not_after + skew {
            true => Ok(()),
            false => Err(Error::protocol("Relay certificate isn't currently valid")),
        }
    }

    fn check_signed_by(&self, signer: &RsaPublicKey) -> Result<()> {
        let (digest_info, digest) = match self.signature_algorithm.as_slice() {
            SHA256_WITH_RSA => {
                (SHA256_DIGEST_INFO, Sha256::digest(&self.signed).to_vec())
            }
            SHA1_WITH_RSA => (SHA1_DIGEST_INFO, Sha1::digest(&self.signed).to_vec()),
            _ => return Err(malformed("unsupported signature algorithm")),
        };
        signer
            .verify(
                Pkcs1v15Sign::new_unprefixed(),
                &[digest_info, &digest].concat(),
                &self.signature,
            )
            .map_err(|_| Error::protocol("Relay certificate signature is invalid"))
    }
}

fn find_one(
    certificates: &[Certificate],
    cert_type: CertType,
) -> Result<Option<&Certificate>> {
    let mut matching = certificates
        .iter()
        .filter(|certificate| certificate.cert_type == cert_type);
    let found = matching.next();
    match matching.next() {
        Some(_) => Err(Error::protocol(format!(
            "CERTS cell has several {cert_type:?} certificates"
        ))),
        None => Ok(found),
    }
}

fn require(certificates: &[Certificate], cert_type: CertType) -> Result<&Certificate> {
    find_one(certificates, cert_type)?.ok_or_else(|| {
        Error::protocol(format!("CERTS cell lacks a {cert_type:?} certificate"))
    })
}

fn rsa_fingerprint(key: &RsaPublicKey) -> Result<String> {
    let der = key
        .to_pkcs1_der()
        .map_err(|_| malformed("identity key can't be encoded"))?;
    Ok(hex::encode_upper(<sha1::Sha1 as Digest>::digest(
        der.as_bytes(),
    )))
}

fn check_rsa_chain(
    certificates: &[Certificate],
    tls_certificate: &[u8],
    now: DateTime<Utc>,
) -> Result<RsaPublicKey> {
    let identity = X509::parse(&require(certificates, CertType::Identity)?.value)?;
    let identity_key = identity.public_key()?;
    if identity_key.size() * 8 != IDENTITY_KEY_BITS {
        return Err(Error::protocol("Relay identity key isn't 1024 bits"));
    }
    identity.check_signed_by(&identity_key)?;
    identity.check_validity(now)?;
    let link = X509::parse(&require(certificates, CertType::Link)?.value)?;
    link.check_signed_by(&identity_key)?;
    link.check_validity(now)?;
    let tls = X509::parse(tls_certificate)?;
    match tls.public_key_info == link.public_key_info {
        true => Ok(identity_key),
        false => Err(Error::protocol(
            "Link certificate isn't the TLS certificate",
        )),
    }
}

fn parse_ed25519(
    certificate: &Certificate,
    expected: CertType,
) -> Result<Ed25519Certificate> {
    let parsed = Ed25519Certificate::unpack(&certificate.value)?;
    if parsed.cert_type != expected {
        return Err(Error::protocol("Ed25519 certificate has the wrong type"));
    }
    match parsed.is_expired() {
        true => Err(Error::protocol("Ed25519 certificate is expired")),
        false => Ok(parsed),
    }
}

fn check_cross_certificate(
    certificate: &Certificate,
    identity_key: &[u8],
    rsa_key: &RsaPublicKey,
    now: DateTime<Utc>,
) -> Result<()> {
    let value = &certificate.value;
    let signature_length = usize::from(*value.get(36).ok_or_else(|| malformed("short"))?);
    let signature = value
        .get(37..37 + signature_length)
        .filter(|_| value.len() == 37 + signature_length)
        .ok_or_else(|| malformed("cross-certificate length"))?;
    if &value[..32] != identity_key {
        return Err(Error::protocol(
            "Cross-certificate is for another Ed25519 key",
        ));
    }
    let expiration_hours = u32::from_be_bytes(value[32..36].try_into().expect("4 bytes"));
    if i64::from(expiration_hours) * 3600 < now.timestamp() {
        return Err(Error::protocol("Cross-certificate is expired"));
    }
    let digest = Sha256::new()
        .chain_update(CROSS_CERTIFICATE_PREFIX)
        .chain_update(&value[..36])
        .finalize();
    rsa_key
        .verify(Pkcs1v15Sign::new_unprefixed(), &digest, signature)
        .map_err(|_| Error::protocol("Cross-certificate signature is invalid"))
}

fn check_ed25519_chain(
    certificates: &[Certificate],
    tls_certificate: &[u8],
    rsa_key: &RsaPublicKey,
    now: DateTime<Utc>,
) -> Result<Option<[u8; 32]>> {
    let signing = find_one(certificates, CertType::Ed25519Signing)?;
    let link = find_one(certificates, CertType::LinkCert)?;
    let cross = find_one(certificates, CertType::Ed25519Identity)?;
    let (Some(signing), Some(link), Some(cross)) = (signing, link, cross) else {
        return match (signing, link, cross) {
            (None, None, None) => Ok(None),
            _ => Err(Error::protocol(
                "CERTS cell has incomplete Ed25519 certificates",
            )),
        };
    };
    let signing = parse_ed25519(signing, CertType::Ed25519Signing)?;
    let identity: [u8; 32] = signing
        .signing_key()
        .and_then(|key| key.try_into().ok())
        .ok_or_else(|| Error::protocol("Signing certificate lacks the identity key"))?;
    signing.verify_certificate_signature(&identity)?;
    let link = parse_ed25519(link, CertType::LinkCert)?;
    link.verify_certificate_signature(&signing.key)?;
    if link.key.as_slice() != Sha256::digest(tls_certificate).as_slice() {
        return Err(Error::protocol(
            "Ed25519 link certificate isn't the TLS certificate",
        ));
    }
    check_cross_certificate(cross, &identity, rsa_key, now)?;
    Ok(Some(identity))
}

pub fn verify_relay_certificates(
    certificates: &[Certificate],
    tls_certificate: &[u8],
) -> Result<RelayIdentity> {
    let now = Utc::now();
    let rsa_key = check_rsa_chain(certificates, tls_certificate, now)?;
    let ed25519 = check_ed25519_chain(certificates, tls_certificate, &rsa_key, now)?;
    Ok(RelayIdentity {
        fingerprint: rsa_fingerprint(&rsa_key)?,
        ed25519,
    })
}
