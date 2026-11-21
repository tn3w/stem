use std::net::{Ipv4Addr, Ipv6Addr};

use sha1::{Digest, Sha1};

use crate::error::{Error, Result};

pub const HASH_LENGTH: usize = 20;
pub const KEY_LENGTH: usize = 16;

macro_rules! integer_enum {
    ($name:ident($int:ty) { $($variant:ident = $value:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
        pub enum $name {
            $($variant,)+
            Unknown($int),
        }

        impl $name {
            pub fn value(self) -> $int {
                match self {
                    $(Self::$variant => $value,)+
                    Self::Unknown(value) => value,
                }
            }

            pub fn from_value(value: $int) -> Self {
                match value {
                    $($value => Self::$variant,)+
                    other => Self::Unknown(other),
                }
            }

            pub fn is_unknown(self) -> bool {
                matches!(self, Self::Unknown(_))
            }
        }
    };
}

integer_enum!(AddrType(u8) {
    Hostname = 0,
    Ipv4 = 4,
    Ipv6 = 6,
    ErrorTransient = 16,
    ErrorPermanent = 17,
});

integer_enum!(RelayCommand(u8) {
    Begin = 1,
    Data = 2,
    End = 3,
    Connected = 4,
    Sendme = 5,
    Extend = 6,
    Extended = 7,
    Truncate = 8,
    Truncated = 9,
    Drop = 10,
    Resolve = 11,
    Resolved = 12,
    BeginDir = 13,
    Extend2 = 14,
    Extended2 = 15,
});

integer_enum!(CertType(u8) {
    Link = 1,
    Identity = 2,
    Authenticate = 3,
    Ed25519Signing = 4,
    LinkCert = 5,
    Ed25519Authenticate = 6,
    Ed25519Identity = 7,
    HsV3DescSigning = 8,
    HsV3IntroAuth = 9,
    NtorOnionKey = 10,
    HsV3NtorEnc = 11,
});

integer_enum!(CloseReason(u8) {
    None = 0,
    Protocol = 1,
    Internal = 2,
    Requested = 3,
    Hibernating = 4,
    ResourceLimit = 5,
    ConnectFailed = 6,
    OrIdentity = 7,
    OrConnClosed = 8,
    Finished = 9,
    Timeout = 10,
    Destroyed = 11,
    NoSuchService = 12,
});

impl RelayCommand {
    pub fn name(self) -> String {
        match self {
            Self::Unknown(value) => format!("UNKNOWN({value})"),
            known => {
                let mut name = String::from("RELAY");
                for character in format!("{known:?}").chars() {
                    if character.is_uppercase() {
                        name.push('_');
                    }
                    name.push(character.to_ascii_uppercase());
                }
                name
            }
        }
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn remaining(&self) -> usize {
        self.data.len()
    }

    pub fn rest(self) -> &'a [u8] {
        self.data
    }

    pub fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.data.len() < count {
            return Err(Error::parse(format!(
                "Expected {count} more bytes, but only {} remained",
                self.data.len()
            )));
        }
        let (taken, rest) = self.data.split_at(count);
        self.data = rest;
        Ok(taken)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkProtocol {
    pub version: u32,
}

impl LinkProtocol {
    pub fn new(version: u32) -> Self {
        Self { version }
    }

    pub fn circuit_id_size(&self) -> usize {
        match self.version > 3 {
            true => 4,
            false => 2,
        }
    }

    pub fn first_circuit_id(&self) -> u32 {
        match self.version > 3 {
            true => 0x8000_0000,
            false => 1,
        }
    }

    pub fn fixed_cell_length(&self) -> usize {
        self.circuit_id_size() + 1 + crate::client::cells::FIXED_PAYLOAD_LENGTH
    }

    pub fn pack_circuit_id(&self, circuit_id: u32) -> Result<Vec<u8>> {
        match self.circuit_id_size() {
            4 => Ok(circuit_id.to_be_bytes().to_vec()),
            _ => u16::try_from(circuit_id)
                .map(|id| id.to_be_bytes().to_vec())
                .map_err(|_| {
                    Error::invalid_input("Circuit id is too large for this link protocol")
                }),
        }
    }

    pub fn pop_circuit_id(&self, reader: &mut Reader<'_>) -> Result<u32> {
        match self.circuit_id_size() {
            4 => reader.u32(),
            _ => reader.u16().map(u32::from),
        }
    }
}

impl From<u32> for LinkProtocol {
    fn from(version: u32) -> Self {
        Self::new(version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    pub addr_type: AddrType,
    value_bin: Vec<u8>,
}

impl Address {
    pub fn parse(value: &str) -> Result<Self> {
        if let Ok(address) = value.parse::<Ipv4Addr>() {
            return Self::from_bytes(AddrType::Ipv4, address.octets().to_vec());
        }
        if let Ok(address) = value.parse::<Ipv6Addr>() {
            return Self::from_bytes(AddrType::Ipv6, address.octets().to_vec());
        }
        Err(Error::invalid_input(format!(
            "'{value}' isn't an IPv4 or IPv6 address"
        )))
    }

    pub fn from_bytes(addr_type: AddrType, value_bin: Vec<u8>) -> Result<Self> {
        match (addr_type, value_bin.len()) {
            (AddrType::Ipv4, 4) | (AddrType::Ipv6, 16) => {}
            (AddrType::Ipv4, _) => {
                return Err(Error::invalid_input(format!(
                    "Packed IPv4 addresses should be four bytes, but was: {value_bin:?}"
                )));
            }
            (AddrType::Ipv6, _) => {
                return Err(Error::invalid_input(format!(
                    "Packed IPv6 addresses should be sixteen bytes, but was: \
                    {value_bin:?}"
                )));
            }
            _ => {}
        }
        Ok(Self {
            addr_type,
            value_bin,
        })
    }

    pub fn value(&self) -> Option<String> {
        match self.addr_type {
            AddrType::Ipv4 => {
                let octets: [u8; 4] = self.value_bin.as_slice().try_into().ok()?;
                Some(Ipv4Addr::from(octets).to_string())
            }
            AddrType::Ipv6 => {
                let octets: [u8; 16] = self.value_bin.as_slice().try_into().ok()?;
                let groups: Vec<String> = Ipv6Addr::from(octets)
                    .segments()
                    .iter()
                    .map(|group| format!("{group:04x}"))
                    .collect();
                Some(groups.join(":"))
            }
            _ => None,
        }
    }

    pub fn value_bin(&self) -> &[u8] {
        &self.value_bin
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut packed = vec![self.addr_type.value(), self.value_bin.len() as u8];
        packed.extend_from_slice(&self.value_bin);
        packed
    }

    pub fn pop(reader: &mut Reader<'_>) -> Result<Self> {
        let addr_type = AddrType::from_value(reader.u8()?);
        let length = usize::from(reader.u8()?);
        if reader.remaining() < length {
            return Err(Error::parse(format!(
                "Address specified a payload of {length} bytes, but only had {}",
                reader.remaining()
            )));
        }
        Self::from_bytes(addr_type, reader.take(length)?.to_vec())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Certificate {
    pub cert_type: CertType,
    pub value: Vec<u8>,
}

impl Certificate {
    pub fn new(cert_type: CertType, value: Vec<u8>) -> Self {
        Self { cert_type, value }
    }

    pub fn pack(&self) -> Result<Vec<u8>> {
        let length = u16::try_from(self.value.len())
            .map_err(|_| Error::invalid_input("Certificates can't exceed 65535 bytes"))?;
        let mut packed = vec![self.cert_type.value()];
        packed.extend_from_slice(&length.to_be_bytes());
        packed.extend_from_slice(&self.value);
        Ok(packed)
    }

    pub fn pop(reader: &mut Reader<'_>) -> Result<Self> {
        let cert_type = CertType::from_value(reader.u8()?);
        let size = usize::from(reader.u16()?);
        if size > reader.remaining() {
            return Err(Error::parse(format!(
                "CERTS cell should have a certificate with {size} bytes, but only had \
                {} remaining",
                reader.remaining()
            )));
        }
        Ok(Self::new(cert_type, reader.take(size)?.to_vec()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub enum LinkSpecifier {
    Ipv4 { address: Ipv4Addr, port: u16 },
    Ipv6 { address: Ipv6Addr, port: u16 },
    Fingerprint([u8; 20]),
    Ed25519([u8; 32]),
    Other { link_type: u8, value: Vec<u8> },
}

impl LinkSpecifier {
    pub fn link_type(&self) -> u8 {
        match self {
            Self::Ipv4 { .. } => 0,
            Self::Ipv6 { .. } => 1,
            Self::Fingerprint(_) => 2,
            Self::Ed25519(_) => 3,
            Self::Other { link_type, .. } => *link_type,
        }
    }

    fn value(&self) -> Vec<u8> {
        match self {
            Self::Ipv4 { address, port } => {
                [address.octets().as_slice(), &port.to_be_bytes()].concat()
            }
            Self::Ipv6 { address, port } => {
                [address.octets().as_slice(), &port.to_be_bytes()].concat()
            }
            Self::Fingerprint(value) => value.to_vec(),
            Self::Ed25519(value) => value.to_vec(),
            Self::Other { value, .. } => value.clone(),
        }
    }

    pub fn pack(&self) -> Vec<u8> {
        let value = self.value();
        let mut packed = vec![self.link_type(), value.len() as u8];
        packed.extend_from_slice(&value);
        packed
    }

    pub fn pop(reader: &mut Reader<'_>) -> Result<Self> {
        let link_type = reader.u8()?;
        let size = usize::from(reader.u8()?);
        if size > reader.remaining() {
            return Err(Error::parse(format!(
                "Link specifier should have {size} bytes, but only had {} remaining",
                reader.remaining()
            )));
        }
        let value = reader.take(size)?;
        Self::from_parts(link_type, value)
    }

    fn from_parts(link_type: u8, value: &[u8]) -> Result<Self> {
        let size_error = |name: &str, expected: usize| {
            Error::parse(format!(
                "{name} link specifiers should be {expected} bytes, but was {} instead: \
                {}",
                value.len(),
                hex::encode(value)
            ))
        };
        Ok(match link_type {
            0 => {
                let bytes: [u8; 6] =
                    value.try_into().map_err(|_| size_error("IPv4", 6))?;
                Self::Ipv4 {
                    address: Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
                    port: u16::from_be_bytes([bytes[4], bytes[5]]),
                }
            }
            1 => {
                let bytes: [u8; 18] =
                    value.try_into().map_err(|_| size_error("IPv6", 18))?;
                let octets: [u8; 16] = bytes[..16].try_into().expect("sixteen bytes");
                Self::Ipv6 {
                    address: Ipv6Addr::from(octets),
                    port: u16::from_be_bytes([bytes[16], bytes[17]]),
                }
            }
            2 => Self::Fingerprint(
                value
                    .try_into()
                    .map_err(|_| size_error("Fingerprint", 20))?,
            ),
            3 => Self::Ed25519(value.try_into().map_err(|_| size_error("Ed25519", 32))?),
            other => Self::Other {
                link_type: other,
                value: value.to_vec(),
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kdf {
    pub key_hash: Vec<u8>,
    pub forward_digest: Vec<u8>,
    pub backward_digest: Vec<u8>,
    pub forward_key: Vec<u8>,
    pub backward_key: Vec<u8>,
}

impl Kdf {
    pub fn from_value(key_material: &[u8]) -> Self {
        let wanted = KEY_LENGTH * 2 + HASH_LENGTH * 3;
        let mut derived = Vec::with_capacity(wanted + HASH_LENGTH);
        let mut counter: u8 = 0;
        while derived.len() < wanted {
            let mut hasher = Sha1::new();
            hasher.update(key_material);
            hasher.update([counter]);
            derived.extend_from_slice(&hasher.finalize());
            counter += 1;
        }
        let mut reader = Reader::new(&derived);
        let mut next = |count| reader.take(count).expect("enough derived bytes").to_vec();
        Self {
            key_hash: next(HASH_LENGTH),
            forward_digest: next(HASH_LENGTH),
            backward_digest: next(HASH_LENGTH),
            forward_key: next(KEY_LENGTH),
            backward_key: next(KEY_LENGTH),
        }
    }
}
