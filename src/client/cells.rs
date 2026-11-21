use aes::Aes128;
use chrono::{DateTime, NaiveDateTime};
use ctr::Ctr128BE;
use ctr::cipher::StreamCipher;
use sha1::{Digest, Sha1};

use crate::client::datatypes::{
    Address, Certificate, CloseReason, HASH_LENGTH, LinkProtocol, Reader, RelayCommand,
};
use crate::error::{Error, Result};

pub const FIXED_PAYLOAD_LENGTH: usize = 509;
pub const AUTH_CHALLENGE_SIZE: usize = 32;
const RELAY_DIGEST_SIZE: usize = 4;

pub type RelayCipher = Ctr128BE<Aes128>;

const STREAM_ID_REQUIRED: [RelayCommand; 7] = [
    RelayCommand::Begin,
    RelayCommand::Data,
    RelayCommand::End,
    RelayCommand::Connected,
    RelayCommand::Resolve,
    RelayCommand::Resolved,
    RelayCommand::BeginDir,
];

const STREAM_ID_DISALLOWED: [RelayCommand; 7] = [
    RelayCommand::Extend,
    RelayCommand::Extended,
    RelayCommand::Truncate,
    RelayCommand::Truncated,
    RelayCommand::Drop,
    RelayCommand::Extend2,
    RelayCommand::Extended2,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCell {
    pub circuit_id: u32,
    pub command: RelayCommand,
    pub data: Vec<u8>,
    pub digest: u32,
    pub stream_id: u16,
    pub recognized: u16,
    pub unused: Vec<u8>,
}

impl RelayCell {
    pub fn new(
        circuit_id: u32,
        command: RelayCommand,
        data: Vec<u8>,
        stream_id: u16,
    ) -> Result<Self> {
        Self::with_digest(circuit_id, command, data, 0, stream_id, 0, Vec::new())
    }

    pub fn with_digest(
        circuit_id: u32,
        command: RelayCommand,
        data: Vec<u8>,
        digest: u32,
        stream_id: u16,
        recognized: u16,
        unused: Vec<u8>,
    ) -> Result<Self> {
        if digest == 0 {
            if stream_id == 0 && STREAM_ID_REQUIRED.contains(&command) {
                return Err(Error::invalid_input(format!(
                    "{} relay cells require a stream id",
                    command.name()
                )));
            }
            if stream_id != 0 && STREAM_ID_DISALLOWED.contains(&command) {
                return Err(Error::invalid_input(format!(
                    "{} relay cells concern the circuit itself and cannot have a stream \
                    id",
                    command.name()
                )));
            }
        }
        Ok(Self {
            circuit_id,
            command,
            data,
            digest,
            stream_id,
            recognized,
            unused,
        })
    }

    fn payload(&self) -> Result<Vec<u8>> {
        let length = u16::try_from(self.data.len())
            .map_err(|_| Error::invalid_input("Relay cell data is too large"))?;
        let mut payload = vec![self.command.value()];
        payload.extend_from_slice(&self.recognized.to_be_bytes());
        payload.extend_from_slice(&self.stream_id.to_be_bytes());
        payload.extend_from_slice(&self.digest.to_be_bytes());
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(&self.data);
        Ok(payload)
    }

    pub fn encrypt(
        &self,
        link_protocol: LinkProtocol,
        key: &mut RelayCipher,
        digest: &mut Sha1,
    ) -> Result<Vec<u8>> {
        let header_size = link_protocol.circuit_id_size() + 1;
        let unsealed = pack_cell(
            link_protocol,
            3,
            &self.payload()?,
            &self.unused,
            Some(self.circuit_id),
        )?;
        digest.update(&unsealed[header_size..]);
        let digest_bytes = digest.clone().finalize();
        let sealed = Self::with_digest(
            self.circuit_id,
            self.command,
            self.data.clone(),
            u32::from_be_bytes(
                digest_bytes[..RELAY_DIGEST_SIZE]
                    .try_into()
                    .expect("four bytes"),
            ),
            self.stream_id,
            self.recognized,
            self.unused.clone(),
        )?;
        let packed = pack_cell(
            link_protocol,
            3,
            &sealed.payload()?,
            &sealed.unused,
            Some(self.circuit_id),
        )?;
        let (header, payload) = packed.split_at(header_size);
        let mut encrypted = payload.to_vec();
        key.apply_keystream(&mut encrypted);
        Ok([header, &encrypted].concat())
    }

    pub fn decrypt(
        link_protocol: LinkProtocol,
        content: &[u8],
        key: &mut RelayCipher,
        digest: &mut Sha1,
    ) -> Result<Self> {
        if content.len() != link_protocol.fixed_cell_length() {
            return Err(Error::protocol(format!(
                "RELAY cells should be {} bytes, but received {}",
                link_protocol.fixed_cell_length(),
                content.len()
            )));
        }
        let mut reader = Reader::new(content);
        let circuit_id = link_protocol.pop_circuit_id(&mut reader)?;
        let command = reader.u8()?;
        if command != 3 {
            return Err(Error::protocol(format!(
                "Cannot decrypt as a RELAY cell. This had command {command} instead."
            )));
        }
        let mut payload = reader.rest().to_vec();
        key.apply_keystream(&mut payload);
        let cell = Self::unpack_payload(&payload, circuit_id)?;
        if cell.recognized != 0 {
            return Err(Error::protocol(
                "Relay cell wasn't recognized by this circuit",
            ));
        }
        let mut zeroed = payload.clone();
        zeroed[5..5 + RELAY_DIGEST_SIZE].fill(0);
        digest.update(&zeroed);
        let expected = digest.clone().finalize();
        if expected[..RELAY_DIGEST_SIZE] != cell.digest.to_be_bytes() {
            return Err(Error::protocol(
                "Relay cell digest didn't match the circuit's",
            ));
        }
        Ok(cell)
    }

    fn unpack_payload(content: &[u8], circuit_id: u32) -> Result<Self> {
        let mut reader = Reader::new(content);
        let command = RelayCommand::from_value(reader.u8()?);
        let recognized = reader.u16()?;
        let stream_id = reader.u16()?;
        let digest = reader.u32()?;
        let data_length = usize::from(reader.u16()?);
        if reader.remaining() < data_length {
            return Err(Error::parse(format!(
                "RELAY cell said it had {data_length} bytes of data, but only had {}",
                reader.remaining()
            )));
        }
        let data = reader.take(data_length)?.to_vec();
        Self::with_digest(
            circuit_id,
            command,
            data,
            digest,
            stream_id,
            recognized,
            reader.rest().to_vec(),
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Padding {
        payload: Vec<u8>,
    },
    Create {
        circuit_id: u32,
        payload: Vec<u8>,
    },
    Created {
        circuit_id: u32,
        payload: Vec<u8>,
    },
    Relay(RelayCell),
    Destroy {
        circuit_id: u32,
        reason: CloseReason,
        unused: Vec<u8>,
    },
    CreateFast {
        circuit_id: u32,
        key_material: Vec<u8>,
        unused: Vec<u8>,
    },
    CreatedFast {
        circuit_id: u32,
        derivative_key: Vec<u8>,
        key_material: Vec<u8>,
        unused: Vec<u8>,
    },
    Versions {
        versions: Vec<u16>,
    },
    Netinfo {
        timestamp: NaiveDateTime,
        receiver_address: Address,
        sender_addresses: Vec<Address>,
        unused: Vec<u8>,
    },
    RelayEarly {
        circuit_id: u32,
        payload: Vec<u8>,
    },
    Create2 {
        circuit_id: u32,
        payload: Vec<u8>,
    },
    Created2 {
        circuit_id: u32,
        payload: Vec<u8>,
    },
    PaddingNegotiate {
        payload: Vec<u8>,
    },
    VPadding {
        payload: Vec<u8>,
    },
    Certs {
        certificates: Vec<Certificate>,
        unused: Vec<u8>,
    },
    AuthChallenge {
        challenge: Vec<u8>,
        methods: Vec<u16>,
        unused: Vec<u8>,
    },
    Authenticate {
        payload: Vec<u8>,
    },
    Authorize {
        payload: Vec<u8>,
    },
}

fn is_fixed_size(command: u8) -> bool {
    !matches!(command, 7 | 128..=255)
}

fn is_circuit_command(command: u8) -> bool {
    matches!(command, 1..=6 | 9..=11)
}

fn pack_cell(
    link_protocol: LinkProtocol,
    command: u8,
    payload: &[u8],
    unused: &[u8],
    circuit_id: Option<u32>,
) -> Result<Vec<u8>> {
    let identifier = match (is_circuit_command(command), circuit_id) {
        (true, None) => {
            return Err(Error::invalid_input(
                "Circuit cells require a circuit identifier",
            ));
        }
        (true, Some(0)) => {
            return Err(Error::invalid_input(
                "Circuit identifiers must a positive integer, not 0",
            ));
        }
        (true, Some(identifier)) => identifier,
        (false, Some(_)) => {
            return Err(Error::invalid_input(
                "This cell type should not specify a circuit identifier",
            ));
        }
        (false, None) => 0,
    };
    let mut cell = link_protocol.pack_circuit_id(identifier)?;
    cell.push(command);
    if !is_fixed_size(command) {
        let length = u16::try_from(payload.len() + unused.len()).map_err(|_| {
            Error::invalid_input("Variable length cell payload is too large")
        })?;
        cell.extend_from_slice(&length.to_be_bytes());
    }
    cell.extend_from_slice(payload);
    cell.extend_from_slice(unused);
    if is_fixed_size(command) {
        if cell.len() > link_protocol.fixed_cell_length() {
            return Err(Error::invalid_input(format!(
                "Cell is too large ({} bytes), must not be more than {}. Check payload \
                size (was {} bytes)",
                cell.len(),
                link_protocol.fixed_cell_length(),
                payload.len()
            )));
        }
        cell.resize(link_protocol.fixed_cell_length(), 0);
    }
    Ok(cell)
}

fn exact_length(name: &str, value: Vec<u8>, length: usize) -> Result<Vec<u8>> {
    match value.len() == length {
        true => Ok(value),
        false => Err(Error::invalid_input(format!(
            "{name} should be {length} bytes, but was {}",
            value.len()
        ))),
    }
}

impl Cell {
    pub fn padding() -> Self {
        Self::Padding {
            payload: rand::random::<[u8; FIXED_PAYLOAD_LENGTH]>().to_vec(),
        }
    }

    pub fn versions(versions: &[u16]) -> Self {
        Self::Versions {
            versions: versions.to_vec(),
        }
    }

    pub fn create_fast(circuit_id: u32) -> Self {
        Self::CreateFast {
            circuit_id,
            key_material: rand::random::<[u8; HASH_LENGTH]>().to_vec(),
            unused: Vec::new(),
        }
    }

    pub fn destroy(circuit_id: u32, reason: CloseReason) -> Self {
        Self::Destroy {
            circuit_id,
            reason,
            unused: Vec::new(),
        }
    }

    pub fn netinfo(receiver_address: Address, sender_addresses: Vec<Address>) -> Self {
        Self::Netinfo {
            timestamp: chrono::Utc::now().naive_utc(),
            receiver_address,
            sender_addresses,
            unused: Vec::new(),
        }
    }

    pub fn command(&self) -> u8 {
        match self {
            Self::Padding { .. } => 0,
            Self::Create { .. } => 1,
            Self::Created { .. } => 2,
            Self::Relay(_) => 3,
            Self::Destroy { .. } => 4,
            Self::CreateFast { .. } => 5,
            Self::CreatedFast { .. } => 6,
            Self::Versions { .. } => 7,
            Self::Netinfo { .. } => 8,
            Self::RelayEarly { .. } => 9,
            Self::Create2 { .. } => 10,
            Self::Created2 { .. } => 11,
            Self::PaddingNegotiate { .. } => 12,
            Self::VPadding { .. } => 128,
            Self::Certs { .. } => 129,
            Self::AuthChallenge { .. } => 130,
            Self::Authenticate { .. } => 131,
            Self::Authorize { .. } => 132,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Padding { .. } => "PADDING",
            Self::Create { .. } => "CREATE",
            Self::Created { .. } => "CREATED",
            Self::Relay(_) => "RELAY",
            Self::Destroy { .. } => "DESTROY",
            Self::CreateFast { .. } => "CREATE_FAST",
            Self::CreatedFast { .. } => "CREATED_FAST",
            Self::Versions { .. } => "VERSIONS",
            Self::Netinfo { .. } => "NETINFO",
            Self::RelayEarly { .. } => "RELAY_EARLY",
            Self::Create2 { .. } => "CREATE2",
            Self::Created2 { .. } => "CREATED2",
            Self::PaddingNegotiate { .. } => "PADDING_NEGOTIATE",
            Self::VPadding { .. } => "VPADDING",
            Self::Certs { .. } => "CERTS",
            Self::AuthChallenge { .. } => "AUTH_CHALLENGE",
            Self::Authenticate { .. } => "AUTHENTICATE",
            Self::Authorize { .. } => "AUTHORIZE",
        }
    }

    pub fn circuit_id(&self) -> Option<u32> {
        match self {
            Self::Create { circuit_id, .. }
            | Self::Created { circuit_id, .. }
            | Self::Destroy { circuit_id, .. }
            | Self::CreateFast { circuit_id, .. }
            | Self::CreatedFast { circuit_id, .. }
            | Self::RelayEarly { circuit_id, .. }
            | Self::Create2 { circuit_id, .. }
            | Self::Created2 { circuit_id, .. } => Some(*circuit_id),
            Self::Relay(cell) => Some(cell.circuit_id),
            _ => None,
        }
    }

    pub fn pack(&self, link_protocol: LinkProtocol) -> Result<Vec<u8>> {
        let command = self.command();
        let circuit_id = self.circuit_id();
        let pack = |payload: &[u8], unused: &[u8]| {
            pack_cell(link_protocol, command, payload, unused, circuit_id)
        };
        match self {
            Self::Padding { payload } => {
                exact_length("Padding payload", payload.clone(), FIXED_PAYLOAD_LENGTH)?;
                pack(payload, &[])
            }
            Self::Create { payload, .. }
            | Self::Created { payload, .. }
            | Self::RelayEarly { payload, .. }
            | Self::Create2 { payload, .. }
            | Self::Created2 { payload, .. }
            | Self::PaddingNegotiate { payload }
            | Self::VPadding { payload }
            | Self::Authenticate { payload }
            | Self::Authorize { payload } => pack(payload, &[]),
            Self::Relay(cell) => {
                let packed = cell.payload()?;
                pack(&packed, &cell.unused)
            }
            Self::Destroy { reason, unused, .. } => pack(&[reason.value()], unused),
            Self::CreateFast {
                key_material,
                unused,
                ..
            } => {
                exact_length("Key material", key_material.clone(), HASH_LENGTH)?;
                pack(key_material, unused)
            }
            Self::CreatedFast {
                derivative_key,
                key_material,
                unused,
                ..
            } => {
                exact_length("Key material", key_material.clone(), HASH_LENGTH)?;
                exact_length("Derivative key", derivative_key.clone(), HASH_LENGTH)?;
                pack(&[key_material.as_slice(), derivative_key].concat(), unused)
            }
            Self::Versions { versions } => {
                let payload: Vec<u8> = versions
                    .iter()
                    .flat_map(|version| version.to_be_bytes())
                    .collect();
                pack(&payload, &[])
            }
            Self::Netinfo {
                timestamp,
                receiver_address,
                sender_addresses,
                unused,
            } => {
                let seconds =
                    u32::try_from(timestamp.and_utc().timestamp()).map_err(|_| {
                        Error::invalid_input("NETINFO timestamp is out of range")
                    })?;
                let mut payload = seconds.to_be_bytes().to_vec();
                payload.extend_from_slice(&receiver_address.pack());
                payload
                    .push(u8::try_from(sender_addresses.len()).map_err(|_| {
                        Error::invalid_input("Too many sender addresses")
                    })?);
                for address in sender_addresses {
                    payload.extend_from_slice(&address.pack());
                }
                pack(&payload, unused)
            }
            Self::Certs {
                certificates,
                unused,
            } => {
                let mut payload = vec![
                    u8::try_from(certificates.len())
                        .map_err(|_| Error::invalid_input("Too many certificates"))?,
                ];
                for certificate in certificates {
                    payload.extend_from_slice(&certificate.pack()?);
                }
                pack(&payload, unused)
            }
            Self::AuthChallenge {
                challenge,
                methods,
                unused,
            } => {
                exact_length("AUTH_CHALLENGE", challenge.clone(), AUTH_CHALLENGE_SIZE)?;
                let mut payload = challenge.clone();
                let count = u16::try_from(methods.len()).map_err(|_| {
                    Error::invalid_input("Too many authentication methods")
                })?;
                payload.extend_from_slice(&count.to_be_bytes());
                methods
                    .iter()
                    .for_each(|method| payload.extend_from_slice(&method.to_be_bytes()));
                pack(&payload, unused)
            }
        }
    }

    pub fn pop(content: &[u8], link_protocol: LinkProtocol) -> Result<(Cell, &[u8])> {
        let mut reader = Reader::new(content);
        let circuit_id = link_protocol.pop_circuit_id(&mut reader)?;
        let command = reader.u8()?;
        if !matches!(command, 0..=12 | 128..=132) {
            return Err(Error::parse(format!(
                "'{command}' isn't a valid cell value"
            )));
        }
        let payload_length = match is_fixed_size(command) {
            true => FIXED_PAYLOAD_LENGTH,
            false => usize::from(reader.u16()?),
        };
        if reader.remaining() < payload_length {
            return Err(Error::parse(format!(
                "Cell {command} should have a payload of {payload_length} bytes, but \
                only had {}",
                reader.remaining()
            )));
        }
        let payload = reader.take(payload_length)?;
        let cell = Self::unpack_payload(command, payload, circuit_id)?;
        Ok((cell, reader.rest()))
    }

    pub fn unpack(mut content: &[u8], link_protocol: LinkProtocol) -> Result<Vec<Cell>> {
        let mut cells = Vec::new();
        while !content.is_empty() {
            let (cell, rest) = Self::pop(content, link_protocol)?;
            cells.push(cell);
            content = rest;
        }
        Ok(cells)
    }

    fn unpack_payload(command: u8, payload: &[u8], circuit_id: u32) -> Result<Cell> {
        let mut reader = Reader::new(payload);
        Ok(match command {
            0 => Self::Padding {
                payload: payload.to_vec(),
            },
            1 => Self::Create {
                circuit_id,
                payload: payload.to_vec(),
            },
            2 => Self::Created {
                circuit_id,
                payload: payload.to_vec(),
            },
            3 => Self::Relay(RelayCell::unpack_payload(payload, circuit_id)?),
            4 => Self::Destroy {
                circuit_id,
                reason: CloseReason::from_value(reader.u8()?),
                unused: reader.rest().to_vec(),
            },
            5 => {
                if payload.len() < HASH_LENGTH {
                    return Err(Error::parse(format!(
                        "Key material should be {HASH_LENGTH} bytes, but was {}",
                        payload.len()
                    )));
                }
                Self::CreateFast {
                    circuit_id,
                    key_material: reader.take(HASH_LENGTH)?.to_vec(),
                    unused: reader.rest().to_vec(),
                }
            }
            6 => {
                if payload.len() < HASH_LENGTH * 2 {
                    return Err(Error::parse(format!(
                        "Key material and derivatived key should be {} bytes, but was {}",
                        HASH_LENGTH * 2,
                        payload.len()
                    )));
                }
                Self::CreatedFast {
                    circuit_id,
                    key_material: reader.take(HASH_LENGTH)?.to_vec(),
                    derivative_key: reader.take(HASH_LENGTH)?.to_vec(),
                    unused: reader.rest().to_vec(),
                }
            }
            7 => {
                let mut versions = Vec::new();
                while reader.remaining() > 0 {
                    versions.push(reader.u16()?);
                }
                Self::Versions { versions }
            }
            8 => {
                let seconds = reader.u32()?;
                let receiver_address = Address::pop(&mut reader)?;
                let count = reader.u8()?;
                let mut sender_addresses = Vec::new();
                for _ in 0..count {
                    sender_addresses.push(Address::pop(&mut reader)?);
                }
                let timestamp = DateTime::from_timestamp(i64::from(seconds), 0)
                    .ok_or_else(|| Error::parse("NETINFO timestamp is out of range"))?
                    .naive_utc();
                Self::Netinfo {
                    timestamp,
                    receiver_address,
                    sender_addresses,
                    unused: reader.rest().to_vec(),
                }
            }
            9 => Self::RelayEarly {
                circuit_id,
                payload: payload.to_vec(),
            },
            10 => Self::Create2 {
                circuit_id,
                payload: payload.to_vec(),
            },
            11 => Self::Created2 {
                circuit_id,
                payload: payload.to_vec(),
            },
            12 => Self::PaddingNegotiate {
                payload: payload.to_vec(),
            },
            128 => Self::VPadding {
                payload: payload.to_vec(),
            },
            129 => {
                let count = reader.u8()?;
                let mut certificates = Vec::new();
                for _ in 0..count {
                    if reader.remaining() == 0 {
                        return Err(Error::parse(format!(
                            "CERTS cell indicates it should have {count} certificates, \
                            but only contained {}",
                            certificates.len()
                        )));
                    }
                    certificates.push(Certificate::pop(&mut reader)?);
                }
                Self::Certs {
                    certificates,
                    unused: reader.rest().to_vec(),
                }
            }
            130 => {
                let minimum = AUTH_CHALLENGE_SIZE + 2;
                if payload.len() < minimum {
                    return Err(Error::parse(format!(
                        "AUTH_CHALLENGE payload should be at least {minimum} bytes, but \
                        was {}",
                        payload.len()
                    )));
                }
                let challenge = reader.take(AUTH_CHALLENGE_SIZE)?.to_vec();
                let count = usize::from(reader.u16()?);
                if reader.remaining() < count * 2 {
                    return Err(Error::parse(format!(
                        "AUTH_CHALLENGE should have {count} methods, but only had {} \
                        bytes for it",
                        reader.remaining()
                    )));
                }
                let mut methods = Vec::new();
                for _ in 0..count {
                    methods.push(reader.u16()?);
                }
                Self::AuthChallenge {
                    challenge,
                    methods,
                    unused: reader.rest().to_vec(),
                }
            }
            131 => Self::Authenticate {
                payload: payload.to_vec(),
            },
            _ => Self::Authorize {
                payload: payload.to_vec(),
            },
        })
    }
}
