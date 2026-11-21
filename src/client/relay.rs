use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use aes::cipher::KeyIvInit;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::client::cells::{Cell, FIXED_PAYLOAD_LENGTH, RelayCell, RelayCipher};
use crate::client::datatypes::{
    Address, CloseReason, Kdf, LinkProtocol, Reader, RelayCommand,
};
use crate::client::link_authentication::{RelayIdentity, verify_relay_certificates};
use crate::error::{Error, Result};

pub const DEFAULT_LINK_PROTOCOLS: [u32; 3] = [3, 4, 5];
const MAX_DIRECTORY_RESPONSE: usize = 1 << 29;
const CIRCUIT_SENDME_INTERVAL: u32 = 100;
const STREAM_SENDME_INTERVAL: u32 = 50;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_END_REASON_DONE: u8 = 6;

#[derive(Debug)]
struct AcceptAnyCertificate;

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error>
    {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

pub struct Relay {
    pub link_protocol: LinkProtocol,
    pub identity: RelayIdentity,
    stream: tokio::sync::Mutex<TlsStream<TcpStream>>,
    circuits: Mutex<HashSet<u32>>,
    connected_at: SystemTime,
    alive: AtomicBool,
}

async fn within<T>(future: impl Future<Output = std::io::Result<T>>) -> Result<T> {
    match tokio::time::timeout(OPERATION_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(Error::Socket(error.to_string())),
        Err(_) => Err(Error::Timeout(
            "The relay didn't respond in time".to_string(),
        )),
    }
}

async fn read_raw_cell(
    stream: &mut TlsStream<TcpStream>,
    link_protocol: LinkProtocol,
) -> Result<Vec<u8>> {
    let header_size = link_protocol.circuit_id_size() + 1;
    let mut raw = vec![0u8; header_size];
    within(stream.read_exact(&mut raw)).await?;
    let command = raw[header_size - 1];
    let is_fixed = !matches!(command, 7 | 128..=255);
    let payload_length = match is_fixed {
        true => FIXED_PAYLOAD_LENGTH,
        false => {
            let mut length = [0u8; 2];
            within(stream.read_exact(&mut length)).await?;
            raw.extend_from_slice(&length);
            usize::from(u16::from_be_bytes(length))
        }
    };
    let start = raw.len();
    raw.resize(start + payload_length, 0);
    within(stream.read_exact(&mut raw[start..])).await?;
    Ok(raw)
}

impl Relay {
    pub async fn connect(
        address: IpAddr,
        port: u16,
        link_protocols: &[u32],
    ) -> Result<Arc<Self>> {
        if port == 0 {
            return Err(Error::invalid_input("'0' isn't a valid port"));
        }
        if link_protocols.is_empty() {
            return Err(Error::invalid_input(
                "Connection can't be established without a link protocol.",
            ));
        }
        let relay_address = Address::parse(&address.to_string())?;
        let mut stream = Self::open_tls(address, port).await?;
        let versions: Vec<u16> = link_protocols
            .iter()
            .map(|version| {
                u16::try_from(*version)
                    .map_err(|_| Error::invalid_input("Invalid link protocol"))
            })
            .collect::<Result<_>>()?;
        let handshake_protocol = LinkProtocol::new(2);
        let versions_cell = Cell::versions(&versions).pack(handshake_protocol)?;
        within(stream.write_all(&versions_cell)).await?;
        within(stream.flush()).await?;
        let reply = read_raw_cell(&mut stream, handshake_protocol).await?;
        let (
            Cell::Versions {
                versions: relay_versions,
            },
            _,
        ) = Cell::pop(&reply, handshake_protocol)?
        else {
            return Err(Error::Socket(format!(
                "Unable to establish a common link protocol with {address}:{port}"
            )));
        };
        let link_protocol = link_protocols
            .iter()
            .filter(|version| {
                relay_versions
                    .iter()
                    .any(|offered| u32::from(*offered) == **version)
            })
            .max()
            .map(|version| LinkProtocol::new(*version))
            .ok_or_else(|| {
                Error::Socket(format!(
                    "Unable to find a common link protocol. We support \
                    {link_protocols:?} but {address}:{port} supports {relay_versions:?}."
                ))
            })?;
        let identity =
            Self::finish_handshake(&mut stream, link_protocol, relay_address).await?;
        Ok(Arc::new(Self {
            link_protocol,
            identity,
            stream: tokio::sync::Mutex::new(stream),
            circuits: Mutex::new(HashSet::new()),
            connected_at: SystemTime::now(),
            alive: AtomicBool::new(true),
        }))
    }

    async fn open_tls(address: IpAddr, port: u16) -> Result<TlsStream<TcpStream>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| Error::Socket(error.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
            .with_no_client_auth();
        let tcp = within(TcpStream::connect(SocketAddr::new(address, port)))
            .await
            .map_err(|error| match error.to_string().contains("refused") {
                true => Error::Socket(format!(
                    "Failed to connect to {address}:{port}. Maybe it isn't an ORPort?"
                )),
                false => error,
            })?;
        let connector = TlsConnector::from(Arc::new(config));
        within(connector.connect(ServerName::IpAddress(address.into()), tcp))
            .await
            .map_err(|error| {
                Error::Socket(format!(
                    "Failed to SSL authenticate to {address}:{port}. Maybe it isn't an \
                    ORPort? ({error})"
                ))
            })
    }

    async fn finish_handshake(
        stream: &mut TlsStream<TcpStream>,
        link_protocol: LinkProtocol,
        relay_address: Address,
    ) -> Result<RelayIdentity> {
        let tls_certificate = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|certificate| certificate.to_vec())
            .ok_or_else(|| Error::protocol("The relay presented no TLS certificate"))?;
        let mut identity = None;
        loop {
            let raw = read_raw_cell(stream, link_protocol).await?;
            match Cell::pop(&raw, link_protocol)?.0 {
                Cell::Netinfo { .. } => break,
                Cell::Certs { certificates, .. } => {
                    identity =
                        Some(verify_relay_certificates(&certificates, &tls_certificate)?);
                }
                Cell::AuthChallenge { .. } | Cell::VPadding { .. } => {}
                other => {
                    return Err(Error::protocol(format!(
                        "Unexpected {} cell during the link handshake",
                        other.name()
                    )));
                }
            }
        }
        let identity =
            identity.ok_or_else(|| Error::protocol("The relay sent no CERTS cell"))?;
        let netinfo = Cell::netinfo(relay_address, Vec::new()).pack(link_protocol)?;
        within(stream.write_all(&netinfo)).await?;
        within(stream.flush()).await?;
        Ok(identity)
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    pub fn connection_time(&self) -> SystemTime {
        self.connected_at
    }

    pub async fn close(&self) {
        self.alive.store(false, Ordering::SeqCst);
        let _ = self.stream.lock().await.shutdown().await;
    }

    pub async fn create_circuit(self: &Arc<Self>) -> Result<Circuit> {
        let mut stream = self.stream.lock().await;
        let circuit_id = {
            let circuits = self.circuits.lock().unwrap();
            circuits
                .iter()
                .max()
                .map_or(self.link_protocol.first_circuit_id(), |highest| highest + 1)
        };
        let create = Cell::create_fast(circuit_id);
        within(stream.write_all(&create.pack(self.link_protocol)?)).await?;
        within(stream.flush()).await?;
        let Cell::CreateFast {
            key_material: our_material,
            ..
        } = &create
        else {
            unreachable!("create_fast always builds a CreateFast cell");
        };
        let created = loop {
            let raw = read_raw_cell(&mut stream, self.link_protocol).await?;
            match Cell::pop(&raw, self.link_protocol)?.0 {
                Cell::CreatedFast {
                    circuit_id: id,
                    derivative_key,
                    key_material,
                    ..
                } if id == circuit_id => {
                    break (derivative_key, key_material);
                }
                Cell::Destroy { reason, .. } => {
                    return Err(Error::protocol(format!(
                        "The relay refused our circuit ({reason:?})"
                    )));
                }
                _ => {}
            }
        };
        let kdf = Kdf::from_value(&[our_material.as_slice(), &created.1].concat());
        if created.0 != kdf.key_hash {
            return Err(Error::protocol(
                "Remote failed to prove that it knows our shared key",
            ));
        }
        self.circuits.lock().unwrap().insert(circuit_id);
        Ok(Circuit::new(self.clone(), circuit_id, &kdf))
    }

    pub fn circuit_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.circuits.lock().unwrap().iter().copied().collect();
        ids.sort_unstable();
        ids
    }
}

pub struct Circuit {
    relay: Arc<Relay>,
    pub id: u32,
    forward_digest: Sha1,
    backward_digest: Sha1,
    forward_key: RelayCipher,
    backward_key: RelayCipher,
    circuit_cells_received: u32,
}

fn cipher(key: &[u8]) -> RelayCipher {
    RelayCipher::new_from_slices(key, &[0u8; 16]).expect("AES-128 keys are sixteen bytes")
}

fn running_digest(seed: &[u8]) -> Sha1 {
    let mut digest = Sha1::new();
    digest.update(seed);
    digest
}

impl Circuit {
    fn new(relay: Arc<Relay>, id: u32, kdf: &Kdf) -> Self {
        Self {
            relay,
            id,
            forward_digest: running_digest(&kdf.forward_digest),
            backward_digest: running_digest(&kdf.backward_digest),
            forward_key: cipher(&kdf.forward_key),
            backward_key: cipher(&kdf.backward_key),
            circuit_cells_received: 0,
        }
    }

    pub async fn directory(&mut self, request: &[u8], stream_id: u16) -> Result<Vec<u8>> {
        let relay = self.relay.clone();
        let mut stream = relay.stream.lock().await;
        self.send(&mut stream, RelayCommand::BeginDir, Vec::new(), stream_id)
            .await?;
        self.send(&mut stream, RelayCommand::Data, request.to_vec(), stream_id)
            .await?;
        let mut response = Vec::new();
        let mut stream_cells_received: u32 = 0;
        loop {
            let raw = read_raw_cell(&mut stream, relay.link_protocol).await?;
            let command =
                Reader::new(&raw[relay.link_protocol.circuit_id_size()..]).u8()?;
            match command {
                3 => {}
                4 => {
                    let (Cell::Destroy { reason, .. }, _) =
                        Cell::pop(&raw, relay.link_protocol)?
                    else {
                        continue;
                    };
                    return Err(Error::protocol(format!(
                        "The circuit was destroyed ({reason:?})"
                    )));
                }
                _ => continue,
            }
            let cell = RelayCell::decrypt(
                relay.link_protocol,
                &raw,
                &mut self.backward_key,
                &mut self.backward_digest,
            )?;
            if cell.circuit_id != self.id {
                return Err(Error::protocol(format!(
                    "Response should be for circuit id {}, not {}",
                    self.id, cell.circuit_id
                )));
            }
            match cell.command {
                RelayCommand::End => {
                    let reason =
                        cell.data.first().copied().unwrap_or(RELAY_END_REASON_DONE);
                    return match reason == RELAY_END_REASON_DONE || !response.is_empty() {
                        true => Ok(response),
                        false => Err(Error::protocol(format!(
                            "The relay ended our directory request (reason {reason})"
                        ))),
                    };
                }
                RelayCommand::Data => {
                    if response.len() + cell.data.len() > MAX_DIRECTORY_RESPONSE {
                        return Err(Error::protocol(
                            "Directory response exceeded the size limit",
                        ));
                    }
                    response.extend_from_slice(&cell.data);
                    self.circuit_cells_received += 1;
                    stream_cells_received += 1;
                    if self
                        .circuit_cells_received
                        .is_multiple_of(CIRCUIT_SENDME_INTERVAL)
                    {
                        let tag = self.backward_digest.clone().finalize();
                        let mut payload = vec![1u8, 0, 20];
                        payload.extend_from_slice(&tag);
                        self.send(&mut stream, RelayCommand::Sendme, payload, 0)
                            .await?;
                    }
                    if stream_cells_received.is_multiple_of(STREAM_SENDME_INTERVAL) {
                        self.send(
                            &mut stream,
                            RelayCommand::Sendme,
                            Vec::new(),
                            stream_id,
                        )
                        .await?;
                    }
                }
                _ => {}
            }
        }
    }

    async fn send(
        &mut self,
        stream: &mut TlsStream<TcpStream>,
        command: RelayCommand,
        data: Vec<u8>,
        stream_id: u16,
    ) -> Result<()> {
        let cell = RelayCell::new(self.id, command, data, stream_id)?;
        let payload = cell.encrypt(
            self.relay.link_protocol,
            &mut self.forward_key,
            &mut self.forward_digest,
        )?;
        within(stream.write_all(&payload)).await?;
        within(stream.flush()).await?;
        Ok(())
    }

    pub async fn close(self) -> Result<()> {
        let mut stream = self.relay.stream.lock().await;
        let destroy =
            Cell::destroy(self.id, CloseReason::None).pack(self.relay.link_protocol)?;
        within(stream.write_all(&destroy)).await?;
        within(stream.flush()).await?;
        self.relay.circuits.lock().unwrap().remove(&self.id);
        Ok(())
    }
}
