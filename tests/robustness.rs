use std::path::PathBuf;

use stem::address::{Endpoint, expand_ipv6_address, masked_bits};
use stem::client::cells::Cell;
use stem::client::datatypes::{
    Address, Certificate, LinkProtocol, LinkSpecifier, Reader,
};
use stem::configuration::Config;
use stem::descriptor::bandwidth_file::BandwidthFile;
use stem::descriptor::certificate::Ed25519Certificate;
use stem::descriptor::collector::parse_index;
use stem::descriptor::extrainfo::{BridgeExtraInfoDescriptor, RelayExtraInfoDescriptor};
use stem::descriptor::hidden_service::{
    HiddenServiceDescriptorV2, HiddenServiceDescriptorV3, InnerLayer,
    IntroductionPointV3, OuterLayer,
};
use stem::descriptor::microdescriptor::Microdescriptor;
use stem::descriptor::network_status::{
    BridgeNetworkStatusDocument, DetachedSignature, KeyCertificate,
    NetworkStatusDocumentV2, NetworkStatusDocumentV3,
};
use stem::descriptor::router_status::RouterStatusEntryV3;
use stem::descriptor::server::{BridgeServerDescriptor, RelayServerDescriptor};
use stem::descriptor::tordnsel::TorDnsel;
use stem::descriptor::{Compression, DocumentHandler, parse_bytes};
use stem::directory::{Authority, Fallback};
use stem::events::Event;
use stem::exit_policy::{ExitPolicy, ExitPolicyRule, MicroExitPolicy, get_config_policy};
use stem::formatting::{self, CropOptions};
use stem::response::{
    AddOnionResponse, ControlLine, ControlMessage, GetConfResponse, GetInfoResponse,
    MapAddressResponse, MessageBuilder, unescape_bytes,
};
use stem::version::Version;

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit.max(1) as u64) as usize
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/descriptor");
    std::fs::read(root.join(name)).unwrap()
}

fn mutate(seed: &[u8], random: &mut Random) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    if bytes.is_empty() {
        return bytes;
    }
    for _ in 0..1 + random.below(4) {
        let position = random.below(bytes.len());
        match random.below(7) {
            0 => bytes[position] ^= 1 << random.below(8),
            1 => bytes[position] = random.next() as u8,
            2 => bytes.truncate(position),
            3 => {
                bytes.remove(position);
            }
            4 => bytes.insert(position, random.next() as u8),
            5 => {
                let end = (position + random.below(40)).min(bytes.len());
                let chunk = bytes[position..end].to_vec();
                bytes.splice(position..position, chunk);
            }
            _ => {
                let end = (position + random.below(80)).min(bytes.len());
                bytes.drain(position..end);
            }
        }
        if bytes.is_empty() {
            break;
        }
    }
    bytes
}

fn noise(random: &mut Random, limit: usize) -> Vec<u8> {
    (0..random.below(limit))
        .map(|_| random.next() as u8)
        .collect()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn rounds() -> usize {
    std::env::var("STEM_FUZZ_ROUNDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(400)
}

#[test]
fn descriptor_parsers_never_panic() {
    let seeds: Vec<(&str, Vec<u8>)> = [
        "example_descriptor",
        "server_descriptor_with_ed25519",
        "bridge_descriptor",
        "extrainfo_relay_descriptor",
        "extrainfo_descriptor_with_ed25519",
        "extrainfo_bridge_descriptor",
        "cached-microdescs",
        "metrics_consensus",
        "metrics_vote",
        "cached-consensus-v2",
        "bridge_network_status",
        "metrics_cert",
        "detached_signatures",
        "hidden_service_basic_auth",
        "hidden_service_v3",
        "hidden_service_v3_outer_layer",
        "hidden_service_v3_inner_layer",
        "hidden_service_v3_intro_point",
        "bandwidth_file_v1.2",
        "negative_uptime",
        "non-ascii_descriptor",
    ]
    .into_iter()
    .map(|name| (name, fixture(name)))
    .collect();
    let mut random = Random(0x9E3779B97F4A7C15);
    for round in 0..rounds() {
        for (name, seed) in &seeds {
            let input = match round % 8 {
                0 => noise(&mut random, 600),
                _ => mutate(seed, &mut random),
            };
            for validate in [true, false] {
                let _ = RelayServerDescriptor::parse(&input, validate);
                let _ = BridgeServerDescriptor::parse(&input, validate);
                let _ = RelayExtraInfoDescriptor::parse(&input, validate);
                let _ = BridgeExtraInfoDescriptor::parse(&input, validate);
                let _ = Microdescriptor::parse(&input, validate);
                let _ = Microdescriptor::parse_many(&input, validate);
                let _ = RouterStatusEntryV3::parse(&input, validate);
                let _ = NetworkStatusDocumentV3::parse(&input, validate);
                let _ = NetworkStatusDocumentV2::parse(&input, validate);
                let _ = BridgeNetworkStatusDocument::parse(&input, validate);
                let _ = KeyCertificate::parse(&input, validate);
                let _ = DetachedSignature::parse(&input, validate);
                let _ = HiddenServiceDescriptorV2::parse(&input, validate);
                let _ = HiddenServiceDescriptorV3::parse(&input, validate);
                let _ = OuterLayer::parse(&input, validate);
                let _ = InnerLayer::parse(&input, validate);
                let _ = BandwidthFile::parse(&input, validate);
                let _ = TorDnsel::parse(&input, validate);
                for handler in [
                    DocumentHandler::Entries,
                    DocumentHandler::Document,
                    DocumentHandler::BareDocument,
                ] {
                    let _ = parse_bytes(&input, None, validate, handler, Some(name));
                    let _ = parse_bytes(
                        &input,
                        Some("network-status-consensus-3 1.0"),
                        validate,
                        handler,
                        None,
                    );
                    let _ = parse_bytes(
                        &input,
                        Some("server-descriptor 1.0"),
                        validate,
                        handler,
                        None,
                    );
                    let _ = parse_bytes(
                        &input,
                        Some("extra-info 1.0"),
                        validate,
                        handler,
                        None,
                    );
                }
            }
            let _ = IntroductionPointV3::parse(&input);
            let _ = Ed25519Certificate::parse(&text(&input));
            let _ = Ed25519Certificate::unpack(&input);
        }
    }
}

#[test]
fn control_protocol_parsers_never_panic() {
    let seeds = [
        "250-version=0.4.9.13\r\n250 OK\r\n",
        "250+info/names=\r\na -- b\r\n.\r\n250 OK\r\n",
        "650 CIRC 1 BUILT $A~b,$C~d BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL \
        TIME_CREATED=2012-11-08T16:48:36.400959\r\n",
        "650 STREAM 1 NEW 0 example.com:80 SOURCE_ADDR=1.2.3.4:5\r\n",
        "650 HS_DESC UPLOAD abc HSDIR $A~b x REASON=NONE\r\n",
        "650 CONF_CHANGED\r\n650-ExitPolicy=reject *:*\r\n650 OK\r\n",
        "650 ADDRMAP a.com 1.2.3.4 \"2013-04-03 22:29:11\" EXPIRES=\"2013-04-03 \
        20:29:11\"\r\n",
        "250-ServiceID=abc\r\n250-PrivateKey=ED25519-V3:xyz\r\n250 OK\r\n",
        "250 AUTHCHALLENGE SERVERHASH=AA SERVERNONCE=BB\r\n",
        "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE COOKIEFILE=\"/x\"\r\n250 OK\r\n",
    ];
    let mut random = Random(0xDEADBEEFCAFEF00D);
    for round in 0..rounds() * 5 {
        for seed in seeds {
            let input = match round % 6 {
                0 => text(&noise(&mut random, 200)),
                _ => text(&mutate(seed.as_bytes(), &mut random)),
            };
            for normalize in [true, false] {
                let Ok(message) = ControlMessage::parse(&input, normalize) else {
                    continue;
                };
                let _ = Event::parse(message.clone());
                let _ = GetInfoResponse::parse(&message);
                let _ = GetConfResponse::parse(&message);
                let _ = MapAddressResponse::parse(&message);
                let _ = AddOnionResponse::parse(&message);
                let _ = message.to_string();
                for mut line in message.lines() {
                    let _ = line.pop(true, true);
                    let _ = line.pop_mapping(true, true);
                    let _ = line.pop_mapping(false, false);
                }
            }
            let _ = Event::from_content(&input);
            let mut builder = MessageBuilder::default();
            for line in input.as_bytes().split_inclusive(|byte| *byte == b'\n') {
                let _ = builder.push_line(line);
            }
            let mut line = ControlLine::new(input.clone());
            while !line.is_empty() {
                if line.pop(round % 2 == 0, round % 3 == 0).is_err() {
                    break;
                }
            }
            let _ = unescape_bytes(&input);
        }
    }
}

#[test]
fn relay_protocol_parsers_never_panic() {
    let mut random = Random(0x0123456789ABCDEF);
    let seed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/client/new_link_cells"
    ))
    .unwrap();
    for round in 0..rounds() * 10 {
        let input = match round % 4 {
            0 => noise(&mut random, 1200),
            _ => mutate(&seed, &mut random),
        };
        for version in [1, 2, 3, 4, 5] {
            let _ = Cell::unpack(&input, LinkProtocol::new(version));
            let _ = Cell::pop(&input, LinkProtocol::new(version));
        }
        let _ = Address::pop(&mut Reader::new(&input));
        let _ = Certificate::pop(&mut Reader::new(&input));
        let _ = LinkSpecifier::pop(&mut Reader::new(&input));
    }
}

#[test]
fn small_text_parsers_never_panic() {
    let mut random = Random(0xFEEDFACE12345678);
    let seeds = [
        "accept *:80",
        "reject 10.0.0.0/8:*",
        "accept6 [::1]:443-8080",
        "accept 80,443",
        "0.4.9.13-rc (git-3c575400909efe65)",
        "1.2.3.4:9001",
        "2001:db8::1",
        "255.255.254.0",
        "# comment\nkey value\nmulti\n|a\n|b\n",
    ];
    for round in 0..rounds() * 20 {
        for seed in seeds {
            let input = match round % 5 {
                0 => text(&noise(&mut random, 60)),
                _ => text(&mutate(seed.as_bytes(), &mut random)),
            };
            let _ = ExitPolicyRule::new(&input);
            let _ = ExitPolicy::new(&[input.as_str()]);
            let _ = MicroExitPolicy::new(&input);
            let _ = get_config_policy(&input, None);
            let _ = get_config_policy(&input, Some("1.2.3.4"));
            let _ = Version::new(&input);
            let _ = Endpoint::new(&input, 80);
            let _ = expand_ipv6_address(&input);
            let _ = masked_bits(&input);
            let _ = formatting::parse_timestamp(&input);
            let _ = formatting::parse_iso_timestamp(&input);
            let _ = formatting::parse_short_time_label(&input);
            let _ = formatting::to_camel_case(&input, '_', " ");
            let _ = formatting::split_by_length(&input, 1 + round % 7);
            let _ = formatting::crop(&input, round % 40, CropOptions::default());
            let _ = formatting::crop_with_remainder(
                &input,
                round % 40,
                CropOptions::default(),
            );
            let _ = stem::address::port_usage(round as u16);
            let _ = stem::address::is_private_address(&input);
            let _ = stem::validation::is_valid_hidden_service_address(&input, &[2, 3]);
            let _ = stem::validation::is_valid_onion_v3_checksum(&input);
            let mut config = Config::new();
            config.load_str(&input, round % 2 == 0);
            let _ = config.get_mapping("key");
            let _ = Authority::parse_inc(&input);
            let _ = Fallback::parse_inc(&input);
            let _ = parse_index(input.as_bytes());
        }
    }
}

#[test]
fn compression_handles_hostile_input() {
    let mut random = Random(0xA5A5A5A55A5A5A5A);
    let valid: Vec<(Compression, Vec<u8>)> = [
        (Compression::Gzip, "compressed_gzip"),
        (Compression::Bzip2, "compressed_bz2"),
        (Compression::Lzma, "compressed_lzma"),
        (Compression::Zstd, "compressed_zstd"),
    ]
    .into_iter()
    .map(|(compression, name)| (compression, fixture(name)))
    .collect();
    for round in 0..rounds() {
        for (compression, seed) in &valid {
            let input = match round % 5 {
                0 => noise(&mut random, 500),
                _ => mutate(seed, &mut random),
            };
            let _ = compression.decompress(&input);
        }
        let input = noise(&mut random, 200);
        for compression in [
            Compression::Plaintext,
            Compression::Gzip,
            Compression::Bzip2,
            Compression::Lzma,
            Compression::Zstd,
        ] {
            let _ = compression.decompress(&input);
        }
    }
}

#[test]
fn archives_never_panic() {
    let mut random = Random(0x1111222233334444);
    let seed = fixture("descriptor_archive.tar");
    let directory = tempfile::tempdir().unwrap();
    for round in 0..200 {
        let input = match round % 4 {
            0 => noise(&mut random, 2048),
            _ => mutate(&seed, &mut random),
        };
        let path = directory.path().join("archive");
        std::fs::write(&path, &input).unwrap();
        for validate in [true, false] {
            let _ = stem::descriptor::parse_path(
                &path,
                None,
                validate,
                DocumentHandler::Entries,
            );
        }
    }
}

#[test]
fn rejects_decompression_bombs() {
    let bomb = {
        use std::io::Write;
        let mut encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        let chunk = vec![0u8; 1 << 20];
        for _ in 0..600 {
            encoder.write_all(&chunk).unwrap();
        }
        encoder.finish().unwrap()
    };
    assert!(bomb.len() < 4 << 20);
    let outcome = Compression::Gzip.decompress(&bomb);
    assert!(outcome.is_err(), "a 600 MiB expansion was accepted");
}
