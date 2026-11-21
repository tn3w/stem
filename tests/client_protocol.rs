use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::NaiveDate;
use stem::client::cells::{Cell, FIXED_PAYLOAD_LENGTH, RelayCell};
use stem::client::datatypes::{
    AddrType, Address, CertType, Certificate, CloseReason, Kdf, LinkProtocol,
    LinkSpecifier, Reader, RelayCommand,
};

fn zeros(count: usize) -> Vec<u8> {
    vec![0; count]
}

fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn link(version: u32) -> LinkProtocol {
    LinkProtocol::new(version)
}

fn roundtrip(bytes: &[u8], protocol: u32) -> Cell {
    let (cell, rest) = Cell::pop(bytes, link(protocol)).unwrap();
    assert!(rest.is_empty());
    assert_eq!(cell.pack(link(protocol)).unwrap(), bytes);
    cell
}

#[test]
fn describes_link_protocols() {
    let old = link(1);
    assert_eq!(old.circuit_id_size(), 2);
    assert_eq!(old.fixed_cell_length(), 512);
    assert_eq!(old.first_circuit_id(), 1);
    let new = link(10);
    assert_eq!(new.circuit_id_size(), 4);
    assert_eq!(new.fixed_cell_length(), 514);
    assert_eq!(new.first_circuit_id(), 0x8000_0000);
    assert_eq!(LinkProtocol::from(3), link(3));
}

#[test]
fn packs_and_unpacks_circuit_ids() {
    assert_eq!(link(3).pack_circuit_id(0x1234).unwrap(), [0x12, 0x34]);
    assert!(link(3).pack_circuit_id(0x1_0000).is_err());
    assert_eq!(
        link(4).pack_circuit_id(0x8000_0001).unwrap(),
        [0x80, 0, 0, 1]
    );
    let mut reader = Reader::new(&[0x80, 0, 0, 1, 9]);
    assert_eq!(link(4).pop_circuit_id(&mut reader).unwrap(), 0x8000_0001);
    assert_eq!(reader.rest(), [9]);
}

#[test]
fn builds_and_packs_addresses() {
    let ipv4 = Address::parse("127.0.0.1").unwrap();
    assert_eq!(ipv4.addr_type, AddrType::Ipv4);
    assert_eq!(ipv4.value().as_deref(), Some("127.0.0.1"));
    assert_eq!(ipv4.value_bin(), [127, 0, 0, 1]);
    assert_eq!(ipv4.pack(), [4, 4, 127, 0, 0, 1]);

    let ipv6 = Address::parse("2001:0DB8:AC10:FE01::").unwrap();
    assert_eq!(ipv6.addr_type, AddrType::Ipv6);
    assert_eq!(
        ipv6.value().as_deref(),
        Some("2001:0db8:ac10:fe01:0000:0000:0000:0000")
    );
    assert_eq!(ipv6.pack().len(), 18);

    assert!(Address::parse("nope").is_err());
    assert!(Address::from_bytes(AddrType::Ipv4, vec![127, 0]).is_err());
    assert!(Address::from_bytes(AddrType::Ipv6, vec![127, 0]).is_err());
    let unknown = Address::from_bytes(AddrType::Unknown(12), b"hello".to_vec()).unwrap();
    assert_eq!(unknown.value(), None);
    assert_eq!(AddrType::from_value(25), AddrType::Unknown(25));
}

#[test]
fn pops_addresses_from_streams() {
    let content = [4, 4, 127, 0, 0, 1, 1, 4, 4, 97, 113, 15, 2, 0, 0, 0, 0];
    let mut reader = Reader::new(&content);
    let address = Address::pop(&mut reader).unwrap();
    assert_eq!(address.value().as_deref(), Some("127.0.0.1"));
    assert_eq!(reader.rest(), [1, 4, 4, 97, 113, 15, 2, 0, 0, 0, 0]);
    assert!(Address::pop(&mut Reader::new(&[4, 4, 1])).is_err());
}

#[test]
fn packs_certificates() {
    let content = [2, 0, 4, 0, 0, 1, 1, 4, 4, 97, 113, 15, 2, 0, 0, 0, 0];
    let mut reader = Reader::new(&content);
    let certificate = Certificate::pop(&mut reader).unwrap();
    assert_eq!(certificate.cert_type, CertType::Identity);
    assert_eq!(certificate.cert_type.value(), 2);
    assert_eq!(certificate.value, [0, 0, 1, 1]);
    assert_eq!(certificate.pack().unwrap(), [2, 0, 4, 0, 0, 1, 1]);
    assert_eq!(reader.rest(), [4, 4, 97, 113, 15, 2, 0, 0, 0, 0]);

    let unknown = Certificate::new(CertType::from_value(12), b"hello".to_vec());
    assert!(unknown.cert_type.is_unknown());
    assert!(Certificate::pop(&mut Reader::new(&[2, 0, 9, 1])).is_err());
}

#[test]
fn derives_keys_like_python_stem() {
    let material = [
        0xec, 0xec, 0x2e, 0xeb, 0x37, 0x52, 0xf2, 0x0a, 0xcb, 0xce, 0x97, 0xf4, 0x86,
        0x82, 0x19, 0x23, 0x10, 0x0f, 0x08, 0xf0, 0xa2, 0x5a, 0xde, 0x4a, 0x8f, 0x32,
        0x8c, 0x63, 0xf6, 0xfa, 0x0e, 0x09, 0x83, 0x66, 0xc5, 0xe2, 0xb3, 0x94, 0xa8,
        0x13,
    ];
    let kdf = Kdf::from_value(&material);
    assert_eq!(
        kdf.key_hash,
        b"\xca+\x81\x05\x14\x9d)o\xa6\x82\xe9B\xa8?\xf2\xaf\x85\x1b]6"
    );
    assert_eq!(
        kdf.forward_digest,
        b"\xac\xcc\xbc\x91\xb1\xaf\xd7\xe0\xe9\x9dF#\xd8\xdbz\xe8\xe6\xca\x83,"
    );
    assert_eq!(
        kdf.backward_digest,
        b"*\xe5scX\xbb+\xca \xcb\xa4\xbc\xad\x0f\x95\x0cO\xcc\xac\xf1"
    );
    assert_eq!(
        kdf.forward_key,
        b"\xc3\xbe\xc9\xe1\xf4\x90f\xdai\xf3\xf3\xf5\x14\xb5\xb9\x03"
    );
    assert_eq!(
        kdf.backward_key,
        b"U\xaf\x1e\x1b\xb1q||\x86A<_\xf7\xa0%\x86"
    );
}

#[test]
fn handles_link_specifiers() {
    let mut reader = Reader::new(b"\x00\x06\x01\x02\x03\x04#)");
    let ipv4 = LinkSpecifier::pop(&mut reader).unwrap();
    assert_eq!(
        ipv4,
        LinkSpecifier::Ipv4 {
            address: Ipv4Addr::new(1, 2, 3, 4),
            port: 9001
        }
    );
    assert_eq!(ipv4.link_type(), 0);

    let ipv6_bytes =
        b"\x01\x12&\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01#)";
    let ipv6 = LinkSpecifier::pop(&mut Reader::new(ipv6_bytes)).unwrap();
    assert_eq!(
        ipv6,
        LinkSpecifier::Ipv6 {
            address: "2600::1".parse::<Ipv6Addr>().unwrap(),
            port: 9001
        }
    );

    let fingerprint =
        LinkSpecifier::pop(&mut Reader::new(b"\x02\x14CCCCCCCCCCCCCCCCCCCC")).unwrap();
    assert_eq!(
        fingerprint,
        LinkSpecifier::Fingerprint(*b"CCCCCCCCCCCCCCCCCCCC")
    );
    let ed25519_bytes = b"\x03\x20CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    let ed25519 = LinkSpecifier::pop(&mut Reader::new(ed25519_bytes)).unwrap();
    assert_eq!(ed25519.link_type(), 3);
    let other = LinkSpecifier::pop(&mut Reader::new(
        b"\x04\x20CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    ))
    .unwrap();
    assert_eq!(other.link_type(), 4);

    for packed in [
        &b"\x03\x20CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"[..],
        b"\x04\x20CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        ipv6_bytes,
        b"\x00\x06\x01\x02\x03\x04#)",
    ] {
        let specifier = LinkSpecifier::pop(&mut Reader::new(packed)).unwrap();
        assert_eq!(specifier.pack(), packed);
    }
    assert!(LinkSpecifier::pop(&mut Reader::new(b"\x04\x20CCCCCCC")).is_err());
    assert!(LinkSpecifier::pop(&mut Reader::new(b"\x00\x05\x01\x02\x03\x04#")).is_err());
}

#[test]
fn handles_padding_cells() {
    let payload = vec![0xAB; FIXED_PAYLOAD_LENGTH];
    let bytes = join(&[&[0, 0, 0], &payload]);
    let cell = roundtrip(&bytes, 2);
    assert!(matches!(&cell, Cell::Padding { payload: found } if *found == payload));
    assert_eq!(Cell::Padding { payload }.pack(link(2)).unwrap(), bytes);
    assert!(
        Cell::Padding {
            payload: vec![1; 10]
        }
        .pack(link(2))
        .is_err()
    );
}

#[test]
fn handles_relay_cells() {
    let begin_dir = join(&[
        b"\x00\x01\x03\r\x00\x00\x00\x01!\xa3?\xec\x00\x00",
        &zeros(498),
    ]);
    let (cell, _) = Cell::pop(&begin_dir, link(2)).unwrap();
    let Cell::Relay(relay) = &cell else {
        panic!("expected a relay cell")
    };
    assert_eq!(relay.circuit_id, 1);
    assert_eq!(relay.command, RelayCommand::BeginDir);
    assert_eq!(relay.command.value(), 13);
    assert_eq!(relay.stream_id, 1);
    assert_eq!(relay.digest, 564346860);
    assert_eq!(relay.data, b"");
    assert_eq!(relay.unused, zeros(498));
    assert_eq!(cell.pack(link(2)).unwrap(), begin_dir);

    let request = b"GET /tor/server/authority HTTP/1.0\r\n\r\n";
    let data_cell = join(&[
        b"\x00\x01\x03\x02\x00\x00\x00\x01\x15:m\xe0\x00&",
        request,
        &zeros(460),
    ]);
    let (cell, _) = Cell::pop(&data_cell, link(2)).unwrap();
    let Cell::Relay(relay) = &cell else {
        panic!("expected a relay cell")
    };
    assert_eq!(relay.data, request);
    assert_eq!(relay.digest, 356150752);
    assert_eq!(cell.pack(link(2)).unwrap(), data_cell);

    let leftover = join(&[
        b"\x00\x01\x03\x02\x00\x00\x00\x01\x15:m\xe0\x00&",
        request,
        &[1],
        &zeros(459),
    ]);
    let (cell, _) = Cell::pop(&leftover, link(2)).unwrap();
    let Cell::Relay(relay) = &cell else {
        panic!("expected a relay cell")
    };
    assert_eq!(relay.unused[0], 1);
    assert_eq!(cell.pack(link(2)).unwrap(), leftover);

    let mismatched = join(&[
        b"\x00\x01\x03\x02\x00\x00\x00\x01\x15:m\xe0\xff\xff",
        &zeros(498),
    ]);
    assert!(Cell::pop(&mismatched, link(2)).is_err());
}

#[test]
fn validates_relay_cell_construction() {
    assert!(RelayCell::new(1, RelayCommand::BeginDir, Vec::new(), 1).is_ok());
    assert!(RelayCell::new(1, RelayCommand::Data, Vec::new(), 0).is_err());
    assert!(RelayCell::new(1, RelayCommand::Sendme, Vec::new(), 0).is_ok());
    assert!(RelayCell::new(1, RelayCommand::Extend2, Vec::new(), 7).is_err());
    assert_eq!(RelayCommand::BeginDir.name(), "RELAY_BEGIN_DIR");
    assert_eq!(RelayCommand::Extend2.name(), "RELAY_EXTEND2");
}

#[test]
fn handles_destroy_cells() {
    let none = join(&[b"\x80\x00\x00\x00\x04\x00", &zeros(508)]);
    let Cell::Destroy {
        circuit_id,
        reason,
        unused,
    } = roundtrip(&none, 5)
    else {
        panic!("expected a destroy cell")
    };
    assert_eq!(
        (circuit_id, reason, unused),
        (0x8000_0000, CloseReason::None, zeros(508))
    );

    let requested = join(&[b"\x80\x00\x00\x00\x04\x03", &zeros(508)]);
    let Cell::Destroy { reason, .. } = roundtrip(&requested, 5) else {
        panic!("expected a destroy cell")
    };
    assert_eq!(reason, CloseReason::Requested);
    assert_eq!(
        Cell::destroy(0x8000_0000, CloseReason::Requested)
            .pack(link(5))
            .unwrap(),
        requested
    );

    let with_unused = join(&[b"\x80\x00\x00\x00\x04\x01\x01", &zeros(507)]);
    let Cell::Destroy { reason, unused, .. } = roundtrip(&with_unused, 5) else {
        panic!("expected a destroy cell")
    };
    assert_eq!(reason, CloseReason::Protocol);
    assert_eq!(unused[0], 1);
}

#[test]
fn handles_create_fast_cells() {
    let key = b"\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce";
    let bytes = join(&[b"\x80\x00\x00\x00\x05", key, &zeros(489)]);
    let Cell::CreateFast {
        circuit_id,
        key_material,
        unused,
    } = roundtrip(&bytes, 5)
    else {
        panic!("expected a create fast cell")
    };
    assert_eq!(circuit_id, 0x8000_0000);
    assert_eq!(key_material, key);
    assert_eq!(unused, zeros(489));
    assert!(
        Cell::CreateFast {
            circuit_id: 5,
            key_material: b"boo".to_vec(),
            unused: Vec::new()
        }
        .pack(link(5))
        .is_err()
    );
    let fresh = Cell::create_fast(0x8000_0001);
    assert_eq!(fresh.pack(link(5)).unwrap().len(), 514);
}

#[test]
fn handles_created_fast_cells() {
    let key = b"\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce";
    let derivative =
        b"\x13Z\x99\xb2\x1e\xb6\x05\x85\x17\xfc\x1c\x00{\xa9\xae\x83^K\x99\xb2";
    let bytes = join(&[b"\x80\x00\x00\x00\x06", key, derivative, &zeros(469)]);
    let Cell::CreatedFast {
        key_material,
        derivative_key,
        unused,
        ..
    } = roundtrip(&bytes, 5)
    else {
        panic!("expected a created fast cell")
    };
    assert_eq!(key_material, key);
    assert_eq!(derivative_key, derivative);
    assert_eq!(unused, zeros(469));
}

#[test]
fn handles_versions_cells() {
    for (bytes, versions, protocol) in [
        (&b"\x00\x00\x07\x00\x00"[..], vec![], 2),
        (b"\x00\x00\x07\x00\x02\x00\x01", vec![1], 2),
        (
            b"\x00\x00\x07\x00\x06\x00\x01\x00\x02\x00\x03",
            vec![1, 2, 3],
            2,
        ),
        (
            b"\x00\x00\x00\x00\x07\x00\x08\x00\x01\x00\x02\x00\x03\x00\x04",
            vec![1, 2, 3, 4],
            4,
        ),
    ] {
        let cell = roundtrip(bytes, protocol);
        assert_eq!(cell, Cell::versions(&versions));
    }
}

#[test]
fn handles_netinfo_cells() {
    let bytes = join(&[
        b"\x00\x00\x08ZZ\xb6\x90\x04\x04\x7f\x00\x00\x01\x01\x04\x04aq\x0f\x02",
        &zeros(FIXED_PAYLOAD_LENGTH - 17),
    ]);
    let Cell::Netinfo {
        timestamp,
        receiver_address,
        sender_addresses,
        unused,
    } = roundtrip(&bytes, 2)
    else {
        panic!("expected a netinfo cell")
    };
    let expected = NaiveDate::from_ymd_opt(2018, 1, 14)
        .unwrap()
        .and_hms_opt(1, 46, 56)
        .unwrap();
    assert_eq!(timestamp, expected);
    assert_eq!(receiver_address, Address::parse("127.0.0.1").unwrap());
    assert_eq!(
        sender_addresses,
        vec![Address::parse("97.113.15.2").unwrap()]
    );
    assert_eq!(unused, zeros(492));
}

#[test]
fn handles_variable_length_padding_cells() {
    for (bytes, payload) in [
        (&b"\x00\x00\x80\x00\x00"[..], &b""[..]),
        (b"\x00\x00\x80\x00\x01\x08", b"\x08"),
        (b"\x00\x00\x80\x00\x02\x08\x11", b"\x08\x11"),
    ] {
        let Cell::VPadding { payload: found } = roundtrip(bytes, 2) else {
            panic!("expected a vpadding cell")
        };
        assert_eq!(found, payload);
    }
}

#[test]
fn handles_certs_cells() {
    let Cell::Certs {
        certificates,
        unused,
    } = roundtrip(b"\x00\x00\x81\x00\x01\x00", 2)
    else {
        panic!("expected a certs cell")
    };
    assert!(certificates.is_empty() && unused.is_empty());

    let Cell::Certs {
        certificates,
        unused,
    } = roundtrip(b"\x00\x00\x81\x00\x07\x01\x01\x00\x01\x08\x06\x04", 2)
    else {
        panic!("expected a certs cell")
    };
    assert_eq!(
        certificates,
        vec![Certificate::new(CertType::Link, vec![8])]
    );
    assert_eq!(unused, [6, 4]);

    assert!(Cell::pop(b"\x00\x00\x81\x00\x05\x01\x01\x00\x03\x08", link(2)).is_err());
    assert!(Cell::pop(b"\x00\x00\x81\x00\x05\x02\x01\x00\x01\x08", link(2)).is_err());
}

#[test]
fn handles_auth_challenge_cells() {
    let challenge = [
        &b"\x89Y\t\x99\xb2\x1e\xd9*V\xb6\x1bn\n\x05\xd8/"[..],
        b"\xe3QH\x85\x13Z\x17\xfc\x1c\x00{\xa9\xae\x83^K",
    ]
    .concat();
    let bytes = join(&[
        b"\x00\x00\x82\x00\x26",
        &challenge,
        b"\x00\x02\x00\x01\x00\x03",
    ]);
    let Cell::AuthChallenge {
        challenge: found,
        methods,
        unused,
    } = roundtrip(&bytes, 2)
    else {
        panic!("expected an auth challenge cell")
    };
    assert_eq!(found, challenge);
    assert_eq!(methods, vec![1, 3]);
    assert!(unused.is_empty());

    let with_unused = join(&[
        b"\x00\x00\x82\x00\x28",
        &challenge,
        b"\x00\x02\x00\x01\x00\x03\x01\x02",
    ]);
    let Cell::AuthChallenge { unused, .. } = roundtrip(&with_unused, 2) else {
        panic!("expected an auth challenge cell")
    };
    assert_eq!(unused, [1, 2]);

    let truncated = join(&[
        b"\x00\x00\x82\x00&",
        &challenge[..10],
        b"\x00\x02\x00\x01\x00\x03",
    ]);
    assert!(Cell::pop(&truncated, link(2)).is_err());
    let miscounted = join(&[
        b"\x00\x00\x82\x00&",
        &challenge,
        b"\x00\x03\x00\x01\x00\x03",
    ]);
    assert!(Cell::pop(&miscounted, link(2)).is_err());
}

#[test]
fn unpacks_a_new_link_handshake() {
    let content = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/client/new_link_cells"
    ))
    .unwrap();
    let cells = Cell::unpack(&content, link(2)).unwrap();
    assert_eq!(cells.len(), 4);
    assert_eq!(cells[0], Cell::versions(&[3, 4, 5]));
    let Cell::Certs { certificates, .. } = &cells[1] else {
        panic!("expected certs")
    };
    let types: Vec<(CertType, u8)> = certificates
        .iter()
        .map(|certificate| (certificate.cert_type, certificate.cert_type.value()))
        .collect();
    assert_eq!(
        types,
        vec![
            (CertType::Link, 1),
            (CertType::Identity, 2),
            (CertType::Ed25519Signing, 4),
            (CertType::LinkCert, 5),
            (CertType::Ed25519Identity, 7),
        ]
    );
    assert!(
        certificates[0]
            .value
            .starts_with(b"0\x82\x02F0\x82\x01\xaf")
    );
    let Cell::AuthChallenge { methods, .. } = &cells[2] else {
        panic!("expected an auth challenge")
    };
    assert_eq!(methods, &vec![1, 3]);
    assert!(matches!(cells[3], Cell::Netinfo { .. }));
}

#[test]
fn rejects_malformed_cells() {
    assert!(Cell::pop(b"", link(3)).is_err());
    assert!(Cell::pop(b"\x00\x01", link(3)).is_err());
    assert!(Cell::pop(b"\x00\x01\x63", link(3)).is_err());
    assert!(Cell::pop(&join(&[b"\x00\x01\x03", &zeros(10)]), link(3)).is_err());
    assert!(Cell::pop(b"\x00\x00\x07\xff\xff", link(3)).is_err());
    for length in 0..40 {
        let noise: Vec<u8> = (0..length).map(|index| (index * 37 % 251) as u8).collect();
        let _ = Cell::unpack(&noise, link(3));
        let _ = Cell::unpack(&noise, link(5));
    }
}

fn cipher() -> stem::client::cells::RelayCipher {
    use ctr::cipher::KeyIvInit;
    stem::client::cells::RelayCipher::new_from_slices(&[7u8; 16], &[0u8; 16]).unwrap()
}

fn digest_seed() -> sha1::Sha1 {
    use sha1::Digest;
    let mut digest = sha1::Sha1::new();
    digest.update(b"seed");
    digest
}

#[test]
fn encrypts_and_decrypts_relay_cells_with_digest_checks() {
    let cell =
        RelayCell::new(0x8000_0001, RelayCommand::Data, b"payload".to_vec(), 3).unwrap();
    let protocol = link(4);
    let mut send_key = cipher();
    let mut send_digest = digest_seed();
    let sealed = cell
        .encrypt(protocol, &mut send_key, &mut send_digest)
        .unwrap();
    assert_eq!(sealed.len(), protocol.fixed_cell_length());

    let decrypted =
        RelayCell::decrypt(protocol, &sealed, &mut cipher(), &mut digest_seed()).unwrap();
    assert_eq!(decrypted.data, b"payload");
    assert_eq!(decrypted.stream_id, 3);
    assert_eq!(decrypted.command, RelayCommand::Data);

    let mut tampered = sealed.clone();
    tampered[20] ^= 0x01;
    assert!(
        RelayCell::decrypt(protocol, &tampered, &mut cipher(), &mut digest_seed())
            .is_err()
    );

    let mut wrong_seed = sha1::Sha1::default();
    sha1::Digest::update(&mut wrong_seed, b"other");
    assert!(
        RelayCell::decrypt(protocol, &sealed, &mut cipher(), &mut wrong_seed).is_err()
    );

    assert!(
        RelayCell::decrypt(protocol, &sealed[1..], &mut cipher(), &mut digest_seed())
            .is_err()
    );
    let mut wrong_command = sealed.clone();
    wrong_command[4] = 2;
    assert!(
        RelayCell::decrypt(protocol, &wrong_command, &mut cipher(), &mut digest_seed())
            .is_err()
    );
}
