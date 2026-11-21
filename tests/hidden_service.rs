use chrono::DateTime;
use ed25519_dalek::SigningKey;
use stem::client::datatypes::LinkSpecifier;
use stem::descriptor::attr;
use stem::descriptor::hidden_service::{
    AuthorizedClient, DEFAULT_TIME_PERIOD_LENGTH, HiddenServiceDescriptor,
    HiddenServiceDescriptorV3, HiddenServiceV3Options, InnerLayer, IntroductionPointV3,
    OuterLayer, address_from_identity_key, blinded_key_for_period,
    identity_key_from_address, subcredential, time_period_number,
};
use stem::descriptor::{AttrValue, DocumentHandler, parse_bytes};

const ADDRESS: &str = "sltib6sxkuxh2scmtuvd5w2g7pahnzkovefxpo4e4ptnkzl5kkq5h2ad.onion";
const PUBLIC_KEY: [u8; 32] = [
    0x92, 0xe6, 0x80, 0xfa, 0x57, 0x55, 0x2e, 0x7d, 0x48, 0x4c, 0x9d, 0x2a, 0x3e, 0xdb,
    0x46, 0xfb, 0xc0, 0x76, 0xe5, 0x4e, 0xa9, 0x0b, 0x77, 0xbb, 0x84, 0xe3, 0xe6, 0xd5,
    0x65, 0x7d, 0x52, 0xa1,
];

fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/data/descriptor/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn parses_a_real_descriptor() {
    let content = data("hidden_service_v3");
    let parsed = parse_bytes(
        &content,
        Some("hidden-service-descriptor-3 1.0"),
        true,
        DocumentHandler::Entries,
        None,
    )
    .unwrap();
    assert_eq!(parsed.len(), 1);
    let descriptor = HiddenServiceDescriptorV3::parse(&content, true).unwrap();
    assert_eq!(descriptor.version, Some(3));
    assert_eq!(descriptor.lifetime, Some(180));
    assert_eq!(descriptor.revision_counter, Some(42));
    assert!(
        descriptor
            .superencrypted
            .as_deref()
            .unwrap()
            .contains("eaH8VdaTKS")
    );
    assert_eq!(
        descriptor.signature.as_deref(),
        Some(concat!(
            "aglChCQF+lbzKgyxJJTpYGVShV/GMDRJ4+cRGCp+a2y/yX/tLSh7hzqI7rVZrUo",
            "Gj74Xr1CLMYO3fXYCS+DPDQ"
        ))
    );
    descriptor.verify_signing_certificate().unwrap();
    assert!(matches!(
        HiddenServiceDescriptor::parse(&content, true).unwrap(),
        HiddenServiceDescriptor::V3(_)
    ));
}

#[test]
fn decrypts_a_real_descriptor() {
    let descriptor =
        HiddenServiceDescriptorV3::parse(&data("hidden_service_v3"), true).unwrap();
    let inner = descriptor.decrypt(ADDRESS).unwrap();
    assert_eq!(
        inner.raw_contents.trim_ascii_end(),
        data("hidden_service_v3_inner_layer").trim_ascii_end()
    );
    assert_eq!(inner.formats, vec![2]);
    assert_eq!(inner.intro_auth, vec!["ed25519"]);
    assert!(inner.is_single_service);
    assert_eq!(inner.introduction_points.len(), 4);
    let first = &inner.introduction_points[0];
    assert_eq!(first.link_specifiers.len(), 2);
    assert_eq!(
        first.link_specifiers[0],
        LinkSpecifier::Fingerprint(*b"CCCCCCCCCCCCCCCCCCCC")
    );
    assert_eq!(
        first.link_specifiers[1],
        LinkSpecifier::Ipv4 {
            address: "1.2.3.4".parse().unwrap(),
            port: 9001
        }
    );
    assert_eq!(
        first.onion_key_raw.as_deref(),
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    );
    assert_eq!(
        first.enc_key_raw.as_deref(),
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    );
    assert!(first.onion_key().unwrap().is_some());
    assert!(first.enc_key().unwrap().is_some());
    assert_eq!(first.legacy_key_raw, None);

    assert!(descriptor.decrypt("a".repeat(56).as_str()).is_err());
    assert!(descriptor.decrypt("boom").is_err());
    let other = address_from_identity_key(&[7u8; 32], true);
    assert!(descriptor.decrypt(&other).is_err());
}

#[test]
fn converts_addresses_and_keys() {
    assert_eq!(address_from_identity_key(&PUBLIC_KEY, true), ADDRESS);
    assert_eq!(
        address_from_identity_key(&PUBLIC_KEY, false),
        ADDRESS.trim_end_matches(".onion")
    );
    assert_eq!(identity_key_from_address(ADDRESS).unwrap(), PUBLIC_KEY);
    assert_eq!(
        identity_key_from_address(&ADDRESS[..56]).unwrap(),
        PUBLIC_KEY
    );
    assert!(identity_key_from_address("boom").is_err());
    let failure = identity_key_from_address(&"5".repeat(56))
        .unwrap_err()
        .to_string();
    assert!(
        failure.contains("Bad checksum (expected def7 but was 842e)"),
        "{failure}"
    );
}

#[test]
fn parses_the_outer_layer() {
    let layer = OuterLayer::parse(&data("hidden_service_v3_outer_layer"), true).unwrap();
    assert_eq!(layer.auth_type.as_deref(), Some("x25519"));
    assert_eq!(
        layer.ephemeral_key.as_deref(),
        Some("WjZCU9sV1oxkxaPcd7/YozeZgq0lEs6DhWyrdYRNJR4=")
    );
    assert!(
        layer
            .encrypted
            .as_deref()
            .unwrap()
            .contains("BsRYMH/No+LgetIFv")
    );
    assert_eq!(layer.clients.len(), 16);
    let client = &layer.clients["D0Bz0OlEMCg"];
    assert_eq!(client.iv, "or3nS3ScSPYfLJuP9osGiQ");
    assert_eq!(client.cookie, "B40RdIWhw7kdA7lt3KJPvQ");
}

#[test]
fn parses_the_inner_layer_and_intro_points() {
    let layer = InnerLayer::parse(&data("hidden_service_v3_inner_layer"), true).unwrap();
    assert_eq!(layer.introduction_points.len(), 4);
    let intro_text = String::from_utf8(data("hidden_service_v3_intro_point")).unwrap();
    let point = IntroductionPointV3::parse(intro_text.as_bytes()).unwrap();
    assert_eq!(point.encode().unwrap(), intro_text.trim_end());
    assert!(
        point
            .legacy_key_raw
            .as_deref()
            .unwrap()
            .contains("JAoGBAMO3")
    );
    assert!(
        point
            .legacy_key_cert
            .as_deref()
            .unwrap()
            .contains("Ln1ITJ0qP")
    );
    assert!(IntroductionPointV3::parse(b"introduction-point garbage").is_err());
}

#[test]
fn creates_introduction_points() {
    let point = IntroductionPointV3::create_for_address("1.1.1.1", 9001, None).unwrap();
    assert_eq!(
        point.link_specifiers,
        vec![LinkSpecifier::Ipv4 {
            address: "1.1.1.1".parse().unwrap(),
            port: 9001
        }]
    );
    let reparsed =
        IntroductionPointV3::parse(point.encode().unwrap().as_bytes()).unwrap();
    assert_eq!(reparsed, point);
    let ipv6 = IntroductionPointV3::create_for_address("::1", 9001, None).unwrap();
    assert!(matches!(
        ipv6.link_specifiers[0],
        LinkSpecifier::Ipv6 { .. }
    ));
    assert!(IntroductionPointV3::create_for_address("bogus", 9001, None).is_err());
    assert!(IntroductionPointV3::create_for_address("1.1.1.1", 0, None).is_err());
}

#[test]
fn creates_inner_layers() {
    let content = InnerLayer::content(&Vec::new(), &[], &[]).unwrap();
    assert_eq!(
        String::from_utf8(content).unwrap().trim(),
        "create2-formats 2"
    );
    let layer =
        InnerLayer::create(&vec![attr("create2-formats", "1 2 3")], &[], true, &[])
            .unwrap();
    assert_eq!(layer.formats, vec![1, 2, 3]);

    let optional = vec![
        attr("intro-auth-required", "ed25519"),
        attr("single-onion-service", ""),
    ];
    let layer = InnerLayer::create(&optional, &[], true, &[]).unwrap();
    assert_eq!(layer.intro_auth, vec!["ed25519"]);
    assert!(layer.is_single_service);

    let points: Vec<IntroductionPointV3> = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        .iter()
        .map(|address| {
            IntroductionPointV3::create_for_address(address, 9001, None).unwrap()
        })
        .collect();
    let layer = InnerLayer::create(&Vec::new(), &[], true, &points).unwrap();
    assert_eq!(layer.introduction_points.len(), 3);
    assert!(
        InnerLayer::create(&vec![attr("create2-formats", "x")], &[], true, &[]).is_err()
    );
}

#[test]
fn creates_and_decrypts_descriptors() {
    let identity = SigningKey::from_bytes(&[1u8; 32]);
    let address = address_from_identity_key(&identity.verifying_key().to_bytes(), true);
    let points: Vec<IntroductionPointV3> = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        .iter()
        .map(|address| {
            IntroductionPointV3::create_for_address(address, 9001, None).unwrap()
        })
        .collect();
    let inner = InnerLayer::create(&Vec::new(), &[], true, &points).unwrap();
    let descriptor = HiddenServiceDescriptorV3::create(
        &Vec::new(),
        &[],
        true,
        HiddenServiceV3Options {
            identity_key: Some(identity),
            blinding_nonce: Some([7u8; 32]),
            inner_layer: Some(inner),
            ..HiddenServiceV3Options::default()
        },
    )
    .unwrap();
    descriptor.verify_signing_certificate().unwrap();
    let decrypted = descriptor.decrypt(&address).unwrap();
    assert_eq!(decrypted.introduction_points.len(), 3);
    assert_eq!(
        decrypted.introduction_points[0].link_specifiers[0],
        LinkSpecifier::Ipv4 {
            address: "1.1.1.1".parse().unwrap(),
            port: 9001
        }
    );

    let other = address_from_identity_key(&[9u8; 32], true);
    assert!(descriptor.decrypt(&other).is_err());
}

#[test]
fn blinds_keys_deterministically() {
    let descriptor = HiddenServiceDescriptorV3::create(
        &Vec::new(),
        &[],
        true,
        HiddenServiceV3Options {
            identity_key: Some(SigningKey::from_bytes(&[b'a'; 32])),
            blinding_nonce: Some([b'a'; 32]),
            ..HiddenServiceV3Options::default()
        },
    )
    .unwrap();
    let certificate = descriptor.signing_cert.as_ref().unwrap();
    assert_eq!(certificate.signature.as_ref().unwrap().len(), 64);
    let expected = [
        &b"\xb5\xefEA\xfaI\x1a\xd8*p\xcd\x97\x01\x90O\xa8"[..],
        b"p\xd3\x10\x16\x8e-\x19\xab+\x92\xbc\xf6\xe7\x92\xc2k",
    ]
    .concat();
    assert_eq!(certificate.signing_key().unwrap(), expected.as_slice());
}

#[test]
fn derives_subcredentials() {
    let first = subcredential(&[1u8; 32], &[2u8; 32]);
    assert_eq!(first.len(), 32);
    assert_eq!(first, subcredential(&[1u8; 32], &[2u8; 32]));
    assert_ne!(first, subcredential(&[1u8; 32], &[3u8; 32]));
}

#[test]
fn rejects_missing_and_malformed_fields() {
    let required = [
        "hs-descriptor",
        "descriptor-lifetime",
        "descriptor-signing-key-cert",
        "revision-counter",
        "superencrypted",
        "signature",
    ];
    for keyword in required {
        let content = HiddenServiceDescriptorV3::content(
            &Vec::new(),
            &[keyword],
            HiddenServiceV3Options::default(),
        )
        .unwrap();
        assert!(
            HiddenServiceDescriptorV3::parse(&content, true).is_err(),
            "{keyword} was optional"
        );
    }
    for (keyword, values) in [
        ("hs-descriptor", ["", "-10", "hello"]),
        ("descriptor-lifetime", ["", "-10", "hello"]),
        ("revision-counter", ["", "-10", "hello"]),
    ] {
        for value in values {
            let attributes =
                vec![(keyword.to_string(), AttrValue::Text(value.to_string()))];
            let content = HiddenServiceDescriptorV3::content(
                &attributes,
                &[],
                HiddenServiceV3Options::default(),
            )
            .unwrap();
            assert!(
                HiddenServiceDescriptorV3::parse(&content, true).is_err(),
                "{keyword}={value}"
            );
        }
    }
}

#[test]
fn authorizes_clients_in_the_outer_layer() {
    let clients = vec![AuthorizedClient::random(), AuthorizedClient::random()];
    let descriptor = HiddenServiceDescriptorV3::create(
        &Vec::new(),
        &[],
        true,
        HiddenServiceV3Options {
            authorized_clients: Some(clients.clone()),
            ..HiddenServiceV3Options::default()
        },
    )
    .unwrap();
    assert!(descriptor.superencrypted.is_some());
    let outer = OuterLayer::parse(
        &OuterLayer::content(
            &Vec::new(),
            &[],
            &InnerLayer::create(&Vec::new(), &[], true, &[]).unwrap(),
            1,
            Some(&clients),
            &stem::descriptor::hidden_service::LayerSecrets {
                subcredential: &[1u8; 32],
                blinded_key: &[2u8; 32],
                descriptor_cookie: &[],
            },
        )
        .unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(outer.clients.len(), 2);
    assert!(outer.clients.contains_key(&clients[0].id));
}

#[test]
fn recomputes_the_blinded_key_of_a_real_descriptor() {
    let descriptor =
        HiddenServiceDescriptorV3::parse(&data("hidden_service_v3"), true).unwrap();
    let blinded_key = descriptor
        .signing_cert
        .as_ref()
        .unwrap()
        .signing_key()
        .unwrap();
    let period_number = 17391;
    assert_eq!(
        blinded_key_for_period(&PUBLIC_KEY, period_number, DEFAULT_TIME_PERIOD_LENGTH)
            .unwrap()
            .as_slice(),
        blinded_key
    );

    let period_start = i64::try_from(period_number * 1440 + 720).unwrap() * 60;
    let inside = DateTime::from_timestamp(period_start + 3600, 0).unwrap();
    assert_eq!(
        time_period_number(inside, DEFAULT_TIME_PERIOD_LENGTH).unwrap(),
        period_number
    );
    descriptor
        .verify_blinded_key(ADDRESS, inside, DEFAULT_TIME_PERIOD_LENGTH)
        .unwrap();

    let years_later = DateTime::from_timestamp(period_start + 86_400 * 800, 0).unwrap();
    assert!(
        descriptor
            .verify_blinded_key(ADDRESS, years_later, DEFAULT_TIME_PERIOD_LENGTH)
            .is_err()
    );
    assert!(time_period_number(inside, 0).is_err());
}
