#![cfg(feature = "integration")]

mod tor_instance;

use std::net::IpAddr;

use stem::client::datatypes::{CertType, Certificate};
use stem::client::link_authentication::verify_relay_certificates;
use stem::client::relay::{DEFAULT_LINK_PROTOCOLS, Relay};
use tor_instance::TorInstance;

const RELAY_CONFIG: &str = "ORPort 127.0.0.1:auto\n\
    Address 127.0.0.1\n\
    Nickname stemtest\n\
    PublishServerDescriptor 0\n\
    ExitRelay 0\n\
    AssumeReachable 1";

async fn connect_to_local_relay(instance: &TorInstance) -> std::sync::Arc<Relay> {
    let controller = instance.controller().await;
    let listeners = controller.get_info("net/listeners/or").await.unwrap();
    let port: u16 = listeners
        .trim()
        .trim_matches('"')
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let address: IpAddr = "127.0.0.1".parse().unwrap();
    Relay::connect(address, port, &DEFAULT_LINK_PROTOCOLS)
        .await
        .unwrap()
}

#[tokio::test]
async fn authenticates_the_relay_identity() {
    let instance = TorInstance::launch_with(false, true, RELAY_CONFIG);
    let relay = connect_to_local_relay(&instance).await;

    let fingerprint_file =
        std::fs::read_to_string(instance.path().join("data/fingerprint")).unwrap();
    let fingerprint = fingerprint_file.split_whitespace().nth(1).unwrap();
    assert_eq!(relay.identity.fingerprint, fingerprint);

    let ed25519_file =
        std::fs::read_to_string(instance.path().join("data/fingerprint-ed25519"))
            .unwrap();
    let ed25519 = ed25519_file.split_whitespace().nth(1).unwrap();
    let identity = relay.identity.ed25519.expect("an ed25519 identity");
    assert_eq!(base64_unpadded(&identity), ed25519.trim_end_matches('='));
    relay.close().await;
}

fn base64_unpadded(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

#[test]
fn refuses_incomplete_or_garbage_certificates() {
    assert!(verify_relay_certificates(&[], &[]).is_err());
    let garbage = [
        Certificate::new(CertType::Identity, vec![1, 2, 3]),
        Certificate::new(CertType::Link, vec![4, 5, 6]),
    ];
    assert!(verify_relay_certificates(&garbage, &[7, 8, 9]).is_err());
    let missing_link = [Certificate::new(CertType::Identity, vec![0x30, 0])];
    assert!(verify_relay_certificates(&missing_link, &[]).is_err());
}
