#![cfg(feature = "integration")]

mod tor_instance;

use std::time::Duration;

use stem::controller::Controller;
use stem::descriptor::hidden_service::{
    DEFAULT_TIME_PERIOD_LENGTH, HiddenServiceDescriptor,
};
use stem::enumerations::{CircPurpose, Flag, StreamStatus};
use stem::events::{EventData, EventType};
use stem::onion_services::{EphemeralServiceOptions, OnionPorts};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tor_instance::shared_online;

async fn online_controller() -> Controller {
    shared_online().controller().await
}

#[tokio::test]
async fn reads_consensus_and_descriptor_information() {
    let controller = online_controller().await;

    let statuses = controller.get_network_statuses().await.unwrap();
    assert!(statuses.len() > 1000);
    let relay = statuses
        .iter()
        .find(|status| status.flags.iter().any(|flag| flag == Flag::Guard.as_str()))
        .expect("a guard relay");
    let fingerprint = relay.fingerprint.clone().unwrap();

    let single = controller
        .get_network_status(Some(&fingerprint))
        .await
        .unwrap();
    assert_eq!(single.fingerprint, relay.fingerprint);
    assert_eq!(single.address, relay.address);
    assert_eq!(single.or_port, relay.or_port);

    let microdescriptors = controller.get_microdescriptors().await.unwrap();
    assert!(microdescriptors.len() > 1000);
    let micro = controller
        .get_microdescriptor(Some(&fingerprint))
        .await
        .unwrap();
    assert!(micro.onion_key.is_some());
    assert!(micro.ntor_onion_key.is_some());

    assert!(
        controller
            .get_network_status(Some("not a fingerprint"))
            .await
            .is_err()
    );
    assert!(
        controller
            .get_network_status(Some("0".repeat(40).as_str()))
            .await
            .is_err()
    );
    controller.close().await;
}

async fn build_circuit(controller: &Controller) -> String {
    let mut last_error = None;
    for _ in 0..3 {
        let timeout = Some(Duration::from_secs(60));
        match controller
            .new_circuit(None, Some(&CircPurpose::General), true, timeout)
            .await
        {
            Ok(circuit_id) => return circuit_id,
            Err(error) => last_error = Some(error),
        }
    }
    panic!("no circuit built in three attempts: {last_error:?}");
}

#[tokio::test]
async fn builds_circuits_and_closes_them() {
    let controller = online_controller().await;

    let circuit_id = build_circuit(&controller).await;
    let circuit = controller.get_circuit(&circuit_id).await.unwrap();
    assert_eq!(circuit.id, circuit_id);
    assert!(circuit.path.len() >= 3);
    assert!(
        controller
            .get_circuits()
            .await
            .unwrap()
            .iter()
            .any(|candidate| candidate.id == circuit_id)
    );

    controller.close_circuit(&circuit_id, "").await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(controller.get_circuit(&circuit_id).await.is_err());
    controller.close().await;
}

async fn socks_connect(port: u16, host: &str, target_port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    stream
}

#[tokio::test]
async fn attaches_streams_to_a_chosen_circuit() {
    let tor = tor_instance::TorInstance::launch(false, "__LeaveStreamsUnattached 1");
    let controller = tor.controller().await;
    let (_, mut events) = controller.subscribe(&[EventType::Stream]).await.unwrap();
    let circuit_id = build_circuit(&controller).await;

    let socks_port = controller.get_socks_listeners().await.unwrap()[0].1;

    let mut body = Vec::new();
    for _ in 0..4 {
        let connecting = tokio::spawn(socks_connect(socks_port, "example.com", 80));
        let stream_id = loop {
            let event = tokio::time::timeout(Duration::from_secs(30), events.recv())
                .await
                .expect("stream event")
                .unwrap();
            if let EventData::Stream(stream) = event.data
                && stream.status == StreamStatus::New
            {
                break stream.id;
            }
        };
        controller
            .attach_stream(&stream_id, &circuit_id, None)
            .await
            .unwrap();

        let mut socks = connecting.await.unwrap();
        let mut reply = [0u8; 10];
        socks.read_exact(&mut reply).await.unwrap();
        if reply[1] != 0 {
            continue;
        }
        socks
            .write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        socks.read_to_end(&mut body).await.unwrap();
        break;
    }
    assert!(body.starts_with(b"HTTP/1."));

    controller.close().await;
}

#[tokio::test]
async fn fetches_the_descriptor_of_its_own_onion_service() {
    let controller = online_controller().await;
    let created = controller
        .create_ephemeral_hidden_service(
            &OnionPorts::Single(80),
            &EphemeralServiceOptions {
                await_publication: true,
                timeout: Some(Duration::from_secs(120)),
                ..EphemeralServiceOptions::default()
            },
        )
        .await
        .unwrap();
    let address = created.service_id.unwrap();

    let mut fetched = None;
    let mut last_error = String::new();
    for _ in 0..6 {
        let outcome = controller
            .get_hidden_service_descriptor(
                &address,
                &[],
                true,
                Some(Duration::from_secs(60)),
            )
            .await;
        match outcome {
            Ok(Some(descriptor)) => {
                fetched = Some(descriptor);
                break;
            }
            Ok(None) => last_error = "no descriptor".to_string(),
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let descriptor = fetched.unwrap_or_else(|| panic!("{last_error}"));
    let HiddenServiceDescriptor::V3(descriptor) = descriptor else {
        panic!("expected a v3 descriptor");
    };
    descriptor.verify_signing_certificate().unwrap();
    descriptor
        .verify_blinded_key(&address, chrono::Utc::now(), DEFAULT_TIME_PERIOD_LENGTH)
        .unwrap();
    let inner = descriptor.decrypt(&address).unwrap();
    assert!(!inner.introduction_points.is_empty());
    controller
        .remove_ephemeral_hidden_service(&address)
        .await
        .unwrap();
    controller.close().await;
}

#[tokio::test]
async fn resolves_through_tor() {
    let controller = online_controller().await;
    let (_, mut events) = controller.subscribe(&[EventType::AddrMap]).await.unwrap();
    controller.resolve(&["example.com"], false).await.unwrap();
    let mapped = loop {
        let event = tokio::time::timeout(Duration::from_secs(30), events.recv())
            .await
            .expect("address mapping")
            .unwrap();
        if let EventData::AddrMap(mapping) = event.data
            && mapping.hostname == "example.com"
        {
            break mapping;
        }
    };
    assert!(mapped.destination.is_some());
    controller.close().await;
}

#[tokio::test]
async fn exposes_server_descriptors_when_available() {
    let controller = online_controller().await;
    let outcome = controller.get_server_descriptors().await;
    match outcome {
        Ok(descriptors) => assert!(!descriptors.is_empty()),
        Err(error) => assert!(error.to_string().contains("not configured")),
    }
    controller.close().await;
}

#[tokio::test]
async fn decrypts_descriptors_restricted_to_authorized_clients() {
    let controller = online_controller().await;
    let secret = x25519_dalek::StaticSecret::from(rand::random::<[u8; 32]>());
    let public = x25519_dalek::PublicKey::from(&secret);
    let created = controller
        .create_ephemeral_hidden_service(
            &OnionPorts::Single(80),
            &EphemeralServiceOptions {
                await_publication: true,
                timeout: Some(Duration::from_secs(120)),
                client_auth_v3: Some(
                    data_encoding::BASE32_NOPAD.encode(public.as_bytes()),
                ),
                ..EphemeralServiceOptions::default()
            },
        )
        .await
        .unwrap();
    let address = created.service_id.unwrap();

    let mut fetched = None;
    let mut last_error = String::new();
    for _ in 0..6 {
        let outcome = controller
            .get_hidden_service_descriptor(
                &address,
                &[],
                true,
                Some(Duration::from_secs(60)),
            )
            .await;
        match outcome {
            Ok(Some(descriptor)) => {
                fetched = Some(descriptor);
                break;
            }
            Ok(None) => last_error = "no descriptor".to_string(),
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let HiddenServiceDescriptor::V3(descriptor) =
        fetched.unwrap_or_else(|| panic!("{last_error}"))
    else {
        panic!("expected a v3 descriptor");
    };
    assert!(descriptor.decrypt(&address).is_err());
    let inner = descriptor
        .decrypt_with_client_auth(&address, &secret.to_bytes())
        .unwrap();
    assert!(!inner.introduction_points.is_empty());
    let stranger = x25519_dalek::StaticSecret::from(rand::random::<[u8; 32]>());
    assert!(
        descriptor
            .decrypt_with_client_auth(&address, &stranger.to_bytes())
            .is_err()
    );
    controller
        .remove_ephemeral_hidden_service(&address)
        .await
        .unwrap();
    controller.close().await;
}
