#![cfg(feature = "integration")]

mod tor_instance;

use base64::Engine;
use stem::Error;
use stem::onion_services::{
    ClientAuthOutcome, EphemeralServiceOptions, HiddenServiceConfig, HiddenServicePort,
    OnionPorts,
};
use tor_instance::TorInstance;

fn client_key() -> String {
    base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 32]>())
}

#[tokio::test]
async fn creates_and_removes_ephemeral_v3_services() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;

    let created = controller
        .create_ephemeral_hidden_service(
            &OnionPorts::Map(vec![(80, "127.0.0.1:8080".to_string())]),
            &EphemeralServiceOptions::default(),
        )
        .await
        .unwrap();
    let service_id = created.service_id.clone().unwrap();
    assert_eq!(service_id.len(), 56);
    assert_eq!(created.private_key_type.as_deref(), Some("ED25519-V3"));
    assert!(created.private_key.is_some());

    let listed = controller
        .list_ephemeral_hidden_services(true, false)
        .await
        .unwrap();
    assert_eq!(listed, vec![service_id.clone()]);

    assert!(
        controller
            .remove_ephemeral_hidden_service(&service_id)
            .await
            .unwrap()
    );
    assert!(
        !controller
            .remove_ephemeral_hidden_service(&service_id)
            .await
            .unwrap()
    );
    assert!(
        controller
            .list_ephemeral_hidden_services(true, false)
            .await
            .unwrap()
            .is_empty()
    );
    controller.close().await;
}

#[tokio::test]
async fn reuses_keys_and_supports_detached_services() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;

    let first = controller
        .create_ephemeral_hidden_service(
            &OnionPorts::Single(80),
            &EphemeralServiceOptions {
                detached: true,
                ..EphemeralServiceOptions::default()
            },
        )
        .await
        .unwrap();
    let key = first.private_key.clone().unwrap();
    let id = first.service_id.clone().unwrap();
    assert_eq!(
        controller
            .list_ephemeral_hidden_services(false, true)
            .await
            .unwrap(),
        vec![id.clone()]
    );
    controller
        .remove_ephemeral_hidden_service(&id)
        .await
        .unwrap();

    let second = controller
        .create_ephemeral_hidden_service(
            &OnionPorts::List(vec![80, 443]),
            &EphemeralServiceOptions {
                key_type: "ED25519-V3".to_string(),
                key_content: key,
                discard_key: true,
                ..EphemeralServiceOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(second.service_id.as_deref(), Some(id.as_str()));
    assert!(second.private_key.is_none());
    controller.close().await;
}

#[tokio::test]
async fn rejects_invalid_ephemeral_service_requests() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;

    assert!(matches!(
        controller
            .create_ephemeral_hidden_service(
                &OnionPorts::Single(0),
                &EphemeralServiceOptions::default()
            )
            .await,
        Err(Error::InvalidInput(_))
    ));
    let injected = EphemeralServiceOptions {
        key_content: "BEST\r\nSIGNAL HALT".to_string(),
        ..EphemeralServiceOptions::default()
    };
    assert!(
        controller
            .create_ephemeral_hidden_service(&OnionPorts::Single(80), &injected)
            .await
            .is_err()
    );
    assert!(
        controller
            .remove_ephemeral_hidden_service("not valid")
            .await
            .is_err()
    );
    assert!(controller.is_alive());
    controller.get_version().await.unwrap();
    controller.close().await;
}

#[tokio::test]
async fn manages_client_authorization_credentials() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    let service = controller
        .create_ephemeral_hidden_service(
            &OnionPorts::Single(80),
            &EphemeralServiceOptions::default(),
        )
        .await
        .unwrap();
    let address = service.service_id.unwrap();
    let key = client_key();

    assert_eq!(
        controller
            .onion_client_auth_add(&address, &key, Some("alice"), false)
            .await
            .unwrap(),
        ClientAuthOutcome::Added
    );
    let viewed = controller
        .onion_client_auth_view(Some(&address))
        .await
        .unwrap();
    assert_eq!(viewed.len(), 1);
    assert_eq!(viewed[0].address, address);
    assert_eq!(viewed[0].private_key, key);
    assert_eq!(viewed[0].client_name.as_deref(), Some("alice"));

    assert_eq!(
        controller
            .onion_client_auth_add(&address, &client_key(), None, false)
            .await
            .unwrap(),
        ClientAuthOutcome::Replaced
    );
    assert!(controller.onion_client_auth_remove(&address).await.unwrap());
    assert!(!controller.onion_client_auth_remove(&address).await.unwrap());
    assert!(
        controller
            .onion_client_auth_view(None)
            .await
            .unwrap()
            .is_empty()
    );

    assert!(
        controller
            .onion_client_auth_add(&address, "bad key", None, false)
            .await
            .is_err()
    );
    assert!(
        controller
            .onion_client_auth_add("short", &key, None, false)
            .await
            .is_err()
    );
    controller.close().await;
}

#[tokio::test]
async fn configures_persistent_hidden_services() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    let directory = tor.path().join("hidden_service");
    let path = directory.to_str().unwrap().to_string();

    let created = controller
        .create_hidden_service(&path, 80, Some("127.0.0.1"), Some(8080), None, &[])
        .await
        .unwrap()
        .unwrap();
    let hostname = created.hostname.unwrap();
    assert!(hostname.ends_with(".onion"));
    assert_eq!(hostname.len(), 62);
    assert_eq!(
        std::fs::read_to_string(directory.join("hostname"))
            .unwrap()
            .trim(),
        hostname
    );

    let again = controller
        .create_hidden_service(&path, 80, Some("127.0.0.1"), Some(8080), None, &[])
        .await
        .unwrap();
    assert!(again.is_none());

    controller.clear_cache();
    let configured = controller.get_hidden_service_conf().await.unwrap();
    assert_eq!(configured.len(), 1);
    assert_eq!(configured[0].path, path);
    assert_eq!(
        configured[0].ports,
        vec![HiddenServicePort {
            port: 80,
            target_address: "127.0.0.1".to_string(),
            target_port: 8080,
        }]
    );

    assert!(
        controller
            .remove_hidden_service(&path, Some(80))
            .await
            .unwrap()
    );
    controller.clear_cache();
    assert!(
        controller
            .get_hidden_service_conf()
            .await
            .unwrap()
            .is_empty()
    );

    controller
        .set_hidden_service_conf(&[HiddenServiceConfig {
            path: path.clone(),
            ports: vec![HiddenServicePort {
                port: 443,
                target_address: "127.0.0.1".to_string(),
                target_port: 8443,
            }],
            options: Vec::new(),
        }])
        .await
        .unwrap();
    controller.clear_cache();
    assert_eq!(
        controller.get_hidden_service_conf().await.unwrap()[0].ports[0].port,
        443
    );
    controller.set_hidden_service_conf(&[]).await.unwrap();
    controller.clear_cache();
    assert!(
        controller
            .get_hidden_service_conf()
            .await
            .unwrap()
            .is_empty()
    );

    assert!(
        controller
            .create_hidden_service(&path, 0, None, None, None, &[])
            .await
            .is_err()
    );
    assert!(
        controller
            .create_hidden_service(&path, 80, Some("not an address"), None, None, &[])
            .await
            .is_err()
    );
    controller.close().await;
}
