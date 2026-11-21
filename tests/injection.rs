#![cfg(feature = "integration")]

mod tor_instance;

use stem::controller::{ConfValue, Controller};
use stem::enumerations::{CircPurpose, RelayEndReason, Signal};
use stem::events::EventType;
use stem::onion_services::{EphemeralServiceOptions, HiddenServiceConfig, OnionPorts};
use tor_instance::TorInstance;

const PAYLOADS: [&str; 9] = [
    "x\r\nSETCONF ContactInfo=pwned",
    "x\nSETCONF ContactInfo=pwned",
    "x\rSETCONF ContactInfo=pwned",
    "x SETCONF ContactInfo=pwned",
    "x\tSETCONF ContactInfo=pwned",
    "x\"\r\nSETCONF ContactInfo=pwned\r\nGETINFO \"",
    "\r\n",
    "x\0y",
    "\u{2028}SETCONF ContactInfo=pwned",
];

async fn assert_untouched(controller: &Controller, context: &str) {
    assert!(controller.is_alive(), "{context} closed the connection");
    controller.clear_cache();
    let contact = controller.get_conf("ContactInfo").await.unwrap_or_default();
    assert!(
        contact.as_deref().unwrap_or_default().is_empty(),
        "{context} changed ContactInfo to {contact:?}"
    );
    assert!(
        controller.get_version().await.is_ok(),
        "{context} broke the control connection"
    );
}

#[tokio::test]
async fn refuses_to_smuggle_commands_through_arguments() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    for payload in PAYLOADS {
        let _ = controller.get_info(payload).await;
        let _ = controller.get_info_multiple(&["version", payload]).await;
        let _ = controller.get_conf(payload).await;
        let _ = controller.get_conf_map(&[payload]).await;
        let _ = controller.is_set(payload).await;
        let _ = controller.reset_conf(&[payload]).await;
        let _ = controller.set_conf(payload, "1").await;
        let _ = controller.set_conf_multiple(payload, &["1"]).await;
        let _ = controller
            .set_options(&[(payload, ConfValue::Single("1".into()))], false)
            .await;
        let _ = controller.signal(&Signal::from(payload)).await;
        let _ = controller.map_address(&[(payload, "example.com")]).await;
        let _ = controller.map_address(&[("example.com", payload)]).await;
        let _ = controller.resolve(&[payload], false).await;
        let _ = controller.resolve(&[payload], true).await;
        let _ = controller.enable_feature(&[payload]).await;
        let _ = controller.subscribe(&[EventType::from(payload)]).await;
        let _ = controller.get_circuit(payload).await;
        let _ = controller.close_circuit(payload, "").await;
        let _ = controller.close_circuit("1", payload).await;
        let _ = controller
            .extend_circuit(payload, None, None, false, None)
            .await;
        let _ = controller
            .new_circuit(Some(&[payload]), None, false, None)
            .await;
        let _ = controller
            .new_circuit(None, Some(&CircPurpose::from(payload)), false, None)
            .await;
        let _ = controller.attach_stream(payload, "1", None).await;
        let _ = controller.attach_stream("1", payload, None).await;
        let _ = controller
            .close_stream(payload, &RelayEndReason::from("MISC"), "")
            .await;
        let _ = controller
            .close_stream("1", &RelayEndReason::from(payload), "")
            .await;
        let _ = controller
            .close_stream("1", &RelayEndReason::from("MISC"), payload)
            .await;
        let _ = controller.redirect_stream(payload, "1.2.3.4", None).await;
        let _ = controller.redirect_stream("1", payload, None).await;
        let _ = controller.set_router_purpose(payload, "general").await;
        let _ = controller.post_descriptor(payload, payload, true).await;
        let _ = controller.remove_ephemeral_hidden_service(payload).await;
        let _ = controller
            .get_hidden_service_descriptor(payload, &[], false, None)
            .await;
        let _ = controller
            .get_hidden_service_descriptor(&"a".repeat(56), &[payload], false, None)
            .await;
        let _ = controller
            .onion_client_auth_add(payload, payload, None, false)
            .await;
        let _ = controller.onion_client_auth_remove(payload).await;
        let _ = controller.onion_client_auth_view(Some(payload)).await;
        let _ = controller
            .create_ephemeral_hidden_service(
                &OnionPorts::Map(vec![(80, payload.to_string())]),
                &EphemeralServiceOptions::default(),
            )
            .await;
        let _ = controller
            .create_ephemeral_hidden_service(
                &OnionPorts::Single(80),
                &EphemeralServiceOptions {
                    key_type: payload.to_string(),
                    ..EphemeralServiceOptions::default()
                },
            )
            .await;
        let _ = controller
            .create_ephemeral_hidden_service(
                &OnionPorts::Single(80),
                &EphemeralServiceOptions {
                    basic_auth: Some(vec![(payload.to_string(), None)]),
                    ..EphemeralServiceOptions::default()
                },
            )
            .await;
        let _ = controller
            .create_hidden_service(payload, 80, Some(payload), None, None, &[])
            .await;
        let _ = controller
            .set_hidden_service_conf(&[HiddenServiceConfig {
                path: payload.to_string(),
                ports: Vec::new(),
                options: vec![(payload.to_string(), payload.to_string())],
            }])
            .await;
        assert_untouched(&controller, &format!("payload {payload:?}")).await;
    }
    controller.close().await;
}

#[tokio::test]
async fn keeps_data_blocks_from_ending_early() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    let hostile = [
        "Nickname x\n.\nSETCONF ContactInfo=pwned\n.\n",
        "Nickname x\r\n.\r\nSETCONF ContactInfo=pwned",
        ".\nSETCONF ContactInfo=pwned",
        "..\nSETCONF ContactInfo=pwned\n.",
    ];
    for text in hostile {
        let _ = controller.load_conf(text).await;
        assert_untouched(&controller, &format!("LOADCONF {text:?}")).await;
    }
    let _ = controller
        .post_descriptor(".\r\nSETCONF ContactInfo=pwned\r\n.", "general", false)
        .await;
    assert_untouched(&controller, "POSTDESCRIPTOR").await;
    controller.close().await;
}

#[tokio::test]
async fn quotes_configuration_values_safely() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    for value in PAYLOADS {
        let _ = controller.set_conf("Nickname", value).await;
        assert!(controller.is_alive(), "{value:?}");
        controller.clear_cache();
        let contact = controller.get_conf("ContactInfo").await.unwrap_or_default();
        assert!(contact.unwrap_or_default().is_empty(), "{value:?}");
    }
    controller.close().await;
}
