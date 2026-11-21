#![cfg(feature = "integration")]

mod tor_instance;

use std::time::Duration;

use stem::Error;
use stem::controller::ListenerType;
use stem::enumerations::Signal;
use stem::events::{EventData, EventType};
use tor_instance::TorInstance;

#[tokio::test]
async fn queries_process_and_version_information() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;

    let version = controller.get_version().await.unwrap();
    assert!(version.to_string().starts_with("0."));
    assert_eq!(controller.get_pid().await.unwrap(), tor.pid());
    assert!(!controller.get_user().await.unwrap().is_empty());
    let start_time = controller.get_start_time().await.unwrap();
    assert!(start_time > 1.6e9);
    assert!(controller.get_uptime().await.unwrap() < 60.0);
    assert!(controller.is_localhost());
    assert!(controller.is_alive());

    let values = controller
        .get_info_multiple(&["version", "config-file"])
        .await
        .unwrap();
    assert_eq!(values.len(), 2);
    assert!(values["version"].starts_with(&version.to_string()));
    assert!(controller.get_info("not-a-real-option").await.is_err());
    assert!(matches!(
        controller.get_info("bad option").await,
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        controller.get_info("version\r\nSIGNAL HALT").await,
        Err(Error::InvalidInput(_))
    ));
    assert!(controller.is_alive());
    assert_eq!(controller.get_pid().await.unwrap(), tor.pid());
    controller.close().await;
}

#[tokio::test]
async fn reports_listeners_and_protocol_information() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;

    let control = controller
        .get_listeners(&ListenerType::Control)
        .await
        .unwrap();
    assert!(control.iter().any(|(_, port)| *port == tor.control_port));
    let ports = controller.get_ports(&ListenerType::Control).await.unwrap();
    assert!(ports.contains(&tor.control_port));
    controller.get_socks_listeners().await.unwrap();

    let info = controller.get_protocolinfo().await.unwrap();
    assert!(info.cookie_path.is_some());
    assert!(!info.auth_methods.is_empty());
    assert_eq!(info.protocol_version, 1);
    controller.close().await;
}

#[tokio::test]
async fn sets_resets_and_reads_configuration() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;

    assert_eq!(
        controller
            .get_conf("ContactInfo")
            .await
            .unwrap()
            .unwrap_or_default(),
        ""
    );
    controller
        .set_conf("ContactInfo", "me@example.com")
        .await
        .unwrap();
    assert_eq!(
        controller.get_conf("ContactInfo").await.unwrap().as_deref(),
        Some("me@example.com")
    );
    assert!(controller.is_set("ContactInfo").await.unwrap());

    controller
        .set_conf("ContactInfo", "with \"quotes\" and spaces")
        .await
        .unwrap();
    assert_eq!(
        controller.get_conf("ContactInfo").await.unwrap().as_deref(),
        Some("with \"quotes\" and spaces")
    );

    controller.reset_conf(&["ContactInfo"]).await.unwrap();
    assert!(!controller.is_set("ContactInfo").await.unwrap());

    controller
        .set_conf_multiple("ExitPolicy", &["accept *:80", "reject *:*"])
        .await
        .unwrap();
    assert_eq!(
        controller.get_conf_multiple("ExitPolicy").await.unwrap(),
        vec!["accept *:80", "reject *:*"]
    );
    let map = controller
        .get_conf_map(&["ExitPolicy", "Nickname"])
        .await
        .unwrap();
    assert_eq!(map["ExitPolicy"].len(), 2);

    let failure = controller.set_conf("NotAnOption", "1").await;
    assert!(matches!(failure, Err(Error::InvalidArguments { .. })));
    controller
        .set_conf("ContactInfo", "line\r\nSIGNAL HALT")
        .await
        .unwrap();
    assert_eq!(
        controller.get_conf("ContactInfo").await.unwrap().as_deref(),
        Some("line\r\nSIGNAL HALT")
    );
    assert!(controller.is_alive());
    controller.get_version().await.unwrap();
    controller.close().await;
}

#[tokio::test]
async fn persists_and_loads_configuration() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;

    controller.set_conf("Nickname", "stemtest").await.unwrap();
    controller.save_conf(true).await.unwrap();
    let saved = std::fs::read_to_string(tor.path().join("torrc")).unwrap();
    assert!(saved.contains("Nickname stemtest"));

    controller
        .load_conf(&format!("{saved}\nContactInfo loaded@example.com\n"))
        .await
        .unwrap();
    assert_eq!(
        controller.get_conf("ContactInfo").await.unwrap().as_deref(),
        Some("loaded@example.com")
    );
    let failure = controller
        .load_conf(&format!("{saved}\nNotAnOption 1\n"))
        .await;
    assert!(matches!(failure, Err(Error::InvalidArguments { .. })));
    controller.close().await;
}

#[tokio::test]
async fn caches_values_until_configuration_changes() {
    let tor = TorInstance::offline();
    let first = tor.controller().await;
    let second = tor.controller().await;
    assert!(first.is_caching_enabled());

    first.set_conf("ContactInfo", "one").await.unwrap();
    assert_eq!(
        first.get_conf("ContactInfo").await.unwrap().as_deref(),
        Some("one")
    );
    second.set_conf("ContactInfo", "two").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        first.get_conf("ContactInfo").await.unwrap().as_deref(),
        Some("two")
    );

    first.set_caching(false);
    assert!(!first.is_caching_enabled());
    second.set_conf("ContactInfo", "three").await.unwrap();
    assert_eq!(
        first.get_conf("ContactInfo").await.unwrap().as_deref(),
        Some("three")
    );
    first.set_caching(true);
    first.clear_cache();
    first.close().await;
    second.close().await;
}

#[tokio::test]
async fn delivers_events_to_listeners() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;

    let (listener, mut events) = controller
        .subscribe(&[EventType::ConfChanged, EventType::Signal, EventType::Bw])
        .await
        .unwrap();
    controller.set_conf("ContactInfo", "events").await.unwrap();
    controller.signal(&Signal::Newnym).await.unwrap();

    let (mut conf_changed, mut signalled, mut bandwidth) = (false, false, false);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !(conf_changed && signalled && bandwidth) {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("events arrive")
            .expect("channel open");
        match event.data {
            EventData::ConfChanged(changed) => {
                conf_changed |= changed.config.contains_key("ContactInfo")
            }
            EventData::Signal(signal) => signalled |= signal.signal == Signal::Newnym,
            EventData::Bandwidth(_) => bandwidth = true,
            _ => {}
        }
    }
    controller.remove_event_listener(listener).await.unwrap();
    assert!(!controller.is_newnym_available());
    assert!(controller.get_newnym_wait() > Duration::ZERO);
    controller.close().await;
}

#[tokio::test]
async fn rejects_unknown_events_and_signals() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;

    assert!(
        controller
            .subscribe(&[EventType::from("NOT_AN_EVENT")])
            .await
            .is_err()
    );
    assert!(
        controller
            .subscribe(&[EventType::from("BW EXTRA")])
            .await
            .is_err()
    );
    assert!(
        controller
            .signal(&Signal::from("NOT_A_SIGNAL"))
            .await
            .is_err()
    );
    assert!(
        controller
            .signal(&Signal::from("HALT\r\nGETINFO version"))
            .await
            .is_err()
    );
    controller.get_version().await.unwrap();
    controller.close().await;
}

#[tokio::test]
async fn manages_features_and_address_mapping() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;

    controller
        .enable_feature(&["EXTENDED_EVENTS"])
        .await
        .unwrap();
    assert!(controller.is_feature_enabled("EXTENDED_EVENTS").await);
    assert!(controller.enable_feature(&["NOT_A_FEATURE"]).await.is_err());

    let mapped = controller
        .map_address(&[("1.2.3.4", "torproject.org")])
        .await
        .unwrap();
    assert_eq!(mapped["1.2.3.4"], "torproject.org");
    assert!(controller.map_address(&[("a=b", "c")]).await.is_err());
    controller.drop_guards().await.unwrap();
    controller.drop_timeouts().await.unwrap();
    controller.close().await;
}

#[tokio::test]
async fn handles_circuit_and_stream_queries_without_a_network() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;

    assert!(controller.get_circuits().await.unwrap().is_empty());
    assert!(controller.get_streams().await.unwrap().is_empty());
    assert!(controller.get_circuit("999").await.is_err());
    assert!(controller.close_circuit("999", "").await.is_err());
    assert!(controller.close_circuit("1", "bad flag").await.is_err());
    controller.close().await;
}

#[tokio::test]
async fn closes_the_connection_on_quit() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    controller.quit().await.unwrap();
    assert!(!controller.is_alive());
    assert!(controller.get_version().await.is_err());
    controller.connect().await.unwrap();
    controller.authenticate(None).await.unwrap();
    assert!(controller.get_version().await.is_ok());
    controller.close().await;
}
