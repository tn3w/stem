#![cfg(feature = "integration")]

mod tor_instance;

use tor_instance::TorInstance;

#[tokio::test]
async fn connects_authenticates_and_reads_version() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    let version = controller.get_version().await.expect("version");
    println!("tor version {version}");
    assert!(controller.is_authenticated());
    let info = controller
        .get_info("config-file")
        .await
        .expect("config file");
    assert!(info.ends_with("torrc"));
    controller.close().await;
}
