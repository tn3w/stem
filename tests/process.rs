#![cfg(feature = "integration")]

mod tor_instance;

use std::time::Duration;

use stem::authentication::connect_socket_file;
use stem::process::{LaunchOptions, TorrcSource, launch_tor, launch_tor_with_config};
use tor_instance::{library_environment, tor_binary};

fn options(percent: u32) -> LaunchOptions {
    LaunchOptions {
        tor_command: tor_binary(),
        completion_percent: percent,
        timeout: Some(Duration::from_secs(120)),
        environment: library_environment(),
        ..LaunchOptions::default()
    }
}

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::Builder::new()
        .prefix("stem-process-")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::set_permissions(
        directory.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    directory
}

fn offline_config<'a>(
    root: &'a str,
    socket: &'a str,
    cookie: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        ("DataDirectory", root),
        ("SocksPort", "0"),
        ("ControlSocket", socket),
        ("CookieAuthentication", "1"),
        ("CookieAuthFile", cookie),
        ("DisableNetwork", "1"),
    ]
}

#[tokio::test]
async fn launches_tor_with_a_generated_configuration() {
    let directory = private_directory();
    let root = format!("{}/data", directory.path().display());
    let socket = format!("{}/control.sock", directory.path().display());
    let cookie = format!("{}/cookie", directory.path().display());
    let config = offline_config(&root, &socket, &cookie);

    let mut lines = Vec::new();
    let mut handler = |line: &str| lines.push(line.to_string());
    let mut child = launch_tor_with_config(&config, options(0), Some(&mut handler))
        .await
        .unwrap();
    assert!(lines.iter().any(|line| line.contains("Bootstrapped 0%")));

    let controller = connect_socket_file(&socket, None, None).await.unwrap();
    assert_eq!(
        controller.get_conf("SocksPort").await.unwrap().as_deref(),
        Some("0")
    );
    assert_eq!(controller.get_pid().await.unwrap(), child.id().unwrap());
    controller.close().await;
    child.kill().await.unwrap();
}

async fn launch_owned(directory: &tempfile::TempDir) -> (tokio::process::Child, String) {
    let root = format!("{}/data", directory.path().display());
    let socket = format!("{}/control.sock", directory.path().display());
    let cookie = format!("{}/cookie", directory.path().display());
    let config = offline_config(&root, &socket, &cookie);
    let mut launch = options(0);
    launch.take_ownership = true;
    let child = launch_tor_with_config(&config, launch, None).await.unwrap();
    (child, socket)
}

#[tokio::test]
async fn takes_ownership_so_tor_exits_with_the_controller() {
    let directory = private_directory();
    let (mut child, socket) = launch_owned(&directory).await;
    let controller = connect_socket_file(&socket, None, None).await.unwrap();
    assert_eq!(
        controller
            .get_conf("__OwningControllerProcess")
            .await
            .unwrap(),
        None
    );
    controller.close().await;
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait()).await;
    assert!(status.unwrap().unwrap().success());
}

#[tokio::test]
async fn keeps_tor_running_after_dropping_ownership() {
    let directory = private_directory();
    let (mut child, socket) = launch_owned(&directory).await;
    let controller = connect_socket_file(&socket, None, None).await.unwrap();
    controller.drop_ownership().await.unwrap();
    controller.close().await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(child.try_wait().unwrap().is_none());

    let controller = connect_socket_file(&socket, None, None).await.unwrap();
    controller
        .signal(&stem::enumerations::Signal::Halt)
        .await
        .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait()).await;
    assert!(status.is_ok());
}

#[tokio::test]
async fn reports_launch_failures() {
    let missing = LaunchOptions {
        tor_command: "/nonexistent/tor".to_string(),
        ..LaunchOptions::default()
    };
    assert!(launch_tor(missing, None).await.is_err());

    let directory = LaunchOptions {
        tor_command: "/tmp".to_string(),
        ..LaunchOptions::default()
    };
    assert!(launch_tor(directory, None).await.is_err());

    let mut bad_torrc = options(100);
    bad_torrc.torrc = TorrcSource::Path("/nonexistent/torrc".into());
    assert!(launch_tor(bad_torrc, None).await.is_err());

    let invalid = [("NotARealTorOption", "1")];
    let failure = launch_tor_with_config(&invalid, options(100), None).await;
    assert!(failure.is_err());

    let mut impatient = options(100);
    impatient.timeout = Some(Duration::from_millis(1));
    let directory = private_directory();
    let root = format!("{}/data", directory.path().display());
    let config = [("DataDirectory", root.as_str()), ("SocksPort", "0")];
    assert!(
        launch_tor_with_config(&config, impatient, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn refuses_configuration_values_that_inject_options() {
    for (key, value) in [
        ("SocksPort", "0\nControlPort 9999"),
        ("SocksPort", "0\r\nExitRelay 1"),
        ("Socks Port", "0"),
        ("", "0"),
        ("SocksPort", "0\0"),
    ] {
        let config = [(key, value)];
        let failure = launch_tor_with_config(&config, options(100), None).await;
        assert!(failure.is_err(), "{key:?} {value:?} was accepted");
    }
}
