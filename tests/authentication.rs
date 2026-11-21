#![cfg(feature = "integration")]

mod tor_instance;

use stem::Error;
use stem::authentication::{
    self, AuthMethod, AuthenticationError, ConnectOptions, authenticate_cookie,
    authenticate_none, authenticate_password, authenticate_safecookie,
};
use stem::controller::Controller;
use stem::socket::ControlSocket;
use tor_instance::{TorInstance, hashed_password};

async fn fresh_socket(tor: &TorInstance) -> ControlSocket {
    let socket = tor.socket();
    socket.connect().await.unwrap();
    socket
}

fn authentication_error(error: Error) -> AuthenticationError {
    match error {
        Error::Authentication(error) => error,
        other => panic!("expected an authentication error, got {other:?}"),
    }
}

#[tokio::test]
async fn authenticates_without_credentials_when_tor_is_open() {
    let tor = TorInstance::launch_with(true, false, "");
    let socket = fresh_socket(&tor).await;
    let info = authentication::get_protocolinfo(&socket).await.unwrap();
    assert_eq!(info.auth_methods, vec![AuthMethod::None]);

    authenticate_none(&socket, false).await.unwrap();
    let controller = tor.controller().await;
    assert!(controller.is_authenticated());
    assert!(controller.get_version().await.is_ok());
}

#[tokio::test]
async fn authenticates_with_a_password() {
    let hashed = hashed_password("correct horse");
    let tor =
        TorInstance::launch_with(true, false, &format!("HashedControlPassword {hashed}"));

    let socket = fresh_socket(&tor).await;
    let info = authentication::get_protocolinfo(&socket).await.unwrap();
    assert_eq!(info.auth_methods, vec![AuthMethod::Password]);
    authenticate_password(&socket, "correct horse", false)
        .await
        .unwrap();

    let wrong = fresh_socket(&tor).await;
    let failure = authenticate_password(&wrong, "wrong", false)
        .await
        .unwrap_err();
    assert!(matches!(
        authentication_error(failure),
        AuthenticationError::IncorrectPassword(_)
    ));

    let controller = Controller::new(fresh_socket(&tor).await);
    let failure = controller.authenticate(None).await.unwrap_err();
    assert!(matches!(
        authentication_error(failure),
        AuthenticationError::MissingPassword(_)
    ));
    controller
        .authenticate(Some("correct horse"))
        .await
        .unwrap();
    assert!(controller.get_version().await.is_ok());

    let tricky = Controller::new(fresh_socket(&tor).await);
    let failure = tricky
        .authenticate(Some("wrong\"\r\nSIGNAL HALT"))
        .await
        .unwrap_err();
    assert!(matches!(
        authentication_error(failure),
        AuthenticationError::IncorrectPassword(_)
    ));
}

#[tokio::test]
async fn authenticates_with_passwords_containing_special_characters() {
    let password = "pa\"ss \\ word";
    let hashed = hashed_password(password);
    let tor =
        TorInstance::launch_with(true, false, &format!("HashedControlPassword {hashed}"));
    let controller = Controller::new(fresh_socket(&tor).await);
    controller.authenticate(Some(password)).await.unwrap();
    assert!(controller.get_version().await.is_ok());
}

#[tokio::test]
async fn authenticates_with_cookies() {
    let tor = TorInstance::offline();
    let socket = fresh_socket(&tor).await;
    let info = authentication::get_protocolinfo(&socket).await.unwrap();
    assert!(info.auth_methods.contains(&AuthMethod::Cookie));
    assert!(info.auth_methods.contains(&AuthMethod::SafeCookie));
    assert_eq!(info.cookie_path.as_deref(), tor.cookie_path().to_str(),);

    authenticate_safecookie(&socket, &tor.cookie_path(), false)
        .await
        .unwrap();
    let plain = fresh_socket(&tor).await;
    authenticate_cookie(&plain, &tor.cookie_path(), false)
        .await
        .unwrap();
}

#[tokio::test]
async fn rejects_bad_cookie_files() {
    let tor = TorInstance::offline();
    let directory = tempfile::tempdir().unwrap();

    let wrong_value = directory.path().join("wrong");
    std::fs::write(&wrong_value, [7u8; 32]).unwrap();
    let socket = fresh_socket(&tor).await;
    let failure = authenticate_cookie(&socket, &wrong_value, false)
        .await
        .unwrap_err();
    assert!(matches!(
        authentication_error(failure),
        AuthenticationError::IncorrectCookieValue(_)
    ));
    let socket = fresh_socket(&tor).await;
    let failure = authenticate_safecookie(&socket, &wrong_value, false)
        .await
        .unwrap_err();
    assert!(matches!(
        authentication_error(failure),
        AuthenticationError::AuthSecurityFailure(_)
    ));

    let wrong_size = directory.path().join("short");
    std::fs::write(&wrong_size, [7u8; 31]).unwrap();
    let socket = fresh_socket(&tor).await;
    let failure = authenticate_cookie(&socket, &wrong_size, false)
        .await
        .unwrap_err();
    assert!(matches!(
        authentication_error(failure),
        AuthenticationError::IncorrectCookieSize(_)
    ));

    let oversized = directory.path().join("huge");
    std::fs::write(&oversized, vec![7u8; 1 << 20]).unwrap();
    let failure = authenticate_cookie(&socket, &oversized, false)
        .await
        .unwrap_err();
    assert!(matches!(
        authentication_error(failure),
        AuthenticationError::IncorrectCookieSize(_)
    ));

    let missing = directory.path().join("missing");
    let failure = authenticate_cookie(&socket, &missing, false)
        .await
        .unwrap_err();
    assert!(matches!(
        authentication_error(failure),
        AuthenticationError::UnreadableCookieFile(_)
    ));

    let link = directory.path().join("link");
    std::os::unix::fs::symlink(tor.cookie_path(), &link).unwrap();
    let linked = fresh_socket(&tor).await;
    authenticate_cookie(&linked, &link, false).await.unwrap();

    let failure = authenticate_cookie(&socket, directory.path(), false)
        .await
        .unwrap_err();
    assert!(matches!(
        authentication_error(failure),
        AuthenticationError::IncorrectCookieSize(_)
    ));
}

#[tokio::test]
async fn authenticates_over_a_unix_socket() {
    let tor = TorInstance::offline();
    let controller = Controller::from_socket_file(tor.socket_path())
        .await
        .unwrap();
    controller.authenticate(None).await.unwrap();
    assert!(controller.get_version().await.is_ok());
    assert!(controller.is_localhost());
    controller.close().await;
}

#[tokio::test]
async fn connects_with_the_helper_functions() {
    let tor = TorInstance::offline();
    let controller = authentication::connect_port(
        std::net::Ipv4Addr::LOCALHOST.into(),
        tor.control_port,
        None,
        None,
    )
    .await
    .unwrap();
    assert!(controller.is_authenticated());

    let by_socket = authentication::connect_socket_file(tor.socket_path(), None, None)
        .await
        .unwrap();
    assert!(by_socket.is_authenticated());

    let options = ConnectOptions {
        control_port: Some((
            std::net::Ipv4Addr::LOCALHOST.into(),
            Some(tor.control_port),
        )),
        control_socket: None,
        ..ConnectOptions::default()
    };
    let connected = authentication::connect(options).await.unwrap();
    assert!(connected.get_version().await.is_ok());

    let nothing = ConnectOptions {
        control_port: None,
        control_socket: None,
        ..ConnectOptions::default()
    };
    assert!(authentication::connect(nothing).await.is_err());
}

#[tokio::test]
async fn fails_to_connect_to_closed_ports() {
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let result = authentication::connect_port(
        std::net::Ipv4Addr::LOCALHOST.into(),
        closed,
        None,
        None,
    )
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn prefers_safecookie_and_survives_reconnects() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    controller.close().await;
    controller.reconnect(None).await.unwrap();
    assert!(controller.get_version().await.is_ok());
}
