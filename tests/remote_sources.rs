use std::time::Duration;

use stem::directory::{Authority, Fallback};
use stem::download::download;
use stem::manual::Manual;
use stem::process_inspection::is_available;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TIMEOUT: Duration = Duration::from_secs(20);
const SIGN_IN_PAGE: &str = "<html><body>You need to sign in.</body></html>";
const HTML_PAGE: &str = "<html><body>Nothing here.</body></html>";

fn fixture(path: &str) -> String {
    std::fs::read_to_string(format!("{}/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn respond(path: &str) -> String {
    let (status, location, body) = match path {
        "/authorities" => ("200 OK", "", fixture("src/data/auth_dirs.inc")),
        "/fallbacks" => ("200 OK", "", fixture("src/data/fallback_dirs.inc")),
        "/manual" => ("200 OK", "", fixture("tests/data/tor_man_example.md")),
        "/blocked" => ("302 Found", "/users/sign_in", String::new()),
        "/html" => ("200 OK", "", HTML_PAGE.to_string()),
        "/users/sign_in" => ("200 OK", "", SIGN_IN_PAGE.to_string()),
        _ => ("404 Not Found", "", String::new()),
    };
    let location = match location.is_empty() {
        true => String::new(),
        false => format!("Location: {location}\r\n"),
    };
    format!(
        "HTTP/1.1 {status}\r\n{location}Content-Length: {}\r\n\
        Connection: close\r\n\r\n{body}",
        body.len()
    )
}

fn squashed(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn keys(map: &indexmap::IndexMap<String, String>) -> Vec<String> {
    map.keys().cloned().collect()
}

async fn serve() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = vec![0u8; 4096];
                let size = socket.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..size]);
                let path = request.split_whitespace().nth(1).unwrap_or("/");
                let _ = socket.write_all(respond(path).as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    format!("http://{address}")
}

#[tokio::test]
async fn downloads_directory_authorities() {
    let server = serve().await;
    let authorities = Authority::from_url(&format!("{server}/authorities"), TIMEOUT)
        .await
        .unwrap();
    assert_eq!(authorities, Authority::from_cache().unwrap());
}

#[tokio::test]
async fn downloads_fallback_directories() {
    let server = serve().await;
    let fallbacks = Fallback::from_url(&format!("{server}/fallbacks"), TIMEOUT)
        .await
        .unwrap();
    assert_eq!(fallbacks, Fallback::from_cache(None).unwrap());
}

#[tokio::test]
async fn reports_sign_in_redirects() {
    let server = serve().await;
    let error = download(&format!("{server}/blocked"), Some(TIMEOUT), 0)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("sign-in"), "{error}");
    assert!(
        Authority::from_url(&format!("{server}/blocked"), TIMEOUT)
            .await
            .is_err()
    );
    assert!(
        Fallback::from_url(&format!("{server}/blocked"), TIMEOUT)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejects_pages_without_authorities() {
    let server = serve().await;
    assert!(
        Authority::from_url(&format!("{server}/html"), TIMEOUT)
            .await
            .is_err()
    );
    assert!(
        Authority::from_url(&format!("{server}/missing"), TIMEOUT)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn converts_a_downloaded_manual_with_pandoc() {
    if !is_available("pandoc") || !is_available("man") {
        return;
    }
    let server = serve().await;
    let downloaded = Manual::from_url(&format!("{server}/manual"), TIMEOUT)
        .await
        .unwrap();
    let direct = Manual::from_man(&format!(
        "{}/tests/data/tor_man_example",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(squashed(&downloaded.name), squashed(&direct.name));
    assert_eq!(squashed(&downloaded.synopsis), squashed(&direct.synopsis));
    assert_eq!(
        squashed(&downloaded.description),
        squashed(&direct.description)
    );
    assert_eq!(
        keys(&downloaded.commandline_options),
        keys(&direct.commandline_options)
    );
    assert_eq!(keys(&downloaded.signals), keys(&direct.signals));
    assert_eq!(keys(&downloaded.files), keys(&direct.files));
    assert_eq!(downloaded.config_options.len(), direct.config_options.len());
    for (name, option) in &direct.config_options {
        let converted = &downloaded.config_options[name];
        assert_eq!(converted.category, option.category);
        assert_eq!(converted.usage, option.usage);
        assert!(!converted.description.is_empty());
    }
    assert!(
        Manual::from_url(&format!("{server}/blocked"), TIMEOUT)
            .await
            .is_err()
    );
}
