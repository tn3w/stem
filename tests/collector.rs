use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use chrono::NaiveDate;
use sha2::{Digest, Sha256};
use stem::Error;
use stem::descriptor::Descriptor;
use stem::descriptor::collector::{CollecTor, CollectorRequest, parse_index};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/data/descriptor/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn checksum(content: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(content))
}

struct FakeCollector {
    address: String,
    requests: Arc<Mutex<Vec<String>>>,
}

async fn serve(routes: HashMap<String, Vec<u8>>) -> FakeCollector {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = requests.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let routes = routes.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
                let path = request
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                log.lock().unwrap().push(path.clone());
                let response = match routes.get(&path) {
                    Some(body) => {
                        let mut response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: \
                            close\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        response.extend_from_slice(body);
                        response
                    }
                    None => b"HTTP/1.1 404 Not Found\r\nContent-Length: \
                        0\r\nConnection: close\r\n\r\n"
                        .to_vec(),
                };
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    FakeCollector { address, requests }
}

fn index_for(files: &[(&str, &[u8], &str)]) -> Vec<u8> {
    let entries: Vec<serde_json::Value> = files
        .iter()
        .map(|(path, content, kind)| {
            serde_json::json!({
                "path": path.rsplit('/').next().unwrap(),
                "size": content.len(),
                "last_modified": "2012-03-01 18:00",
                "types": [kind],
                "first_published": "2012-03-01 17:00",
                "last_published": "2012-03-01 18:00",
                "sha256": checksum(content),
            })
        })
        .collect();
    let index = serde_json::json!({
        "index_created": "2012-03-01 18:00",
        "path": "https://collector.example",
        "directories": [{
            "path": "recent",
            "directories": [{
                "path": "relay-descriptors",
                "directories": [{"path": "server-descriptors", "files": entries}]
            }]
        }]
    });
    let mut compressed = Vec::new();
    lzma_rs::lzma_compress(
        &mut serde_json::to_vec(&index).unwrap().as_slice(),
        &mut compressed,
    )
    .unwrap();
    compressed
}

const SERVER_PATH: &str = "recent/relay-descriptors/server-descriptors/example";

async fn collector_with(
    descriptor: &[u8],
    advertised: &[u8],
) -> (CollecTor, FakeCollector) {
    let routes = HashMap::from([
        (
            "/index/index.json.xz".to_string(),
            index_for(&[(SERVER_PATH, advertised, "server-descriptor 1.0")]),
        ),
        (format!("/{SERVER_PATH}"), descriptor.to_vec()),
    ]);
    let server = serve(routes).await;
    let collector = CollecTor::with_url(&server.address).with_retries(0);
    (collector, server)
}

#[test]
fn parses_the_collector_index() {
    let json = br#"{
        "index_created": "2020-01-01 00:00",
        "directories": [
            {"path": "archive", "directories": [
                {"path": "relay-descriptors", "files": [
                    {"path": "server-descriptors-2019-02.tar.xz", "size": 10,
                     "last_modified": "2019-03-01 00:00",
                     "types": ["server-descriptor 1.0"], "sha256": "AAAA"},
                    {"path": "consensus-2018-06-30-10-00-00", "size": 10,
                     "last_modified": "2018-07-01 00:00",
                     "types": ["network-status-consensus-3 1.0"]}
                ]}
            ]},
            {"path": "recent", "files": [
                {"path": "bridge-pool.txt", "size": 1,
                 "last_modified": "2020-01-01 00:00", "types": [],
                 "first_published": "", "last_published": ""}
            ]}
        ]
    }"#;
    let files = parse_index(json).unwrap();
    assert_eq!(files.len(), 3);

    let monthly = files
        .iter()
        .find(|file| file.path.ends_with(".tar.xz"))
        .unwrap();
    assert_eq!(
        monthly.path,
        "archive/relay-descriptors/server-descriptors-2019-02.tar.xz"
    );
    assert_eq!(monthly.file_name(), "server-descriptors-2019-02.tar.xz");
    assert_eq!(monthly.compression, stem::descriptor::Compression::Lzma);
    assert_eq!(
        monthly.start,
        NaiveDate::from_ymd_opt(2019, 2, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
    );
    assert_eq!(
        monthly.end,
        NaiveDate::from_ymd_opt(2019, 3, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
    );

    let hourly = files
        .iter()
        .find(|file| file.path.contains("consensus-2018"))
        .unwrap();
    assert_eq!(
        hourly.start,
        NaiveDate::from_ymd_opt(2018, 6, 30)
            .unwrap()
            .and_hms_opt(10, 0, 0)
    );
    assert_eq!(
        hourly.end,
        NaiveDate::from_ymd_opt(2018, 6, 30)
            .unwrap()
            .and_hms_opt(11, 0, 0)
    );
    assert_eq!(hourly.compression, stem::descriptor::Compression::Plaintext);

    let undated = files
        .iter()
        .find(|file| file.path.ends_with("bridge-pool.txt"))
        .unwrap();
    assert_eq!((undated.start, undated.end), (None, None));
    assert_eq!(files.last().unwrap().path, "recent/bridge-pool.txt");
}

#[test]
fn rejects_unsafe_and_malformed_indexes() {
    for path in [
        "../escape",
        "a//b",
        "a/./b",
        "has space",
        "semi;colon",
        "back\\slash",
        "a/%2e%2e/b",
    ] {
        let entry =
            serde_json::json!({"path": path, "last_modified": "2020-01-01 00:00"});
        let json = serde_json::json!({"files": [entry]});
        assert!(
            parse_index(json.to_string().as_bytes()).is_err(),
            "{path:?} was accepted"
        );
    }
    assert!(parse_index(b"not json").is_err());
    assert!(parse_index(b"[]").is_err());
    let bad_time =
        serde_json::json!({"files": [{"path": "a", "last_modified": "yesterday"}]});
    assert!(parse_index(bad_time.to_string().as_bytes()).is_err());
    assert!(parse_index(b"{}").unwrap().is_empty());
}

#[tokio::test]
async fn downloads_and_verifies_descriptors() {
    let content = fixture("example_descriptor");
    let (collector, server) = collector_with(&content, &content).await;

    let files = collector
        .files(Some("server-descriptor"), None, None)
        .await
        .unwrap();
    assert_eq!(files.len(), 1);
    let request = CollectorRequest {
        retries: 0,
        ..CollectorRequest::default()
    };
    let descriptors = collector
        .get_server_descriptors(&request, false)
        .await
        .unwrap();
    assert_eq!(descriptors.len(), 1);
    let Descriptor::RelayServer(descriptor) = &descriptors[0] else {
        panic!("expected a relay descriptor")
    };
    assert_eq!(descriptor.nickname.as_deref(), Some("caerSidi"));

    let indexes = server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|path| path.starts_with("/index"))
        .count();
    assert_eq!(indexes, 1);
}

#[tokio::test]
async fn filters_files_by_time_range_and_type() {
    let content = fixture("example_descriptor");
    let (collector, _server) = collector_with(&content, &content).await;
    let day = |day| {
        NaiveDate::from_ymd_opt(2012, 3, day)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
    };

    assert_eq!(
        collector
            .files(None, Some(day(1)), Some(day(2)))
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        collector
            .files(None, Some(day(2)), None)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        collector
            .files(
                None,
                None,
                Some(
                    NaiveDate::from_ymd_opt(2012, 2, 1)
                        .unwrap()
                        .and_hms_opt(0, 0, 0)
                        .unwrap()
                )
            )
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        collector
            .files(Some("extra-info"), None, None)
            .await
            .unwrap()
            .is_empty()
    );

    let request = CollectorRequest {
        start: Some(day(1)),
        end: Some(
            NaiveDate::from_ymd_opt(2012, 3, 1)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap(),
        ),
        retries: 0,
        ..CollectorRequest::default()
    };
    assert!(
        collector
            .get_server_descriptors(&request, false)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn rejects_content_that_mismatches_the_checksum() {
    let content = fixture("example_descriptor");
    let mut tampered = content.clone();
    tampered[10] ^= 0x01;
    let (collector, _server) = collector_with(&tampered, &content).await;
    let request = CollectorRequest {
        retries: 0,
        ..CollectorRequest::default()
    };
    let failure = collector.get_server_descriptors(&request, false).await;
    assert!(matches!(failure, Err(Error::DownloadFailed { .. })));
}

#[tokio::test]
async fn caches_verified_downloads_on_disk() {
    let content = fixture("example_descriptor");
    let (collector, server) = collector_with(&content, &content).await;
    let directory = tempfile::tempdir().unwrap();
    let request = CollectorRequest {
        cache_to: Some(directory.path().join("nested/cache")),
        retries: 0,
        ..CollectorRequest::default()
    };
    collector
        .get_server_descriptors(&request, false)
        .await
        .unwrap();
    let cached = directory.path().join("nested/cache/example");
    assert_eq!(std::fs::read(&cached).unwrap(), content);
    let downloads = |server: &FakeCollector| {
        server
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.contains("example"))
            .count()
    };
    assert_eq!(downloads(&server), 1);

    collector
        .get_server_descriptors(&request, false)
        .await
        .unwrap();
    assert_eq!(downloads(&server), 1);

    std::fs::write(&cached, b"tampered").unwrap();
    assert!(
        collector
            .get_server_descriptors(&request, false)
            .await
            .is_err()
    );
    let files = collector.files(None, None, None).await.unwrap();
    let path = files[0]
        .download_to(
            collector.base_url(),
            cached.parent().unwrap(),
            None,
            0,
            true,
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), content);
}

#[tokio::test]
async fn refuses_non_regular_cache_entries() {
    let content = fixture("example_descriptor");
    let (collector, _server) = collector_with(&content, &content).await;
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("example")).unwrap();
    let request = CollectorRequest {
        cache_to: Some(directory.path().to_path_buf()),
        retries: 0,
        ..CollectorRequest::default()
    };
    assert!(
        collector
            .get_server_descriptors(&request, false)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejects_invalid_consensus_requests() {
    let collector = CollecTor::with_url("http://127.0.0.1:9");
    let request = CollectorRequest::default();
    assert!(
        collector
            .get_consensus(&request, 3, true, false)
            .await
            .is_err_and(|_| true)
    );
    assert!(matches!(
        collector.get_consensus(&request, 5, false, false).await,
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        collector.get_consensus(&request, 2, true, false).await,
        Err(Error::InvalidInput(_))
    ));
}

#[cfg(feature = "integration")]
#[tokio::test]
async fn reads_the_live_collector() {
    let collector = CollecTor::new()
        .with_retries(5)
        .with_timeout(std::time::Duration::from_secs(60));
    let files = collector.files(Some("tordnsel"), None, None).await.unwrap();
    assert!(!files.is_empty());
    let recent: Vec<_> = files
        .iter()
        .filter(|file| file.path.starts_with("recent/"))
        .collect();
    assert!(!recent.is_empty());
    let request = CollectorRequest {
        retries: 5,
        timeout: Some(std::time::Duration::from_secs(120)),
        validate: true,
        ..CollectorRequest::default()
    };
    let newest = recent[recent.len() - 2];
    let content = newest
        .read(collector.base_url(), Some("tordnsel 1.0"), &request)
        .await
        .unwrap();
    assert!(!content.is_empty());
    assert!(matches!(content[0], Descriptor::TorDnsel(_)));

    let certificates = collector
        .files(Some("dir-key-certificate-3"), None, None)
        .await
        .unwrap();
    assert!(!certificates.is_empty());
}
