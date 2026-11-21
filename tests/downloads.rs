#![cfg(feature = "integration")]

use std::time::Duration;

use stem::address::OrPort;
use stem::descriptor::Descriptor;
use stem::descriptor::network_status::NetworkStatusDocumentV3;
use stem::descriptor::parsing::DocumentHandler;
use stem::descriptor::remote::{DescriptorDownloader, Query, RemoteEndpoint};
use stem::directory::{Authority, Fallback};

fn directory_endpoints(count: usize) -> Vec<RemoteEndpoint> {
    Fallback::from_cache(None)
        .unwrap()
        .values()
        .filter_map(|fallback| {
            RemoteEndpoint::dir(&fallback.address, fallback.dir_port?).ok()
        })
        .take(count)
        .collect()
}

fn relay_endpoints(count: usize) -> Vec<RemoteEndpoint> {
    Fallback::from_cache(None)
        .unwrap()
        .values()
        .filter(|fallback| fallback.address.parse::<std::net::Ipv4Addr>().is_ok())
        .filter_map(|fallback| {
            OrPort::new(&fallback.address, fallback.or_port, None)
                .ok()
                .map(RemoteEndpoint::Or)
        })
        .take(count)
        .collect()
}

fn consensus_documents(descriptors: Vec<Descriptor>) -> Vec<NetworkStatusDocumentV3> {
    descriptors
        .into_iter()
        .filter_map(|descriptor| match descriptor {
            Descriptor::NetworkStatusV3(document) => Some(*document),
            _ => None,
        })
        .collect()
}

fn patient(query: Query) -> Query {
    query.with_retries(8).with_timeout(Duration::from_secs(60))
}

#[tokio::test]
async fn downloads_a_consensus_over_http_directory_ports() {
    let downloader = DescriptorDownloader::new();
    let query = patient(
        downloader
            .get_consensus(None, true)
            .with_endpoints(directory_endpoints(60))
            .with_document_handler(DocumentHandler::Document),
    );
    let documents = consensus_documents(query.run().await.unwrap());
    assert_eq!(documents.len(), 1);
    let document = &documents[0];
    assert!(document.routers.len() > 1000);
    assert!(document.is_valid() || document.valid_until.is_some());
    assert_eq!(document.version, Some(3));
    assert!(document.is_microdescriptor);
    assert!(document.signatures.len() >= 5);
}

#[tokio::test]
async fn downloads_a_consensus_over_or_ports() {
    let downloader = DescriptorDownloader::new();
    let query = patient(
        downloader
            .get_consensus(None, true)
            .with_endpoints(relay_endpoints(40))
            .with_document_handler(DocumentHandler::Document),
    );
    let documents = consensus_documents(query.run().await.unwrap());
    assert_eq!(documents.len(), 1);
    assert!(documents[0].routers.len() > 1000);
}

#[tokio::test]
async fn validates_consensus_signatures_against_authority_certificates() {
    let mut downloader = DescriptorDownloader::new();
    downloader.set_endpoints(directory_endpoints(60));
    downloader.default_timeout = Some(Duration::from_secs(60));
    let validated = downloader
        .get_consensus_validated(None, false)
        .await
        .unwrap();
    let documents = consensus_documents(validated);
    assert_eq!(documents.len(), 1);
    assert!(documents[0].routers.len() > 1000);

    let known: Vec<String> = Authority::from_cache()
        .unwrap()
        .values()
        .filter_map(|authority| authority.v3ident.clone())
        .collect();
    let signers: Vec<&String> = documents[0]
        .signatures
        .iter()
        .map(|signature| &signature.identity)
        .collect();
    assert!(
        signers
            .iter()
            .filter(|signer| known.contains(signer))
            .count()
            >= 5
    );
}

#[tokio::test]
async fn downloads_and_verifies_server_and_extrainfo_descriptors() {
    let downloader = DescriptorDownloader::new();
    let consensus = patient(
        downloader
            .get_consensus(None, true)
            .with_endpoints(directory_endpoints(60))
            .with_document_handler(DocumentHandler::Document),
    );
    let documents = consensus_documents(consensus.run().await.unwrap());
    let fingerprints: Vec<String> = documents[0]
        .routers
        .values()
        .filter(|entry| {
            entry
                .common()
                .flags
                .iter()
                .any(|flag| flag == "Running" || flag == "Valid")
        })
        .filter_map(|entry| entry.common().fingerprint.clone())
        .take(5)
        .collect();
    let references: Vec<&str> = fingerprints.iter().map(String::as_str).collect();

    let servers = patient(
        downloader
            .get_server_descriptors(&references)
            .unwrap()
            .with_endpoints(directory_endpoints(60))
            .with_validation(true),
    )
    .run()
    .await
    .unwrap();
    assert!(!servers.is_empty());
    for descriptor in &servers {
        let Descriptor::RelayServer(server) = descriptor else {
            panic!("expected relay server descriptors");
        };
        assert!(fingerprints.contains(server.fingerprint.as_ref().unwrap()));
        assert!(server.signature.is_some());
    }

    let extrainfo = patient(
        downloader
            .get_extrainfo_descriptors(&references)
            .unwrap()
            .with_endpoints(directory_endpoints(60))
            .with_validation(true),
    )
    .run()
    .await
    .unwrap();
    assert!(!extrainfo.is_empty());
}

#[tokio::test]
async fn reports_failures_for_unreachable_and_invalid_requests() {
    let downloader = DescriptorDownloader::new();
    assert!(downloader.get_server_descriptors(&["nope"]).is_err());
    assert!(downloader.get_microdescriptors(&["!!"]).is_err());
    assert!(downloader.query("not/a/resource").is_err());

    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let query = downloader
        .get_consensus(None, false)
        .with_endpoints(vec![RemoteEndpoint::dir("127.0.0.1", closed).unwrap()])
        .with_retries(1)
        .with_timeout(Duration::from_secs(5));
    assert!(query.run().await.is_err());
}
