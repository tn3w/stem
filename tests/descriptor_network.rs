mod python_comparison;

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use serde_json::Value;
use stem::descriptor::network_status::RouterEntry;
use stem::descriptor::remote::{DescriptorDownloader, Query, RemoteEndpoint};
use stem::descriptor::{Descriptor, DocumentHandler, parse_bytes};
use stem::directory::Fallback;

const SAMPLE_SIZE: usize = 1500;

fn python_stem_path() -> Option<String> {
    std::env::var("STEM_PYTHON_PATH").ok()
}

fn endpoints() -> Vec<RemoteEndpoint> {
    Fallback::from_cache(None)
        .unwrap()
        .values()
        .filter_map(|fallback| {
            RemoteEndpoint::dir(&fallback.address, fallback.dir_port?).ok()
        })
        .take(60)
        .collect()
}

async fn fetch(query: Query) -> Vec<u8> {
    query
        .with_endpoints(endpoints())
        .with_retries(8)
        .with_timeout(Duration::from_secs(120))
        .download()
        .await
        .unwrap()
        .content
}

fn python_dump(stem_path: &str, content: &[u8], descriptor_type: &str) -> Vec<Value> {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("sample");
    std::fs::write(&file, content).unwrap();
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/generate.py");
    let output = Command::new("python3")
        .arg("-W")
        .arg("ignore")
        .arg(script)
        .arg(&file)
        .arg(SAMPLE_SIZE.to_string())
        .arg(descriptor_type)
        .env("PYTHONPATH", stem_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "python failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn compare_with_python(stem_path: &str, content: &[u8], descriptor_type: &str) {
    let rust = parse_bytes(
        content,
        Some(descriptor_type),
        true,
        DocumentHandler::Entries,
        None,
    )
    .unwrap();
    let python = python_dump(stem_path, content, descriptor_type);
    assert!(python.len() >= SAMPLE_SIZE.min(rust.len()));
    let mut issues = Vec::new();
    for (index, (expected, descriptor)) in python.iter().zip(&rust).enumerate() {
        issues.extend(python_comparison::differences(
            &format!("[{index}]"),
            expected,
            descriptor,
        ));
    }
    for issue in issues.iter().take(30) {
        println!("{issue}");
    }
    assert!(
        issues.is_empty(),
        "{} differences in {descriptor_type}",
        issues.len()
    );
}

#[tokio::test]
async fn live_server_descriptors_match_python_stem() {
    let Some(stem_path) = python_stem_path() else {
        println!("skipped: set STEM_PYTHON_PATH to a python stem checkout");
        return;
    };
    let downloader = DescriptorDownloader::new();
    let content = fetch(downloader.get_server_descriptors(&[]).unwrap()).await;
    compare_with_python(&stem_path, &content, "server-descriptor 1.0");
}

#[tokio::test]
async fn live_extrainfo_descriptors_match_python_stem() {
    let Some(stem_path) = python_stem_path() else {
        println!("skipped: set STEM_PYTHON_PATH to a python stem checkout");
        return;
    };
    let downloader = DescriptorDownloader::new();
    let content = fetch(downloader.get_extrainfo_descriptors(&[]).unwrap()).await;
    compare_with_python(&stem_path, &content, "extra-info 1.0");
}

#[tokio::test]
async fn live_microdescriptors_match_python_stem() {
    let Some(stem_path) = python_stem_path() else {
        println!("skipped: set STEM_PYTHON_PATH to a python stem checkout");
        return;
    };
    let downloader = DescriptorDownloader::new();
    let consensus = fetch(downloader.get_consensus(None, true)).await;
    let descriptors = parse_bytes(
        &consensus,
        Some("network-status-microdesc-consensus-3 1.0"),
        true,
        DocumentHandler::Entries,
        None,
    )
    .unwrap();
    let hashes: Vec<String> = descriptors
        .iter()
        .filter_map(|descriptor| match descriptor {
            Descriptor::RouterEntry(entry) => match &**entry {
                RouterEntry::Micro(micro) => micro.microdescriptor_digest.clone(),
                RouterEntry::Full(_) => None,
            },
            _ => None,
        })
        .take(80)
        .collect();
    let references: Vec<&str> = hashes.iter().map(String::as_str).collect();
    let content = fetch(downloader.get_microdescriptors(&references).unwrap()).await;
    compare_with_python(&stem_path, &content, "microdescriptor 1.0");
}

#[tokio::test]
async fn live_consensus_matches_python_stem() {
    let Some(stem_path) = python_stem_path() else {
        println!("skipped: set STEM_PYTHON_PATH to a python stem checkout");
        return;
    };
    let downloader = DescriptorDownloader::new();
    let content = fetch(downloader.get_consensus(None, false)).await;
    let rust = parse_bytes(
        &content,
        Some("network-status-consensus-3 1.0"),
        true,
        DocumentHandler::Document,
        None,
    )
    .unwrap();
    let python = python_dump(&stem_path, &content, "network-status-consensus-3 1.0");
    let issues = python_comparison::differences("[0]", &python[0], &rust[0]);
    for issue in issues.iter().take(30) {
        println!("{issue}");
    }
    assert!(issues.is_empty(), "{} differences", issues.len());
}
