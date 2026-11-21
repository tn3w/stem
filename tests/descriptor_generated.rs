use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;
use stem::descriptor::bandwidth_file::BandwidthFile;
use stem::descriptor::extrainfo::{BridgeExtraInfoDescriptor, RelayExtraInfoDescriptor};
use stem::descriptor::hidden_service::{
    HiddenServiceDescriptorV3, HiddenServiceV3Options,
};
use stem::descriptor::microdescriptor::Microdescriptor;
use stem::descriptor::network_status::{
    KeyCertificate, NetworkStatusDocumentV2, NetworkStatusDocumentV3,
};
use stem::descriptor::server::{RelayServerDescriptor, create_signing_key};
use stem::descriptor::{DocumentHandler, parse_bytes};

struct Generated {
    name: &'static str,
    descriptor_type: &'static str,
    handler: &'static str,
    content: Vec<u8>,
}

fn generated() -> Vec<Generated> {
    let key = create_signing_key().unwrap();
    let none = Vec::new();
    let v3_options = HiddenServiceV3Options::default();
    let bandwidth_header = vec![(
        "version".to_string(),
        stem::descriptor::AttrValue::Text("1.2.0".to_string()),
    )];
    vec![
        Generated {
            name: "relay server",
            descriptor_type: "server-descriptor 1.0",
            handler: "entries",
            content: RelayServerDescriptor::content(&none, &[], Some(&key), None)
                .unwrap(),
        },
        Generated {
            name: "relay extrainfo",
            descriptor_type: "extra-info 1.0",
            handler: "entries",
            content: RelayExtraInfoDescriptor::content(&none, &[], Some(&key)).unwrap(),
        },
        Generated {
            name: "bridge extrainfo",
            descriptor_type: "bridge-extra-info 1.0",
            handler: "entries",
            content: BridgeExtraInfoDescriptor::content(&none, &[]),
        },
        Generated {
            name: "microdescriptor",
            descriptor_type: "microdescriptor 1.0",
            handler: "entries",
            content: Microdescriptor::content(&none, &[]),
        },
        Generated {
            name: "key certificate",
            descriptor_type: "dir-key-certificate-3 1.0",
            handler: "entries",
            content: KeyCertificate::content(&none, &[]),
        },
        Generated {
            name: "consensus",
            descriptor_type: "network-status-consensus-3 1.0",
            handler: "document",
            content: NetworkStatusDocumentV3::content(&none, &[], None, &[]),
        },
        Generated {
            name: "v2 status",
            descriptor_type: "network-status-2 1.0",
            handler: "document",
            content: NetworkStatusDocumentV2::content(&none, &[]),
        },
        Generated {
            name: "hidden service v3",
            descriptor_type: "hidden-service-descriptor-3 1.0",
            handler: "entries",
            content: HiddenServiceDescriptorV3::content(&none, &[], v3_options).unwrap(),
        },
        Generated {
            name: "bandwidth file",
            descriptor_type: "bandwidth-file 1.2",
            handler: "entries",
            content: BandwidthFile::content(&bandwidth_header, &[], &[]).unwrap(),
        },
    ]
}

fn mutations(content: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(content).into_owned();
    let lines: Vec<&str> = text.split('\n').collect();
    let mut variants = Vec::new();
    for index in 0..lines.len() {
        let mut deleted = lines.clone();
        deleted.remove(index);
        variants.push(deleted.join("\n").into_bytes());
        let mut duplicated = lines.clone();
        duplicated.insert(index, lines[index]);
        variants.push(duplicated.join("\n").into_bytes());
    }
    variants
}

fn rust_accepts(case: &Generated, content: &[u8]) -> bool {
    let handler = match case.handler {
        "document" => DocumentHandler::Document,
        _ => DocumentHandler::Entries,
    };
    parse_bytes(content, Some(case.descriptor_type), true, handler, None).is_ok()
}

fn python_accepts(stem_path: &str, requests: &[serde_json::Value]) -> Vec<Option<bool>> {
    let script = format!("{}/tests/golden/accepts.py", env!("CARGO_MANIFEST_DIR"));
    let mut child = Command::new("python3")
        .args(["-W", "ignore", &script])
        .env("PYTHONPATH", stem_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(requests).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn generated_descriptors_are_valid_for_rust() {
    for case in generated() {
        assert!(
            rust_accepts(&case, &case.content),
            "{} was rejected",
            case.name
        );
    }
}

#[test]
fn generated_descriptors_are_accepted_like_python_stem() {
    let Ok(stem_path) = std::env::var("STEM_PYTHON_PATH") else {
        println!("skipped: set STEM_PYTHON_PATH to a python stem checkout");
        return;
    };
    let mut disagreements = Vec::new();
    for case in generated() {
        let mut variants = vec![case.content.clone()];
        variants.extend(mutations(&case.content));
        let requests: Vec<serde_json::Value> = variants
            .iter()
            .map(|content| {
                json!({
                    "type": case.descriptor_type,
                    "handler": case.handler,
                    "hex": hex::encode(content),
                })
            })
            .collect();
        let python = python_accepts(&stem_path, &requests);
        assert_eq!(
            python[0],
            Some(true),
            "python rejected the generated {}",
            case.name
        );
        for (index, (content, python_accepted)) in variants.iter().zip(python).enumerate()
        {
            let Some(python_accepted) = python_accepted else {
                continue;
            };
            if rust_accepts(&case, content) != python_accepted {
                disagreements.push(format!(
                    "{} variant {index}: python {python_accepted}\n{}",
                    case.name,
                    String::from_utf8_lossy(content)
                        .chars()
                        .take(300)
                        .collect::<String>()
                ));
            }
        }
    }
    for disagreement in disagreements.iter().take(10) {
        println!("{disagreement}");
    }
    assert!(
        disagreements.is_empty(),
        "{} disagreements",
        disagreements.len()
    );
}
