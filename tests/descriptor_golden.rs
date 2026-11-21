use std::collections::BTreeMap;
use std::path::PathBuf;

mod python_comparison;

use serde_json::Value;
use stem::descriptor::{DocumentHandler, parse_path};

fn data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/descriptor")
        .join(name)
}

fn golden() -> Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/descriptors.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn parsed_descriptors_match_python_stem() {
    let golden = golden();
    let mut report: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, case) in golden.as_object().unwrap() {
        let validate = case["validate"].as_bool();
        let handler = match case["handler"].as_str() {
            Some("document") => DocumentHandler::Document,
            _ => DocumentHandler::Entries,
        };
        let descriptor_type = case["descriptor_type"].as_str();
        let outcome = parse_path(
            &data_path(name),
            descriptor_type,
            validate.unwrap_or(false),
            handler,
        );
        let mut issues = Vec::new();
        match (case["error"].is_null(), outcome) {
            (true, Err(error)) => issues.push(format!("rust failed: {error}")),
            (true, Ok(parsed)) => {
                let expected = case["descriptors"].as_array().unwrap();
                let total = case["total"].as_u64().unwrap() as usize;
                if parsed.len() != total {
                    issues.push(format!("count python {total} rust {}", parsed.len()));
                }
                for (index, (py_value, file)) in expected.iter().zip(parsed).enumerate() {
                    issues.extend(python_comparison::differences(
                        &format!("[{index}]"),
                        py_value,
                        &file.descriptor,
                    ));
                }
            }
            (false, _) => {}
        }
        if !issues.is_empty() {
            report.insert(name.clone(), issues);
        }
    }
    for (name, issues) in &report {
        println!("== {name} ({})", issues.len());
        for issue in issues.iter().take(12) {
            println!("   {issue}");
        }
    }
    assert!(report.is_empty(), "{} cases differ", report.len());
}
