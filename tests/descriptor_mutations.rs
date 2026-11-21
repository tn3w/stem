use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::Value;
use stem::descriptor::{DocumentHandler, parse_bytes};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn mutate(lines: &[String], operation: &str, index: usize) -> Option<Vec<String>> {
    let mut lines = lines.to_vec();
    match operation {
        "delete" => {
            lines.remove(index);
        }
        "duplicate" => lines.insert(index, lines[index].clone()),
        "append_junk" => lines[index].push_str(" junk"),
        "keyword_only" => {
            lines[index] = lines[index]
                .split(' ')
                .next()
                .unwrap_or_default()
                .to_string()
        }
        "blank" => lines[index] = String::new(),
        "swap_with_next" => {
            if index + 1 >= lines.len() {
                return None;
            }
            lines.swap(index, index + 1);
        }
        other => panic!("unknown operation {other}"),
    }
    Some(lines)
}

#[test]
fn mutated_descriptors_are_accepted_like_python_stem() {
    let cases: Vec<Value> = serde_json::from_slice(
        &std::fs::read(root().join("golden/mutations.json")).unwrap(),
    )
    .unwrap();
    let mut originals: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut disagreements: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for case in &cases {
        let name = case["file"].as_str().unwrap();
        let lines = originals.entry(name.to_string()).or_insert_with(|| {
            let content =
                std::fs::read(root().join("data/descriptor").join(name)).unwrap();
            String::from_utf8(content)
                .unwrap()
                .split('\n')
                .map(str::to_string)
                .collect()
        });
        let operation = case["operation"].as_str().unwrap();
        let index = case["index"].as_u64().unwrap() as usize;
        let content = mutate(lines, operation, index).unwrap().join("\n");
        let handler = match case["handler"].as_str() {
            Some("document") => DocumentHandler::Document,
            _ => DocumentHandler::Entries,
        };
        let outcome = parse_bytes(
            content.as_bytes(),
            case["type"].as_str(),
            true,
            handler,
            None,
        );
        let python_accepted = case["accepted"].as_bool().unwrap();
        let lenient_timestamp = python_accepted
            && operation == "append_junk"
            && outcome
                .as_ref()
                .err()
                .is_some_and(|error| error.to_string().contains("parsable"));
        if lenient_timestamp {
            continue;
        }
        if outcome.is_ok() != python_accepted {
            let detail = match &outcome {
                Ok(_) => "rust accepted".to_string(),
                Err(error) => format!("rust rejected: {error}"),
            };
            disagreements
                .entry(name.to_string())
                .or_default()
                .push(format!(
                    "{operation}[{index}] python {} {detail} :: {:?}",
                    if python_accepted {
                        "accepted"
                    } else {
                        "rejected"
                    },
                    lines[index].chars().take(60).collect::<String>()
                ));
        }
    }
    for (name, entries) in &disagreements {
        println!("== {name} ({})", entries.len());
        for entry in entries.iter().take(40) {
            println!("   {entry}");
        }
    }
    assert!(
        disagreements.is_empty(),
        "{} files have disagreements",
        disagreements.len()
    );
}
