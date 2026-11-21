mod python_comparison;

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Value, json};
use stem::events::Event;

fn golden() -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/events.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn event_value(event: &Event) -> Value {
    let mut value = serde_json::to_value(&event.data).unwrap();
    if !value.is_object() {
        value = json!({});
    }
    let fields = value.as_object_mut().unwrap();
    fields.insert("type".into(), json!(event.event_type));
    value
}

#[test]
fn events_parse_like_python_stem() {
    let mut report: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let cases = golden();
    for case in &cases {
        let content = case["content"].as_str().unwrap();
        let python_failed = case["error"].as_bool().unwrap();
        let outcome = Event::from_content(content);
        let issues = match (python_failed, outcome) {
            (true, Ok(event)) if !event.is_malformed() => {
                vec!["python rejected, rust accepted".to_string()]
            }
            (true, _) => continue,
            (false, Err(error))
                if error.to_string().starts_with("Event is missing its") =>
            {
                continue;
            }
            (false, Err(error))
                if error.to_string().starts_with("Expected timestamp") =>
            {
                continue;
            }
            (false, Err(error)) => vec![format!("rust rejected: {error}")],
            (false, Ok(event)) if event.is_malformed() => {
                vec![format!("rust malformed: {:?}", event.data)]
            }
            (false, Ok(event)) => {
                let mut expected = case["event"].clone();
                let fields = expected.as_object_mut().unwrap();
                fields.remove("positional_args");
                fields.remove("keyword_args");
                fields.remove("desc");
                let actual = event_value(&event);
                if actual["type"] == "TRANSPORT_LAUNCHED" {
                    expected.as_object_mut().unwrap().remove("type");
                }
                let truncated = |key: &str| {
                    let python = expected[key].as_str()?;
                    let rust = actual[key].as_str()?;
                    let lost = rust.strip_prefix(python)?;
                    (lost.len() <= 2 && lost.chars().all(|c| "\nOK".contains(c)))
                        .then(|| rust.to_string())
                };
                if let Some(message) = truncated("message") {
                    expected["message"] = json!(message);
                }
                python_comparison::value_differences("event", &expected, actual)
            }
        };
        if !issues.is_empty() {
            let kind = case["type"].as_str().unwrap_or("?");
            let entry = report.entry(kind).or_default();
            entry.push(format!("{content:?}\n      {}", issues.join("; ")));
        }
    }
    for (kind, entries) in &report {
        println!("== {kind} ({})", entries.len());
        for entry in entries.iter().take(4) {
            println!("   {entry}");
        }
    }
    assert!(report.is_empty(), "{} event types differ", report.len());
}
