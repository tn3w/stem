#![allow(dead_code)]

use serde_json::Value;

pub fn python_shape(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut shaped = serde_json::Map::new();
            for (key, child) in map {
                match key.as_str() {
                    "cert_type" => {
                        let name = child.as_str().unwrap_or_default();
                        shaped.insert("type".to_string(), screaming_snake(name).into());
                    }
                    _ => flatten_into(&mut shaped, key, python_shape(child)),
                }
            }
            Value::Object(shaped)
        }
        Value::Array(items) => {
            Value::Array(items.into_iter().map(python_shape).collect())
        }
        other => other,
    }
}

fn screaming_snake(camel: &str) -> String {
    let mut snake = String::new();
    for (index, character) in camel.chars().enumerate() {
        if character.is_uppercase() && index > 0 {
            snake.push('_');
        }
        snake.push(character.to_ascii_uppercase());
    }
    snake
}

const PYTHON_ONLY_KEYS: [&str; 1] = ["type_int"];

fn flatten_into(target: &mut serde_json::Map<String, Value>, key: String, value: Value) {
    let Value::Object(fields) = &value else {
        target.insert(key, value);
        return;
    };
    let has = |name: &str| fields.contains_key(name);
    if fields.len() == 3 && has("address") && has("port") && has("args") {
        let ordered = ["address", "port", "args"].map(|name| fields[name].clone());
        target.insert(key, Value::Array(ordered.to_vec()));
    } else if has("end") && has("interval") {
        let base = key.strip_suffix("_period").unwrap_or(&key).to_string();
        for (name, child) in fields.clone() {
            target.insert(format!("{base}_{name}"), child);
        }
    } else if fields.len() == 2 && has("value") && has("attributes") {
        target.insert(format!("{key}_attr"), fields["attributes"].clone());
        target.insert(key, fields["value"].clone());
    } else if fields.len() == 2 && has("recognized") && has("unknown") {
        target.insert(format!("{key}_unknown"), fields["unknown"].clone());
        target.insert(key, fields["recognized"].clone());
    } else {
        target.insert(key, value);
    }
}

fn comparable_text(text: &str) -> String {
    let bytes = text.as_bytes();
    let is_timestamp = text.len() >= 19
        && matches!(bytes.get(10), Some(b'T' | b' '))
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-';
    if !is_timestamp {
        return text.to_string();
    }
    let normalized = text.replacen('T', " ", 1);
    match normalized.len() {
        19 => format!("{normalized}.000000"),
        _ => normalized,
    }
}

fn is_blank(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

pub fn compare(path: &str, python: &Value, rust: &Value, issues: &mut Vec<String>) {
    match (python, rust) {
        (Value::Null, Value::Null) => {}
        (Value::Object(py_map), Value::Object(rust_map)) => {
            for (key, py_value) in py_map {
                if key == "__class__" || PYTHON_ONLY_KEYS.contains(&key.as_str()) {
                    continue;
                }
                let child = format!("{path}.{key}");
                match rust_map.get(key) {
                    Some(rust_value) => compare(&child, py_value, rust_value, issues),
                    None if is_blank(py_value) => {}
                    None => issues
                        .push(format!("{child}: missing in rust (python {py_value})")),
                }
            }
        }
        (Value::Array(py_items), Value::Array(rust_items)) => {
            if py_items.len() != rust_items.len() {
                issues.push(format!(
                    "{path}: length python {} rust {}",
                    py_items.len(),
                    rust_items.len()
                ));
                return;
            }
            for (index, (py_value, rust_value)) in
                py_items.iter().zip(rust_items).enumerate()
            {
                compare(&format!("{path}[{index}]"), py_value, rust_value, issues);
            }
        }
        (Value::String(py_text), Value::String(rust_text)) => {
            if comparable_text(py_text) != comparable_text(rust_text) {
                issues.push(format!("{path}: python {py_text:?} rust {rust_text:?}"));
            }
        }
        (Value::Number(py_number), Value::Number(rust_number)) => {
            let close = match (py_number.as_f64(), rust_number.as_f64()) {
                (Some(left), Some(right)) => {
                    (left - right).abs() <= 1e-9 * left.abs().max(1.0)
                }
                _ => false,
            };
            if !close {
                issues.push(format!("{path}: python {py_number} rust {rust_number}"));
            }
        }
        (py_value, rust_value) if is_blank(py_value) && is_blank(rust_value) => {}
        (py_value, rust_value) if py_value == rust_value => {}
        (py_value, rust_value) => {
            issues.push(format!("{path}: python {py_value} rust {rust_value}"));
        }
    }
}

pub fn differences(
    path: &str,
    python: &Value,
    descriptor: &impl serde::Serialize,
) -> Vec<String> {
    let mut issues = Vec::new();
    match serde_json::to_value(descriptor) {
        Ok(value) => compare(path, python, &python_shape(value), &mut issues),
        Err(error) => issues.push(format!("{path}: serialization failed: {error}")),
    }
    issues
}

pub fn value_differences(path: &str, python: &Value, rust: Value) -> Vec<String> {
    let mut issues = Vec::new();
    compare(path, python, &python_shape(rust), &mut issues);
    issues
}
