use std::path::PathBuf;

use serde_json::{Value, json};
use stem::directory::{Authority, Directory, Fallback};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn golden() -> Value {
    serde_json::from_slice(
        &std::fs::read(root().join("tests/golden/directories.json")).unwrap(),
    )
    .unwrap()
}

fn directory_json(directory: &Directory) -> serde_json::Map<String, Value> {
    let Value::Object(map) = json!({
        "address": directory.address,
        "or_port": directory.or_port,
        "dir_port": directory.dir_port,
        "fingerprint": directory.fingerprint,
        "nickname": directory.nickname,
        "orport_v6": directory
            .orport_v6
            .as_ref()
            .map(|(address, port)| json!([address, port])),
    }) else {
        unreachable!()
    };
    map
}

fn authority_json(authority: &Authority) -> Value {
    let mut map = directory_json(authority);
    map.insert("v3ident".into(), json!(authority.v3ident));
    map.insert(
        "is_bandwidth_authority".into(),
        json!(authority.is_bandwidth_authority),
    );
    Value::Object(map)
}

fn fallback_json(fallback: &Fallback) -> Value {
    let mut map = directory_json(fallback);
    map.insert("has_extrainfo".into(), json!(fallback.has_extrainfo));
    map.insert("header".into(), json!(fallback.header));
    Value::Object(map)
}

fn assert_same(kind: &str, expected: &Value, actual: Value) {
    let expected = expected.as_object().unwrap();
    let actual = actual.as_object().unwrap();
    assert_eq!(expected.len(), actual.len(), "{kind} count");
    for (name, entry) in expected {
        assert_eq!(entry, &actual[name], "{kind} {name}");
    }
}

#[test]
fn parses_authorities_like_python_stem() {
    let content = std::fs::read_to_string(root().join("src/data/auth_dirs.inc")).unwrap();
    let parsed = Authority::parse_inc(&content).unwrap();
    let actual: serde_json::Map<String, Value> = parsed
        .iter()
        .map(|(name, authority)| (name.clone(), authority_json(authority)))
        .collect();
    assert_same(
        "authorities",
        &golden()["authorities"],
        Value::Object(actual),
    );
    assert_eq!(Authority::from_cache().unwrap(), parsed);
}

#[test]
fn parses_fallbacks_like_python_stem() {
    let content =
        std::fs::read_to_string(root().join("src/data/fallback_dirs.inc")).unwrap();
    let parsed = Fallback::parse_inc(&content).unwrap();
    let actual: serde_json::Map<String, Value> = parsed
        .iter()
        .map(|(name, fallback)| (name.clone(), fallback_json(fallback)))
        .collect();
    assert_same("fallbacks", &golden()["fallbacks"], Value::Object(actual));
    assert_eq!(Fallback::from_cache(None).unwrap(), parsed);
}

#[test]
fn loads_cached_fallbacks_like_python_stem() {
    let path = root().join("tests/data/cached_fallbacks.cfg");
    let parsed = Fallback::from_cache(Some(&path)).unwrap();
    let actual: serde_json::Map<String, Value> = parsed
        .iter()
        .map(|(name, fallback)| (name.clone(), fallback_json(fallback)))
        .collect();
    assert_same(
        "cached fallbacks",
        &golden()["cached_fallbacks"],
        Value::Object(actual),
    );
}

#[test]
fn round_trips_the_fallback_cache() {
    let content =
        std::fs::read_to_string(root().join("src/data/fallback_dirs.inc")).unwrap();
    let parsed = Fallback::parse_inc(&content).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fallbacks.cfg");
    let headers = parsed.values().next().unwrap().header.clone();
    Fallback::write_cache(&parsed, "tor-commit", "stem-commit", &headers, &path).unwrap();
    let reloaded = Fallback::from_cache(Some(&path)).unwrap();
    assert_eq!(reloaded.len(), parsed.len());
    for (fingerprint, fallback) in &parsed {
        assert_eq!(&reloaded[fingerprint].directory, &fallback.directory);
    }
}

#[test]
fn rejects_malformed_directory_data() {
    assert!(
        Directory::new("not an address", 443, None, &"A".repeat(40), None, None).is_err()
    );
    assert!(Directory::new("1.2.3.4", 0, None, &"A".repeat(40), None, None).is_err());
    assert!(
        Directory::new("1.2.3.4", 443, Some(0), &"A".repeat(40), None, None).is_err()
    );
    assert!(Directory::new("1.2.3.4", 443, None, "short", None, None).is_err());
    assert!(
        Directory::new(
            "1.2.3.4",
            443,
            None,
            &"A".repeat(40),
            Some("bad nick!"),
            None
        )
        .is_err()
    );
    assert!(Authority::parse_inc("not an authority list").is_err());
    assert!(Fallback::parse_inc("/* type=fallback */\ngarbage\n").is_err());
    assert!(
        Directory::new("1.2.3.4", 443, Some(80), &"A".repeat(40), Some("ok"), None)
            .is_ok()
    );
}
