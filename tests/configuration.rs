use stem::Error;
use stem::configuration::{Config, parse_enum, parse_enum_csv};

const INSECTS: [&str; 3] = ["BUTTERFLY", "LADYBUG", "CRICKET"];

#[test]
fn reads_typed_values() {
    let mut config = Config::new();
    config.set("bool_value", "true", true);
    config.set("int_value", "11", true);
    config.set("float_value", "11.1", true);
    config.set("str_value", "world", true);
    for value in ["a", "b", "c"] {
        config.set("list_value", value, false);
    }
    config.set("map_value", "foo => bar", true);

    assert!(config.get_bool("bool_value", false));
    assert!(config.get_bool("missing", true));
    assert!(!config.get_bool("int_value", false));
    assert_eq!(config.get_integer("int_value", 0), 11);
    assert_eq!(config.get_integer("str_value", 5), 5);
    assert_eq!(config.get_float("float_value", 0.0), 11.1);
    assert_eq!(config.get_value("str_value"), Some("world"));
    assert_eq!(config.get_value("list_value"), Some("c"));
    assert_eq!(config.get_values("list_value"), vec!["a", "b", "c"]);
    assert_eq!(config.get_value("foo"), None);
    assert!(config.get_values("foo").is_empty());
    assert_eq!(config.get_mapping("map_value")["foo"], "bar");
}

#[test]
fn tracks_unused_keys() {
    let mut config = Config::new();
    config.set("hello", "world", true);
    config.set("foo", "bar", true);
    config.set("pw", "12345", true);
    config.get_value("hello");
    config.get_values("foo");
    assert_eq!(config.unused_keys(), ["pw".to_string()].into());
    config.get_value("pw");
    assert!(config.unused_keys().is_empty());
}

#[test]
fn clears_and_removes_entries() {
    let mut config = Config::new();
    assert!(config.keys().is_empty());
    config.clear();
    config.set("hello", "world", true);
    assert_eq!(config.keys(), vec!["hello"]);
    config.set("hello", "again", true);
    assert_eq!(config.get_values("hello"), vec!["again"]);
    config.set_values("list", vec!["a".into(), "b".into()], false);
    config.set_values("list", vec!["c".into()], false);
    assert_eq!(config.get_values("list"), vec!["a", "b", "c"]);
    config.remove("list");
    assert_eq!(config.keys(), vec!["hello"]);
    config.clear();
    assert!(config.keys().is_empty());
}

#[test]
fn parses_configuration_text() {
    let mut config = Config::new();
    config.load_str(
        "# comment\nsimple value\nspaced key some  value \nempty_multiline\n|first\n|  \
        second\n\nafter x # trailing\n",
        true,
    );
    assert_eq!(config.get_value("simple"), Some("value"));
    assert_eq!(config.get_value("spaced"), Some("key some  value"));
    assert_eq!(config.get_value("empty_multiline"), Some("first\n  second"));
    assert_eq!(config.get_value("after"), Some("x"));

    let mut verbatim = Config::new();
    verbatim.load_str("key value # not a comment\n", false);
    assert_eq!(verbatim.get_value("key"), Some("value # not a comment"));
}

#[test]
fn saves_and_loads_files_and_directories() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = Config::new();
    config.set("single", "value", true);
    config.set("multi", "line one\nline two", true);
    config.set("list", "a", false);
    config.set("list", "b", false);
    let path = directory.path().join("nested/config.cfg");
    config.save(&path).unwrap();

    let mut loaded = Config::new();
    loaded.load(&path).unwrap();
    assert_eq!(loaded.get_value("single"), Some("value"));
    assert_eq!(loaded.get_value("multi"), Some("line one\nline two"));
    assert_eq!(loaded.get_values("list"), vec!["a", "b"]);

    let folder = directory.path().join("folder");
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(folder.join("b.cfg"), "key second\n").unwrap();
    std::fs::write(folder.join("a.cfg"), "key first\n").unwrap();
    std::fs::write(folder.join(".a.cfg.swp"), "key swap\n").unwrap();
    let mut merged = Config::new();
    merged.load(&folder).unwrap();
    assert_eq!(merged.get_values("key"), vec!["first", "second"]);

    assert!(matches!(
        Config::new().load(directory.path().join("missing")),
        Err(Error::Io(_))
    ));
}

#[test]
fn parses_single_enumerations() {
    assert_eq!(
        parse_enum("my_option", "ladybug", &INSECTS).unwrap(),
        "LADYBUG"
    );
    assert!(parse_enum("my_option", "ugabuga", &INSECTS).is_err());
    assert!(parse_enum("my_option", "ladybug, cricket", &INSECTS).is_err());
    assert!(parse_enum("my_option", "", &INSECTS).is_err());
}

#[test]
fn parses_enumeration_lists() {
    for spelling in ["ladybug", "Ladybug", "LaDyBuG", "LADYBUG"] {
        assert_eq!(
            parse_enum_csv("my_option", spelling, &INSECTS, None).unwrap(),
            vec!["LADYBUG"]
        );
    }
    assert!(
        parse_enum_csv("my_option", "", &INSECTS, None)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        parse_enum_csv("my_option", "ladybug, butterfly, cricket", &INSECTS, None)
            .unwrap(),
        vec!["LADYBUG", "BUTTERFLY", "CRICKET"]
    );
    let two = "ladybug, butterfly";
    for bounds in [
        (Some(2), Some(2)),
        (Some(1), Some(2)),
        (Some(2), Some(3)),
        (None, Some(2)),
        (Some(2), None),
    ] {
        assert_eq!(
            parse_enum_csv("my_option", two, &INSECTS, Some(bounds))
                .unwrap()
                .len(),
            2
        );
    }
    for value in ["ugabuga", "ladybug, ugabuga", "ladybug butterfly"] {
        assert!(
            parse_enum_csv("my_option", value, &INSECTS, None).is_err(),
            "{value}"
        );
    }
    assert!(
        parse_enum_csv("my_option", "ladybug", &INSECTS, Some((Some(2), Some(2))))
            .is_err()
    );
    assert!(
        parse_enum_csv("my_option", "ladybug", &INSECTS, Some((Some(2), Some(3))))
            .is_err()
    );
    assert!(parse_enum_csv("my_option", two, &INSECTS, Some((None, Some(1)))).is_err());
}
