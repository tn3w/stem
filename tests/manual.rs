use std::path::PathBuf;

use stem::manual::{ConfigOption, Manual, event_description, is_important};

fn data(name: &str) -> String {
    format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))
}

const DESCRIPTION: &str = "Tor is a connection-oriented anonymizing communication \
    service. Users choose a source-routed path through a set of nodes, and negotiate a \
    \"virtual circuit\" through the network, in which each node knows its predecessor \
    and successor, but no others. Traffic flowing down the circuit is unwrapped by a \
    symmetric key at each node, which reveals the downstream node.";

fn pairs(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn collected(map: &indexmap::IndexMap<String, String>) -> Vec<(String, String)> {
    map.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn option(
    name: &str,
    category: &str,
    usage: &str,
    summary: &str,
    description: &str,
) -> ConfigOption {
    ConfigOption {
        name: name.to_string(),
        category: category.to_string(),
        usage: usage.to_string(),
        summary: summary.to_string(),
        description: description.to_string(),
    }
}

#[test]
fn parses_a_trimmed_man_page() {
    let manual = Manual::from_man(&data("tor_man_example")).unwrap();
    assert_eq!(manual.name, "tor - The second-generation onion router");
    assert_eq!(manual.synopsis, "tor [OPTION value]...");
    assert_eq!(manual.description, DESCRIPTION);
    let sorted = |map: &indexmap::IndexMap<String, String>| {
        let mut entries = collected(map);
        entries.sort();
        entries
    };
    let mut expected_commandline = pairs(&[
        (
            "-f FILE",
            "Specify a new configuration file to contain further Tor configuration \
            options OR pass - to make Tor read its configuration from standard input. \
            (Default: @CONFDIR@/torrc, or $HOME/.torrc if that file is not found)",
        ),
        ("-h, -help", "Display a short help message and exit."),
        (
            "--allow-missing-torrc",
            "Do not require that configuration file specified by -f exist if default \
            torrc can be accessed.",
        ),
    ]);
    expected_commandline.sort();
    assert_eq!(sorted(&manual.commandline_options), expected_commandline);
    let mut expected_signals = pairs(&[
        (
            "SIGHUP",
            "The signal instructs Tor to reload its configuration (including closing \
            and reopening logs), and kill and restart its helper processes if \
            applicable.",
        ),
        (
            "SIGTERM",
            "Tor will catch this, clean up and sync to disk if necessary, and exit.",
        ),
        (
            "SIGINT",
            "Tor clients behave as with SIGTERM; but Tor servers will do a controlled \
            slow shutdown, closing listeners and waiting 30 seconds before exiting. \
            (The delay can be configured with the ShutdownWaitLength config option.)",
        ),
    ]);
    expected_signals.sort();
    assert_eq!(sorted(&manual.signals), expected_signals);
    let files = collected(&manual.files);
    assert_eq!(files.len(), 7);
    assert_eq!(
        manual.files["@LOCALSTATEDIR@/lib/tor/"],
        "The tor process stores keys and other data here."
    );
    assert_eq!(
        manual.files["@CONFDIR@/torrc"],
        "The configuration file, which contains \"option value\" pairs."
    );
    assert_eq!(
        manual.files["$HOME/.torrc"],
        "Fallback location for torrc, if @CONFDIR@/torrc is not found."
    );
    assert_eq!(
        manual.files["DataDirectory/bw_accounting"],
        "Used to track bandwidth accounting values (when the current period starts and \
        ends; how much has been read and written so far this period). This file is \
        obsolete, and the data is now stored in the 'state' file as well. Only used \
        when bandwidth accounting is enabled."
    );

    let usage = "N bytes|KBytes|MBytes|GBytes|KBits|MBits|GBits";
    let expected = vec![
        option(
            "BandwidthRate",
            "GENERAL",
            usage,
            "Average bandwidth usage limit",
            "A token bucket limits the average incoming bandwidth usage on this node to \
            the specified number of bytes per second, and the average outgoing \
            bandwidth usage to that same value. If you want to run a relay in the \
            public network, this needs to be at the very least 75 KBytes for a relay \
            (that is, 600 kbits) or 50 KBytes for a bridge (400 kbits) -- but of \
            course, more is better; we recommend at least 250 KBytes (2 mbits) if \
            possible. (Default: 1 GByte)\n\nWith this option, and in other options that \
            take arguments in bytes, KBytes, and so on, other formats are also \
            supported. Notably, \"KBytes\" can also be written as \"kilobytes\" or \
            \"kb\"; \"MBytes\" can be written as \"megabytes\" or \"MB\"; \"kbits\" can \
            be written as \"kilobits\"; and so forth. Tor also accepts \"byte\" and \
            \"bit\" in the singular. The prefixes \"tera\" and \"T\" are also \
            recognized. If no units are given, we default to bytes. To avoid confusion, \
            we recommend writing \"bytes\" or \"bits\" explicitly, since it's easy to \
            forget that \"B\" means bytes, not bits.",
        ),
        option(
            "BandwidthBurst",
            "GENERAL",
            usage,
            "Maximum bandwidth usage limit",
            "Limit the maximum token bucket size (also known as the burst) to the given \
            number of bytes in each direction. (Default: 1 GByte)",
        ),
        option(
            "MaxAdvertisedBandwidth",
            "GENERAL",
            usage,
            "Limit for the bandwidth we advertise as being available for relaying",
            "If set, we will not advertise more than this amount of bandwidth for our \
            BandwidthRate. Server operators who want to reduce the number of clients \
            who ask to build circuits through them (since this is proportional to \
            advertised bandwidth rate) can thus reduce the CPU demands on their server \
            without impacting network performance.",
        ),
        option(
            "Bridge",
            "CLIENT",
            "[transport] IP:ORPort [fingerprint]",
            "Available bridges",
            "When set along with UseBridges, instructs Tor to use the relay at \
            \"IP:ORPort\" as a \"bridge\" relaying into the Tor network. If \
            \"fingerprint\" is provided (using the same format as for DirAuthority), we \
            will verify that the relay running at that location has the right \
            fingerprint. We also use fingerprint to look up the bridge descriptor at \
            the bridge authority, if it's provided and if UpdateBridgesFromAuthority is \
            set too.\n\nIf \"transport\" is provided, and matches to a \
            ClientTransportPlugin line, we use that pluggable transports proxy to \
            transfer data to the bridge.",
        ),
    ];
    let actual: Vec<ConfigOption> = manual.config_options.values().cloned().collect();
    assert_eq!(actual, expected);
}

#[test]
fn parses_unknown_options() {
    let manual = Manual::from_man(&data("tor_man_with_unknown")).unwrap();
    assert_eq!(manual.name, "tor - The second-generation onion router");
    assert_eq!(manual.synopsis, "");
    assert_eq!(manual.description, "");
    assert!(manual.commandline_options.is_empty());
    assert!(manual.signals.is_empty());
    assert!(manual.files.is_empty());
    assert_eq!(manual.config_options.len(), 2);
    let unknown = manual
        .config_options
        .values()
        .find(|entry| entry.category == "UNKNOWN")
        .unwrap();
    assert_eq!(unknown.name, "SpiffyNewOption");
    assert_eq!(unknown.usage, "transport exec path-to-binary [options]");
    assert_eq!(unknown.summary, "");
    assert_eq!(unknown.description, "Description of this new option.");
}

#[test]
fn fails_for_missing_man_pages() {
    assert!(Manual::from_man("/nonexistent/man/page").is_err());
}

#[test]
fn saves_and_reloads_as_config_and_sqlite() {
    let manual = Manual::from_man(&data("tor_man_example")).unwrap();
    let directory = tempfile::tempdir().unwrap();
    for name in ["manual.cfg", "manual.sqlite"] {
        let path = directory.path().join(name);
        manual.save(&path).unwrap();
        let loaded = Manual::from_cache(Some(&path)).unwrap();
        assert_eq!(loaded.name, manual.name);
        assert_eq!(loaded.synopsis, manual.synopsis);
        assert_eq!(loaded.description, manual.description);
        assert_eq!(loaded.commandline_options, manual.commandline_options);
        assert_eq!(loaded.signals, manual.signals);
        assert_eq!(loaded.files, manual.files);
        assert_eq!(loaded.config_options, manual.config_options);
    }
}

#[test]
fn reads_the_embedded_manual() {
    let manual = Manual::from_cache(None).unwrap();
    assert_eq!(manual.name, "tor - The second-generation onion router");
    assert_eq!(manual.synopsis, "tor [OPTION value]...");
    assert!(
        manual.description.starts_with(
            "Tor is a connection-oriented anonymizing communication service."
        )
    );
    assert!(manual.commandline_options.len() > 10);
    assert!(manual.signals.len() > 5);
    assert!(manual.files.len() > 20);
    assert!(manual.config_options.len() > 200);
    let cookie = &manual.config_options["CookieAuthFile"];
    assert!(
        cookie.description.contains(
            "overrides the default location and file name for Tor's cookie file"
        )
    );
}

#[test]
fn has_summaries_for_every_embedded_option() {
    let manual = Manual::from_cache(None).unwrap();
    let missing: Vec<&String> = manual
        .config_options
        .iter()
        .filter(|(_, option)| option.summary.is_empty())
        .map(|(name, _)| name)
        .collect();
    assert!(missing.len() < 30, "options without summaries: {missing:?}");
    for name in ["ExitPolicy", "ControlPort", "SocksPort", "HiddenServiceDir"] {
        assert!(!manual.config_options[name].summary.is_empty(), "{name}");
    }
}

#[test]
fn rejects_corrupt_and_missing_caches() {
    let directory = tempfile::tempdir().unwrap();
    assert!(Manual::from_cache(Some(&directory.path().join("missing.cfg"))).is_err());
    let corrupt = directory.path().join("corrupt.sqlite");
    std::fs::write(&corrupt, b"not a database").unwrap();
    assert!(Manual::from_cache(Some(&corrupt)).is_err());
    let truncated: PathBuf = directory.path().join("empty.sqlite");
    std::fs::write(&truncated, b"").unwrap();
    assert!(Manual::from_cache(Some(&truncated)).is_err());
}

#[test]
fn knows_important_options_and_event_descriptions() {
    assert!(is_important("ExitPolicy"));
    assert!(is_important("exitpolicy"));
    assert!(is_important("EXITPOLICY"));
    assert!(!is_important("ConstrainedSockSize"));
    assert!(event_description("BW").is_some());
    assert!(event_description("bw").is_some());
    assert_eq!(event_description("NOT_AN_EVENT"), None);
}
