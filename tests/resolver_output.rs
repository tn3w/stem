use std::net::IpAddr;

use stem::process_inspection::{Connection, Protocol, Resolver, parse_connections};

const OUTPUTS: [(Resolver, &[&str]); 8] = [
    (
        Resolver::Netstat,
        &[
            "Active Internet connections (w/o servers)",
            "Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name",
            "tcp 0 0 10.0.0.1:44284 10.0.0.2:443 ESTABLISHED 15843/tor",
            "tcp 0 0 10.0.0.1:50000 10.0.0.3:9050 ESTABLISHED 999/other",
        ],
    ),
    (
        Resolver::NetstatWindows,
        &[
            " Proto Local Address Foreign Address State PID",
            " TCP 10.0.0.1:44284 10.0.0.2:443 ESTABLISHED 15843",
            " TCP 10.0.0.1:50000 10.0.0.3:9050 ESTABLISHED 999",
        ],
    ),
    (
        Resolver::Ss,
        &[
            "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
            "tcp ESTAB 0 0 10.0.0.1:44284 10.0.0.2:443 users:((\"tor\",pid=15843,fd=10))",
            "tcp ESTAB 0 0 10.0.0.1:50000 10.0.0.3:9050 users:((\"other\",pid=999,fd=3))",
        ],
    ),
    (
        Resolver::Lsof,
        &[
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME",
            "tor 15843 user 14u IPv4 1 0 TCP 10.0.0.1:44284->10.0.0.2:443 (ESTABLISHED)",
            "other 999 user 3u IPv4 2 0 TCP 10.0.0.1:50000->10.0.0.3:9050 (ESTABLISHED)",
        ],
    ),
    (
        Resolver::Sockstat,
        &[
            "USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS STATE",
            "user tor 15843 tcp4 10.0.0.1:44284 10.0.0.2:443 ESTABLISHED",
            "user other 999 tcp4 10.0.0.1:50000 10.0.0.3:9050 ESTABLISHED",
        ],
    ),
    (
        Resolver::BsdSockstat,
        &[
            "USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS",
            "_tor tor 15843 7 tcp4 10.0.0.1:44284 10.0.0.2:443",
            "_tor other 999 7 tcp4 10.0.0.1:50000 10.0.0.3:9050",
        ],
    ),
    (
        Resolver::BsdProcstat,
        &[
            " PID COMMAND FD T V FLAGS REF OFFSET PRO NAME",
            "15843 tor 8 s - rw---n-- 2 0 TCP 10.0.0.1:44284 10.0.0.2:443",
        ],
    ),
    (
        Resolver::BsdFstat,
        &[
            "USER CMD PID FD MOUNT INUM MODE SZ|DV R/W",
            "_tor tor 15843 14* stream tcp 0xfffff80e 10.0.0.1:44284 --> 10.0.0.2:443",
        ],
    ),
];

fn expected() -> Connection {
    Connection {
        local_address: "10.0.0.1".parse::<IpAddr>().unwrap(),
        local_port: 44284,
        remote_address: "10.0.0.2".parse::<IpAddr>().unwrap(),
        remote_port: 443,
        protocol: Protocol::Tcp,
        is_ipv6: false,
    }
}

fn lines(raw: &[&str]) -> Vec<String> {
    raw.iter().map(|line| line.to_string()).collect()
}

#[test]
fn parses_the_output_of_every_resolver() {
    for (resolver, raw) in OUTPUTS {
        let connections =
            parse_connections(resolver, &lines(raw), Some(15843), Some("tor")).unwrap();
        assert_eq!(connections, [expected()], "{resolver:?}");
    }
}

#[test]
fn ignores_other_processes() {
    for (resolver, raw) in OUTPUTS {
        let connections =
            parse_connections(resolver, &lines(raw), Some(4242), Some("tor")).unwrap();
        assert!(connections.is_empty(), "{resolver:?}");
    }
}

#[test]
fn parses_ipv6_and_udp_entries() {
    let output =
        lines(&["udp6 0 0 [2001:db8::1]:5353 [2001:db8::2]:9999 ESTABLISHED 15843/tor"]);
    let connections =
        parse_connections(Resolver::Netstat, &output, Some(15843), Some("tor")).unwrap();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].protocol, Protocol::Udp);
    assert!(connections[0].is_ipv6);
    assert_eq!(connections[0].remote_port, 9999);
}
