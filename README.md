# stem

Rust port of [Stem](https://stem.torproject.org/), the Python library for Tor. Async (tokio), strict parsing, no panics on untrusted input.

Targets tor 0.4.9 (Tor Expert Bundle 15.0.24) and python stem `7d420c20`.

## Install

```toml
stem = "2"
```

Rust 1.88+, edition 2024. Feature `integration` enables the tests that need a tor binary.

## Examples

Control port:

```rust
use stem::descriptor::collector::{CollecTor, CollectorRequest};
use stem::enumerations::Signal;
use stem::events::EventType;
use stem::onion_services::{EphemeralServiceOptions, OnionPorts};
use stem::{ConnectOptions, connect};

#[tokio::main]
async fn main() -> stem::Result<()> {
    let controller = connect(ConnectOptions::default()).await?;
    println!("tor {}", controller.get_version().await?);
    println!("{}", controller.get_info("traffic/read").await?);

    controller.set_conf("ContactInfo", "me@example.com").await?;
    controller.signal(&Signal::Newnym).await?;

    let (_, mut events) = controller.subscribe(&[EventType::Bw]).await?;
    while let Some(event) = events.recv().await {
        println!("{}", event.message);
    }

    let service = controller
        .create_ephemeral_hidden_service(
            &OnionPorts::Single(80),
            &EphemeralServiceOptions::default(),
        )
        .await?;
    println!("{}.onion", service.service_id.unwrap_or_default());
    Ok(())
}
```

Launch tor:

```rust
use stem::process::{LaunchOptions, launch_tor_with_config};

let config = [("SocksPort", "auto"), ("ControlPort", "auto")];
let options = LaunchOptions { take_ownership: true, ..LaunchOptions::default() };
let tor = launch_tor_with_config(&config, options, None).await?;
```

Descriptors:

```rust
use stem::descriptor::remote::DescriptorDownloader;
use stem::descriptor::{DocumentHandler, parse_path};

for file in parse_path("cached-consensus".as_ref(), None, true, DocumentHandler::Entries)? {
    println!("{:?}", file.descriptor.published());
}
let consensus = DescriptorDownloader::new().get_consensus_validated(None, true).await?;
let exit_lists = CollecTor::shared().get_exit_lists(&CollectorRequest::default()).await?;
```

Interpreter: `cargo run --bin tor-prompt -- -i 9051` (`--help` for options).

## Modules

| Module | Covers |
|---|---|
| `controller`, `onion_services` | `Controller`: GETINFO/GETCONF/SETCONF, events, circuits, streams, signals, caching, ephemeral and persistent hidden services, client authorization |
| `authentication` | PROTOCOLINFO, none/password/cookie/SAFECOOKIE, `connect`, unix sockets, chroot paths |
| `socket`, `response`, `events` | `ControlSocket`, message framing, response parsers, all event types |
| `process`, `process_inspection` | `launch_tor*`, pid/cwd/user/connection lookups via `/proc` and system tools |
| `descriptor::*` | server, extra-info, micro, router status, network status (v2/v3/bridge), key certificates, detached signatures, hidden service v2/v3, bandwidth files, tordnsel, Ed25519 certificates, `reader`, `export` |
| `descriptor::remote`, `descriptor::collector`, `directory` | downloads over DirPort or ORPort, CollecTor with checksum verification, authorities and fallbacks |
| `client` | link handshake with CERTS verification (`link_authentication`), CREATE_FAST circuits, directory requests with SENDME flow control |
| `exit_policy`, `version`, `address`, `validation`, `formatting`, `configuration`, `manual`, `interpreter` | helpers and the `tor-prompt` interpreter |

Descriptors parse with `X::parse(bytes, validate)`; `validate = false` is lenient. Generators (`content`/`create`) produce valid, signed descriptors. Descriptor types implement `serde::Serialize`.

## Security

- Command arguments are validated per token, config values are quoted and escaped, data blocks are dot-stuffed; CR/LF or NUL cannot start a second command.
- Control messages: 1 MiB per line, 512 MiB per message. Decompression is capped at 512 MiB. Downloads are capped and checksummed (CollecTor sha256 before decompression).
- Cookies must be regular files of exactly 32 bytes, are compared in constant time and zeroized. Passwords, cookies and keys are redacted from trace logs.
- Relay cell digests are verified. `Relay::connect` verifies the CERTS cell (RSA identity self-signature, link certificate against the TLS certificate, Ed25519 signing, link and RSA cross-certificates, validity with 24 h skew) and exposes `Relay::identity` (RSA fingerprint, Ed25519 key). Compare it with the expected relay; still verify signatures of what you download (`validate = true`, `get_consensus_validated`).
- HS v3: `blinded_key_for_period` / `time_period_number` recompute the blinded key (default 1440 minute periods); `HiddenServiceDescriptorV3::verify_blinded_key` checks a descriptor against its address for the current, previous and next period. Checked against a real tor descriptor.
- Downloads fail with a clear error when the host redirects to a sign-in page (gitlab.torproject.org does this for anonymous raw downloads from some networks); `Authority::from_url`, `Fallback::from_url` and `Manual::from_url` accept a mirror.

## Differences from python stem

- Async API; typed values (`IpAddr`, enums with an `Other` variant) instead of strings.
- Stricter than python: trailing newlines, unicode digits, lax `int()`, prefix-only timestamps and unbounded protocol ranges are rejected. Fixed python bugs: `crop` negative slice, `size_label` returning `None`, bandwidth file blank-line hang, event log truncation, GETCONF quoted values, collector checksum, `[::1]` accepted as plain IPv6.
- Modern `man tor` layout is parsed (python yields no options); the embedded manual is generated from tor 0.4.9. `from_remote` / `from_url` need `pandoc`.
- `LaunchOptions::environment` sets environment variables for the tor child and its version check (for example `LD_LIBRARY_PATH` of a Tor Expert Bundle).
- Not ported: the python interpreter's embedded Python console, `stem.util.conf` listeners and `config_dict`, `size_of`, `set_process_name`, `DaemonTask`.
- Descriptor CSV export uses JSON for nested values.

## Tests

```sh
cargo test                                   # unit, golden, differential, fuzz
TOR_BINARY=/path/to/tor LD_LIBRARY_PATH=/path/to/tor/dir \
  cargo test --features integration          # real tor, network
STEM_PYTHON_PATH=/path/to/python-stem cargo test --release \
  --test descriptor_network --test descriptor_generated
```

- `tests/golden/*.py` regenerate the JSON in `tests/golden` from python stem; `descriptor_golden`, `descriptor_mutations`, `helpers_golden`, `events_golden` and `directories_golden` compare against it (descriptors, 5300 mutated inputs, events, helpers, exit policies, directories).
- Live differential tests compare 1500 server and extra-info descriptors, microdescriptors and a full consensus with python stem, and check that python accepts what this crate generates.
- Integration tests run tor 0.4.9.12 and 0.4.9.13: authentication methods, configuration, events, hidden services (including client authorization), process launch, circuits, stream attach, directory downloads over DirPort and ORPort, signature validation, CollecTor.
- `relay_authentication` connects to a local relay and checks the authenticated RSA and Ed25519 identity against tor's own files; `remote_sources` serves authorities, fallbacks and a markdown manual from a local HTTP server (the pandoc test skips without pandoc, CI installs it); `resolver_output` parses sample output of every connection resolver (netstat, ss, lsof, sockstat, procstat, fstat, Windows netstat) on any platform.
- `robustness` fuzzes every parser (`STEM_FUZZ_ROUNDS` raises the rounds); `injection` and `logging` cover command smuggling and secret redaction.

`tests/data` is copied from python stem, see `tests/data/NOTICE`.

## License

stem is a port of [python stem](https://stem.torproject.org) (Copyright Damian Johnson and The Tor Project) and, like it, is licensed under the GNU Lesser General Public License v3.0 ([LICENSE](LICENSE)), which supplements the GNU General Public License v3.0 ([COPYING](COPYING)).
