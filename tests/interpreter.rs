#![cfg(feature = "integration")]

mod tor_instance;

use std::path::PathBuf;

use stem::Error;
use stem::interpreter::{
    Arguments, Autocompleter, ControlInterpreter, help_response, help_text, message,
};
use tor_instance::TorInstance;

fn parse(arguments: &[&str]) -> Result<Arguments, Error> {
    let owned: Vec<String> = arguments
        .iter()
        .map(|argument| argument.to_string())
        .collect();
    Arguments::parse(&owned)
}

#[test]
fn provides_default_arguments() {
    let defaults = parse(&[]).unwrap();
    assert_eq!(defaults, Arguments::default());
    assert_eq!(defaults.control_address.to_string(), "127.0.0.1");
    assert_eq!(defaults.control_port, None);
    assert_eq!(
        defaults.control_socket,
        PathBuf::from("/var/run/tor/control")
    );
    assert_eq!(defaults.tor_path, "tor");
    assert!(!defaults.user_provided_port && !defaults.user_provided_socket);
}

#[test]
fn loads_arguments() {
    let args = parse(&["--interface", "10.0.0.25:80"]).unwrap();
    assert_eq!(args.control_address.to_string(), "10.0.0.25");
    assert_eq!(args.control_port, Some(80));
    assert!(args.user_provided_port);

    let args = parse(&["--interface", "80"]).unwrap();
    assert_eq!(args.control_address, Arguments::default().control_address);
    assert_eq!(args.control_port, Some(80));

    let args = parse(&["--socket", "/tmp/my_socket"]).unwrap();
    assert_eq!(args.control_socket, PathBuf::from("/tmp/my_socket"));
    assert!(args.user_provided_socket);

    assert!(parse(&["--help"]).unwrap().print_help);
    assert!(parse(&["-h"]).unwrap().print_help);
    assert_eq!(parse(&["-i", "1643"]).unwrap().control_port, Some(1643));
    assert_eq!(parse(&["-i1643"]).unwrap().control_port, Some(1643));
    assert_eq!(
        parse(&["--interface=1643"]).unwrap().control_port,
        Some(1643)
    );
    assert_eq!(parse(&["--int", "1643"]).unwrap().control_port, Some(1643));
    assert_eq!(
        parse(&["-s", "~/.tor/socket"]).unwrap().control_socket,
        PathBuf::from("~/.tor/socket")
    );
    assert_eq!(
        parse(&["--tor", "/usr/bin/tor"]).unwrap().tor_path,
        "/usr/bin/tor"
    );
    assert!(parse(&["--no-color"]).unwrap().disable_color);
    assert!(parse(&["-hs", "/tmp/x"]).unwrap().print_help);
}

#[test]
fn rejects_unrecognized_arguments() {
    for arguments in [
        vec!["--blarg", "stuff"],
        vec!["-x"],
        vec!["stuff"],
        vec!["--interface"],
        vec!["-i"],
        vec!["--no-color=yes"],
        vec!["--run"],
        vec!["--"],
    ] {
        let outcome = parse(&arguments);
        match arguments == vec!["--"] {
            true => assert!(outcome.is_ok()),
            false => assert!(outcome.is_err(), "{arguments:?} was accepted"),
        }
    }
    let message = parse(&["--blarg"]).unwrap_err().to_string();
    assert!(message.contains("for usage provide --help"));
}

#[test]
fn rejects_invalid_interfaces() {
    for invalid in [
        "",
        "    ",
        "blarg",
        "127.0.0.1",
        "127.0.0.1:",
        ":80",
        "400.0.0.1:80",
        "127.0.0.1:-5",
        "127.0.0.1:500000",
        "127.0.0.1:0",
        "[::1]:80",
        "127.0.0.1:080",
    ] {
        assert!(
            parse(&["--interface", invalid]).is_err(),
            "{invalid:?} was accepted"
        );
    }
}

#[test]
fn distinguishes_commands_from_files_for_run() {
    assert_eq!(
        parse(&["--run", "GETINFO version"])
            .unwrap()
            .run_command
            .as_deref(),
        Some("GETINFO version")
    );
    let file = env!("CARGO_MANIFEST_DIR").to_string() + "/Cargo.toml";
    let args = parse(&["--run", &file]).unwrap();
    assert_eq!(args.run_path, Some(PathBuf::from(&file)));
    assert_eq!(args.run_command, None);
}

#[test]
fn renders_help_and_messages() {
    let help = help_text();
    assert!(help.contains("Interactive interpreter for Tor."));
    assert!(help.contains("change control interface from 127.0.0.1:default"));
    assert!(help.contains("/var/run/tor/control"));
    assert_eq!(
        message("msg.unable_to_start_tor", &[("error", "kaboom")]),
        "Unable to start tor: kaboom"
    );
    assert!(
        message("msg.startup_banner", &[])
            .contains("Welcome to Stem's interpreter prompt")
    );
    assert_eq!(message("msg.not_a_key", &[]), "");
}

#[test]
fn completes_commands_without_a_controller() {
    let completer = futures_block(Autocompleter::new(None));
    assert_eq!(completer.matches("/help"), vec!["/help"]);
    assert_eq!(completer.matches("/he"), vec!["/help"]);
    assert_eq!(
        completer.matches("/"),
        vec!["/help", "/events", "/info", "/quit"]
    );
    assert_eq!(completer.matches("/HeLp"), vec!["/help"]);
    assert!(completer.matches("blarg").is_empty());
    assert!(completer.matches("PROTOCOLINFO").contains(&"PROTOCOLINFO"));
}

fn futures_block<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(future)
}

#[tokio::test]
async fn completes_commands_from_tor() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    let completer = Autocompleter::new(Some(&controller)).await;
    for expected in [
        "GETINFO info/names",
        "GETINFO ip-to-country/",
        "GETCONF ExitPolicy",
        "SETCONF ExitPolicy",
        "RESETCONF ExitPolicy",
        "SETEVENTS BW",
        "USEFEATURE VERBOSE_NAMES",
        "SIGNAL RELOAD",
        "SIGNAL SHUTDOWN",
        "/help GETINFO",
    ] {
        assert!(
            completer.matches(expected).contains(&expected),
            "{expected} is missing"
        );
    }
    assert!(!completer.matches("GETINFO ").is_empty());
    assert!(!completer.matches("GETINFO ").contains(&"GETINFO "));
    controller.close().await;
}

#[tokio::test]
async fn provides_help_responses() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;

    let unknown = help_response(&controller, "FOOBAR").await;
    assert!(unknown.contains("No help information available for 'FOOBAR'..."));

    let general = help_response(&controller, "").await;
    assert!(general.contains("Interpreter commands include:"));
    assert!(general.contains("GETINFO"));
    assert_eq!(help_response(&controller, "   ").await, general);

    let getinfo = help_response(&controller, "getinfo version").await;
    assert!(getinfo.contains("Queries the tor process for information. Options are..."));
    assert!(getinfo.contains("info/names"));
    assert!(
        help_response(&controller, "/info caerSidi")
            .await
            .contains("/info [relay")
    );

    let getconf = help_response(&controller, "GETCONF").await;
    assert!(
        getconf.contains("Provides the current value for a given configuration value.")
    );
    assert!(getconf.contains("ExitPolicy"));
    let signal = help_response(&controller, "SIGNAL").await;
    assert!(signal.contains("RELOAD / HUP"));
    let events = help_response(&controller, "SETEVENTS").await;
    assert!(events.contains("BW"));
    let features = help_response(&controller, "USEFEATURE").await;
    assert!(features.contains("EXTENDED_EVENTS"));
    let multiline = help_response(&controller, "LOADCONF").await;
    assert!(multiline.contains("not yet implemented"));
    controller.close().await;
}

#[tokio::test]
async fn runs_interpreter_and_tor_commands() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    let interpreter = ControlInterpreter::new(&controller);

    assert!(
        interpreter
            .run_command("/help")
            .await
            .unwrap()
            .contains("Interpreter commands include:")
    );
    assert!(
        interpreter
            .run_command("/help GETINFO version")
            .await
            .unwrap()
            .contains("Queries the tor process for information.")
    );
    let unknown = interpreter.run_command("/unrecognized").await.unwrap();
    assert!(unknown.contains("'/unrecognized' isn't a recognized command"));

    let version = interpreter.run_command("GETINFO version").await.unwrap();
    assert!(version.contains("250-version="));
    assert!(version.contains("250 OK"));
    let lowercase = interpreter
        .run_command("getinfo process/user")
        .await
        .unwrap();
    assert!(lowercase.contains("250-process/user="));

    let failure = interpreter
        .run_command("GETINFO bogus/option")
        .await
        .unwrap();
    assert!(failure.contains("552"));
    let multiline = interpreter.run_command("LOADCONF").await.unwrap();
    assert!(multiline.contains("not yet implemented"));
    assert!(
        interpreter
            .run_command("+POSTDESCRIPTOR")
            .await
            .unwrap()
            .contains("not yet")
    );

    assert_eq!(
        interpreter.run_command("").await.unwrap_or_default().trim(),
        ""
    );
    controller.close().await;
}

#[tokio::test]
async fn collects_events_for_the_backlog() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    let interpreter = ControlInterpreter::new(&controller);

    assert_eq!(interpreter.run_command("/events").await.unwrap(), "");
    let reply = interpreter
        .run_command("SETEVENTS BW SIGNAL")
        .await
        .unwrap();
    assert!(reply.contains("250 OK"));
    interpreter.run_command("SIGNAL DUMP").await.unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while interpreter.events(&["SIGNAL"]).is_empty()
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(interpreter.events(&["signal"])[0].starts_with("SIGNAL"));
    let listing = interpreter.run_command("/events signal").await.unwrap();
    assert!(listing.contains("SIGNAL DUMP"));
    assert!(!listing.contains("BW "));
    assert!(
        interpreter
            .run_command("/events clear")
            .await
            .unwrap()
            .contains("cleared event backlog")
    );
    assert!(interpreter.events(&[]).is_empty());

    assert!(
        interpreter
            .run_command("SETEVENTS")
            .await
            .unwrap()
            .contains("250 OK")
    );
    let rejected = interpreter
        .run_command("SETEVENTS NOT_AN_EVENT")
        .await
        .unwrap();
    assert!(
        rejected.contains("isn't a valid event type") || rejected.contains("rejected")
    );
    controller.close().await;
}

#[tokio::test]
async fn keeps_only_the_most_recent_events() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    let interpreter = ControlInterpreter::new(&controller);
    interpreter.run_command("SETEVENTS BW").await.unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while interpreter.events(&[]).len() < 3 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(interpreter.events(&[]).len() <= stem::interpreter::MAX_EVENTS);
    controller.close().await;
}

#[tokio::test]
async fn closes_for_quit_commands() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    let interpreter = ControlInterpreter::new(&controller);
    assert!(matches!(
        interpreter.run_command("/quit").await,
        Err(Error::SocketClosed)
    ));
    assert!(matches!(
        interpreter.run_command("QUIT").await,
        Err(Error::SocketClosed)
    ));
    assert!(matches!(
        interpreter.run_command("GETINFO version").await,
        Err(Error::SocketClosed)
    ));
    assert!(
        interpreter
            .run_command("/help")
            .await
            .unwrap()
            .contains("Interpreter commands")
    );
}

#[tokio::test]
async fn describes_relays_and_reports_lookup_failures() {
    let tor = TorInstance::offline();
    let controller = tor.controller().await;
    let interpreter = ControlInterpreter::new(&controller);

    let ourselves = interpreter.run_command("/info").await.unwrap();
    assert!(ourselves.contains("We aren't a relay"));
    for invalid in ["blarg!", "127.0.0.1:-1", "127.0.0.901:80", "1.2.3.4:"] {
        let output = interpreter
            .run_command(&format!("/info {invalid}"))
            .await
            .unwrap();
        assert!(
            output.contains('\u{1b}') || output.contains("isn't"),
            "{invalid}: {output}"
        );
    }
    let missing = interpreter
        .run_command("/info 9695DFC35FFEB861329B9F1AB04C46397020CE31")
        .await
        .unwrap();
    assert!(missing.contains("Unable to find consensus information"));
    controller.close().await;
}
