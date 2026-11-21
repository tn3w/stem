use std::collections::VecDeque;
use std::io::IsTerminal;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use indexmap::IndexMap;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};

use crate::address::{is_valid_ipv4_address, parse_port};
use crate::authentication::{ConnectOptions, connect};
use crate::configuration::Config;
use crate::controller::{Controller, ListenerId};
use crate::descriptor::Descriptor;
use crate::descriptor::remote::DescriptorDownloader;
use crate::error::{Error, Result};
use crate::events::EventType;
use crate::formatting::{
    TerminalColor, TerminalStyle, format_terminal, set_color_support_disabled,
};
use crate::process::{LaunchOptions, launch_tor_with_config};
use crate::process_inspection::{is_available, is_running};
use crate::validation::{is_valid_fingerprint, is_valid_nickname};

pub const MAX_EVENTS: usize = 100;

const PROMPT: &str = ">>> ";
const SETTINGS: &str = include_str!("data/interpreter.cfg");
const STANDARD_OUTPUT: &[TerminalStyle] = &[
    TerminalStyle::Foreground(TerminalColor::Blue),
    TerminalStyle::Lines,
];
const BOLD_OUTPUT: &[TerminalStyle] = &[
    TerminalStyle::Foreground(TerminalColor::Blue),
    TerminalStyle::Bold,
    TerminalStyle::Lines,
];
const HEADER_OUTPUT: &[TerminalStyle] = &[
    TerminalStyle::Foreground(TerminalColor::Green),
    TerminalStyle::Lines,
];
const HEADER_BOLD_OUTPUT: &[TerminalStyle] = &[
    TerminalStyle::Foreground(TerminalColor::Green),
    TerminalStyle::Bold,
    TerminalStyle::Lines,
];
const ERROR_OUTPUT: &[TerminalStyle] = &[
    TerminalStyle::Bold,
    TerminalStyle::Foreground(TerminalColor::Red),
    TerminalStyle::Lines,
];
const PROMPT_STYLES: &[TerminalStyle] = &[
    TerminalStyle::Foreground(TerminalColor::Green),
    TerminalStyle::Bold,
];

static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let mut config = Config::new();
    config.load_str(SETTINGS, true);
    config
});

pub fn message(key: &str, replacements: &[(&str, &str)]) -> String {
    let mut text = CONFIG.get_value(key).unwrap_or_default().to_string();
    for (name, value) in replacements {
        text = text.replace(&format!("{{{name}}}"), value);
    }
    text
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub control_address: Ipv4Addr,
    pub control_port: Option<u16>,
    pub user_provided_port: bool,
    pub control_socket: PathBuf,
    pub user_provided_socket: bool,
    pub tor_path: String,
    pub run_command: Option<String>,
    pub run_path: Option<PathBuf>,
    pub disable_color: bool,
    pub print_help: bool,
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            control_address: Ipv4Addr::LOCALHOST,
            control_port: None,
            user_provided_port: false,
            control_socket: PathBuf::from("/var/run/tor/control"),
            user_provided_socket: false,
            tor_path: "tor".to_string(),
            run_command: None,
            run_path: None,
            disable_color: false,
            print_help: false,
        }
    }
}

#[derive(Clone, Copy)]
enum ParsedOption {
    Interface,
    Socket,
    Tor,
    Run,
    NoColor,
    Help,
}

const LONG_OPTIONS: &[(&str, ParsedOption, bool)] = &[
    ("interface", ParsedOption::Interface, true),
    ("socket", ParsedOption::Socket, true),
    ("tor", ParsedOption::Tor, true),
    ("run", ParsedOption::Run, true),
    ("no-color", ParsedOption::NoColor, false),
    ("help", ParsedOption::Help, false),
];

fn usage_error(message: impl std::fmt::Display) -> Error {
    Error::invalid_input(format!("{message} (for usage provide --help)"))
}

fn long_option(name: &str) -> Result<&'static (&'static str, ParsedOption, bool)> {
    if let Some(exact) = LONG_OPTIONS.iter().find(|option| option.0 == name) {
        return Ok(exact);
    }
    let candidates: Vec<_> = LONG_OPTIONS
        .iter()
        .filter(|option| option.0.starts_with(name))
        .collect();
    match candidates.as_slice() {
        [] => Err(usage_error(format!("option --{name} not recognized"))),
        [only] => Ok(only),
        _ => Err(usage_error(format!("option --{name} not a unique prefix"))),
    }
}

fn short_option(character: char) -> Result<(ParsedOption, bool)> {
    match character {
        'i' => Ok((ParsedOption::Interface, true)),
        's' => Ok((ParsedOption::Socket, true)),
        'h' => Ok((ParsedOption::Help, false)),
        _ => Err(usage_error(format!("option -{character} not recognized"))),
    }
}

type OptionPair = (ParsedOption, Option<String>);

fn option_pairs(argv: &[String]) -> Result<(Vec<OptionPair>, Vec<String>)> {
    let mut pairs = Vec::new();
    let mut position = 0;
    while position < argv.len() {
        let argument = &argv[position];
        position += 1;
        if argument == "--" {
            break;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (long, None),
            };
            let (full_name, option, takes_value) = long_option(name)?;
            let value = match (takes_value, inline) {
                (true, Some(value)) => Some(value),
                (true, None) => Some(next_value(argv, &mut position, full_name, "--")?),
                (false, None) => None,
                (false, Some(_)) => {
                    return Err(usage_error(format!(
                        "option --{full_name} must not have an argument"
                    )));
                }
            };
            pairs.push((*option, value));
            continue;
        }
        let Some(cluster) = argument.strip_prefix('-').filter(|rest| !rest.is_empty())
        else {
            position -= 1;
            break;
        };
        parse_short_cluster(cluster, argv, &mut position, &mut pairs)?;
    }
    Ok((pairs, argv[position..].to_vec()))
}

fn next_value(
    argv: &[String],
    position: &mut usize,
    name: &str,
    prefix: &str,
) -> Result<String> {
    let Some(value) = argv.get(*position) else {
        return Err(usage_error(format!(
            "option {prefix}{name} requires argument"
        )));
    };
    *position += 1;
    Ok(value.clone())
}

fn parse_short_cluster(
    cluster: &str,
    argv: &[String],
    position: &mut usize,
    pairs: &mut Vec<OptionPair>,
) -> Result<()> {
    for (index, character) in cluster.char_indices() {
        let (option, takes_value) = short_option(character)?;
        if !takes_value {
            pairs.push((option, None));
            continue;
        }
        let attached = &cluster[index + character.len_utf8()..];
        let value = match attached.is_empty() {
            true => next_value(argv, position, &character.to_string(), "-")?,
            false => attached.to_string(),
        };
        pairs.push((option, Some(value)));
        return Ok(());
    }
    Ok(())
}

impl Arguments {
    pub fn parse(argv: &[String]) -> Result<Self> {
        let (pairs, unrecognized) = option_pairs(argv)?;
        if !unrecognized.is_empty() {
            let phrase = match unrecognized.len() > 1 {
                true => "aren't recognized arguments",
                false => "isn't a recognized argument",
            };
            return Err(usage_error(format!(
                "'{}' {phrase}",
                unrecognized.join("', '")
            )));
        }
        let mut arguments = Self::default();
        for (option, value) in pairs {
            let value = value.unwrap_or_default();
            match option {
                ParsedOption::Interface => arguments.set_interface(&value)?,
                ParsedOption::Socket => {
                    arguments.control_socket = PathBuf::from(value);
                    arguments.user_provided_socket = true;
                }
                ParsedOption::Tor => arguments.tor_path = value,
                ParsedOption::Run => match PathBuf::from(&value).exists() {
                    true => arguments.run_path = Some(PathBuf::from(value)),
                    false => arguments.run_command = Some(value),
                },
                ParsedOption::NoColor => arguments.disable_color = true,
                ParsedOption::Help => arguments.print_help = true,
            }
        }
        Ok(arguments)
    }

    fn set_interface(&mut self, value: &str) -> Result<()> {
        let (address, port) = match value.rsplit_once(':') {
            Some((address, port)) => (Some(address), port),
            None => (None, value),
        };
        if let Some(address) = address {
            if !is_valid_ipv4_address(address) {
                return Err(Error::invalid_input(format!(
                    "'{address}' isn't a valid IPv4 address"
                )));
            }
            self.control_address = address
                .parse()
                .map_err(|_| Error::invalid_input("Invalid IPv4 address"))?;
        }
        let Some(port) = parse_port(port, false) else {
            return Err(Error::invalid_input(format!(
                "'{port}' isn't a valid port number"
            )));
        };
        self.control_port = Some(port);
        self.user_provided_port = true;
        Ok(())
    }
}

pub fn help_text() -> String {
    let defaults = Arguments::default();
    message(
        "msg.help",
        &[
            ("address", &defaults.control_address.to_string()),
            ("port", "default"),
            ("socket", &defaults.control_socket.to_string_lossy()),
        ],
    )
}

pub struct Autocompleter {
    commands: Vec<String>,
}

async fn info_lines(controller: &Controller, key: &str) -> Option<String> {
    controller
        .get_info(key)
        .await
        .ok()
        .filter(|text| !text.is_empty())
}

impl Autocompleter {
    pub async fn new(controller: Option<&Controller>) -> Self {
        let mut commands = CONFIG.get_values("autocomplete");
        if let Some(controller) = controller {
            commands.extend(dynamic_commands(controller).await);
            for command in CONFIG.get_mapping("help.usage").keys() {
                commands.push(format!("/help {command}"));
            }
        }
        Self { commands }
    }

    pub fn matches(&self, text: &str) -> Vec<&str> {
        let lowercase = text.to_lowercase();
        self.commands
            .iter()
            .filter(|command| command.to_lowercase().starts_with(&lowercase))
            .map(String::as_str)
            .collect()
    }
}

async fn dynamic_commands(controller: &Controller) -> Vec<String> {
    let mut commands = Vec::new();
    match info_lines(controller, "info/names").await {
        Some(results) => commands.extend(results.lines().map(|line| {
            let option = line.split(' ').next().unwrap_or_default();
            format!("GETINFO {}", option.trim_end_matches('*'))
        })),
        None => commands.push("GETINFO ".to_string()),
    }
    match info_lines(controller, "config/names").await {
        Some(results) => {
            for line in results.lines() {
                let option = line.split(' ').next().unwrap_or_default();
                commands.push(format!("GETCONF {option}"));
                commands.push(format!("SETCONF {option}"));
                commands.push(format!("RESETCONF {option}"));
            }
        }
        None => commands.extend(["GETCONF ", "SETCONF ", "RESETCONF "].map(String::from)),
    }
    let sources = [
        ("SETEVENTS ", "events/names"),
        ("USEFEATURE ", "features/names"),
        ("SIGNAL ", "signal/names"),
    ];
    for (prefix, key) in sources {
        match info_lines(controller, key).await {
            Some(results) => commands.extend(
                results
                    .split_whitespace()
                    .map(|value| format!("{prefix}{value}")),
            ),
            None => commands.push(prefix.to_string()),
        }
    }
    commands
}

fn normalize_help_argument(argument: &str) -> String {
    let upper = argument.to_uppercase();
    let first = upper.split(' ').next().unwrap_or_default();
    first.strip_prefix('/').unwrap_or(first).to_string()
}

fn general_help() -> String {
    message("help.general", &[])
        .lines()
        .map(|line| match line.find(" - ") {
            Some(divider) => {
                let (command, description) = line.split_at(divider);
                format_terminal(command, BOLD_OUTPUT)
                    + &format_terminal(description, STANDARD_OUTPUT)
            }
            None => format_terminal(line, BOLD_OUTPUT),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn columns(entries: &[&str], per_row: usize, width: usize) -> String {
    entries
        .chunks(per_row)
        .map(|row| {
            let line: String =
                row.iter().map(|entry| format!("{entry:<width$}")).collect();
            format_terminal(line.trim_end(), STANDARD_OUTPUT) + "\n"
        })
        .collect()
}

async fn getinfo_help(controller: &Controller) -> String {
    let Some(results) = info_lines(controller, "info/names").await else {
        return String::new();
    };
    let mut output = String::new();
    for line in results.lines() {
        if let Some((option, summary)) = line.split_once(" -- ") {
            output += &format_terminal(&format!("{option:<33}"), BOLD_OUTPUT);
            output +=
                &(format_terminal(&format!(" - {summary}"), STANDARD_OUTPUT) + "\n");
        }
    }
    output
}

async fn help_extras(controller: &Controller, argument: &str) -> String {
    match argument {
        "GETINFO" => getinfo_help(controller).await,
        "GETCONF" => {
            let results = info_lines(controller, "config/names").await;
            let names: Vec<&str> = results
                .iter()
                .flat_map(|text| text.lines())
                .filter_map(|line| line.split(' ').next())
                .collect();
            columns(&names, 2, 42)
        }
        "SIGNAL" => CONFIG
            .get_mapping("help.signal.options")
            .iter()
            .map(|(signal, summary)| {
                format_terminal(&format!("{signal:<15}"), BOLD_OUTPUT)
                    + &format_terminal(&format!(" - {summary}"), STANDARD_OUTPUT)
                    + "\n"
            })
            .collect(),
        "SETEVENTS" => {
            let results = info_lines(controller, "events/names").await;
            let names: Vec<&str> = results
                .iter()
                .flat_map(|text| text.split_whitespace())
                .collect();
            columns(&names, 4, 20)
        }
        "USEFEATURE" => match info_lines(controller, "features/names").await {
            Some(results) => format_terminal(&results, STANDARD_OUTPUT) + "\n",
            None => String::new(),
        },
        "LOADCONF" | "POSTDESCRIPTOR" => {
            format_terminal(
                &message("msg.multiline_unimplemented_notice", &[]),
                ERROR_OUTPUT,
            ) + "\n"
        }
        _ => String::new(),
    }
}

pub async fn help_response(controller: &Controller, argument: &str) -> String {
    let argument = normalize_help_argument(argument);
    if argument.is_empty() {
        return general_help();
    }
    let usage: IndexMap<String, String> = CONFIG.get_mapping("help.usage");
    let Some(usage_line) = usage.get(&argument) else {
        return format_terminal(
            &format!("No help information available for '{argument}'..."),
            ERROR_OUTPUT,
        );
    };
    let mut output = format_terminal(&format!("{usage_line}\n"), BOLD_OUTPUT);
    let description = message(
        &format!("help.description.{}", argument.to_lowercase()),
        &[],
    );
    for line in description.lines() {
        output += &(format_terminal(&format!("  {line}"), STANDARD_OUTPUT) + "\n");
    }
    output += "\n";
    output += &help_extras(controller, &argument).await;
    output.trim_end().to_string()
}

async fn resolve_fingerprint(controller: &Controller, argument: &str) -> Result<String> {
    if argument.is_empty() {
        return controller.get_info("fingerprint").await.map_err(|_| {
            Error::invalid_input("We aren't a relay, no information to provide")
        });
    }
    if is_valid_fingerprint(argument, false) {
        return Ok(argument.to_string());
    }
    if is_valid_nickname(argument) {
        return controller
            .get_network_status(Some(argument))
            .await
            .ok()
            .and_then(|status| status.fingerprint.clone())
            .ok_or_else(|| {
                Error::invalid_input(format!(
                    "Unable to find a relay with the nickname of '{argument}'"
                ))
            });
    }
    if argument.contains(':') || is_valid_ipv4_address(argument) {
        return fingerprint_by_address(controller, argument).await;
    }
    Err(Error::invalid_input(format!(
        "'{argument}' isn't a fingerprint, nickname, or IP address"
    )))
}

fn split_relay_address(argument: &str) -> Result<(&str, Option<u16>)> {
    let Some((address, port)) = argument.rsplit_once(':') else {
        return Ok((argument, None));
    };
    if !is_valid_ipv4_address(address) {
        return Err(Error::invalid_input(format!(
            "'{address}' isn't a valid IPv4 address"
        )));
    }
    match parse_port(port, false) {
        Some(port) => Ok((address, Some(port))),
        None => Err(Error::invalid_input(format!("'{port}' isn't a valid port"))),
    }
}

async fn fingerprint_by_address(
    controller: &Controller,
    argument: &str,
) -> Result<String> {
    let (address, port) = split_relay_address(argument)?;
    let mut matches: IndexMap<u16, String> = IndexMap::new();
    for status in controller.get_network_statuses().await? {
        let (Some(status_address), Some(or_port), Some(fingerprint)) =
            (&status.address, status.or_port, &status.fingerprint)
        else {
            continue;
        };
        if status_address == address && port.is_none_or(|port| port == or_port) {
            matches.insert(or_port, fingerprint.clone());
        }
    }
    match matches.len() {
        0 => Err(Error::invalid_input(format!(
            "No relays found at {argument}"
        ))),
        1 => Ok(matches.into_values().next().unwrap_or_default()),
        _ => {
            let mut response = format!(
                "There's multiple relays at {argument}, include a port to specify \
                which.\n\n"
            );
            for (index, (or_port, fingerprint)) in matches.iter().enumerate() {
                response += &format!(
                    "  {}. {address}:{or_port}, fingerprint: {fingerprint}\n",
                    index + 1
                );
            }
            Err(Error::invalid_input(response))
        }
    }
}

fn readable_contact(contact: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(contact).into_owned();
    for alias in [" at ", " AT "] {
        text = text.replace(alias, "@");
    }
    for alias in [" dot ", " DOT "] {
        text = text.replace(alias, ".");
    }
    text
}

fn labeled(label: &str, value: &str) -> String {
    format_terminal(label, BOLD_OUTPUT) + value
}

pub struct ControlInterpreter<'a> {
    controller: &'a Controller,
    received_events: Arc<Mutex<VecDeque<String>>>,
    event_listener: Mutex<Option<ListenerId>>,
}

impl<'a> ControlInterpreter<'a> {
    pub fn new(controller: &'a Controller) -> Self {
        Self {
            controller,
            received_events: Arc::default(),
            event_listener: Mutex::new(None),
        }
    }

    pub fn events(&self, event_types: &[&str]) -> Vec<String> {
        let wanted: Vec<String> =
            event_types.iter().map(|name| name.to_uppercase()).collect();
        let events = self
            .received_events
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        events
            .iter()
            .filter(|event| {
                let kind = event.split_whitespace().next().unwrap_or_default();
                wanted.is_empty() || wanted.iter().any(|name| name == kind)
            })
            .cloned()
            .collect()
    }

    fn clear_events(&self) {
        let mut events = self
            .received_events
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        events.clear();
    }

    async fn watch_events(&self, names: &[&str]) -> Result<()> {
        let previous = self
            .event_listener
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(previous) = previous {
            self.controller.remove_event_listener(previous).await?;
        }
        if names.is_empty() {
            return Ok(());
        }
        let event_types: Vec<EventType> =
            names.iter().map(|name| (*name).into()).collect();
        let backlog = self.received_events.clone();
        let listener = self
            .controller
            .add_event_listener(
                move |event| {
                    let mut events =
                        backlog.lock().unwrap_or_else(|error| error.into_inner());
                    events.push_front(event.message.to_string());
                    events.truncate(MAX_EVENTS);
                },
                &event_types,
            )
            .await?;
        *self
            .event_listener
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(listener);
        Ok(())
    }

    fn do_events(&self, argument: &str) -> String {
        let names: Vec<&str> = argument.split_whitespace().collect();
        if names.iter().any(|name| name.eq_ignore_ascii_case("CLEAR")) {
            self.clear_events();
            return format_terminal("cleared event backlog", STANDARD_OUTPUT);
        }
        self.events(&names)
            .iter()
            .map(|event| format_terminal(event, STANDARD_OUTPUT))
            .collect::<Vec<_>>()
            .join("\n")
    }

    async fn do_info(&self, argument: &str) -> String {
        match self.describe_relay(argument).await {
            Ok(lines) => lines.join("\n"),
            Err(error) => format_terminal(&error.to_string(), ERROR_OUTPUT),
        }
    }

    async fn describe_relay(&self, argument: &str) -> Result<Vec<String>> {
        let fingerprint = resolve_fingerprint(self.controller, argument).await?;
        let status = self
            .controller
            .get_network_status(Some(&fingerprint))
            .await
            .map_err(|_| {
                Error::invalid_input(format!(
                    "Unable to find consensus information for {fingerprint}"
                ))
            })?;
        let mut server = self
            .controller
            .get_server_descriptor(Some(&fingerprint))
            .await
            .ok();
        let mut extrainfo = None;
        let micro = self
            .controller
            .get_microdescriptor(Some(&fingerprint))
            .await
            .ok();
        let mut downloader = DescriptorDownloader::new();
        downloader.default_timeout = Some(Duration::from_secs(5));
        let hashes = [fingerprint.as_str()];
        for descriptor in downloaded(downloader.get_server_descriptors(&hashes)).await {
            if let Descriptor::RelayServer(descriptor) = descriptor {
                server = Some(*descriptor);
            }
        }
        for descriptor in downloaded(downloader.get_extrainfo_descriptors(&hashes)).await
        {
            if let Descriptor::RelayExtraInfo(descriptor) = descriptor {
                extrainfo = Some(*descriptor);
            }
        }
        let address = status.address.clone().unwrap_or_default();
        let country = self
            .controller
            .get_info(&format!("ip-to-country/{address}"))
            .await
            .ok();
        let address_label = country
            .map(|country| format!(" ({country})"))
            .unwrap_or_default();
        let exit_policy = match (&server, &micro) {
            (Some(server), _) => server.exit_policy.to_string(),
            (None, Some(micro)) => micro.exit_policy.to_string(),
            _ => "Unknown".to_string(),
        };
        let mut lines = vec![
            format!(
                "{} ({fingerprint})",
                status.nickname.clone().unwrap_or_default()
            ),
            labeled(
                "address: ",
                &format!(
                    "{address}:{}{address_label}",
                    status.or_port.unwrap_or_default()
                ),
            ),
        ];
        if let Some(version) = server
            .as_ref()
            .and_then(|server| server.tor_version.as_ref())
        {
            lines.push(labeled("tor version: ", &version.to_string()));
        }
        lines.push(labeled("flags: ", &status.flags.join(", ")));
        lines.push(labeled("exit policy: ", &exit_policy));
        if let Some(contact) =
            server.as_ref().and_then(|server| server.contact.as_deref())
        {
            lines.push(labeled("contact: ", &readable_contact(contact)));
        }
        let sections = [
            (
                "Server Descriptor:",
                server.map(|server| server.common.raw_contents),
            ),
            (
                "Extrainfo Descriptor:",
                extrainfo.map(|extrainfo| extrainfo.common.raw_contents),
            ),
            ("Microdescriptor:", micro.map(|micro| micro.raw_contents)),
            (
                "Router Status Entry:",
                Some(status.common.raw_contents.clone()),
            ),
        ];
        let divider = format_terminal(&"-".repeat(80), STANDARD_OUTPUT);
        for (label, contents) in sections {
            let Some(contents) = contents else {
                continue;
            };
            lines.extend(["".to_string(), divider.clone()]);
            lines.extend([
                format_terminal(label, BOLD_OUTPUT),
                divider.clone(),
                String::new(),
            ]);
            let text = String::from_utf8_lossy(&contents).into_owned();
            lines.extend(
                text.lines()
                    .map(|line| format_terminal(line, STANDARD_OUTPUT)),
            );
        }
        Ok(lines)
    }

    async fn run_tor_command(&self, command: &str, keyword: &str) -> Result<String> {
        if keyword == "SETEVENTS" {
            let names: Vec<&str> = command.split_whitespace().skip(1).collect();
            self.watch_events(&names).await?;
            return Ok(format_terminal("250 OK", STANDARD_OUTPUT));
        }
        let response = self.controller.msg(command).await?;
        Ok(format_terminal(
            response.raw_content().trim(),
            STANDARD_OUTPUT,
        ))
    }

    pub async fn run_command(&self, command: &str) -> Result<String> {
        let command = command.trim();
        if command.is_empty() {
            return Ok(String::new());
        }
        let (keyword, argument) = command.split_once(' ').unwrap_or((command, ""));
        let output = match keyword.starts_with('/') {
            true => {
                self.run_interpreter_command(command, keyword, argument)
                    .await?
            }
            false => {
                self.run_raw_command(command, &keyword.to_uppercase())
                    .await?
            }
        };
        match output.is_empty() {
            true => Ok(output),
            false => Ok(output + "\n"),
        }
    }

    async fn run_interpreter_command(
        &self,
        command: &str,
        keyword: &str,
        argument: &str,
    ) -> Result<String> {
        Ok(match keyword.to_lowercase().as_str() {
            "/quit" => return Err(Error::SocketClosed),
            "/events" => self.do_events(argument),
            "/info" => self.do_info(argument).await,
            "/help" => help_response(self.controller, argument).await,
            _ => format_terminal(
                &format!("'{command}' isn't a recognized command"),
                ERROR_OUTPUT,
            ),
        })
    }

    async fn run_raw_command(&self, command: &str, keyword: &str) -> Result<String> {
        if matches!(
            keyword.replace('+', "").as_str(),
            "LOADCONF" | "POSTDESCRIPTOR"
        ) {
            return Ok(format_terminal(
                &message("msg.multiline_unimplemented_notice", &[]),
                ERROR_OUTPUT,
            ));
        }
        if keyword == "QUIT" {
            self.controller.msg(command).await?;
            return Err(Error::SocketClosed);
        }
        match self.run_tor_command(command, keyword).await {
            Err(Error::SocketClosed) => Err(Error::SocketClosed),
            Err(error) => Ok(format_terminal(&error.to_string(), ERROR_OUTPUT)),
            Ok(output) => Ok(output),
        }
    }
}

async fn downloaded(query: Result<crate::descriptor::remote::Query>) -> Vec<Descriptor> {
    match query {
        Ok(query) => query.run().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

struct PromptHelper {
    autocompleter: Autocompleter,
}

impl Completer for PromptHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        position: usize,
        _context: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let prefix = &line[..position];
        let pairs = self
            .autocompleter
            .matches(prefix)
            .into_iter()
            .map(|command| Pair {
                display: command.to_string(),
                replacement: command.to_string(),
            })
            .collect();
        Ok((0, pairs))
    }
}

impl Hinter for PromptHelper {
    type Hint = String;
}

impl Highlighter for PromptHelper {}
impl Validator for PromptHelper {}
impl Helper for PromptHelper {}

fn print_styled(text: &str, styles: &[TerminalStyle]) {
    println!("{}", format_terminal(text, styles));
}

async fn launch_temporary_tor(
    arguments: &Arguments,
) -> Result<Option<tokio::process::Child>> {
    let running = is_running(&["tor", "tor.real"]).unwrap_or(false);
    if running {
        return Ok(None);
    }
    if arguments.tor_path == "tor" && !is_available("tor") {
        return Err(Error::invalid_input(message("msg.tor_unavailable", &[])));
    }
    if arguments.run_command.is_none() && arguments.run_path.is_none() {
        print_styled(&message("msg.starting_tor", &[]), HEADER_OUTPUT);
    }
    let port = arguments.control_port.unwrap_or(9051).to_string();
    let config = [
        ("SocksPort", "0"),
        ("ControlPort", port.as_str()),
        ("CookieAuthentication", "1"),
        ("ExitPolicy", "reject *:*"),
    ];
    let options = LaunchOptions {
        tor_command: arguments.tor_path.clone(),
        completion_percent: 5,
        take_ownership: true,
        ..LaunchOptions::default()
    };
    let child = launch_tor_with_config(&config, options, None)
        .await
        .map_err(|error| {
            Error::invalid_input(message(
                "msg.unable_to_start_tor",
                &[("error", &error.to_string())],
            ))
        })?;
    Ok(Some(child))
}

fn connect_options(arguments: &Arguments) -> ConnectOptions {
    let port = (!arguments.user_provided_socket || arguments.user_provided_port)
        .then_some((
            IpAddr::V4(arguments.control_address),
            arguments.control_port,
        ));
    let socket = (!arguments.user_provided_port || arguments.user_provided_socket)
        .then(|| arguments.control_socket.clone());
    ConnectOptions {
        control_port: port,
        control_socket: socket,
        password_prompt: true,
        ..ConnectOptions::default()
    }
}

async fn run_event_listener(controller: &Controller, command: &str) -> Result<()> {
    let names: Vec<String> = command
        .split_whitespace()
        .skip(1)
        .map(str::to_uppercase)
        .collect();
    let events: Vec<EventType> = names.iter().map(|name| name.as_str().into()).collect();
    if std::io::stdout().is_terminal() {
        let notice = format!(
            "Listening to {} events. Press any key to quit.\n",
            names.join(" ")
        );
        print_styled(&notice, HEADER_BOLD_OUTPUT);
    }
    controller
        .add_event_listener(
            |event| print_styled(&event.message.to_string(), STANDARD_OUTPUT),
            &events,
        )
        .await?;
    let mut line = String::new();
    let _ = tokio::io::AsyncBufReadExt::read_line(
        &mut tokio::io::BufReader::new(tokio::io::stdin()),
        &mut line,
    )
    .await;
    Ok(())
}

async fn run_batch(interpreter: &ControlInterpreter<'_>, arguments: &Arguments) -> i32 {
    if let Some(command) = &arguments.run_command {
        if command.to_uppercase().starts_with("SETEVENTS ") {
            let outcome = run_event_listener(interpreter.controller, command).await;
            return i32::from(outcome.is_err());
        }
        return print_outcome(interpreter.run_command(command).await);
    }
    let Some(path) = &arguments.run_path else {
        return 0;
    };
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) => {
            let text = message(
                "msg.unable_to_read_file",
                &[
                    ("path", &path.to_string_lossy()),
                    ("error", &error.to_string()),
                ],
            );
            print_styled(&text, ERROR_OUTPUT);
            return 1;
        }
    };
    for line in content.lines() {
        let outcome = interpreter.run_command(line.trim()).await;
        if outcome.as_ref().is_err_and(Error::is_socket_closed) {
            return 1;
        }
        print_outcome(outcome);
    }
    0
}

fn print_outcome(outcome: Result<String>) -> i32 {
    match outcome {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
            0
        }
        Err(error) if error.is_socket_closed() => 1,
        Err(error) => {
            print_styled(&error.to_string(), ERROR_OUTPUT);
            1
        }
    }
}

fn print_banner() {
    for line in message("msg.startup_banner", &[]).lines() {
        let styles = match line.starts_with("  ") {
            true => HEADER_BOLD_OUTPUT,
            false => HEADER_OUTPUT,
        };
        print_styled(line, styles);
    }
    println!();
}

fn ask_to_continue(
    editor: &mut Editor<PromptHelper, rustyline::history::DefaultHistory>,
) -> bool {
    let prompt = format_terminal(
        "Tor's control port has closed. Do you want to continue this interpreter? (y/n) ",
        HEADER_BOLD_OUTPUT,
    );
    let answer = tokio::task::block_in_place(|| editor.readline(&prompt));
    println!();
    answer.is_ok_and(|answer| matches!(answer.to_lowercase().as_str(), "y" | "yes"))
}

async fn run_interactive(controller: &Controller, prompt: &str) -> Result<()> {
    let interpreter = ControlInterpreter::new(controller);
    let autocompleter = Autocompleter::new(Some(controller)).await;
    let mut editor = Editor::new().map_err(|error| Error::Socket(error.to_string()))?;
    editor.set_helper(Some(PromptHelper { autocompleter }));
    print_banner();
    let mut showed_close_confirmation = false;
    loop {
        let line = tokio::task::block_in_place(|| editor.readline(prompt));
        let input = match line {
            Ok(input) => input,
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                println!();
                return Ok(());
            }
            Err(error) => return Err(Error::Io(std::io::Error::other(error))),
        };
        let _ = editor.add_history_entry(input.as_str());
        match interpreter.run_command(&input).await {
            Ok(output) => {
                if !output.is_empty() {
                    println!("{output}");
                }
            }
            Err(error) if error.is_socket_closed() => {
                if showed_close_confirmation {
                    let text = "Unable to run tor commands. The control connection has \
                        been closed.";
                    print_styled(text, ERROR_OUTPUT);
                    continue;
                }
                if !ask_to_continue(&mut editor) {
                    return Ok(());
                }
                showed_close_confirmation = true;
            }
            Err(error) => print_styled(&error.to_string(), ERROR_OUTPUT),
        }
    }
}

pub async fn run(argv: &[String]) -> i32 {
    let arguments = match Arguments::parse(argv) {
        Ok(arguments) => arguments,
        Err(error) => {
            println!("{error}");
            return 1;
        }
    };
    if arguments.print_help {
        println!("{}", help_text());
        return 0;
    }
    let interactive_output = std::io::stdout().is_terminal();
    if arguments.disable_color || !interactive_output {
        set_color_support_disabled(true);
    }
    let prompt = match arguments.disable_color || !interactive_output {
        true => PROMPT.to_string(),
        false => format_terminal(PROMPT, PROMPT_STYLES),
    };
    let _tor = match arguments.user_provided_port || arguments.user_provided_socket {
        true => None,
        false => match launch_temporary_tor(&arguments).await {
            Ok(child) => child,
            Err(error) => {
                print_styled(&error.to_string(), ERROR_OUTPUT);
                return 1;
            }
        },
    };
    let controller = match connect(connect_options(&arguments)).await {
        Ok(controller) => controller,
        Err(error) => {
            println!("{error}");
            return 1;
        }
    };
    let status = match (&arguments.run_command, &arguments.run_path) {
        (None, None) => match run_interactive(&controller, &prompt).await {
            Ok(()) => 0,
            Err(error) => {
                print_styled(&error.to_string(), ERROR_OUTPUT);
                1
            }
        },
        _ => run_batch(&ControlInterpreter::new(&controller), &arguments).await,
    };
    controller.close().await;
    status
}
