use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

use crate::error::{Error, Result};
use crate::process_inspection::is_available;
use crate::version::{Requirement, get_system_tor_version_with_environment};

pub const DEFAULT_INIT_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Clone)]
pub enum TorrcSource {
    None,
    Empty,
    Path(PathBuf),
}

pub struct LaunchOptions {
    pub tor_command: String,
    pub args: Vec<String>,
    pub torrc: TorrcSource,
    pub completion_percent: u32,
    pub timeout: Option<Duration>,
    pub take_ownership: bool,
    pub close_output: bool,
    pub stdin: Option<String>,
    pub environment: Vec<(String, String)>,
}

impl Default for LaunchOptions {
    fn default() -> Self {
        Self {
            tor_command: "tor".to_string(),
            args: Vec::new(),
            torrc: TorrcSource::None,
            completion_percent: 100,
            timeout: Some(DEFAULT_INIT_TIMEOUT),
            take_ownership: false,
            close_output: true,
            stdin: None,
            environment: Vec::new(),
        }
    }
}

pub type InitHandler<'a> = Option<&'a mut (dyn FnMut(&str) + Send)>;

fn bootstrap_percent(line: &str) -> Option<u32> {
    let rest = line.split_once("Bootstrapped ")?.1;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    match rest[digits.len()..].starts_with('%') {
        true => digits.parse().ok(),
        false => None,
    }
}

fn problem_message(line: &str) -> Option<String> {
    let rest = line
        .split_once("[warn] ")
        .or_else(|| line.split_once("[err] "))?
        .1;
    match rest.contains("see warnings above") {
        true => None,
        false => Some(rest.rsplit(": ").next().unwrap_or(rest).trim().to_string()),
    }
}

fn check_tor_command(tor_command: &str) -> Result<()> {
    if tor_command.contains(std::path::MAIN_SEPARATOR) {
        let path = Path::new(tor_command);
        if path.is_dir() {
            return Err(launch_error(format!(
                "'{tor_command}' is a directory, not the tor executable"
            )));
        }
        if !path.is_file() {
            return Err(launch_error(format!("'{tor_command}' doesn't exist")));
        }
        return Ok(());
    }
    match is_available(tor_command) {
        true => Ok(()),
        false => Err(launch_error(format!(
            "'{tor_command}' isn't available on your system. Maybe it's not in your PATH?"
        ))),
    }
}

fn launch_error(message: String) -> Error {
    Error::Io(std::io::Error::other(message))
}

fn create_empty_torrc() -> Result<PathBuf> {
    use std::io::Write;
    let mut attempt = 0;
    loop {
        let suffix: u64 = rand::random();
        let path = std::env::temp_dir().join(format!("empty-torrc-{suffix:016x}"));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                file.flush()?;
                return Ok(path);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::AlreadyExists && attempt < 8 =>
            {
                attempt += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub async fn launch_tor(
    options: LaunchOptions,
    init_handler: InitHandler<'_>,
) -> Result<Child> {
    check_tor_command(&options.tor_command)?;
    if let TorrcSource::Path(path) = &options.torrc
        && !path.exists()
    {
        return Err(launch_error(format!(
            "torrc doesn't exist ({})",
            path.display()
        )));
    }
    let mut arguments = options.args.clone();
    let mut temporary_torrc = None;
    match &options.torrc {
        TorrcSource::None => {}
        TorrcSource::Empty => {
            let path = create_empty_torrc()?;
            arguments.extend(["-f".to_string(), path.to_string_lossy().into_owned()]);
            temporary_torrc = Some(path);
        }
        TorrcSource::Path(path) => {
            arguments.extend(["-f".to_string(), path.to_string_lossy().into_owned()])
        }
    }
    if options.take_ownership {
        arguments.extend([
            "__OwningControllerProcess".to_string(),
            std::process::id().to_string(),
        ]);
    }
    let outcome = spawn_and_wait(&options, &arguments, init_handler).await;
    if let Some(path) = temporary_torrc {
        let _ = std::fs::remove_file(path);
    }
    outcome
}

async fn spawn_and_wait(
    options: &LaunchOptions,
    arguments: &[String],
    mut init_handler: InitHandler<'_>,
) -> Result<Child> {
    let mut child = Command::new(&options.tor_command)
        .args(arguments)
        .envs(options.environment.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let waited = wait_for_bootstrap(&mut child, options, &mut init_handler);
    let result = match options.timeout {
        Some(limit) => match tokio::time::timeout(limit, waited).await {
            Ok(result) => result,
            Err(_) => Err(launch_error(format!(
                "reached a {} second timeout without success",
                limit.as_secs()
            ))),
        },
        None => waited.await,
    };
    match result {
        Ok(()) => {
            if options.close_output {
                child.stdout.take();
                child.stderr.take();
            }
            Ok(child)
        }
        Err(error) => {
            let _ = child.kill().await;
            Err(error)
        }
    }
}

async fn wait_for_bootstrap(
    child: &mut Child,
    options: &LaunchOptions,
    init_handler: &mut InitHandler<'_>,
) -> Result<()> {
    let mut stdin = child.stdin.take();
    if let (Some(content), Some(pipe)) = (&options.stdin, stdin.as_mut()) {
        pipe.write_all(content.as_bytes()).await?;
    }
    drop(stdin);
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| launch_error("tor has no stdout".into()))?;
    let mut lines = BufReader::new(stdout).lines();
    let mut last_problem = "Timed out".to_string();
    loop {
        let Some(line) = lines.next_line().await? else {
            return Err(launch_error(format!("Process terminated: {last_problem}")));
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            return Err(launch_error(format!("Process terminated: {last_problem}")));
        }
        if let Some(handler) = init_handler.as_mut() {
            handler(&line);
        }
        if let Some(percent) = bootstrap_percent(&line)
            && percent >= options.completion_percent
        {
            child.stdout = Some(lines.into_inner().into_inner());
            return Ok(());
        }
        if let Some(problem) = problem_message(&line) {
            last_problem = problem;
        }
    }
}

pub type TorConfig<'a> = &'a [(&'a str, &'a str)];

fn render_config(config: TorConfig<'_>) -> Result<String> {
    let mut entries: Vec<(&str, &str)> = config.to_vec();
    let has_log = entries.iter().any(|(key, _)| *key == "Log");
    let has_stdout = entries.iter().any(|(key, value)| {
        *key == "Log"
            && matches!(*value, "DEBUG stdout" | "INFO stdout" | "NOTICE stdout")
    });
    if has_log && !has_stdout {
        entries.push(("Log", "NOTICE stdout"));
    }
    let mut rendered = String::new();
    for (key, value) in entries {
        let key_is_valid = !key.is_empty()
            && key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if !key_is_valid || value.contains(['\n', '\r', '\0']) {
            return Err(Error::invalid_input(format!(
                "Invalid torrc entry (keys must be alphanumeric and values \
                single-line): {key}"
            )));
        }
        rendered.push_str(&format!("{key} {value}\n"));
    }
    Ok(rendered)
}

pub async fn launch_tor_with_config(
    config: TorConfig<'_>,
    mut options: LaunchOptions,
    init_handler: InitHandler<'_>,
) -> Result<Child> {
    let rendered = render_config(config)?;
    let supports_stdin = get_system_tor_version_with_environment(
        &options.tor_command,
        &options.environment,
    )
    .is_ok_and(|version| version.meets(Requirement::TorrcViaStdin));
    if supports_stdin {
        options.args.extend(["-f".to_string(), "-".to_string()]);
        options.stdin = Some(rendered);
        return launch_tor(options, init_handler).await;
    }
    let path = create_empty_torrc()?;
    std::fs::write(&path, rendered)?;
    options
        .args
        .extend(["__ReloadTorrcOnSIGHUP".to_string(), "0".to_string()]);
    options.torrc = TorrcSource::Path(path.clone());
    let outcome = launch_tor(options, init_handler).await;
    let _ = std::fs::remove_file(path);
    outcome
}
