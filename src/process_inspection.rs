use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use regex::Regex;

use crate::error::{Error, Result};
use crate::formatting::parse_short_time_label;

const CLOCK_TICKS: f64 = 100.0;
const TAIL_BLOCK_SIZE: u64 = 1024;
const COMMON_NAME_LENGTH: usize = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Connection {
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub is_ipv6: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resolver {
    Proc,
    Netstat,
    NetstatWindows,
    Ss,
    Lsof,
    Sockstat,
    BsdSockstat,
    BsdProcstat,
    BsdFstat,
}

impl Resolver {
    pub fn command(&self) -> &'static str {
        match self {
            Resolver::Proc => "",
            Resolver::Netstat => "netstat -npW",
            Resolver::NetstatWindows => "netstat -ano",
            Resolver::Ss => "ss -nptu",
            Resolver::Lsof => "lsof +c 0 -wnPi",
            Resolver::Sockstat => "sockstat",
            Resolver::BsdSockstat => "sockstat -4c",
            Resolver::BsdProcstat => "procstat -f {pid}",
            Resolver::BsdFstat => "fstat -p {pid}",
        }
    }

    fn filter(&self) -> &'static str {
        match self {
            Resolver::Proc => "",
            Resolver::Netstat => {
                r"^{protocol}\s+.*\s+{local}\s+{remote}\s+ESTABLISHED\s+{pid}/{name}\s*$"
            }
            Resolver::NetstatWindows => {
                r"^\s*{protocol}\s+{local}\s+{remote}\s+ESTABLISHED\s+{pid}\s*$"
            }
            Resolver::Ss => {
                concat!(
                    r#"^{protocol}\s+ESTAB\s+.*\s+{local}\s+{remote}\s+"#,
                    r#"users:\(\("{name}",(?:pid=)?{pid},(?:fd=)?[0-9]+\)\)$"#
                )
            }
            Resolver::Lsof => {
                r"^{name}\s+{pid}\s+.*\s+{protocol}\s+{local}->{remote} \(ESTABLISHED\)$"
            }
            Resolver::Sockstat => {
                r"^\S+\s+{name}\s+{pid}\s+{protocol}4\s+{local}\s+{remote}\s+ESTABLISHED$"
            }
            Resolver::BsdSockstat => {
                r"^\S+\s+{name}\s+{pid}\s+\S+\s+{protocol}4\s+{local}\s+{remote}$"
            }
            Resolver::BsdProcstat => {
                r"^\s*{pid}\s+{name}\s+.*\s+{protocol}\s+{local}\s+{remote}$"
            }
            Resolver::BsdFstat => {
                concat!(
                    r"^\S+\s+{name}\s+{pid}\s+.*\s+{protocol}\s+\S+\s+{local}\s+",
                    r"[-<]-[->]\s+{remote}$"
                )
            }
        }
    }

    fn requires_pid(&self) -> bool {
        matches!(
            self,
            Resolver::NetstatWindows | Resolver::Proc | Resolver::BsdProcstat
        )
    }
}

pub fn is_windows() -> bool {
    cfg!(windows)
}

pub fn is_mac() -> bool {
    cfg!(target_os = "macos")
}

pub fn is_bsd() -> bool {
    cfg!(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))
}

pub fn is_gentoo() -> bool {
    Path::new("/etc/gentoo-release").exists()
}

pub fn is_slackware() -> bool {
    Path::new("/etc/slackware-version").exists()
}

pub fn is_available(command: &str) -> bool {
    static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    let name = command.split(' ').next().unwrap_or_default();
    if name == "ulimit" {
        return true;
    }
    let cache = CACHE.get_or_init(Default::default);
    if let Some(known) = cache.lock().unwrap().get(name) {
        return *known;
    }
    let found = std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths)
            .any(|directory| is_executable(&directory.join(name)))
    });
    cache.lock().unwrap().insert(name.to_string(), found);
    found
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata().is_ok_and(|metadata| {
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    })
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.with_extension("exe").is_file() || path.is_file()
}

pub fn call(command: &[&str], timeout: Option<Duration>) -> Result<Vec<String>> {
    call_with_options(command, false, timeout)
}

pub fn call_with_options(
    command: &[&str],
    ignore_exit_status: bool,
    timeout: Option<Duration>,
) -> Result<Vec<String>> {
    call_with_environment(command, ignore_exit_status, timeout, &[])
}

pub fn call_with_environment(
    command: &[&str],
    ignore_exit_status: bool,
    timeout: Option<Duration>,
    environment: &[(&str, &str)],
) -> Result<Vec<String>> {
    let Some((program, arguments)) = command.split_first() else {
        return Err(Error::invalid_input("An empty command can't be run"));
    };
    let started = Instant::now();
    let mut child = Command::new(program)
        .args(arguments)
        .envs(environment.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            log::debug!(
                "System call (failed): {} (error: {error})",
                command.join(" ")
            );
            Error::Io(error)
        })?;
    let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
    let stdout_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buffer);
        buffer
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buffer);
        buffer
    });
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None => {
                if timeout.is_some_and(|limit| started.elapsed() > limit) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::Timeout(format!(
                        "Process didn't finish after {:.1} seconds",
                        timeout.map_or(0.0, |limit| limit.as_secs_f64())
                    )));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    };
    let stdout = stdout_reader.join().unwrap_or_default();
    let _ = stderr_reader.join();
    log::debug!(
        "System call: {} (runtime: {:.2})",
        command.join(" "),
        started.elapsed().as_secs_f64()
    );
    if !ignore_exit_status && !status.success() {
        return Err(Error::Io(std::io::Error::other(format!(
            "{} returned exit status {}",
            command.join(" "),
            status.code().unwrap_or(-1)
        ))));
    }
    Ok(String::from_utf8_lossy(&stdout)
        .trim()
        .lines()
        .map(str::to_string)
        .collect())
}

fn quiet_call(command: &[&str]) -> Option<Vec<String>> {
    call(command, None).ok().filter(|lines| !lines.is_empty())
}

pub fn is_running_pid(pid: u32) -> bool {
    match cfg!(target_os = "linux") {
        true => Path::new(&format!("/proc/{pid}")).exists(),
        false => quiet_call(&["ps", "-p", &pid.to_string(), "-o", "pid="]).is_some(),
    }
}

pub fn is_running(commands: &[&str]) -> Option<bool> {
    if !is_available("ps") {
        return None;
    }
    let (primary, secondary): (&[&str], &[&str]) = match is_bsd() {
        true => (&["ps", "-ao", "ucomm="], &["ps", "-A", "co", "command"]),
        false => (&["ps", "-A", "co", "command"], &["ps", "-ao", "ucomm="]),
    };
    let listing = quiet_call(primary).or_else(|| quiet_call(secondary))?;
    let names: HashSet<String> =
        listing.iter().map(|line| line.trim().to_string()).collect();
    Some(commands.iter().any(|command| names.contains(*command)))
}

fn proc_directory_pids() -> Vec<u32> {
    fs::read_dir("/proc")
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

pub fn is_proc_available() -> bool {
    cfg!(target_os = "linux")
        && [
            "/proc/stat",
            "/proc/meminfo",
            "/proc/net/tcp",
            "/proc/net/udp",
        ]
        .iter()
        .all(|path| Path::new(path).exists())
}

pub fn name_by_pid(pid: u32) -> Option<String> {
    if is_proc_available()
        && let Ok(stats) = process_stats(pid)
    {
        return Some(stats.command);
    }
    let results = call(&["ps", "-p", &pid.to_string(), "-o", "comm"], None).ok()?;
    match results.as_slice() {
        [header, name] if header == "COMMAND" => Some(name.trim().to_string()),
        _ => None,
    }
}

fn parse_pids(lines: &[String]) -> Option<Vec<u32>> {
    lines.iter().map(|line| line.trim().parse().ok()).collect()
}

fn select_pids(pids: Vec<u32>, multiple: bool) -> Option<Vec<u32>> {
    match multiple || pids.len() == 1 {
        true => Some(pids),
        false => None,
    }
}

fn pids_from_proc_names(process_name: &str) -> Vec<u32> {
    let mut matches: Vec<u32> = proc_directory_pids()
        .into_iter()
        .filter(|pid| {
            fs::read_to_string(format!("/proc/{pid}/comm"))
                .is_ok_and(|comm| comm.trim_end() == process_name)
        })
        .collect();
    matches.sort_unstable();
    matches
}

pub fn pids_by_name(process_name: &str) -> Vec<u32> {
    if process_name.is_empty() || process_name.starts_with('-') {
        return Vec::new();
    }
    if is_proc_available() && process_name.len() <= COMMON_NAME_LENGTH {
        let found = pids_from_proc_names(process_name);
        if !found.is_empty() {
            return found;
        }
    }
    if is_available("pgrep")
        && let Some(lines) = quiet_call(&["pgrep", "-x", process_name])
        && let Some(pids) = parse_pids(&lines)
    {
        return pids;
    }
    if is_available("pidof")
        && let Some(lines) = quiet_call(&["pidof", process_name])
        && lines.len() == 1
        && let Some(pids) = parse_pids(
            &lines[0]
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>(),
        )
    {
        return pids;
    }
    if is_available("ps")
        && !is_bsd()
        && let Some(lines) = quiet_call(&["ps", "-o", "pid", "-C", process_name])
        && let Some(pids) = parse_pids(&lines[1..])
    {
        return pids;
    }
    if is_available("ps") && is_bsd() {
        let suffix = format!(" {process_name}");
        let pids = quiet_call(&["ps", "axc"]).and_then(|lines| {
            let first_columns: Vec<String> = lines
                .iter()
                .filter(|line| line.ends_with(&suffix))
                .filter_map(|line| line.split_whitespace().next().map(str::to_string))
                .collect();
            parse_pids(&first_columns)
        });
        if let Some(pids) = pids.filter(|pids| !pids.is_empty()) {
            return pids;
        }
    }
    if is_available("lsof")
        && let Some(lines) = quiet_call(&["lsof", "-tc", process_name])
        && let Some(pids) = parse_pids(&lines)
    {
        return pids;
    }
    log::debug!("failed to resolve a pid for '{process_name}'");
    Vec::new()
}

pub fn pid_by_name(process_name: &str) -> Option<u32> {
    select_pids(pids_by_name(process_name), false).and_then(|pids| pids.first().copied())
}

fn socket_inodes_listening_on(port: u16) -> HashSet<String> {
    let mut inodes = HashSet::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let local_port = fields
                .get(1)
                .and_then(|local| local.rsplit_once(':'))
                .and_then(|(_, hex)| u16::from_str_radix(hex, 16).ok());
            if fields.get(3) == Some(&"0A")
                && local_port == Some(port)
                && fields.len() > 9
            {
                inodes.insert(fields[9].to_string());
            }
        }
    }
    inodes
}

fn pids_owning_inodes(inodes: &HashSet<String>) -> Vec<u32> {
    let mut owners = Vec::new();
    for pid in proc_directory_pids() {
        let Ok(descriptors) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        let owns = descriptors.flatten().any(|descriptor| {
            fs::read_link(descriptor.path())
                .ok()
                .and_then(|target| target.to_str().map(str::to_string))
                .and_then(|target| {
                    target
                        .strip_prefix("socket:[")
                        .and_then(|rest| rest.strip_suffix(']'))
                        .map(str::to_string)
                })
                .is_some_and(|inode| inodes.contains(&inode))
        });
        if owns {
            owners.push(pid);
        }
    }
    owners
}

pub fn pid_by_port(port: u16) -> Option<u32> {
    if is_proc_available() {
        let inodes = socket_inodes_listening_on(port);
        let owners = match inodes.is_empty() {
            true => Vec::new(),
            false => pids_owning_inodes(&inodes),
        };
        if owners.len() == 1 {
            return owners.first().copied();
        }
    }
    let needle = format!(":{port}");
    if is_available("netstat")
        && let Some(lines) = quiet_call(&["netstat", "-npltu"])
    {
        let matching: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains(&format!("127.0.0.1:{port}")))
            .collect();
        if let [line] = matching.as_slice()
            && let fields = line.split_whitespace().collect::<Vec<_>>()
            && fields.len() == 7
            && let Some((pid, _)) = fields[6].split_once('/')
            && let Ok(pid) = pid.parse()
        {
            return Some(pid);
        }
    }
    if is_available("sockstat")
        && let Some(lines) =
            quiet_call(&["sockstat", "-4l", "-P", "tcp", "-p", &port.to_string()])
    {
        let matching: Vec<Vec<&str>> = lines
            .iter()
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            .filter(|fields| fields.len() == 7 && fields[5].contains(&needle))
            .collect();
        if let [fields] = matching.as_slice()
            && let Ok(pid) = fields[2].parse()
        {
            return Some(pid);
        }
    }
    if is_available("lsof")
        && let Some(lines) = quiet_call(&["lsof", "-wnP", "-iTCP", "-sTCP:LISTEN"])
    {
        let matching: Vec<Vec<&str>> = lines
            .iter()
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            .filter(|fields| fields.len() == 10 && fields[8].contains(&needle))
            .collect();
        if let [fields] = matching.as_slice()
            && let Ok(pid) = fields[1].parse()
        {
            return Some(pid);
        }
    }
    None
}

pub fn pid_by_open_file(path: &Path) -> Option<u32> {
    if is_proc_available() {
        let target = fs::canonicalize(path).ok()?;
        let owners: Vec<u32> = proc_directory_pids()
            .into_iter()
            .filter(|pid| {
                fs::read_dir(format!("/proc/{pid}/fd")).is_ok_and(|descriptors| {
                    descriptors.flatten().any(|descriptor| {
                        fs::read_link(descriptor.path()).ok().as_ref() == Some(&target)
                    })
                })
            })
            .collect();
        if owners.len() == 1 {
            return owners.first().copied();
        }
    }
    if !is_available("lsof") {
        return None;
    }
    let lines = call(&["lsof", "-tw", &path.to_string_lossy()], None).ok()?;
    match lines.as_slice() {
        [line] => line.trim().parse().ok(),
        _ => None,
    }
}

pub fn pids_by_user(user: &str) -> Option<Vec<u32>> {
    if !is_available("ps") {
        return None;
    }
    let flag = if is_bsd() { "-U" } else { "-u" };
    let lines = quiet_call(&["ps", "-o", "pid", flag, user])?;
    parse_pids(&lines[1..])
}

pub fn cwd(pid: u32) -> Option<PathBuf> {
    if is_proc_available()
        && let Ok(path) = proc_cwd(pid)
    {
        return Some(path);
    }
    let prefix = format!("{pid}: ");
    if is_available("pwdx")
        && let Some(lines) = quiet_call(&["pwdx", &pid.to_string()])
        && let [line] = lines.as_slice()
        && line.starts_with(&prefix)
        && line.matches(' ').count() == 1
    {
        return Some(PathBuf::from(line.split_once(' ')?.1.trim()));
    }
    if is_available("lsof")
        && let Ok(lines) = call(
            &["lsof", "-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"],
            None,
        )
        && lines.len() >= 2
        && let Some(path) = lines.last().and_then(|line| line.strip_prefix('n'))
        && path.starts_with('/')
        && !path.contains(' ')
    {
        return Some(PathBuf::from(path.trim()));
    }
    None
}

fn find_line(path: &str, prefix: &str) -> Result<String> {
    let content = fs::read_to_string(path)?;
    content
        .lines()
        .find(|line| line.starts_with(prefix))
        .map(str::to_string)
        .ok_or_else(|| {
            Error::Io(std::io::Error::other(format!(
                "{path} did not contain a {prefix} entry"
            )))
        })
}

pub fn system_start_time() -> Result<f64> {
    let line = find_line("/proc/stat", "btime")?;
    line.split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            Error::parse(format!(
                "unable to parse the /proc/stat btime entry: {line}"
            ))
        })
}

pub fn physical_memory() -> Result<u64> {
    let line = find_line("/proc/meminfo", "MemTotal:")?;
    line.split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
        .map(|kilobytes| kilobytes * 1024)
        .ok_or_else(|| {
            Error::parse(format!(
                "unable to parse the /proc/meminfo MemTotal entry: {line}"
            ))
        })
}

pub fn proc_cwd(pid: u32) -> Result<PathBuf> {
    if pid == 0 {
        return Ok(PathBuf::new());
    }
    Ok(fs::read_link(format!("/proc/{pid}/cwd"))?)
}

pub fn proc_uid(pid: u32) -> Result<u32> {
    let path = format!("/proc/{pid}/status");
    let line = find_line(&path, "Uid:")?;
    line.split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            Error::parse(format!("unable to parse the {path} Uid entry: {line}"))
        })
}

pub fn memory_usage(pid: u32) -> Result<(u64, u64)> {
    if pid == 0 {
        return Ok((0, 0));
    }
    let path = format!("/proc/{pid}/status");
    let kilobytes = |prefix: &str| -> Result<u64> {
        let line = find_line(&path, prefix)?;
        line.split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u64>().ok())
            .map(|value| value * 1024)
            .ok_or_else(|| {
                Error::parse(format!("unable to parse the {path} {prefix} entry: {line}"))
            })
    };
    Ok((kilobytes("VmRSS:")?, kilobytes("VmSize:")?))
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessStats {
    pub command: String,
    pub cpu_user_time: f64,
    pub cpu_system_time: f64,
    pub start_time: f64,
}

pub fn process_stats(pid: u32) -> Result<ProcessStats> {
    if pid == 0 {
        return Ok(ProcessStats {
            command: "sched".to_string(),
            cpu_user_time: 0.0,
            cpu_system_time: 0.0,
            start_time: system_start_time()?,
        });
    }
    let path = format!("/proc/{pid}/stat");
    let line = fs::read_to_string(&path)?;
    let unexpected =
        || Error::parse(format!("stat file had an unexpected format: {path}"));
    let command_start = line.find('(').ok_or_else(unexpected)?;
    let command_end = line.rfind(')').ok_or_else(unexpected)?;
    let command = line[command_start + 1..command_end].to_string();
    let fields: Vec<&str> = line[command_end + 1..].split_whitespace().collect();
    let tick_field = |index: usize| -> Result<f64> {
        fields
            .get(index)
            .and_then(|field| field.parse::<f64>().ok())
            .ok_or_else(unexpected)
    };
    Ok(ProcessStats {
        command,
        cpu_user_time: tick_field(11)? / CLOCK_TICKS,
        cpu_system_time: tick_field(12)? / CLOCK_TICKS,
        start_time: tick_field(19)? / CLOCK_TICKS + system_start_time()?,
    })
}

pub fn file_descriptors_used(pid: u32) -> Result<usize> {
    Ok(fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|error| {
            Error::Io(std::io::Error::other(format!(
                "Unable to check number of file descriptors used: {error}"
            )))
        })?
        .count())
}

fn passwd_field(
    path: &str,
    matcher: impl Fn(&[&str]) -> Option<String>,
) -> Option<String> {
    fs::read_to_string(path)
        .ok()?
        .lines()
        .find_map(|line| matcher(&line.split(':').collect::<Vec<_>>()))
}

pub fn user(pid: u32) -> Option<String> {
    if is_proc_available()
        && let Ok(uid) = proc_uid(pid)
    {
        let found = passwd_field("/etc/passwd", |fields| {
            (fields.get(2).and_then(|value| value.parse::<u32>().ok()) == Some(uid))
                .then(|| fields[0].to_string())
        });
        if found.is_some() {
            return found;
        }
    }
    if !is_available("ps") {
        return None;
    }
    let lines = call(&["ps", "-o", "user", &pid.to_string()], None).ok()?;
    (lines.len() >= 2).then(|| lines[1].trim().to_string())
}

fn uid_for_user(user: &str) -> Option<u32> {
    passwd_field("/etc/passwd", |fields| {
        (fields.first() == Some(&user))
            .then(|| fields.get(2).map(|uid| uid.to_string()))?
    })
    .and_then(|uid| uid.parse().ok())
}

pub fn start_time(pid: u32) -> Option<f64> {
    if is_proc_available()
        && let Ok(stats) = process_stats(pid)
    {
        return Some(stats.start_time);
    }
    let lines = call(&["ps", "-p", &pid.to_string(), "-o", "etime"], None).ok()?;
    let elapsed = parse_short_time_label(lines.get(1)?.trim()).ok()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs_f64();
    Some(now - elapsed as f64)
}

pub fn tail(path: &Path, lines: Option<usize>) -> Result<Vec<String>> {
    let mut file = fs::File::open(path)?;
    let length = file.metadata()?.len();
    let mut remaining = lines.unwrap_or(usize::MAX);
    let mut collected = Vec::new();
    let mut content: Vec<u8> = Vec::new();
    let mut block_end = length;
    while remaining > 0 && block_end > 0 {
        let block_start = block_end.saturating_sub(TAIL_BLOCK_SIZE);
        file.seek(SeekFrom::Start(block_start))?;
        let mut block = vec![0u8; (block_end - block_start) as usize];
        file.read_exact(&mut block)?;
        block.extend_from_slice(&content);
        let completed;
        if block_start > 0 {
            let split = block.iter().position(|byte| *byte == b'\n');
            let Some(split) = split else {
                content = block;
                block_end = block_start;
                continue;
            };
            content = block[..split].to_vec();
            completed = block[split + 1..].to_vec();
        } else {
            content = Vec::new();
            completed = block;
        }
        let text = String::from_utf8_lossy(&completed).into_owned();
        for line in text.lines().rev() {
            if remaining == 0 {
                break;
            }
            remaining -= 1;
            collected.push(line.to_string());
        }
        block_end = block_start;
    }
    Ok(collected)
}

pub fn bsd_jail_id(pid: u32) -> u32 {
    let Ok(lines) = call(&["ps", "-p", &pid.to_string(), "-o", "jid"], None) else {
        return 0;
    };
    match lines.as_slice() {
        [_, jid] if jid.split_whitespace().count() == 1 => {
            jid.trim().parse().unwrap_or(0)
        }
        _ => 0,
    }
}

pub fn bsd_jail_path(jail_id: u32) -> Option<String> {
    if jail_id == 0 {
        return None;
    }
    let lines = call(&["jls", "-j", &jail_id.to_string()], None).ok()?;
    let fields: Vec<&str> = lines.get(1)?.split_whitespace().collect();
    (lines.len() == 2 && fields.len() == 4).then(|| fields[3].to_string())
}

pub fn is_tarfile(path: &Path) -> bool {
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut header = [0u8; 512];
    if file.read_exact(&mut header).is_err() {
        return path.extension().is_some_and(|extension| extension == "tar");
    }
    let magic_matches = &header[257..262] == b"ustar";
    let checksum_field = std::str::from_utf8(&header[148..156])
        .ok()
        .map(|text| text.trim_matches(|c: char| c == '\0' || c == ' '));
    let expected = checksum_field.and_then(|text| u32::from_str_radix(text, 8).ok());
    let actual: u32 = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                32
            } else {
                u32::from(*byte)
            }
        })
        .sum();
    magic_matches || expected == Some(actual)
}

pub fn expand_path(path: &str, cwd: Option<&Path>) -> PathBuf {
    let trimmed = match path.len() > 1 {
        true => path.trim_end_matches('/'),
        false => path,
    };
    if trimmed.is_empty() || Path::new(trimmed).is_absolute() {
        return PathBuf::from(trimmed);
    }
    if let Some(rest) = trimmed.strip_prefix('~')
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest.trim_start_matches('/'));
    }
    let base = cwd
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_default();
    match trimmed.strip_prefix("./").unwrap_or(trimmed) {
        "." | "" => base,
        relative => base.join(relative),
    }
}

pub fn files_with_suffix(base_path: &Path, suffix: &str) -> Vec<PathBuf> {
    if base_path.is_file() {
        return match base_path.to_string_lossy().ends_with(suffix) {
            true => vec![base_path.to_path_buf()],
            false => Vec::new(),
        };
    }
    let mut found = Vec::new();
    let mut pending = vec![base_path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push(path),
                Ok(_) if path.to_string_lossy().ends_with(suffix) => found.push(path),
                _ => {}
            }
        }
    }
    found.sort();
    found
}

fn unpack_address(encoded: &str) -> Option<IpAddr> {
    let mut bytes = hex::decode(encoded).ok()?;
    let is_little_endian = cfg!(target_endian = "little");
    match bytes.len() {
        4 => {
            if is_little_endian {
                bytes.reverse();
            }
            let octets: [u8; 4] = bytes.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        16 => {
            if is_little_endian {
                bytes.chunks_mut(4).for_each(<[u8]>::reverse);
            }
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn socket_inodes(pid: u32) -> Result<HashSet<String>> {
    let descriptors = fs::read_dir(format!("/proc/{pid}/fd")).map_err(|error| {
        Error::Io(std::io::Error::other(format!(
            "Unable to read our file descriptors: {error}"
        )))
    })?;
    let mut inodes = HashSet::new();
    for descriptor in descriptors.flatten() {
        let Ok(target) = fs::read_link(descriptor.path()) else {
            continue;
        };
        let target = target.to_string_lossy().into_owned();
        if let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
        {
            inodes.insert(inode.to_string());
        }
    }
    Ok(inodes)
}

fn parse_proc_endpoint(field: &str) -> Option<(IpAddr, u16)> {
    let (address, port) = field.split_once(':')?;
    Some((
        unpack_address(address)?,
        u16::from_str_radix(port, 16).ok()?,
    ))
}

pub fn proc_connections(pid: Option<u32>, user: Option<&str>) -> Result<Vec<Connection>> {
    let inodes = match pid {
        Some(pid) => socket_inodes(pid)?,
        None => HashSet::new(),
    };
    let wanted_uid = match user {
        Some(name) => Some(
            uid_for_user(name)
                .ok_or_else(|| Error::invalid_input(format!("unknown user '{name}'")))?,
        ),
        None => None,
    };
    let mut connections = Vec::new();
    for (path, protocol, is_ipv6) in [
        ("/proc/net/tcp", Protocol::Tcp, false),
        ("/proc/net/tcp6", Protocol::Tcp, true),
        ("/proc/net/udp", Protocol::Udp, false),
        ("/proc/net/udp6", Protocol::Udp, true),
    ] {
        if is_ipv6 && !Path::new(path).exists() {
            continue;
        }
        let content = fs::read_to_string(path).map_err(|error| {
            Error::Io(std::io::Error::other(format!(
                "unable to read '{path}': {error}"
            )))
        })?;
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let (local, remote, status, uid, inode) =
                (fields[1], fields[2], fields[3], fields[7], fields[9]);
            let filtered_by_inode = pid.is_some() && !inodes.contains(inode);
            let filtered_by_user =
                wanted_uid.is_some_and(|wanted| uid.parse::<u32>().ok() != Some(wanted));
            if filtered_by_inode
                || filtered_by_user
                || (protocol == Protocol::Tcp && status != "01")
            {
                continue;
            }
            let (Some((local_address, local_port)), Some((remote_address, remote_port))) =
                (parse_proc_endpoint(local), parse_proc_endpoint(remote))
            else {
                return Err(Error::parse(format!("unable to parse '{path}'")));
            };
            if remote_address.is_unspecified() || local_port == 0 || remote_port == 0 {
                continue;
            }
            connections.push(Connection {
                local_address,
                local_port,
                remote_address,
                remote_port,
                protocol,
                is_ipv6,
            });
        }
    }
    Ok(connections)
}

pub fn system_resolvers() -> Vec<Resolver> {
    let candidates: Vec<Resolver> = if is_windows() {
        vec![Resolver::NetstatWindows]
    } else if is_mac() {
        vec![Resolver::Lsof]
    } else if cfg!(target_os = "openbsd") {
        vec![Resolver::BsdFstat]
    } else if cfg!(target_os = "freebsd") {
        vec![Resolver::BsdSockstat, Resolver::BsdProcstat, Resolver::Lsof]
    } else {
        vec![
            Resolver::Netstat,
            Resolver::Sockstat,
            Resolver::Lsof,
            Resolver::Ss,
        ]
    };
    let mut resolvers: Vec<Resolver> = candidates
        .into_iter()
        .filter(|resolver| is_available(resolver.command()))
        .collect();
    let can_use_proc = is_proc_available()
        && fs::File::open("/proc/net/tcp").is_ok()
        && fs::File::open("/proc/net/udp").is_ok();
    if can_use_proc {
        resolvers.insert(0, Resolver::Proc);
    }
    resolvers
}

fn parse_resolver_address(entry: &str) -> Option<(IpAddr, u16)> {
    let (address, port) = entry.rsplit_once(':')?;
    let address = address.trim_start_matches('[').trim_end_matches(']');
    Some((
        address.parse().ok()?,
        crate::address::parse_port(port, false)?,
    ))
}

pub fn parse_connections(
    resolver: Resolver,
    lines: &[String],
    process_pid: Option<u32>,
    process_name: Option<&str>,
) -> Result<Vec<Connection>> {
    let address_pattern = r"[\[\]0-9a-f.:]+";
    let pattern = resolver
        .filter()
        .replace("{protocol}", r"(?P<protocol>\S+)")
        .replace("{local}", &format!("(?P<local>{address_pattern})"))
        .replace("{remote}", &format!("(?P<remote>{address_pattern})"))
        .replace(
            "{pid}",
            &process_pid.map_or("[0-9]*".to_string(), |pid| pid.to_string()),
        )
        .replace(
            "{name}",
            &process_name.map_or(r"\S*".to_string(), regex::escape),
        );
    let matcher = Regex::new(&pattern)
        .map_err(|error| Error::parse(format!("invalid resolver pattern: {error}")))?;
    let mut connections = Vec::new();
    for line in lines {
        let Some(captures) = matcher.captures(line) else {
            continue;
        };
        let (Some((local_address, local_port)), Some((remote_address, remote_port))) = (
            parse_resolver_address(&captures["local"]),
            parse_resolver_address(&captures["remote"]),
        ) else {
            continue;
        };
        let protocol = match captures["protocol"].to_lowercase().as_str() {
            "tcp" | "tcp6" => Protocol::Tcp,
            "udp" | "udp6" => Protocol::Udp,
            _ => continue,
        };
        connections.push(Connection {
            local_address,
            local_port,
            remote_address,
            remote_port,
            protocol,
            is_ipv6: local_address.is_ipv6(),
        });
    }
    Ok(connections)
}

pub fn get_connections(
    resolver: Option<Resolver>,
    process_pid: Option<u32>,
    process_name: Option<&str>,
) -> Result<Vec<Connection>> {
    let resolver = match resolver {
        Some(resolver) => resolver,
        None => *system_resolvers().first().ok_or_else(|| {
            Error::Io(std::io::Error::other(
                "Unable to determine a connection resolver",
            ))
        })?,
    };
    if process_pid.is_none() && process_name.is_none() {
        return Err(Error::invalid_input(
            "You must provide a pid or process name to provide connections for",
        ));
    }
    let mut process_pid = process_pid;
    if process_pid.is_none()
        && let Some(name) = process_name
    {
        let pids = pids_by_name(name);
        match pids.as_slice() {
            [] if resolver.requires_pid() => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "Unable to determine the pid of '{name}'. {resolver:?} requires the \
                    pid to provide the connections."
                ))));
            }
            [pid] => process_pid = Some(*pid),
            [_, _, ..] if resolver.requires_pid() => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "There's multiple processes named '{name}'. {resolver:?} requires a \
                    single pid to provide the connections."
                ))));
            }
            _ => {}
        }
    }
    if resolver == Resolver::Proc {
        return proc_connections(process_pid, None);
    }
    let pid_text = process_pid.map(|pid| pid.to_string()).unwrap_or_default();
    let command_text = resolver.command().replace("{pid}", &pid_text);
    let command: Vec<&str> = command_text.split(' ').collect();
    let results = call(&command, None).map_err(|error| {
        Error::Io(std::io::Error::other(format!(
            "Unable to query '{command_text}': {error}"
        )))
    })?;
    let connections = parse_connections(resolver, &results, process_pid, process_name)?;
    if connections.is_empty() {
        return Err(Error::Io(std::io::Error::other(format!(
            "No results found using: {command_text}"
        ))));
    }
    Ok(connections)
}
