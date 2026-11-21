#![cfg(target_os = "linux")]

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stem::Error;
use stem::process_inspection::{
    Protocol, Resolver, call, call_with_environment, call_with_options, cwd, expand_path,
    file_descriptors_used, files_with_suffix, get_connections, is_available,
    is_proc_available, is_running_pid, is_tarfile, memory_usage, name_by_pid,
    pid_by_name, pid_by_open_file, pid_by_port, pids_by_name, proc_cwd, proc_uid,
    process_stats, start_time, system_resolvers, system_start_time, tail, user,
};

struct NamedProcess {
    child: Child,
    directory: tempfile::TempDir,
}

impl Drop for NamedProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_named(name: &str) -> NamedProcess {
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join(name);
    std::os::unix::fs::symlink(which("sleep"), &binary).unwrap();
    let child = Command::new(&binary)
        .arg("60")
        .current_dir(directory.path())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    NamedProcess { child, directory }
}

fn which(command: &str) -> std::path::PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|directory| directory.join(command))
        .find(|candidate| candidate.is_file())
        .unwrap()
}

#[test]
fn inspects_a_running_process() {
    let process = spawn_named("stemprobe1");
    let pid = process.child.id();

    assert!(is_running_pid(pid));
    assert_eq!(name_by_pid(pid).as_deref(), Some("stemprobe1"));
    assert_eq!(pid_by_name("stemprobe1"), Some(pid));
    assert_eq!(pids_by_name("stemprobe1"), vec![pid]);
    assert_eq!(pid_by_name("definitely-not-a-process"), None);
    assert!(pids_by_name("definitely-not-a-process").is_empty());

    let expected = std::fs::canonicalize(process.directory.path()).unwrap();
    assert_eq!(cwd(pid), Some(expected.clone()));
    assert_eq!(proc_cwd(pid).unwrap(), expected);

    let uid = proc_uid(pid).unwrap();
    assert_eq!(uid, std::fs::metadata("/proc/self").unwrap().uid_value());
    assert!(user(pid).is_some());

    let started = start_time(pid).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    assert!(
        now - started >= 0.0 && now - started < 30.0,
        "{started} vs {now}"
    );

    let stats = process_stats(pid).unwrap();
    assert_eq!(stats.command, "stemprobe1");
    assert!((stats.start_time - started).abs() < 2.0);
    let (resident, virtual_size) = memory_usage(pid).unwrap();
    assert!(resident > 0 && virtual_size >= resident);
    assert!(file_descriptors_used(pid).unwrap() >= 3);
    assert!(is_proc_available());
    assert!(system_start_time().unwrap() > 1.0e9);
}

trait Owner {
    fn uid_value(&self) -> u32;
}

impl Owner for std::fs::Metadata {
    fn uid_value(&self) -> u32 {
        std::os::unix::fs::MetadataExt::uid(self)
    }
}

#[test]
fn reports_missing_processes() {
    let impossible = 4_194_303;
    assert!(!is_running_pid(impossible));
    assert_eq!(name_by_pid(impossible), None);
    assert_eq!(cwd(impossible), None);
    assert_eq!(user(impossible), None);
    assert_eq!(start_time(impossible), None);
    assert!(proc_cwd(impossible).is_err());
    assert!(process_stats(impossible).is_err());
    assert!(file_descriptors_used(impossible).is_err());
}

#[test]
fn finds_processes_by_port_and_open_file() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    assert_eq!(pid_by_port(port), Some(std::process::id()));

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("held-open");
    let file = std::fs::File::create(&path).unwrap();
    assert_eq!(pid_by_open_file(&path), Some(std::process::id()));
    drop(file);
    assert_eq!(pid_by_open_file(&path), None);
}

fn established(
    connections: &[stem::process_inspection::Connection],
    local: u16,
    remote: u16,
) -> bool {
    connections.iter().any(|connection| {
        connection.protocol == Protocol::Tcp
            && connection.local_port == local
            && connection.remote_port == remote
            && connection.local_address.to_string() == "127.0.0.1"
    })
}

#[test]
fn resolves_connections_with_every_available_resolver() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = listener.local_addr().unwrap().port();
    let client = TcpStream::connect(("127.0.0.1", server)).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    let local = client.local_addr().unwrap().port();
    let pid = std::process::id();
    let process_name = name_by_pid(pid).unwrap();

    let resolvers = system_resolvers();
    assert!(resolvers.contains(&Resolver::Proc));
    for resolver in resolvers {
        let connections = get_connections(Some(resolver), Some(pid), Some(&process_name))
            .unwrap_or_else(|error| panic!("{resolver:?}: {error}"));
        assert!(
            established(&connections, local, server),
            "{resolver:?} missed the client connection"
        );
        assert!(
            established(&connections, server, local),
            "{resolver:?} missed the server side"
        );
    }
    drop((client, accepted));

    assert!(get_connections(None, None, None).is_err());
    assert!(matches!(
        get_connections(Some(Resolver::Proc), Some(4_194_303), None),
        Err(_) | Ok(_)
    ));
}

#[test]
fn tails_files_from_the_end() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("log");
    let lines: Vec<String> = (0..500)
        .map(|index| format!("line number {index}"))
        .collect();
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let last = tail(&path, Some(3)).unwrap();
    assert_eq!(
        last,
        vec!["line number 499", "line number 498", "line number 497"]
    );
    assert!(tail(&path, Some(0)).unwrap().is_empty());
    let everything = tail(&path, None).unwrap();
    assert_eq!(everything.len(), 500);
    assert_eq!(everything.last().unwrap(), "line number 0");
    assert_eq!(tail(&path, Some(1000)).unwrap().len(), 500);

    let long = directory.path().join("long");
    let wide = "x".repeat(5000);
    std::fs::write(&long, format!("first\n{wide}\nlast")).unwrap();
    assert_eq!(
        tail(&long, Some(2)).unwrap(),
        vec!["last".to_string(), wide]
    );

    let empty = directory.path().join("empty");
    std::fs::write(&empty, b"").unwrap();
    assert!(tail(&empty, Some(5)).unwrap().is_empty());
    assert!(tail(&directory.path().join("missing"), Some(1)).is_err());
}

#[test]
fn expands_paths() {
    let home = std::env::var("HOME").unwrap();
    assert_eq!(expand_path("~/.tor", None), Path::new(&home).join(".tor"));
    assert_eq!(
        expand_path("/absolute/path/", None),
        Path::new("/absolute/path")
    );
    assert_eq!(expand_path("/", None), Path::new("/"));
    assert_eq!(
        expand_path("relative/path", Some(Path::new("/base"))),
        Path::new("/base/relative/path")
    );
    assert_eq!(
        expand_path("./relative", Some(Path::new("/base"))),
        Path::new("/base/relative")
    );
    assert_eq!(
        expand_path(".", Some(Path::new("/base"))),
        Path::new("/base")
    );
    assert_eq!(expand_path("", None), Path::new(""));
}

#[test]
fn lists_files_with_suffixes() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("nested")).unwrap();
    for name in ["a.txt", "b.log", "nested/c.txt"] {
        std::fs::write(directory.path().join(name), b"x").unwrap();
    }
    let mut found = files_with_suffix(directory.path(), ".txt");
    found.sort();
    assert_eq!(
        found,
        vec![
            directory.path().join("a.txt"),
            directory.path().join("nested/c.txt")
        ]
    );
    assert_eq!(
        files_with_suffix(&directory.path().join("b.log"), ".log").len(),
        1
    );
    assert!(files_with_suffix(&directory.path().join("b.log"), ".txt").is_empty());
    assert!(files_with_suffix(&directory.path().join("missing"), "").is_empty());
}

#[test]
fn detects_tar_files() {
    assert!(is_tarfile(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/descriptor/descriptor_archive.tar"
    ))));
    assert!(!is_tarfile(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/Cargo.toml"
    ))));
    assert!(!is_tarfile(Path::new("/nonexistent")));
    let directory = tempfile::tempdir().unwrap();
    let short = directory.path().join("short.txt");
    std::fs::write(&short, b"tiny").unwrap();
    assert!(!is_tarfile(&short));
}

#[test]
fn runs_system_commands() {
    assert_eq!(call(&["echo", "hello"], None).unwrap(), vec!["hello"]);
    assert_eq!(call(&["printf", "a\\nb\\n"], None).unwrap(), vec!["a", "b"]);
    assert!(call(&["false"], None).is_err());
    assert!(
        call_with_options(&["false"], true, None)
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        call(&["/nonexistent/command"], None),
        Err(Error::Io(_))
    ));
    assert!(call(&[], None).is_err());
    let timeout = call(&["sleep", "5"], Some(Duration::from_millis(100)));
    assert!(matches!(timeout, Err(Error::Timeout(_))));
    let environment = call_with_environment(
        &["sh", "-c", "echo $STEM_PROBE"],
        false,
        None,
        &[("STEM_PROBE", "visible")],
    )
    .unwrap();
    assert_eq!(environment, vec!["visible"]);
    let injected = call(&["echo", "a; touch /tmp/stem-injection-marker"], None).unwrap();
    assert_eq!(injected, vec!["a; touch /tmp/stem-injection-marker"]);
    assert!(!Path::new("/tmp/stem-injection-marker").exists());
}

#[test]
fn checks_command_availability() {
    assert!(is_available("ls"));
    assert!(is_available("ls -l"));
    assert!(is_available("ulimit"));
    assert!(!is_available("definitely-not-a-command"));
    let mut file =
        std::fs::File::create(std::env::temp_dir().join("stem-not-executable")).unwrap();
    file.write_all(b"x").unwrap();
    assert!(!is_available("stem-not-executable"));
}
