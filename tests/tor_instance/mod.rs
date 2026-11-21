#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use stem::controller::Controller;
use stem::socket::ControlSocket;

pub fn tor_binary() -> String {
    match std::env::var("TOR_BINARY") {
        Ok(path) => path,
        Err(_) => "tor".to_string(),
    }
}

pub fn library_environment() -> Vec<(String, String)> {
    let binary = tor_binary();
    match Path::new(&binary).parent().filter(|path| path.is_dir()) {
        Some(directory) => vec![(
            "LD_LIBRARY_PATH".to_string(),
            directory.to_string_lossy().into_owned(),
        )],
        None => Vec::new(),
    }
}

fn tor_command() -> Command {
    let mut command = Command::new(tor_binary());
    command.envs(library_environment());
    command
}

pub struct TorInstance {
    child: Child,
    sentinel: Child,
    directory: tempfile::TempDir,
    pub control_port: u16,
}

impl TorInstance {
    pub fn launch(offline: bool, extra_config: &str) -> Self {
        Self::launch_with(offline, true, extra_config)
    }

    pub fn launch_with(offline: bool, cookie: bool, extra_config: &str) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("stem-")
            .tempdir_in("/tmp")
            .expect("temporary directory");
        let root = directory.path();
        std::os::unix::fs::PermissionsExt::set_mode(
            &mut std::fs::metadata(root).expect("metadata").permissions(),
            0o700,
        );
        std::fs::set_permissions(
            root,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private directory");
        let sentinel = Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("sentinel process");
        let config = format!(
            "DataDirectory {root}/data\n\
             ControlPort auto\n\
             ControlPortWriteToFile {root}/control_port\n\
             ControlSocket {root}/control.sock\n\
             CookieAuthentication {cookie}\n\
             CookieAuthFile {root}/control_auth_cookie\n\
             SocksPort auto\n\
             Log notice stdout\n\
             DisableNetwork {offline}\n\
             __OwningControllerProcess {owner}\n\
             {extra_config}\n",
            root = root.display(),
            offline = u8::from(offline),
            cookie = u8::from(cookie),
            owner = sentinel.id(),
        );
        std::fs::write(root.join("torrc"), config).expect("torrc");
        let mut child = tor_command()
            .arg("-f")
            .arg(root.join("torrc"))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("tor starts");
        let stdout = child.stdout.take().expect("stdout is piped");
        let deadline = Instant::now() + Duration::from_secs(240);
        let (sender, receiver) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let control_port = loop {
            let content =
                std::fs::read_to_string(root.join("control_port")).unwrap_or_default();
            if let Some(port) = content
                .lines()
                .find_map(|line| line.strip_prefix("PORT="))
                .and_then(|address| address.rsplit(':').next()?.parse().ok())
            {
                break port;
            }
            assert!(
                Instant::now() < deadline,
                "tor didn't write its control port"
            );
            assert!(
                child.try_wait().expect("wait").is_none(),
                "tor exited early"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        if !offline {
            loop {
                let line = receiver
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .expect("tor didn't bootstrap in time");
                if line.contains("Bootstrapped 100%") {
                    break;
                }
            }
        }
        std::thread::spawn(move || while receiver.recv().is_ok() {});
        Self {
            child,
            sentinel,
            directory,
            control_port,
        }
    }

    pub fn offline() -> Self {
        Self::launch(true, "")
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    pub fn cookie_path(&self) -> PathBuf {
        self.path().join("control_auth_cookie")
    }

    pub fn socket_path(&self) -> PathBuf {
        self.path().join("control.sock")
    }

    pub fn socket(&self) -> ControlSocket {
        ControlSocket::port(IpAddr::V4(Ipv4Addr::LOCALHOST), self.control_port)
    }

    pub async fn controller(&self) -> Controller {
        let socket = self.socket();
        socket.connect().await.expect("connect to control port");
        let controller = Controller::new(socket);
        controller.authenticate(None).await.expect("authenticate");
        controller
    }
}

impl Drop for TorInstance {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = self.sentinel.kill();
        let _ = self.sentinel.wait();
    }
}

pub fn hashed_password(password: &str) -> String {
    let output = tor_command()
        .args(["--hash-password", password])
        .output()
        .expect("tor hashes a password");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .rev()
        .find(|line| line.starts_with("16:"))
        .expect("hashed password line")
        .to_string()
}

pub fn shared_online() -> &'static TorInstance {
    static INSTANCE: OnceLock<TorInstance> = OnceLock::new();
    INSTANCE.get_or_init(|| TorInstance::launch(false, ""))
}
