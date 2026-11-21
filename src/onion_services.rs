use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::address::parse_port;
use crate::controller::{Controller, receive_with_timeout};
use crate::descriptor::hidden_service::HiddenServiceDescriptor;
use crate::enumerations::{HsDescAction, HsDescReason};
use crate::error::{Error, Result};
use crate::events::{EventData, EventType};
use crate::process_inspection;
use crate::response::{AddOnionResponse, GetConfResponse};
use crate::validation::{is_valid_fingerprint, is_valid_hidden_service_address};
use crate::version::Requirement;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenServicePort {
    pub port: u16,
    pub target_address: String,
    pub target_port: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HiddenServiceConfig {
    pub path: String,
    pub ports: Vec<HiddenServicePort>,
    pub options: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct CreateHiddenServiceOutput {
    pub path: String,
    pub hostname: Option<String>,
    pub hostname_for_client: HashMap<String, String>,
    pub config: Vec<HiddenServiceConfig>,
}

#[derive(Debug, Clone)]
pub enum OnionPorts {
    Single(u16),
    List(Vec<u16>),
    Map(Vec<(u16, String)>),
}

#[derive(Debug, Clone)]
pub struct EphemeralServiceOptions {
    pub key_type: String,
    pub key_content: String,
    pub discard_key: bool,
    pub detached: bool,
    pub await_publication: bool,
    pub timeout: Option<Duration>,
    pub basic_auth: Option<Vec<(String, Option<String>)>>,
    pub max_streams: Option<u32>,
    pub client_auth_v3: Option<String>,
}

impl Default for EphemeralServiceOptions {
    fn default() -> Self {
        Self {
            key_type: "NEW".to_string(),
            key_content: "BEST".to_string(),
            discard_key: false,
            detached: false,
            await_publication: false,
            timeout: None,
            basic_auth: None,
            max_streams: None,
            client_auth_v3: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionClientAuth {
    pub address: String,
    pub key_type: String,
    pub private_key: String,
    pub client_name: Option<String>,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthOutcome {
    Added,
    Replaced,
    ReplacedAndDecrypted,
}

fn is_safe_value(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| !character.is_whitespace() && !character.is_control())
}

fn require_safe(value: &str, label: &str) -> Result<()> {
    match is_safe_value(value) {
        true => Ok(()),
        false => Err(Error::invalid_input(format!(
            "{label} can't be empty or contain whitespace or control characters"
        ))),
    }
}

fn parse_hidden_service_port(value: &str, content: &str) -> Result<HiddenServicePort> {
    let invalid = |what: &str, entry: &str| {
        Error::protocol(format!(
            "GETCONF provided an invalid HiddenServicePort {what} ({entry}): {content}"
        ))
    };
    let is_plain = value.bytes().all(|byte| byte.is_ascii_digit());
    let (port, target_address, target_port) = match is_plain {
        true => (value, "127.0.0.1", value),
        false => {
            let pieces: Vec<&str> = value.split_whitespace().collect();
            let [port, target] = pieces.as_slice() else {
                return Err(invalid("port", value));
            };
            match target.bytes().all(|byte| byte.is_ascii_digit()) {
                true => (*port, "127.0.0.1", *target),
                false => {
                    let (address, target_port) = target
                        .rsplit_once(':')
                        .ok_or_else(|| invalid("target", target))?;
                    (*port, address, target_port)
                }
            }
        }
    };
    let bare_address = target_address.trim_start_matches('[').trim_end_matches(']');
    if !crate::controller::is_valid_target_address(bare_address) {
        return Err(invalid("target address", target_address));
    }
    Ok(HiddenServicePort {
        port: parse_port(port, false).ok_or_else(|| invalid("port", port))?,
        target_address: target_address.to_string(),
        target_port: parse_port(target_port, false)
            .ok_or_else(|| invalid("target port", target_port))?,
    })
}

impl Controller {
    pub async fn get_hidden_service_conf(&self) -> Result<Vec<HiddenServiceConfig>> {
        if let Some(cached) = self.cached_hidden_service_conf() {
            return Ok(cached);
        }
        let response = self.msg("GETCONF HiddenServiceOptions").await?;
        GetConfResponse::parse(&response)?;
        let mut services: Vec<HiddenServiceConfig> = Vec::new();
        for (_, _, content) in response.content() {
            if content == "HiddenServiceOptions" {
                continue;
            }
            let Some((key, value)) = content.split_once('=') else {
                continue;
            };
            if key == "HiddenServiceDir" {
                services.push(HiddenServiceConfig {
                    path: value.to_string(),
                    ..Default::default()
                });
                continue;
            }
            let Some(service) = services.last_mut() else {
                continue;
            };
            match key {
                "HiddenServicePort" => service
                    .ports
                    .push(parse_hidden_service_port(value, &content)?),
                _ => service.options.push((key.to_string(), value.to_string())),
            }
        }
        self.store_hidden_service_conf(Some(services.clone()));
        Ok(services)
    }

    pub async fn set_hidden_service_conf(
        &self,
        config: &[HiddenServiceConfig],
    ) -> Result<()> {
        if config.is_empty() {
            return self.reset_conf(&["HiddenServiceDir"]).await;
        }
        let mut options: Vec<(String, String)> = Vec::new();
        for service in config {
            options.push(("HiddenServiceDir".to_string(), service.path.clone()));
            for port in &service.ports {
                options.push((
                    "HiddenServicePort".to_string(),
                    format!("{} {}:{}", port.port, port.target_address, port.target_port),
                ));
            }
            options.extend(service.options.iter().cloned());
        }
        let entries: Vec<(&str, crate::controller::ConfValue)> = options
            .iter()
            .map(|(key, value)| {
                (
                    key.as_str(),
                    crate::controller::ConfValue::Single(value.clone()),
                )
            })
            .collect();
        self.set_options(&entries, false).await
    }

    pub async fn create_hidden_service(
        &self,
        path: &str,
        port: u16,
        target_address: Option<&str>,
        target_port: Option<u16>,
        auth_type: Option<&str>,
        client_names: &[&str],
    ) -> Result<Option<CreateHiddenServiceOutput>> {
        if port == 0 {
            return Err(Error::invalid_input("0 isn't a valid port number"));
        }
        if let Some(address) = target_address
            && !crate::controller::is_valid_target_address(address)
        {
            return Err(Error::invalid_input(format!(
                "{address} isn't a valid IP address"
            )));
        }
        if !matches!(auth_type, None | Some("basic") | Some("stealth")) {
            return Err(Error::invalid_input(format!(
                "{} isn't a recognized type of authentication",
                auth_type.unwrap_or_default()
            )));
        }
        let target = HiddenServicePort {
            port,
            target_address: target_address.unwrap_or("127.0.0.1").to_string(),
            target_port: target_port.unwrap_or(port),
        };
        let mut config = self.get_hidden_service_conf().await?;
        if config
            .iter()
            .any(|service| service.path == path && service.ports.contains(&target))
        {
            return Ok(None);
        }
        let index = match config.iter().position(|service| service.path == path) {
            Some(index) => index,
            None => {
                config.push(HiddenServiceConfig {
                    path: path.to_string(),
                    ..Default::default()
                });
                config.len() - 1
            }
        };
        config[index].ports.push(target);
        if let (Some(auth_type), false) = (auth_type, client_names.is_empty()) {
            config[index]
                .options
                .retain(|(key, _)| key != "HiddenServiceAuthorizeClient");
            config[index].options.push((
                "HiddenServiceAuthorizeClient".to_string(),
                format!("{auth_type} {}", client_names.join(",")),
            ));
        }
        for service in &mut config {
            let needs_v2 = service.options.iter().any(|(key, _)| {
                key == "HiddenServiceAuthorizeClient" || key == "RendPostPeriod"
            });
            if needs_v2 {
                service
                    .options
                    .retain(|(key, _)| key != "HiddenServiceVersion");
                service
                    .options
                    .push(("HiddenServiceVersion".to_string(), "2".to_string()));
            }
        }
        self.set_hidden_service_conf(&config).await?;
        let (hostname, hostname_for_client) =
            self.read_hostname(path, client_names).await;
        Ok(Some(CreateHiddenServiceOutput {
            path: path.to_string(),
            hostname,
            hostname_for_client,
            config,
        }))
    }

    async fn read_hostname(
        &self,
        path: &str,
        client_names: &[&str],
    ) -> (Option<String>, HashMap<String, String>) {
        if !self.is_localhost() {
            return (None, HashMap::new());
        }
        let mut hostname_path = Path::new(path).join("hostname");
        if !hostname_path.is_absolute()
            && let Ok(pid) = self.get_pid().await
            && let Ok(Some(cwd)) =
                tokio::task::spawn_blocking(move || process_inspection::cwd(pid)).await
        {
            hostname_path = process_inspection::expand_path(
                &hostname_path.to_string_lossy(),
                Some(&cwd),
            );
        }
        if !hostname_path.is_absolute() {
            return (None, HashMap::new());
        }
        let started = Instant::now();
        while !hostname_path.exists() && started.elapsed() < Duration::from_secs(3) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let Ok(content) = tokio::fs::read_to_string(&hostname_path).await else {
            return (None, HashMap::new());
        };
        let hostname = content.trim().to_string();
        let mut per_client = HashMap::new();
        if !client_names.is_empty() && hostname.contains('\n') {
            for line in hostname.lines() {
                let Some((address_part, client)) = line.split_once(" # client: ") else {
                    continue;
                };
                let address = address_part.split_whitespace().next().unwrap_or_default();
                if address.len() == 22 && address.ends_with(".onion") {
                    per_client.insert(client.to_string(), address.to_string());
                }
            }
        }
        (Some(hostname), per_client)
    }

    pub async fn remove_hidden_service(
        &self,
        path: &str,
        port: Option<u16>,
    ) -> Result<bool> {
        let mut config = self.get_hidden_service_conf().await?;
        let Some(index) = config.iter().position(|service| service.path == path) else {
            return Ok(false);
        };
        match port {
            None => {
                config.remove(index);
            }
            Some(port) => {
                let before = config[index].ports.len();
                config[index].ports.retain(|entry| entry.port != port);
                if config[index].ports.len() == before {
                    return Ok(false);
                }
                if config[index].ports.is_empty() {
                    config.remove(index);
                }
            }
        }
        self.set_hidden_service_conf(&config).await?;
        Ok(true)
    }

    pub async fn list_ephemeral_hidden_services(
        &self,
        our_services: bool,
        detached: bool,
    ) -> Result<Vec<String>> {
        self.require_onion_support().await?;
        let mut result = Vec::new();
        let queries = [
            (our_services, "onions/current"),
            (detached, "onions/detached"),
        ];
        for (enabled, query) in queries {
            if !enabled {
                continue;
            }
            match self.get_info(query).await {
                Ok(text) => result.extend(text.split('\n').map(str::to_string)),
                Err(error)
                    if error
                        .to_string()
                        .contains("No onion services of the specified type.") => {}
                Err(error) => return Err(error),
            }
        }
        Ok(result
            .into_iter()
            .filter(|entry| !entry.is_empty())
            .collect())
    }

    async fn require_onion_support(&self) -> Result<()> {
        let requirement = Requirement::AddOnion;
        match self.get_version().await?.meets(requirement) {
            true => Ok(()),
            false => Err(Error::unsatisfiable(format!(
                "Ephemeral hidden services were added in tor version {requirement}"
            ))),
        }
    }

    pub async fn create_ephemeral_hidden_service(
        &self,
        ports: &OnionPorts,
        options: &EphemeralServiceOptions,
    ) -> Result<AddOnionResponse> {
        self.require_onion_support().await?;
        let request = self.build_add_onion_request(ports, options).await?;
        let started = Instant::now();
        let subscription = match options.await_publication {
            true => Some(self.subscribe(&[EventType::HsDesc]).await?),
            false => None,
        };
        let created = self
            .msg(&request)
            .await
            .and_then(|response| AddOnionResponse::parse(&response));
        let Some((listener_id, mut receiver)) = subscription else {
            return created;
        };
        let outcome = match created {
            Ok(response) => {
                let service_id = response.service_id.clone().unwrap_or_default();
                self.await_descriptor_upload(
                    &mut receiver,
                    &service_id,
                    options.timeout,
                    started,
                )
                .await
                .map(|()| response)
            }
            Err(error) => Err(error),
        };
        let _ = self.remove_event_listener(listener_id).await;
        outcome
    }

    async fn build_add_onion_request(
        &self,
        ports: &OnionPorts,
        options: &EphemeralServiceOptions,
    ) -> Result<String> {
        require_safe(&options.key_type, "The key type")?;
        require_safe(&options.key_content, "The key content")?;
        let version = self.get_version().await?;
        let unsatisfied = |requirement: Requirement, what: &str| {
            Error::unsatisfiable(format!(
                "{what} was added to ADD_ONION in tor version {requirement}"
            ))
        };
        let mut flags: Vec<&str> = Vec::new();
        if options.discard_key {
            flags.push("DiscardPK");
        }
        if options.detached {
            flags.push("Detach");
        }
        if options.basic_auth.is_some() {
            if !version.meets(Requirement::AddOnionBasicAuth) {
                return Err(unsatisfied(
                    Requirement::AddOnionBasicAuth,
                    "Basic authentication support",
                ));
            }
            flags.push("BasicAuth");
        }
        if options.max_streams.is_some() {
            if !version.meets(Requirement::AddOnionMaxStreams) {
                return Err(unsatisfied(
                    Requirement::AddOnionMaxStreams,
                    "Limitation of the maximum number of streams to accept",
                ));
            }
            flags.push("MaxStreamsCloseCircuit");
        }
        if version.meets(Requirement::AddOnionNonAnonymous) {
            let single_hop = self
                .get_conf("HiddenServiceSingleHopMode")
                .await
                .ok()
                .flatten();
            let non_anonymous = self
                .get_conf("HiddenServiceNonAnonymousMode")
                .await
                .ok()
                .flatten();
            if single_hop.as_deref() == Some("1") && non_anonymous.as_deref() == Some("1")
            {
                flags.push("NonAnonymous");
            }
        }
        if options.client_auth_v3.is_some() {
            if !version.meets(Requirement::OnionServiceAuthAdd) {
                return Err(unsatisfied(
                    Requirement::OnionServiceAuthAdd,
                    "Client authentication support for v3 onions",
                ));
            }
            flags.push("V3Auth");
        }
        let mut request =
            format!("ADD_ONION {}:{}", options.key_type, options.key_content);
        if !flags.is_empty() {
            request.push_str(&format!(" Flags={}", flags.join(",")));
        }
        if let Some(max_streams) = options.max_streams {
            request.push_str(&format!(" MaxStreams={max_streams}"));
        }
        let requested: Vec<u16> = match ports {
            OnionPorts::Single(port) => vec![*port],
            OnionPorts::List(list) => list.clone(),
            OnionPorts::Map(map) => map.iter().map(|(port, _)| *port).collect(),
        };
        if requested.is_empty() || requested.contains(&0) {
            return Err(Error::invalid_input(
                "Hidden services need at least one port, and 0 isn't a valid port",
            ));
        }
        match ports {
            OnionPorts::Single(port) => request.push_str(&format!(" Port={port}")),
            OnionPorts::List(list) => list
                .iter()
                .for_each(|port| request.push_str(&format!(" Port={port}"))),
            OnionPorts::Map(map) => {
                for (port, target) in map {
                    require_safe(target, "A port target")?;
                    if target.contains(',') {
                        return Err(Error::invalid_input(
                            "A port target can't contain a comma",
                        ));
                    }
                    request.push_str(&format!(" Port={port},{target}"));
                }
            }
        }
        for (name, blob) in options.basic_auth.iter().flatten() {
            require_safe(name, "A client name")?;
            match blob {
                Some(blob) => {
                    require_safe(blob, "A client credential")?;
                    request.push_str(&format!(" ClientAuth={name}:{blob}"));
                }
                None => request.push_str(&format!(" ClientAuth={name}")),
            }
        }
        if let Some(auth) = &options.client_auth_v3 {
            require_safe(auth, "A v3 client credential")?;
            request.push_str(&format!(" ClientAuthV3={auth}"));
        }
        Ok(request)
    }

    async fn await_descriptor_upload(
        &self,
        receiver: &mut tokio::sync::mpsc::UnboundedReceiver<crate::events::Event>,
        service_id: &str,
        timeout: Option<Duration>,
        started: Instant,
    ) -> Result<()> {
        let mut uploaded_to: Vec<Option<String>> = Vec::new();
        let mut failures: Vec<String> = Vec::new();
        loop {
            let event = receive_with_timeout(receiver, timeout, started).await?;
            let EventData::HsDesc(desc) = event.data else {
                continue;
            };
            match desc.action {
                HsDescAction::Upload if desc.address == service_id => {
                    uploaded_to.push(desc.directory_fingerprint)
                }
                HsDescAction::Uploaded
                    if uploaded_to.contains(&desc.directory_fingerprint) =>
                {
                    return Ok(());
                }
                HsDescAction::Failed
                    if uploaded_to.contains(&desc.directory_fingerprint) =>
                {
                    let reason = desc
                        .reason
                        .as_ref()
                        .map_or("None".to_string(), ToString::to_string);
                    failures.push(format!(
                        "{} ({reason})",
                        desc.directory_fingerprint.unwrap_or_default()
                    ));
                    if uploaded_to.len() == failures.len() {
                        return Err(Error::operation_failed(
                            "551",
                            format!(
                                "Failed to upload our hidden service descriptor to {}",
                                failures.join(", ")
                            ),
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    pub async fn remove_ephemeral_hidden_service(
        &self,
        service_id: &str,
    ) -> Result<bool> {
        self.require_onion_support().await?;
        let is_valid = is_valid_hidden_service_address(service_id, &[2, 3]);
        if !is_valid {
            return Err(Error::invalid_input(format!(
                "'{service_id}' isn't a valid hidden service id"
            )));
        }
        let response = self.single_line(&format!("DEL_ONION {service_id}")).await?;
        match response.code.as_str() {
            "250" => Ok(true),
            "552" => Ok(false),
            code => Err(Error::protocol(format!(
                "DEL_ONION returned unexpected response code: {code}"
            ))),
        }
    }

    pub async fn get_hidden_service_descriptor(
        &self,
        address: &str,
        servers: &[&str],
        await_result: bool,
        timeout: Option<Duration>,
    ) -> Result<Option<HiddenServiceDescriptor>> {
        let address = address.strip_suffix(".onion").unwrap_or(address);
        if !is_valid_hidden_service_address(address, &[2, 3]) {
            return Err(Error::invalid_input(format!(
                "'{address}.onion' isn't a valid hidden service address"
            )));
        }
        let version = self.get_version().await?;
        if !version.meets(Requirement::HsFetch) {
            return Err(Error::unsatisfiable(format!(
                "HSFETCH was added in tor version {}",
                Requirement::HsFetch
            )));
        }
        if address.len() == 56 && !version.meets(Requirement::HsFetchV3) {
            return Err(Error::unsatisfiable(format!(
                "HSFETCH for v3 addresses was added in tor version {}",
                Requirement::HsFetchV3
            )));
        }
        let mut request = format!("HSFETCH {address}");
        for server in servers {
            let bare = server.strip_prefix('$').unwrap_or(server);
            let fingerprint = bare.split(['~', '=']).next().unwrap_or_default();
            if !is_valid_fingerprint(fingerprint, false) {
                return Err(Error::invalid_input(format!(
                    "'{server}' isn't a valid relay"
                )));
            }
            request.push_str(&format!(" SERVER={server}"));
        }
        let started = Instant::now();
        let subscription = match await_result {
            true => Some(
                self.subscribe(&[EventType::HsDesc, EventType::HsDescContent])
                    .await?,
            ),
            false => None,
        };
        let sent = self.single_line(&request).await.and_then(|response| {
            match response.is_ok() {
                true => Ok(()),
                false => Err(Error::protocol(format!(
                    "HSFETCH returned unexpected response code: {}",
                    response.code
                ))),
            }
        });
        let Some((listener_id, mut receiver)) = subscription else {
            return sent.map(|()| None);
        };
        let outcome = match sent {
            Ok(()) => {
                self.await_descriptor(&mut receiver, address, timeout, started)
                    .await
            }
            Err(error) => Err(error),
        };
        let _ = self.remove_event_listener(listener_id).await;
        outcome.map(Some)
    }

    async fn await_descriptor(
        &self,
        receiver: &mut tokio::sync::mpsc::UnboundedReceiver<crate::events::Event>,
        address: &str,
        timeout: Option<Duration>,
        started: Instant,
    ) -> Result<HiddenServiceDescriptor> {
        loop {
            let event = receive_with_timeout(receiver, timeout, started).await?;
            match event.data {
                EventData::HsDescContent(content)
                    if content.address.as_deref() == Some(address) =>
                {
                    if let Some(descriptor) = content.descriptor {
                        return Ok(descriptor);
                    }
                }
                EventData::HsDesc(desc)
                    if desc.address == address && desc.action == HsDescAction::Failed =>
                {
                    return Err(match desc.reason {
                        Some(HsDescReason::NotFound) => Error::DescriptorUnavailable(
                            format!("No running hidden service at {address}.onion"),
                        ),
                        reason => Error::DescriptorUnavailable(format!(
                            "Unable to retrieve the descriptor for {address}.onion \
                            (retrieved from {}): {}",
                            desc.directory_fingerprint.unwrap_or_default(),
                            reason
                                .map_or("None".to_string(), |reason| reason.to_string())
                        )),
                    });
                }
                _ => {}
            }
        }
    }

    pub async fn hs_post(
        &self,
        descriptor: &str,
        servers: &[&str],
        address: Option<&str>,
    ) -> Result<()> {
        self.require_version(Requirement::HsPost, "HSPOST").await?;
        let mut command = String::from("HSPOST");
        for server in servers {
            require_safe(server, "An HSDir")?;
            command.push_str(&format!(" SERVER={server}"));
        }
        if let Some(address) = address {
            if !is_valid_hidden_service_address(address, &[3]) {
                return Err(Error::invalid_input(format!(
                    "'{address}' isn't a valid v3 onion address"
                )));
            }
            command.push_str(&format!(" HSADDRESS={address}"));
        }
        let response = self
            .single_line(&format!("{command}\n{descriptor}"))
            .await?;
        match response.code.as_str() {
            "250" => Ok(()),
            "513" | "552" | "554" => {
                Err(Error::invalid_request(&response.code, response.message))
            }
            code => Err(Error::protocol(format!(
                "HSPOST returned unexpected response code: {code}"
            ))),
        }
    }

    pub async fn onion_client_auth_add(
        &self,
        address: &str,
        private_key: &str,
        client_name: Option<&str>,
        permanent: bool,
    ) -> Result<ClientAuthOutcome> {
        let address = address.strip_suffix(".onion").unwrap_or(address);
        if !is_valid_hidden_service_address(address, &[3]) {
            return Err(Error::invalid_input(format!(
                "'{address}' isn't a valid v3 onion address"
            )));
        }
        require_safe(private_key, "A client private key")?;
        let mut command = format!("ONION_CLIENT_AUTH_ADD {address} x25519:{private_key}");
        if let Some(name) = client_name {
            require_safe(name, "A client name")?;
            command.push_str(&format!(" ClientName={name}"));
        }
        if permanent {
            command.push_str(" Flags=Permanent");
        }
        let response = self.single_line(&command).await?;
        match response.code.as_str() {
            "250" => Ok(ClientAuthOutcome::Added),
            "251" => Ok(ClientAuthOutcome::Replaced),
            "252" => Ok(ClientAuthOutcome::ReplacedAndDecrypted),
            "451" => Err(Error::operation_failed("451", response.message)),
            "512" | "551" | "552" => {
                Err(Error::invalid_request(&response.code, response.message))
            }
            code => Err(Error::protocol(format!(
                "ONION_CLIENT_AUTH_ADD returned unexpected response code: {code}"
            ))),
        }
    }

    pub async fn onion_client_auth_remove(&self, address: &str) -> Result<bool> {
        let address = address.strip_suffix(".onion").unwrap_or(address);
        if !is_valid_hidden_service_address(address, &[3]) {
            return Err(Error::invalid_input(format!(
                "'{address}' isn't a valid v3 onion address"
            )));
        }
        let response = self
            .single_line(&format!("ONION_CLIENT_AUTH_REMOVE {address}"))
            .await?;
        match response.code.as_str() {
            "250" => Ok(true),
            "251" => Ok(false),
            "512" => Err(Error::invalid_request("512", response.message)),
            code => Err(Error::protocol(format!(
                "ONION_CLIENT_AUTH_REMOVE returned unexpected response code: {code}"
            ))),
        }
    }

    pub async fn onion_client_auth_view(
        &self,
        address: Option<&str>,
    ) -> Result<Vec<OnionClientAuth>> {
        let mut command = String::from("ONION_CLIENT_AUTH_VIEW");
        if let Some(address) = address {
            let address = address.strip_suffix(".onion").unwrap_or(address);
            if !is_valid_hidden_service_address(address, &[3]) {
                return Err(Error::invalid_input(format!(
                    "'{address}' isn't a valid v3 onion address"
                )));
            }
            command.push_str(&format!(" {address}"));
        }
        let response = self.msg(&command).await?;
        if !response.is_ok() {
            return Err(Error::invalid_request(
                response.status_code(),
                response.to_string(),
            ));
        }
        let mut credentials = Vec::new();
        for mut line in response.lines() {
            if !matches!(line.pop(false, false), Ok(kind) if kind == "CLIENT") {
                continue;
            }
            let address = line.pop(false, false)?;
            let key = line.pop(false, false)?;
            let (key_type, private_key) = key.split_once(':').ok_or_else(|| {
                Error::protocol(format!(
                    "ONION_CLIENT_AUTH_VIEW had a malformed key: {key}"
                ))
            })?;
            let mut credential = OnionClientAuth {
                address,
                key_type: key_type.to_string(),
                private_key: private_key.to_string(),
                client_name: None,
                flags: Vec::new(),
            };
            while line.is_next_mapping(None, false, false) {
                match line.pop_mapping(false, false)? {
                    (key, value) if key == "ClientName" => {
                        credential.client_name = Some(value)
                    }
                    (key, value) if key == "Flags" => {
                        credential.flags = value.split(',').map(str::to_string).collect()
                    }
                    _ => {}
                }
            }
            credentials.push(credential);
        }
        Ok(credentials)
    }
}
