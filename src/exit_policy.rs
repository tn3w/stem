use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::ops::Deref;

use crate::address::{
    address_to_int, expand_ipv6_address, get_mask_ipv4, get_mask_ipv6,
    is_valid_ipv4_address, is_valid_ipv6_address, masked_bits, parse_port,
};
use crate::error::{Error, Result};

const PRIVATE_ADDRESSES: [&str; 6] = [
    "0.0.0.0/8",
    "169.254.0.0/16",
    "127.0.0.0/8",
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
];

const DEFAULT_POLICY_RULES: [&str; 11] = [
    "reject *:25",
    "reject *:119",
    "reject *:135-139",
    "reject *:445",
    "reject *:563",
    "reject *:1214",
    "reject *:4661-4666",
    "reject *:6346-6429",
    "reject *:6699",
    "reject *:6881-6999",
    "accept *:*",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    Wildcard,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone)]
pub struct ExitPolicyRule {
    pub is_accept: bool,
    pub address: Option<String>,
    pub min_port: u16,
    pub max_port: u16,
    address_type: AddressType,
    masked_bits: Option<u32>,
    mask: Option<String>,
    mask_value: u128,
    address_value: u128,
    skip_rule: bool,
    is_private: bool,
    is_default_suffix: bool,
}

impl PartialEq for ExitPolicyRule {
    fn eq(&self, other: &Self) -> bool {
        self.is_accept == other.is_accept
            && self.address == other.address
            && self.min_port == other.min_port
            && self.max_port == other.max_port
            && self.mask == other.mask
    }
}

impl Eq for ExitPolicyRule {}

fn port_spec(rule: &str, spec: &str) -> Result<(u16, u16)> {
    if spec == "*" {
        return Ok((1, 65535));
    }
    if !spec.is_empty() && spec.bytes().all(|byte| byte.is_ascii_digit()) {
        return match parse_port(spec, true) {
            Some(port) => Ok((port, port)),
            None => Err(Error::parse(format!(
                "'{spec}' isn't within a valid port range: {rule}"
            ))),
        };
    }
    let Some((first, last)) = spec.split_once('-') else {
        return Err(Error::parse(format!(
            "Port value isn't a wildcard, integer, or range: {rule}"
        )));
    };
    let (Some(min_port), Some(max_port)) =
        (parse_port(first, true), parse_port(last, true))
    else {
        return Err(Error::parse(format!("Malformed port range: {rule}")));
    };
    if min_port > max_port {
        return Err(Error::parse(format!(
            "Port range has a lower bound that's greater than its upper bound: {rule}"
        )));
    }
    Ok((min_port, max_port))
}

impl ExitPolicyRule {
    pub fn new(rule: &str) -> Result<Self> {
        let is_accept = rule.starts_with("accept");
        let is_ipv6_only = rule.starts_with("accept6") || rule.starts_with("reject6");
        let pattern = if is_ipv6_only {
            &rule[7..]
        } else if is_accept || rule.starts_with("reject") {
            &rule[6..]
        } else {
            return Err(Error::parse(format!(
                "An exit policy must start with either 'accept[6]' or 'reject[6]': {rule}"
            )));
        };
        if !pattern.starts_with(' ') {
            return Err(Error::parse(format!(
                "An exit policy should have a space separating its accept/reject from \
                the exit pattern: {rule}"
            )));
        }
        let pattern = pattern.trim_start();
        let well_formed = pattern
            .rsplit_once(':')
            .is_some_and(|(_, ports)| !ports.contains(']'));
        if !well_formed {
            return Err(Error::parse(format!(
                "An exitpattern must be of the form 'addrspec:portspec': {rule}"
            )));
        }
        let (address_spec, port_text) = pattern.rsplit_once(':').expect("checked above");
        let (min_port, max_port) = port_spec(rule, port_text)?;
        let mut parsed = Self {
            is_accept,
            address: None,
            min_port,
            max_port,
            address_type: AddressType::Wildcard,
            masked_bits: None,
            mask: None,
            mask_value: 0,
            address_value: 0,
            skip_rule: false,
            is_private: false,
            is_default_suffix: false,
        };
        parsed.apply_address_spec(rule, address_spec, is_ipv6_only)?;
        Ok(parsed)
    }

    pub fn from_ports(is_accept: bool, min_port: u16, max_port: u16) -> Self {
        Self {
            is_accept,
            address: None,
            min_port,
            max_port,
            address_type: AddressType::Wildcard,
            masked_bits: None,
            mask: None,
            mask_value: 0,
            address_value: 0,
            skip_rule: false,
            is_private: false,
            is_default_suffix: false,
        }
    }

    fn apply_address_spec(
        &mut self,
        rule: &str,
        address_spec: &str,
        ipv6_only: bool,
    ) -> Result<()> {
        let spec = match address_spec {
            "*4" => "0.0.0.0/0",
            "*6" => "[0000:0000:0000:0000:0000:0000:0000:0000]/0",
            "*" if ipv6_only => "[0000:0000:0000:0000:0000:0000:0000:0000]/0",
            other => other,
        };
        let (address, extra) = match spec.split_once('/') {
            Some((address, extra)) => (address, Some(extra)),
            None => (spec, None),
        };
        if spec == "*" {
            self.address_type = AddressType::Wildcard;
            return Ok(());
        }
        if is_valid_ipv4_address(address) {
            return self.apply_ipv4(rule, address, extra, ipv6_only);
        }
        let inner = address
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'));
        match inner {
            Some(inner) if is_valid_ipv6_address(inner, false) => {
                self.apply_ipv6(rule, inner, extra)
            }
            _ => Err(Error::parse(format!(
                "'{address_spec}' isn't a wildcard, IPv4, or IPv6 address: {rule}"
            ))),
        }
    }

    fn apply_ipv4(
        &mut self,
        rule: &str,
        address: &str,
        extra: Option<&str>,
        ipv6_only: bool,
    ) -> Result<()> {
        self.skip_rule = ipv6_only;
        self.address_type = AddressType::Ipv4;
        self.address = Some(address.to_string());
        match extra {
            None => self.masked_bits = Some(32),
            Some(extra) if is_valid_ipv4_address(extra) => match masked_bits(extra) {
                Ok(bits) => self.masked_bits = Some(bits),
                Err(_) => {
                    self.mask = Some(extra.to_string());
                    self.mask_value = address_to_int(extra)?;
                }
            },
            Some(extra)
                if !extra.is_empty()
                    && extra.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                let bits: u32 = extra.parse().unwrap_or(u32::MAX);
                if bits > 32 {
                    return Err(Error::parse(
                        "IPv4 masks must be in the range of 0-32 bits",
                    ));
                }
                self.masked_bits = Some(bits);
            }
            Some(extra) => {
                return Err(Error::parse(format!(
                    "The '{extra}' isn't a mask nor number of bits: {rule}"
                )));
            }
        }
        if let Some(bits) = self.masked_bits {
            self.mask = Some(get_mask_ipv4(bits)?);
            self.mask_value = address_to_int(self.mask.as_deref().unwrap_or_default())?;
        }
        self.address_value = address_to_int(address)? & self.mask_value;
        Ok(())
    }

    fn apply_ipv6(
        &mut self,
        rule: &str,
        address: &str,
        extra: Option<&str>,
    ) -> Result<()> {
        self.address_type = AddressType::Ipv6;
        self.address = Some(expand_ipv6_address(address)?.to_uppercase());
        let bits = match extra {
            None => 128,
            Some(extra)
                if !extra.is_empty()
                    && extra.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                let bits: u32 = extra.parse().unwrap_or(u32::MAX);
                if bits > 128 {
                    return Err(Error::parse(
                        "IPv6 masks must be in the range of 0-128 bits",
                    ));
                }
                bits
            }
            Some(extra) => {
                return Err(Error::parse(format!(
                    "The '{extra}' isn't a number of bits: {rule}"
                )));
            }
        };
        self.masked_bits = Some(bits);
        let mask = get_mask_ipv6(bits)?;
        self.mask_value = address_to_int(&mask)?;
        self.mask = Some(mask);
        self.address_value = address_to_int(self.address.as_deref().unwrap_or_default())?
            & self.mask_value;
        Ok(())
    }

    pub fn is_address_wildcard(&self) -> bool {
        self.address_type == AddressType::Wildcard
    }

    pub fn is_port_wildcard(&self) -> bool {
        matches!(self.min_port, 0 | 1) && self.max_port == 65535
    }

    pub fn address_type(&self) -> AddressType {
        self.address_type
    }

    pub fn mask(&self) -> Option<&str> {
        self.mask.as_deref()
    }

    pub fn masked_bits(&self) -> Option<u32> {
        self.masked_bits
    }

    pub fn is_private(&self) -> bool {
        self.is_private
    }

    pub fn is_default(&self) -> bool {
        self.is_default_suffix
    }

    pub fn is_match(
        &self,
        address: Option<&str>,
        port: Option<u16>,
        strict: bool,
    ) -> Result<bool> {
        if self.skip_rule {
            return Ok(false);
        }
        let parsed_address = address.map(parse_exit_address).transpose()?;
        if let Some(parsed) = &parsed_address {
            let mismatched = matches!(
                (self.address_type, parsed),
                (AddressType::Ipv6, IpAddr::V4(_)) | (AddressType::Ipv4, IpAddr::V6(_))
            );
            if mismatched {
                return Ok(false);
            }
        }
        if let Some(0) = port {
            return Err(Error::invalid_input("'0' isn't a valid port"));
        }
        let mut fuzzy_match = false;
        if !self.is_address_wildcard() {
            match &parsed_address {
                None => fuzzy_match = true,
                Some(parsed) => {
                    let comparison = ip_to_integer(parsed) & self.mask_value;
                    if self.address_value != comparison {
                        return Ok(false);
                    }
                }
            }
        }
        if !self.is_port_wildcard() {
            match port {
                None => fuzzy_match = true,
                Some(port) if port < self.min_port || port > self.max_port => {
                    return Ok(false);
                }
                Some(_) => {}
            }
        }
        Ok(match fuzzy_match {
            true => strict != self.is_accept,
            false => true,
        })
    }
}

fn ip_to_integer(address: &IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u128::from(u32::from(*address)),
        IpAddr::V6(address) => u128::from(*address),
    }
}

fn parse_exit_address(address: &str) -> Result<IpAddr> {
    let unwrapped = address
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(address);
    unwrapped.parse().map_err(|_| {
        Error::invalid_input(format!("'{address}' isn't a valid IPv4 or IPv6 address"))
    })
}

impl fmt::Display for ExitPolicyRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} ",
            if self.is_accept { "accept" } else { "reject" }
        )?;
        match (self.address_type, self.address.as_deref()) {
            (AddressType::Wildcard, _) | (_, None) => write!(formatter, "*:")?,
            (kind, Some(address)) => {
                match kind {
                    AddressType::Ipv4 => write!(formatter, "{address}")?,
                    _ => write!(formatter, "[{address}]")?,
                }
                let is_full = matches!(
                    (kind, self.masked_bits),
                    (AddressType::Ipv4, Some(32)) | (AddressType::Ipv6, Some(128))
                );
                match (is_full, self.masked_bits) {
                    (true, _) => write!(formatter, ":")?,
                    (false, Some(bits)) => write!(formatter, "/{bits}:")?,
                    (false, None) => {
                        write!(formatter, "/{}:", self.mask.as_deref().unwrap_or(""))?
                    }
                }
            }
        }
        match (self.is_port_wildcard(), self.min_port == self.max_port) {
            (true, _) => write!(formatter, "*"),
            (false, true) => write!(formatter, "{}", self.min_port),
            (false, false) => write!(formatter, "{}-{}", self.min_port, self.max_port),
        }
    }
}

fn flag_private_rules(rules: &mut [ExitPolicyRule]) {
    let describe = |rule: &ExitPolicyRule| {
        format!(
            "{}/{}",
            rule.address.as_deref().unwrap_or("None"),
            rule.masked_bits
                .map_or("None".to_string(), |bits| bits.to_string())
        )
    };
    let starts: Vec<usize> = (0..rules.len())
        .take_while(|index| index + PRIVATE_ADDRESSES.len() <= rules.len())
        .filter(|index| describe(&rules[*index]) == PRIVATE_ADDRESSES[0])
        .collect();
    for start in starts {
        let end = start + PRIVATE_ADDRESSES.len();
        let (min_port, max_port, is_accept) = {
            let first = &rules[start];
            (first.min_port, first.max_port, first.is_accept)
        };
        let is_match = rules[start..end].iter().enumerate().all(|(offset, rule)| {
            describe(rule) == PRIVATE_ADDRESSES[offset]
                && rule.min_port == min_port
                && rule.max_port == max_port
                && rule.is_accept == is_accept
        });
        if !is_match {
            continue;
        }
        rules[start..end]
            .iter_mut()
            .for_each(|rule| rule.is_private = true);
        if let Some(last) = rules.get_mut(end)
            && !last.is_address_wildcard()
            && last.min_port == min_port
            && last.max_port == max_port
            && last.is_accept == is_accept
        {
            last.is_private = true;
        }
    }
}

fn flag_default_rules(rules: &mut [ExitPolicyRule]) {
    if rules.len() < DEFAULT_POLICY_RULES.len() {
        return;
    }
    let split = rules.len() - DEFAULT_POLICY_RULES.len();
    let defaults: Vec<ExitPolicyRule> = DEFAULT_POLICY_RULES
        .iter()
        .map(|rule| ExitPolicyRule::new(rule).expect("default rules are valid"))
        .collect();
    if rules[split..] == defaults[..] {
        rules[split..]
            .iter_mut()
            .for_each(|rule| rule.is_default_suffix = true);
    }
}

#[derive(Debug, Clone)]
pub struct ExitPolicy {
    rules: Vec<ExitPolicyRule>,
    is_allowed_default: bool,
}

impl ExitPolicy {
    pub fn new<S: AsRef<str>>(rules: &[S]) -> Result<Self> {
        let parsed = rules
            .iter()
            .map(AsRef::as_ref)
            .map(str::trim)
            .filter(|rule| !rule.is_empty())
            .map(ExitPolicyRule::new)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self::from_rules(parsed, true))
    }

    pub fn from_rules(input: Vec<ExitPolicyRule>, is_allowed_default: bool) -> Self {
        let mut rules = Vec::new();
        let (mut is_all_accept, mut is_all_reject) = (true, true);
        for rule in input {
            match rule.is_accept {
                true => is_all_reject = false,
                false => is_all_accept = false,
            }
            let is_final = rule.is_address_wildcard() && rule.is_port_wildcard();
            rules.push(rule);
            if is_final {
                break;
            }
        }
        let ends_with_wildcard = rules
            .last()
            .is_some_and(|rule| rule.is_address_wildcard() && rule.is_port_wildcard());
        if ends_with_wildcard && (is_all_accept || is_all_reject) {
            let wildcard = if is_all_accept {
                "accept *:*"
            } else {
                "reject *:*"
            };
            rules = vec![ExitPolicyRule::new(wildcard).expect("literal rule is valid")];
        }
        flag_private_rules(&mut rules);
        flag_default_rules(&mut rules);
        Self {
            rules,
            is_allowed_default,
        }
    }

    pub fn rules(&self) -> &[ExitPolicyRule] {
        &self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, ExitPolicyRule> {
        self.rules.iter()
    }

    pub fn can_exit_to(
        &self,
        address: Option<&str>,
        port: Option<u16>,
        strict: bool,
    ) -> Result<bool> {
        if !self.is_exiting_allowed() {
            return Ok(false);
        }
        for rule in &self.rules {
            if rule.is_match(address, port, strict)? {
                return Ok(rule.is_accept);
            }
        }
        Ok(self.is_allowed_default)
    }

    pub fn is_exiting_allowed(&self) -> bool {
        let mut rejected_ports: HashSet<u16> = HashSet::new();
        for rule in &self.rules {
            if rule.is_accept {
                if (rule.min_port..=rule.max_port)
                    .any(|port| !rejected_ports.contains(&port))
                {
                    return true;
                }
            } else if rule.is_address_wildcard() {
                if rule.is_port_wildcard() {
                    return false;
                }
                rejected_ports.extend(rule.min_port..=rule.max_port);
            }
        }
        self.is_allowed_default
    }

    pub fn summary(&self) -> String {
        let mut is_whitelist = !self.is_allowed_default;
        if let Some(rule) = self
            .rules
            .iter()
            .find(|rule| rule.is_address_wildcard() && rule.is_port_wildcard())
        {
            is_whitelist = !rule.is_accept;
        }
        let mut display_ports: Vec<u16> = Vec::new();
        let mut skip_ports: HashSet<u16> = HashSet::new();
        for rule in &self.rules {
            if !rule.is_address_wildcard() {
                continue;
            }
            if rule.is_port_wildcard() {
                break;
            }
            for port in rule.min_port..=rule.max_port {
                if skip_ports.insert(port) && rule.is_accept == is_whitelist {
                    display_ports.push(port);
                }
            }
        }
        let ranges = match display_ports.is_empty() {
            true => {
                is_whitelist = !is_whitelist;
                vec!["1-65535".to_string()]
            }
            false => port_ranges(display_ports),
        };
        let prefix = if is_whitelist { "accept " } else { "reject " };
        format!("{prefix}{}", ranges.join(", ")).trim().to_string()
    }

    pub fn has_private(&self) -> bool {
        self.rules.iter().any(ExitPolicyRule::is_private)
    }

    pub fn strip_private(&self) -> Self {
        let kept = self
            .rules
            .iter()
            .filter(|rule| !rule.is_private())
            .cloned()
            .collect();
        Self::from_rules(kept, self.is_allowed_default)
    }

    pub fn has_default(&self) -> bool {
        self.rules.iter().any(ExitPolicyRule::is_default)
    }

    pub fn strip_default(&self) -> Self {
        let kept = self
            .rules
            .iter()
            .filter(|rule| !rule.is_default())
            .cloned()
            .collect();
        Self::from_rules(kept, self.is_allowed_default)
    }
}

fn port_ranges(mut ports: Vec<u16>) -> Vec<String> {
    ports.sort_unstable();
    let mut ranges = Vec::new();
    let mut run: Vec<u16> = Vec::new();
    for port in ports {
        if run.last().is_none_or(|last| *last + 1 == port) {
            run.push(port);
            continue;
        }
        ranges.push(format_run(&run));
        run = vec![port];
    }
    if !run.is_empty() {
        ranges.push(format_run(&run));
    }
    ranges
}

fn format_run(run: &[u16]) -> String {
    match run {
        [single] => single.to_string(),
        [first, .., last] => format!("{first}-{last}"),
        [] => String::new(),
    }
}

impl PartialEq for ExitPolicy {
    fn eq(&self, other: &Self) -> bool {
        self.rules == other.rules
    }
}

impl Eq for ExitPolicy {}

impl serde::Serialize for ExitPolicy {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl fmt::Display for ExitPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rules: Vec<String> = self.rules.iter().map(ToString::to_string).collect();
        formatter.write_str(&rules.join(", "))
    }
}

impl<'a> IntoIterator for &'a ExitPolicy {
    type Item = &'a ExitPolicyRule;
    type IntoIter = std::slice::Iter<'a, ExitPolicyRule>;

    fn into_iter(self) -> Self::IntoIter {
        self.rules.iter()
    }
}

#[derive(Debug, Clone)]
pub struct MicroExitPolicy {
    policy: ExitPolicy,
    text: String,
    pub is_accept: bool,
}

impl MicroExitPolicy {
    pub fn new(policy: &str) -> Result<Self> {
        let is_accept = match policy {
            text if text.starts_with("accept") => true,
            text if text.starts_with("reject") => false,
            _ => {
                return Err(Error::parse(format!(
                    "A microdescriptor exit policy must start with either 'accept' or \
                    'reject': {policy}"
                )));
            }
        };
        let ports = &policy[6..];
        if !ports.starts_with(' ') {
            return Err(Error::parse(format!(
                "A microdescriptor exit policy should have a space separating \
                accept/reject from its port list: {policy}"
            )));
        }
        let mut rules = Vec::new();
        for entry in ports.trim_start().split(',') {
            let (first, last) = entry.split_once('-').unwrap_or((entry, entry));
            let (Some(min_port), Some(max_port)) =
                (parse_port(first, false), parse_port(last, false))
            else {
                return Err(Error::parse(format!("'{entry}' is an invalid port range")));
            };
            rules.push(ExitPolicyRule::from_ports(is_accept, min_port, max_port));
        }
        Ok(Self {
            policy: ExitPolicy::from_rules(rules, !is_accept),
            text: policy.to_string(),
            is_accept,
        })
    }
}

impl Deref for MicroExitPolicy {
    type Target = ExitPolicy;

    fn deref(&self) -> &ExitPolicy {
        &self.policy
    }
}

impl PartialEq for MicroExitPolicy {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

impl Eq for MicroExitPolicy {}

impl serde::Serialize for MicroExitPolicy {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl fmt::Display for MicroExitPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

fn local_host_address() -> Option<String> {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .ok()?;
    let target = format!("{}:0", hostname.trim());
    std::net::ToSocketAddrs::to_socket_addrs(&target)
        .ok()?
        .find(|address| address.is_ipv4())
        .map(|address| address.ip().to_string())
}

pub fn get_config_policy(rules: &str, ip_address: Option<&str>) -> Result<ExitPolicy> {
    let entries: Vec<&str> = rules.split(',').collect();
    get_config_policy_from(&entries, ip_address)
}

pub fn get_config_policy_from<S: AsRef<str>>(
    rules: &[S],
    ip_address: Option<&str>,
) -> Result<ExitPolicy> {
    let ip_address = match ip_address {
        Some(address) if is_valid_ipv4_address(address) => Some(address.to_string()),
        Some(address) if is_valid_ipv6_address(address, true) => {
            let bare = address.trim_start_matches('[').trim_end_matches(']');
            Some(format!("[{bare}]"))
        }
        Some(address) => {
            return Err(Error::invalid_input(format!(
                "{address} isn't a valid IP address"
            )));
        }
        None => None,
    };
    let has_port_suffix = |rule: &str| {
        rule.rsplit_once(':').is_some_and(|(_, suffix)| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'*')
        })
    };
    let mut result = Vec::new();
    for rule in rules.iter().map(|rule| rule.as_ref().trim()) {
        if rule.is_empty() {
            continue;
        }
        let rule = match has_port_suffix(rule) {
            true => rule.to_string(),
            false => format!("{rule}:*"),
        };
        if !rule.contains("private") {
            result.push(ExitPolicyRule::new(&rule)?);
            continue;
        }
        let acceptance = rule.split(' ').next().unwrap_or_default();
        let port = rule.rsplit_once(':').map_or("*", |(_, port)| port);
        let mut addresses: Vec<String> =
            PRIVATE_ADDRESSES.iter().map(|a| a.to_string()).collect();
        match &ip_address {
            Some(address) => addresses.push(address.clone()),
            None => addresses.extend(local_host_address()),
        }
        for private_address in addresses {
            result.push(ExitPolicyRule::new(&format!(
                "{acceptance} {private_address}:{port}"
            ))?);
        }
    }
    Ok(ExitPolicy::from_rules(result, true))
}
