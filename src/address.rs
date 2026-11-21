use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use crate::error::{Error, Result};

pub const FULL_IPV4_MASK: &str = "255.255.255.255";
pub const FULL_IPV6_MASK: &str = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF";

const PORT_DESCRIPTIONS: &str = include_str!("data/ports.cfg");

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}

impl Endpoint {
    pub fn new(address: &str, port: u16) -> Result<Self> {
        let address = address.parse().map_err(|_| {
            Error::invalid_input(format!(
                "'{address}' isn't a valid IPv4 or IPv6 address"
            ))
        })?;
        if port == 0 {
            return Err(Error::invalid_input("'0' isn't a valid port"));
        }
        Ok(Self { address, port })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrPort {
    pub endpoint: Endpoint,
    pub link_protocols: Option<Vec<u32>>,
}

impl OrPort {
    pub fn new(
        address: &str,
        port: u16,
        link_protocols: Option<Vec<u32>>,
    ) -> Result<Self> {
        Ok(Self {
            endpoint: Endpoint::new(address, port)?,
            link_protocols,
        })
    }

    pub fn address(&self) -> IpAddr {
        self.endpoint.address
    }

    pub fn port(&self) -> u16 {
        self.endpoint.port
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DirPort {
    pub endpoint: Endpoint,
}

impl DirPort {
    pub fn new(address: &str, port: u16) -> Result<Self> {
        Ok(Self {
            endpoint: Endpoint::new(address, port)?,
        })
    }

    pub fn address(&self) -> IpAddr {
        self.endpoint.address
    }

    pub fn port(&self) -> u16 {
        self.endpoint.port
    }
}

pub fn is_valid_ipv4_address(address: &str) -> bool {
    address.parse::<Ipv4Addr>().is_ok()
}

pub fn is_valid_ipv6_address(address: &str, allow_brackets: bool) -> bool {
    let unwrapped = match allow_brackets {
        true => address
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(address),
        false => address,
    };
    unwrapped.parse::<Ipv6Addr>().is_ok()
}

pub fn parse_port(entry: &str, allow_zero: bool) -> Option<u16> {
    let is_plain = !entry.is_empty()
        && entry.len() <= 5
        && entry.bytes().all(|byte| byte.is_ascii_digit())
        && (entry == "0" || !entry.starts_with('0'));
    if !is_plain {
        return None;
    }
    match entry.parse::<u16>().ok()? {
        0 if !allow_zero => None,
        port => Some(port),
    }
}

pub fn is_valid_port(entry: &str, allow_zero: bool) -> bool {
    parse_port(entry, allow_zero).is_some()
}

pub fn is_private_address(address: &str) -> Result<bool> {
    let parsed: Ipv4Addr = address.parse().map_err(|_| {
        Error::invalid_input(format!("'{address}' isn't a valid IPv4 address"))
    })?;
    Ok(parsed.is_private() || parsed.is_loopback())
}

pub fn address_to_int(address: &str) -> Result<u128> {
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(parsed)) => Ok(u128::from(u32::from(parsed))),
        Ok(IpAddr::V6(parsed)) => Ok(u128::from(parsed)),
        Err(_) => Err(Error::invalid_input(format!(
            "'{address}' is neither an IPv4 or IPv6 address"
        ))),
    }
}

pub fn expand_ipv6_address(address: &str) -> Result<String> {
    if !is_valid_ipv6_address(address, false) {
        return Err(Error::invalid_input(format!(
            "'{address}' isn't a valid IPv6 address"
        )));
    }
    let mut text = address.to_string();
    if let Some(dot) = text.find('.') {
        let start = text[..dot].rfind(':').map_or(0, |colon| colon + 1);
        let embedded: Ipv4Addr = text[start..].parse().map_err(|_| {
            Error::invalid_input(format!("'{address}' isn't a valid IPv6 address"))
        })?;
        let octets = embedded.octets();
        let groups = format!(
            "{:02x}{:02x}:{:02x}{:02x}",
            octets[0], octets[1], octets[2], octets[3]
        );
        text.replace_range(start.., &groups);
    }
    if text.contains("::") {
        let missing = 7usize.saturating_sub(text.matches(':').count());
        text = text.replacen("::", &format!("::{}", ":".repeat(missing)), 1);
    }
    let groups: Vec<String> = text
        .split(':')
        .map(|group| format!("{group:0>4}"))
        .collect();
    Ok(groups.join(":"))
}

pub fn get_mask_ipv4(bits: u32) -> Result<String> {
    if bits > 32 {
        return Err(Error::invalid_input(format!(
            "A mask can only be 0-32 bits, got {bits}"
        )));
    }
    let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
    Ok(Ipv4Addr::from(mask).to_string())
}

pub fn get_mask_ipv6(bits: u32) -> Result<String> {
    if bits > 128 {
        return Err(Error::invalid_input(format!(
            "A mask can only be 0-128 bits, got {bits}"
        )));
    }
    let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
    let groups: Vec<String> = (0..8)
        .map(|index| format!("{:04X}", (mask >> (112 - 16 * index)) as u16))
        .collect();
    Ok(groups.join(":"))
}

pub fn masked_bits(mask: &str) -> Result<u32> {
    let parsed: Ipv4Addr = mask.parse().map_err(|_| {
        Error::invalid_input(format!("'{mask}' is an invalid subnet mask"))
    })?;
    let value = u32::from(parsed);
    match value.leading_ones() + value.trailing_zeros() {
        32 => Ok(value.leading_ones()),
        _ => Err(Error::invalid_input(format!(
            "Unable to convert mask to a bit count: {mask}"
        ))),
    }
}

pub fn port_usage(port: u16) -> Option<&'static str> {
    static USAGES: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();
    USAGES
        .get_or_init(|| parse_port_descriptions(PORT_DESCRIPTIONS))
        .get(&port)
        .copied()
}

fn parse_port_descriptions(content: &'static str) -> HashMap<u16, &'static str> {
    let mut usages = HashMap::new();
    for line in content.lines() {
        let Some((key, description)) = line
            .strip_prefix("port ")
            .and_then(|rest| rest.split_once(" => "))
        else {
            continue;
        };
        let (first, last) = key.split_once('-').unwrap_or((key, key));
        let (Ok(first), Ok(last)) =
            (first.trim().parse::<u16>(), last.trim().parse::<u16>())
        else {
            continue;
        };
        for port in first..=last {
            usages.insert(port, description.trim());
        }
    }
    usages
}

pub fn split_address_port(entry: &str) -> Option<(&str, &str)> {
    entry.rsplit_once(':')
}
