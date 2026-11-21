use data_encoding::BASE32_NOPAD;
use sha3::{Digest, Sha3_256};

const ONION_V3_CHECKSUM_PREFIX: &[u8] = b".onion checksum";
const ONION_V3_VERSION: u8 = 3;

pub fn is_hex_digits(entry: &str, count: usize) -> bool {
    entry.len() == count && entry.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn is_valid_fingerprint(entry: &str, check_prefix: bool) -> bool {
    match check_prefix {
        true => entry
            .strip_prefix('$')
            .is_some_and(|digits| is_hex_digits(digits, 40)),
        false => is_hex_digits(entry, 40),
    }
}

fn is_alphanumeric_within(entry: &str, max_length: usize) -> bool {
    (1..=max_length).contains(&entry.len())
        && entry.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

pub fn is_valid_nickname(entry: &str) -> bool {
    is_alphanumeric_within(entry, 19)
}

pub fn is_valid_circuit_id(entry: &str) -> bool {
    is_alphanumeric_within(entry, 16)
}

pub fn is_valid_stream_id(entry: &str) -> bool {
    is_valid_circuit_id(entry)
}

pub fn is_valid_connection_id(entry: &str) -> bool {
    is_valid_circuit_id(entry)
}

fn is_lowercase_base32(entry: &str, length: usize) -> bool {
    entry.len() == length
        && entry
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
}

pub fn is_valid_hidden_service_address(entry: &str, versions: &[u8]) -> bool {
    let wants = |version: u8| versions.contains(&version);
    (wants(2) && is_lowercase_base32(entry, 16))
        || (wants(3) && is_lowercase_base32(entry, 56))
}

pub fn is_valid_onion_v3_checksum(entry: &str) -> bool {
    if !is_lowercase_base32(entry, 56) {
        return false;
    }
    let Ok(decoded) = BASE32_NOPAD.decode(entry.to_ascii_uppercase().as_bytes()) else {
        return false;
    };
    let (public_key, tail) = decoded.split_at(32);
    let mut hasher = Sha3_256::new();
    hasher.update(ONION_V3_CHECKSUM_PREFIX);
    hasher.update(public_key);
    hasher.update([ONION_V3_VERSION]);
    let digest = hasher.finalize();
    tail[2] == ONION_V3_VERSION && tail[..2] == digest[..2]
}
