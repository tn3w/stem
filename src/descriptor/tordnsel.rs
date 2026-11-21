use chrono::NaiveDateTime;

use crate::address::is_valid_ipv4_address;
use crate::descriptor::{LineCursor, ReadOptions, descriptor_components};
use crate::error::{Error, Result};
use crate::formatting::parse_timestamp;
use crate::validation::is_valid_fingerprint;

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct TorDnsel {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub fingerprint: Option<String>,
    pub published: Option<NaiveDateTime>,
    pub last_status: Option<NaiveDateTime>,
    pub exit_addresses: Vec<(String, NaiveDateTime)>,
}

fn unexpected_block(validate: bool, block: &Option<String>) -> Result<()> {
    match (validate, block) {
        (true, Some(contents)) => Err(Error::parse(format!(
            "Unexpected block content: {contents}"
        ))),
        _ => Ok(()),
    }
}

impl TorDnsel {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        let (entries, _) = descriptor_components(content, validate, &[], &[])?;
        let mut descriptor = Self {
            raw_contents: content.to_vec(),
            ..Default::default()
        };
        for (keyword, values) in entries.iter() {
            let first = &values[0];
            unexpected_block(validate, &first.block_contents)?;
            match keyword.as_str() {
                "ExitNode" => {
                    if validate && !is_valid_fingerprint(&first.value, false) {
                        return Err(Error::parse(format!(
                            "Tor relay fingerprints consist of forty hex digits: {}",
                            first.value
                        )));
                    }
                    descriptor.fingerprint = Some(first.value.clone());
                }
                "Published" | "LastStatus" => match parse_timestamp(&first.value) {
                    Ok(timestamp) if keyword == "Published" => {
                        descriptor.published = Some(timestamp)
                    }
                    Ok(timestamp) => descriptor.last_status = Some(timestamp),
                    Err(_) if validate => {
                        return Err(Error::parse(format!(
                            "{keyword} time wasn't parsable: {}",
                            first.value
                        )));
                    }
                    Err(_) => {}
                },
                "ExitAddress" => {
                    for entry in values {
                        let Some((address, date)) = entry.value.split_once(' ') else {
                            if validate {
                                return Err(Error::parse(format!(
                                    "ExitAddress found time wasn't parsable: {}",
                                    entry.value
                                )));
                            }
                            continue;
                        };
                        if validate {
                            if !is_valid_ipv4_address(address) {
                                return Err(Error::parse(format!(
                                    "ExitAddress isn't a valid IPv4 address: {address}"
                                )));
                            }
                            unexpected_block(true, &entry.block_contents)?;
                        }
                        match parse_timestamp(date) {
                            Ok(found) => descriptor
                                .exit_addresses
                                .push((address.to_string(), found)),
                            Err(_) if validate => {
                                return Err(Error::parse(format!(
                                    "ExitAddress found time wasn't parsable: {}",
                                    entry.value
                                )));
                            }
                            Err(_) => {}
                        }
                    }
                }
                other if validate => {
                    return Err(Error::parse(format!("Unrecognized keyword: {other}")));
                }
                _ => {}
            }
        }
        Ok(descriptor)
    }

    pub fn parse_many(content: &[u8], validate: bool) -> Result<Vec<Self>> {
        let mut cursor = LineCursor::new(content);
        cursor.read_until_keywords(&["ExitNode"], ReadOptions::default());
        let mut descriptors = Vec::new();
        loop {
            let mut body = cursor
                .read_until_keywords(&["ExitAddress"], ReadOptions::default())
                .content;
            body.extend(
                cursor
                    .read_until_keywords(&["ExitNode"], ReadOptions::default())
                    .content,
            );
            if body.is_empty() {
                break;
            }
            descriptors.push(Self::parse(&body, validate)?);
        }
        Ok(descriptors)
    }
}
