use indexmap::IndexMap;

use crate::descriptor::router_status::{OrAddress, parse_a_lines};
use crate::descriptor::{
    AttrValue, Attributes, DigestEncoding, DigestHash, LineCursor, Protocols,
    ReadOptions, descriptor_components, descriptor_content, encode_digest, hash_bytes,
    key_block, lenient, lenient_option, parse_protocol_line, random_crypto_blob,
};
use crate::error::{Error, Result};
use crate::exit_policy::MicroExitPolicy;

const REQUIRED_FIELDS: [&str; 1] = ["onion-key"];
const SINGLE_FIELDS: [&str; 6] =
    ["onion-key", "ntor-onion-key", "family", "p", "p6", "pr"];
const RECOGNIZED_KEYWORDS: [&str; 8] = [
    "onion-key",
    "ntor-onion-key",
    "a",
    "family",
    "p",
    "p6",
    "pr",
    "id",
];

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Microdescriptor {
    #[serde(skip)]
    pub raw_contents: Vec<u8>,
    pub unrecognized_lines: Vec<String>,
    #[serde(serialize_with = "crate::descriptor::serialize_text_list")]
    pub annotation_lines: Vec<Vec<u8>>,
    pub onion_key: Option<String>,
    pub ntor_onion_key: Option<String>,
    pub or_addresses: Vec<OrAddress>,
    pub family: Vec<String>,
    pub exit_policy: MicroExitPolicy,
    pub exit_policy_v6: Option<MicroExitPolicy>,
    pub identifier_type: Option<String>,
    pub identifier: Option<String>,
    pub identifiers: IndexMap<String, String>,
    pub protocols: Protocols,
}

fn parse_id_lines(
    entries: &crate::descriptor::Entries,
) -> Result<IndexMap<String, String>> {
    let mut identities = IndexMap::new();
    for entry in entries.values("id") {
        let parts: Vec<&str> = entry.split_whitespace().collect();
        let [key_type, key_value, ..] = parts.as_slice() else {
            return Err(Error::parse(format!(
                "'id' lines should contain both the key type and digest: id {entry}"
            )));
        };
        if identities
            .insert(key_type.to_string(), key_value.to_string())
            .is_some()
        {
            return Err(Error::parse(format!(
                "There can only be one 'id' line per a key type, but '{key_type}' \
                appeared multiple times"
            )));
        }
    }
    Ok(identities)
}

impl Microdescriptor {
    pub fn parse(content: &[u8], validate: bool) -> Result<Self> {
        Self::parse_with_annotations(content, validate, Vec::new())
    }

    pub fn parse_with_annotations(
        content: &[u8],
        validate: bool,
        annotation_lines: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let (entries, _) = descriptor_components(content, validate, &[], &[])?;
        if validate {
            for keyword in REQUIRED_FIELDS {
                if !entries.contains(keyword) {
                    return Err(Error::parse(format!(
                        "Microdescriptor must have a '{keyword}' entry"
                    )));
                }
            }
            for keyword in SINGLE_FIELDS {
                if entries.get(keyword).is_some_and(|values| values.len() > 1) {
                    return Err(Error::parse(format!(
                        "The '{keyword}' entry can only appear once in a microdescriptor"
                    )));
                }
            }
            if entries.first_key() != Some("onion-key") {
                return Err(Error::parse(
                    "Microdescriptor must start with a 'onion-key' entry",
                ));
            }
        }
        let mut descriptor = Self {
            raw_contents: content.to_vec(),
            unrecognized_lines: entries.unrecognized_lines(&RECOGNIZED_KEYWORDS),
            annotation_lines,
            onion_key: None,
            ntor_onion_key: None,
            or_addresses: Vec::new(),
            family: Vec::new(),
            exit_policy: MicroExitPolicy::new("reject 1-65535").expect("default policy"),
            exit_policy_v6: None,
            identifier_type: None,
            identifier: None,
            identifiers: IndexMap::new(),
            protocols: Protocols::new(),
        };
        if entries.contains("onion-key") {
            descriptor.onion_key = lenient_option(
                validate,
                key_block(&entries, "onion-key", "RSA PUBLIC KEY")
                    .map(|(_, block)| block),
            )?;
        }
        if let Ok(value) = entries.value("ntor-onion-key") {
            descriptor.ntor_onion_key = Some(value.to_string());
        }
        if entries.contains("a") {
            descriptor.or_addresses =
                lenient(validate, parse_a_lines("microdescriptor", &entries))?;
        }
        if let Ok(value) = entries.value("family") {
            descriptor.family = value.split(' ').map(str::to_string).collect();
        }
        if let Ok(value) = entries.value("p") {
            let parsed = lenient_option(
                validate,
                MicroExitPolicy::new(value).map_err(|error| {
                    Error::parse(format!(
                        "microdescriptor exit policy is malformed ({error}): p {value}"
                    ))
                }),
            )?;
            if let Some(policy) = parsed {
                descriptor.exit_policy = policy;
            }
        }
        if let Ok(value) = entries.value("p6") {
            descriptor.exit_policy_v6 =
                lenient_option(validate, MicroExitPolicy::new(value))?;
        }
        if entries.contains("id") {
            descriptor.identifiers = lenient(validate, parse_id_lines(&entries))?;
            if let Some((kind, value)) = descriptor.identifiers.last() {
                descriptor.identifier_type = Some(kind.clone());
                descriptor.identifier = Some(value.clone());
            }
        }
        if let Ok(value) = entries.value("pr") {
            descriptor.protocols = lenient(validate, parse_protocol_line("pr", value))?;
        }
        Ok(descriptor)
    }

    pub fn parse_many(content: &[u8], validate: bool) -> Result<Vec<Self>> {
        let mut cursor = LineCursor::new(content);
        let mut descriptors = Vec::new();
        loop {
            let annotations =
                cursor.read_until_keywords(&["onion-key"], ReadOptions::default());
            let Some(onion_key_line) = cursor.read_line() else {
                break;
            };
            let mut lines: Vec<u8> = onion_key_line.to_vec();
            loop {
                let position = cursor.tell();
                let Some(line) = cursor.read_line() else {
                    break;
                };
                if line.starts_with(b"@") || line.starts_with(b"onion-key") {
                    cursor.seek(position);
                    break;
                }
                lines.extend_from_slice(line);
            }
            let annotation_lines: Vec<Vec<u8>> = annotations
                .content
                .split(|byte| *byte == b'\n')
                .map(|line| line.trim_ascii().to_vec())
                .filter(|line| !line.is_empty())
                .collect();
            descriptors.push(Self::parse_with_annotations(
                &lines,
                validate,
                annotation_lines,
            )?);
        }
        Ok(descriptors)
    }

    pub fn digest(&self, hash: DigestHash, encoding: DigestEncoding) -> String {
        encode_digest(&hash_bytes(hash, &self.raw_contents), encoding)
    }

    pub fn annotations(&self) -> IndexMap<Vec<u8>, Option<Vec<u8>>> {
        self.annotation_lines
            .iter()
            .map(|line| match line.iter().position(|byte| *byte == b' ') {
                Some(split) => (line[..split].to_vec(), Some(line[split + 1..].to_vec())),
                None => (line.clone(), None),
            })
            .collect()
    }

    pub fn content(attributes: &Attributes, exclude: &[&str]) -> Vec<u8> {
        descriptor_content(
            attributes,
            exclude,
            &[(
                "onion-key",
                AttrValue::Text(random_crypto_blob(Some("RSA PUBLIC KEY"))),
            )],
            &[],
        )
    }

    pub fn create(
        attributes: &Attributes,
        exclude: &[&str],
        validate: bool,
    ) -> Result<Self> {
        Self::parse(&Self::content(attributes, exclude), validate)
    }
}
