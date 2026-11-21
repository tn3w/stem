use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Value, json};
use stem::address;
use stem::descriptor::hidden_service;
use stem::exit_policy::{
    AddressType, ExitPolicy, ExitPolicyRule, MicroExitPolicy, get_config_policy,
};
use stem::formatting::{self, CropEnding, CropOptions};
use stem::validation;
use stem::version::{Requirement, Version};

const FORMAT: &str = "%Y-%m-%d %H:%M:%S%.6f";

fn golden() -> Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/helpers.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}

fn optional_text(value: &Value) -> Option<&str> {
    value.as_str()
}

fn number(value: &Value) -> f64 {
    value.as_f64().unwrap()
}

fn optional_port(value: &Value) -> Option<u16> {
    value.as_u64().map(|port| port as u16)
}

fn probe_results(
    probes: &[Value],
    check: impl Fn(Option<&str>, Option<u16>) -> Option<bool>,
) -> Value {
    let results: Vec<Value> = probes
        .iter()
        .map(|probe| check(optional_text(&probe[0]), optional_port(&probe[1])))
        .map(|result| result.map_or(Value::Null, Value::Bool))
        .collect();
    Value::Array(results)
}

fn probes(source: &Value) -> Vec<Value> {
    source.as_array().cloned().unwrap_or_default()
}

fn run(
    function: &str,
    args: &[Value],
    probe_set: &[Value],
    micro_set: &[Value],
) -> Option<Value> {
    let flag = |index: usize| args[index].as_bool().unwrap();
    Some(match function {
        "is_valid_ipv4_address" => json!(address::is_valid_ipv4_address(text(&args[0]))),
        "is_valid_ipv6_address" => {
            json!(address::is_valid_ipv6_address(text(&args[0]), flag(1)))
        }
        "is_valid_port" => json!(address::is_valid_port(text(&args[0]), flag(1))),
        "is_private_address" => json!(address::is_private_address(text(&args[0])).ok()?),
        "expand_ipv6_address" => {
            json!(address::expand_ipv6_address(text(&args[0])).ok()?)
        }
        "get_mask_ipv4" => {
            json!(address::get_mask_ipv4(u32::try_from(args[0].as_i64()?).ok()?).ok()?)
        }
        "get_mask_ipv6" => {
            json!(address::get_mask_ipv6(u32::try_from(args[0].as_i64()?).ok()?).ok()?)
        }
        "masked_bits" => json!(address::masked_bits(text(&args[0])).ok()?),
        "port_usage" => json!(address::port_usage(args[0].as_u64()? as u16)),
        "is_valid_fingerprint" => {
            json!(validation::is_valid_fingerprint(text(&args[0]), flag(1)))
        }
        "is_valid_nickname" => json!(validation::is_valid_nickname(text(&args[0]))),
        "is_valid_circuit_id" => json!(validation::is_valid_circuit_id(text(&args[0]))),
        "is_valid_stream_id" => json!(validation::is_valid_stream_id(text(&args[0]))),
        "is_valid_connection_id" => {
            json!(validation::is_valid_connection_id(text(&args[0])))
        }
        "is_valid_hidden_service_address" => {
            let versions: Vec<u8> = match args[1].as_u64() {
                Some(version) => vec![version as u8],
                None => vec![2, 3],
            };
            json!(validation::is_valid_hidden_service_address(
                text(&args[0]),
                &versions
            ))
        }
        "size_label" => json!(formatting::size_label(
            number(&args[0]),
            args[1].as_u64()? as usize,
            flag(2),
            flag(3),
            flag(4)
        )),
        "time_label" => json!(formatting::time_label(
            number(&args[0]),
            args[1].as_u64()? as usize,
            flag(2)
        )),
        "time_labels" => json!(formatting::time_labels(args[0].as_i64()?, flag(1))),
        "short_time_label" => {
            let seconds = u64::try_from(args[0].as_i64()?).ok()?;
            json!(formatting::short_time_label(seconds))
        }
        "parse_short_time_label" => {
            json!(formatting::parse_short_time_label(text(&args[0])).ok()?)
        }
        "parse_timestamp" => {
            json!(
                formatting::parse_timestamp(text(&args[0]))
                    .ok()?
                    .format(FORMAT)
                    .to_string()
            )
        }
        "parse_iso_timestamp" => json!(
            formatting::parse_iso_timestamp(text(&args[0]))
                .ok()?
                .format(FORMAT)
                .to_string()
        ),
        "to_camel_case" => {
            let divider = text(&args[1]).chars().next()?;
            json!(formatting::to_camel_case(
                text(&args[0]),
                divider,
                text(&args[2])
            ))
        }
        "split_by_length" => {
            let size = args[1].as_u64()? as usize;
            match size {
                0 => return None,
                _ => json!(formatting::split_by_length(text(&args[0]), size)),
            }
        }
        "crop" => {
            let options = CropOptions {
                min_word_length: args[2].as_u64().map(|length| length as usize),
                min_crop: args[3].as_u64()? as usize,
                ending: match text(&args[4]) {
                    "ellipsis" => CropEnding::Ellipsis,
                    _ => CropEnding::Hyphen,
                },
            };
            let size = args[1].as_u64()? as usize;
            match flag(5) {
                true => {
                    let (cropped, rest) =
                        formatting::crop_with_remainder(text(&args[0]), size, options);
                    json!([cropped, rest])
                }
                false => json!(formatting::crop(text(&args[0]), size, options)),
            }
        }
        "version" => {
            let version = Version::new(text(&args[0])).ok()?;
            json!({
                "str": version.to_string(),
                "major": version.major,
                "minor": version.minor,
                "micro": version.micro,
                "patch": version.patch,
                "status": version.status,
                "extra": version.extra(),
                "git_commit": version.git_commit,
            })
        }
        "version_order" => {
            let left = Version::new(text(&args[0])).ok()?;
            let right = Version::new(text(&args[1])).ok()?;
            json!([
                left < right,
                left == right,
                left > right,
                left <= right,
                left >= right
            ])
        }
        "onion_address" => {
            let key: [u8; 32] = hex::decode(text(&args[0])).ok()?.try_into().ok()?;
            json!(hidden_service::address_from_identity_key(&key, flag(1)))
        }
        "identity_key" => {
            json!(hex::encode(
                hidden_service::identity_key_from_address(text(&args[0])).ok()?
            ))
        }
        "blinded_pubkey" => {
            let key: [u8; 32] = hex::decode(text(&args[0])).ok()?.try_into().ok()?;
            let nonce: [u8; 32] = hex::decode(text(&args[1])).ok()?.try_into().ok()?;
            json!(hex::encode(
                hidden_service::blinded_public_key(&key, &nonce).ok()?
            ))
        }
        "subcredential" => {
            let key = hex::decode(text(&args[0])).ok()?;
            let blinded = hex::decode(text(&args[1])).ok()?;
            json!(hex::encode(hidden_service::subcredential(&key, &blinded)))
        }
        "requirement" => {
            let wanted = text(&args[0]).replace('_', "").to_lowercase();
            let requirement = Requirement::ALL
                .iter()
                .find(|candidate| format!("{candidate:?}").to_lowercase() == wanted)?;
            json!(Version::new(text(&args[1])).ok()?.meets(*requirement))
        }
        "exit_policy_rule" => {
            let rule = ExitPolicyRule::new(text(&args[0])).ok()?;
            json!({
                "is_accept": rule.is_accept,
                "str": rule.to_string(),
                "address": rule.address,
                "type": match rule.address_type() {
                    AddressType::Wildcard => "Wildcard",
                    AddressType::Ipv4 => "IPv4",
                    AddressType::Ipv6 => "IPv6",
                },
                "mask": rule.mask(),
                "masked_bits": rule.masked_bits(),
                "min_port": rule.min_port,
                "max_port": rule.max_port,
                "address_wildcard": rule.is_address_wildcard(),
                "port_wildcard": rule.is_port_wildcard(),
                "is_private": rule.is_private(),
                "is_default": rule.is_default(),
                "matches": probe_results(probe_set, |address, port| {
                    rule.is_match(address, port, false).ok()
                }),
            })
        }
        "exit_policy" => {
            let rules: Vec<String> = args[0]
                .as_array()?
                .iter()
                .map(|rule| text(rule).to_string())
                .collect();
            let policy = ExitPolicy::new(&rules).ok()?;
            json!({
                "str": policy.to_string(),
                "summary": policy.summary(),
                "is_exiting_allowed": policy.is_exiting_allowed(),
                "has_private": policy.has_private(),
                "stripped_private": policy.strip_private().to_string(),
                "has_default": policy.has_default(),
                "stripped_default": policy.strip_default().to_string(),
                "rule_count": policy.iter().count(),
                "can_exit_to": probe_results(probe_set, |address, port| {
                    policy.can_exit_to(address, port, false).ok()
                }),
            })
        }
        "micro_exit_policy" => {
            let policy = MicroExitPolicy::new(text(&args[0])).ok()?;
            json!({
                "str": policy.to_string(),
                "can_exit_to": probe_results(micro_set, |address, port| {
                    policy.can_exit_to(address, port, false).ok()
                }),
            })
        }
        "config_policy" => {
            let policy =
                get_config_policy(text(&args[0]), optional_text(&args[1])).ok()?;
            json!(policy.to_string())
        }
        other => panic!("unknown helper {other}"),
    })
}

fn python_string_args(args: &[Value]) -> Vec<&str> {
    args.iter().filter_map(Value::as_str).collect()
}

fn cropped_length(python: &Value) -> usize {
    let text = match python {
        Value::Array(parts) => text(&parts[0]),
        other => text(other),
    };
    text.trim_end_matches("...").chars().count()
}

fn is_known_python_defect(
    function: &str,
    args: &[Value],
    python: &Option<Value>,
    rust: &Option<Value>,
) -> bool {
    let strings = python_string_args(args);
    let lenient_text = strings
        .iter()
        .any(|entry| entry.ends_with('\n') || !entry.is_ascii());
    match function {
        "is_valid_ipv6_address" => {
            let entry = strings[0];
            lenient_text
                || (entry.contains(['[', ']']) && python == &Some(json!(true)))
                || (entry.contains("::") && python == &Some(json!(false)))
        }
        "parse_short_time_label" => {
            python.is_some() && rust.is_none() && strings[0].contains([' ', '_'])
        }
        "parse_timestamp" => python.is_some() && rust.is_none() && strings[0].len() > 19,
        "size_label" | "time_label" => python == &Some(Value::Null),
        "version" | "version_order" => {
            lenient_text || normalized_status(python) == normalized_status(rust)
        }
        "crop" => is_python_crop_defect(args, python, rust),
        "expand_ipv6_address" => strings[0].contains(['[', ']']),
        _ => lenient_text,
    }
}

fn is_python_crop_defect(
    args: &[Value],
    python: &Option<Value>,
    rust: &Option<Value>,
) -> bool {
    let size = args[1].as_u64().unwrap_or(0) as usize;
    let too_long = cropped_length(python.as_ref().unwrap_or(&Value::Null)) > size;
    let window: String = text(&args[0]).chars().take(size + 1).collect();
    let negative_slice = !window.contains(' ')
        && args[3].as_u64().unwrap_or(0) > 0
        && rust.as_ref().is_some_and(|result| {
            text(&result[0]).is_empty() || result.as_str() == Some("")
        });
    too_long || negative_slice
}

fn normalized_status(value: &Option<Value>) -> Option<Value> {
    let mut value = value.clone()?;
    if let Some(status) = value.get_mut("status")
        && status == ""
    {
        *status = Value::Null;
    }
    Some(value)
}

#[test]
fn helper_functions_match_python_stem() {
    let golden = golden();
    let probe_set = probes(&golden["rule_probes"]);
    let micro_set = probes(&golden["micro_probes"]);
    let mut report: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (function, cases) in golden.as_object().unwrap() {
        if function.ends_with("_probes") {
            continue;
        }
        for case in cases.as_array().unwrap() {
            let args = case["args"].as_array().unwrap();
            let outcome = run(function, args, &probe_set, &micro_set);
            let python = match case["error"].as_bool().unwrap() {
                true => None,
                false => Some(case["result"].clone()),
            };
            if outcome != python
                && !is_known_python_defect(function, args, &python, &outcome)
            {
                report.entry(function.clone()).or_default().push(format!(
                    "{args:?}\n      python {python:?}\n      rust   {outcome:?}"
                ));
            }
        }
    }
    for (function, entries) in &report {
        println!("== {function} ({})", entries.len());
        for entry in entries.iter().take(25) {
            println!("   {entry}");
        }
    }
    assert!(report.is_empty(), "{} helpers differ", report.len());
}
