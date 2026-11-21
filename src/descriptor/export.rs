use std::collections::BTreeSet;

use serde_json::Value;

use crate::descriptor::parsing::Descriptor;
use crate::error::{Error, Result};

fn descriptor_fields(descriptor: &Descriptor) -> Result<serde_json::Map<String, Value>> {
    match serde_json::to_value(descriptor) {
        Ok(Value::Object(fields)) => Ok(fields),
        Ok(_) => Err(Error::invalid_input(
            "Unable to export a descriptor that has no attributes",
        )),
        Err(error) => Err(Error::invalid_input(format!(
            "Unable to export a descriptor: {error}"
        ))),
    }
}

fn csv_cell(value: Option<&Value>) -> String {
    let text = match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    };
    match text.contains(['"', ',', '\n', '\r']) {
        true => format!("\"{}\"", text.replace('"', "\"\"")),
        false => text,
    }
}

pub fn export_csv(
    descriptors: &[Descriptor],
    included_fields: &[&str],
    excluded_fields: &[&str],
    header: bool,
) -> Result<String> {
    let Some(first) = descriptors.first() else {
        return Ok(String::new());
    };
    let kind = first.type_annotation().name;
    let first_fields = descriptor_fields(first)?;
    let available: BTreeSet<&String> = first_fields.keys().collect();
    let mut columns: Vec<String> = match included_fields.is_empty() {
        true => available.iter().map(|field| (*field).clone()).collect(),
        false => {
            for field in included_fields {
                if !available
                    .iter()
                    .any(|candidate| candidate.as_str() == *field)
                {
                    return Err(Error::invalid_input(format!(
                        "{kind} does not have a '{field}' attribute, valid fields are: \
                        {}",
                        available
                            .iter()
                            .map(|field| field.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
            }
            included_fields
                .iter()
                .map(|field| field.to_string())
                .collect()
        }
    };
    columns.retain(|column| !excluded_fields.contains(&column.as_str()));
    let mut lines = Vec::new();
    if header {
        lines.push(columns.join(","));
    }
    for descriptor in descriptors {
        if descriptor.type_annotation().name != kind {
            return Err(Error::invalid_input(format!(
                "To export a descriptor CSV all of the descriptors must be of the same \
                type. First descriptor was a {kind} but we later got a {}.",
                descriptor.type_annotation().name
            )));
        }
        let fields = descriptor_fields(descriptor)?;
        let cells: Vec<String> = columns
            .iter()
            .map(|column| csv_cell(fields.get(column)))
            .collect();
        lines.push(cells.join(","));
    }
    Ok(lines.join("\n") + "\n")
}
