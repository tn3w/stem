use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;

use crate::error::{Error, Result};

#[derive(Debug, Default)]
pub struct Config {
    path: Option<PathBuf>,
    contents: IndexMap<String, Vec<String>>,
    requested_keys: std::sync::Mutex<HashSet<String>>,
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(&mut self, path: impl AsRef<Path>) -> Result<()> {
        self.load_with_options(path, true)
    }

    pub fn load_with_options(
        &mut self,
        path: impl AsRef<Path>,
        commenting: bool,
    ) -> Result<()> {
        let path = path.as_ref();
        self.path = Some(path.to_path_buf());
        if path.is_dir() {
            let mut files: Vec<PathBuf> =
                crate::process_inspection::files_with_suffix(path, "");
            files.sort();
            for file in files
                .into_iter()
                .filter(|file| file.extension().is_none_or(|ext| ext != "swp"))
            {
                self.load_with_options(&file, commenting)?;
            }
            return Ok(());
        }
        let content = fs::read_to_string(path)?;
        self.load_str(&content, commenting);
        Ok(())
    }

    pub fn load_str(&mut self, content: &str, commenting: bool) {
        let mut lines: std::collections::VecDeque<&str> = content.lines().collect();
        while let Some(raw) = lines.pop_front() {
            let uncommented = match (commenting, raw.find('#')) {
                (true, Some(start)) => &raw[..start],
                _ => raw,
            };
            let line = uncommented.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((key, value)) = line.split_once(' ') {
                self.set(key, value.trim(), false);
                continue;
            }
            let mut buffer: Vec<&str> = Vec::new();
            while let Some(next) = lines
                .front()
                .filter(|next| next.trim_start().starts_with('|'))
            {
                buffer.push(&next.trim_start()[1..]);
                lines.pop_front();
            }
            self.set(line, &buffer.join("\n"), false);
        }
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let mut output = String::new();
        for (key, values) in &self.contents {
            for value in values {
                let rendered = match value.contains('\n') {
                    true => format!("\n|{}", value.replace('\n', "\n|")),
                    false => value.clone(),
                };
                output.push_str(&format!("{key} {rendered}\n"));
            }
        }
        fs::write(path, output)?;
        Ok(())
    }

    pub fn clear(&mut self) {
        self.contents.clear();
        self.requested_keys.lock().unwrap().clear();
    }

    pub fn keys(&self) -> Vec<String> {
        self.contents.keys().cloned().collect()
    }

    pub fn unused_keys(&self) -> HashSet<String> {
        let requested = self.requested_keys.lock().unwrap();
        self.contents
            .keys()
            .filter(|key| !requested.contains(*key))
            .cloned()
            .collect()
    }

    pub fn set(&mut self, key: &str, value: &str, overwrite: bool) {
        match overwrite {
            true => {
                self.contents
                    .insert(key.to_string(), vec![value.to_string()]);
            }
            false => self
                .contents
                .entry(key.to_string())
                .or_default()
                .push(value.to_string()),
        }
    }

    pub fn set_values(&mut self, key: &str, values: Vec<String>, overwrite: bool) {
        match overwrite {
            true => {
                self.contents.insert(key.to_string(), values);
            }
            false => self
                .contents
                .entry(key.to_string())
                .or_default()
                .extend(values),
        }
    }

    pub fn remove(&mut self, key: &str) {
        self.contents.shift_remove(key);
    }

    pub fn get_value(&self, key: &str) -> Option<&str> {
        let values = self.contents.get(key)?;
        self.requested_keys.lock().unwrap().insert(key.to_string());
        values.last().map(String::as_str)
    }

    pub fn get_values(&self, key: &str) -> Vec<String> {
        match self.contents.get(key) {
            Some(values) => {
                self.requested_keys.lock().unwrap().insert(key.to_string());
                values.clone()
            }
            None => Vec::new(),
        }
    }

    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        match self.get_value(key).map(str::to_lowercase).as_deref() {
            Some("true") => true,
            Some("false") => false,
            _ => default,
        }
    }

    pub fn get_integer(&self, key: &str, default: i64) -> i64 {
        self.get_value(key)
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    }

    pub fn get_float(&self, key: &str, default: f64) -> f64 {
        self.get_value(key)
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    }

    pub fn get_mapping(&self, key: &str) -> IndexMap<String, String> {
        self.get_values(key)
            .into_iter()
            .filter_map(|entry| {
                let (name, value) = entry.split_once("=>")?;
                Some((name.trim().to_string(), value.trim().to_string()))
            })
            .collect()
    }
}

pub fn parse_enum_csv(
    key: &str,
    value: &str,
    options: &[&str],
    count: Option<(Option<usize>, Option<usize>)>,
) -> Result<Vec<String>> {
    let values: Vec<String> = value
        .split(',')
        .map(|entry| entry.trim().to_uppercase())
        .collect();
    if values == [""] {
        return Ok(Vec::new());
    }
    if let Some((minimum, maximum)) = count {
        if minimum.is_some_and(|minimum| values.len() < minimum) {
            return Err(Error::invalid_input(format!(
                "Config entry '{key}' must have at least {} comma separated values, got \
                '{value}'",
                minimum.unwrap_or(0)
            )));
        }
        if maximum.is_some_and(|maximum| values.len() > maximum) {
            return Err(Error::invalid_input(format!(
                "Config entry '{key}' can have at most {} comma separated values, got \
                '{value}'",
                maximum.unwrap_or(0)
            )));
        }
    }
    values
        .into_iter()
        .map(|entry| {
            options
                .iter()
                .find(|option| option.to_uppercase() == entry)
                .map(|option| option.to_string())
                .ok_or_else(|| {
                    Error::invalid_input(format!(
                        "The '{entry}' entry of config entry '{key}' wasn't in the \
                        enumeration (expected {})",
                        options
                            .iter()
                            .map(|option| option.to_uppercase())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                })
        })
        .collect()
}

pub fn parse_enum(key: &str, value: &str, options: &[&str]) -> Result<String> {
    let mut values = parse_enum_csv(key, value, options, Some((Some(1), Some(1))))?;
    values.pop().ok_or_else(|| {
        Error::invalid_input(format!(
            "Config entry '{key}' is expected to be a single value"
        ))
    })
}
