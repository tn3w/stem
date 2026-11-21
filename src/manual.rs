use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use indexmap::IndexMap;
use rusqlite::{Connection, params};

use crate::configuration::Config;
use crate::download::download;
use crate::enumerations::string_enum;
use crate::error::{Error, Result};
use crate::process_inspection::{
    call_with_environment, is_available, is_bsd, is_mac, is_slackware,
};

pub const MANUAL_URL: &str =
    "https://gitlab.torproject.org/tpo/core/tor/-/raw/main/doc/man/tor.1.md";
const SCHEMA_VERSION: i64 = 1;
const EMBEDDED_SETTINGS: &str = include_str!("data/settings.cfg");
const EMBEDDED_MANUAL: &str = include_str!("data/cached_manual.cfg");
const SCHEMA: [&str; 5] = [
    "CREATE TABLE metadata(name TEXT, synopsis TEXT, description TEXT, man_commit TEXT, \
    stem_commit TEXT)",
    "CREATE TABLE commandline(name TEXT PRIMARY KEY, description TEXT)",
    "CREATE TABLE signals(name TEXT PRIMARY KEY, description TEXT)",
    "CREATE TABLE files(name TEXT PRIMARY KEY, description TEXT)",
    "CREATE TABLE torrc(key TEXT PRIMARY KEY, name TEXT, category TEXT, usage TEXT, \
    summary TEXT, description TEXT, position INTEGER)",
];

string_enum!(Category {
    General = "GENERAL",
    Client = "CLIENT",
    Relay = "RELAY",
    Directory = "DIRECTORY",
    Authority = "AUTHORITY",
    HiddenService = "HIDDEN_SERVICE",
    DenialOfService = "DENIAL_OF_SERVICE",
    Testing = "TESTING",
    Unknown = "UNKNOWN",
});

const CATEGORY_SECTIONS: [(&str, Category); 8] = [
    ("GENERAL OPTIONS", Category::General),
    ("CLIENT OPTIONS", Category::Client),
    ("SERVER OPTIONS", Category::Relay),
    ("DIRECTORY SERVER OPTIONS", Category::Directory),
    ("DIRECTORY AUTHORITY SERVER OPTIONS", Category::Authority),
    ("HIDDEN SERVICE OPTIONS", Category::HiddenService),
    (
        "DENIAL OF SERVICE MITIGATION OPTIONS",
        Category::DenialOfService,
    ),
    ("TESTING NETWORK OPTIONS", Category::Testing),
];

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SchemaMismatch {
    pub message: String,
    pub database_schema: i64,
    pub library_schema: i64,
}

impl From<SchemaMismatch> for Error {
    fn from(mismatch: SchemaMismatch) -> Self {
        Error::Io(std::io::Error::other(mismatch.message))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigOption {
    pub name: String,
    pub category: String,
    pub usage: String,
    pub summary: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Manual {
    pub name: String,
    pub synopsis: String,
    pub description: String,
    pub commandline_options: IndexMap<String, String>,
    pub signals: IndexMap<String, String>,
    pub files: IndexMap<String, String>,
    pub config_options: IndexMap<String, ConfigOption>,
    pub man_commit: Option<String>,
    pub stem_commit: Option<String>,
    pub schema: Option<i64>,
}

struct ManualSettings {
    summaries: HashMap<String, String>,
    important: Vec<String>,
    event_descriptions: HashMap<String, String>,
}

fn settings() -> &'static ManualSettings {
    static SETTINGS: OnceLock<ManualSettings> = OnceLock::new();
    SETTINGS.get_or_init(|| {
        let mut config = Config::new();
        config.load_str(EMBEDDED_SETTINGS, true);
        let mut settings = ManualSettings {
            summaries: HashMap::new(),
            important: config
                .get_values("manual.important")
                .iter()
                .map(|name| name.to_lowercase())
                .collect(),
            event_descriptions: HashMap::new(),
        };
        for key in config.keys() {
            let Some(value) = config.get_value(&key) else {
                continue;
            };
            if key.starts_with("manual.summary.") {
                settings
                    .summaries
                    .insert(key.to_lowercase(), value.to_string());
            }
            if let Some(event) = key.strip_prefix("event.description.") {
                settings
                    .event_descriptions
                    .insert(event.to_lowercase(), value.to_string());
            }
        }
        settings
    })
}

pub fn event_description(event: &str) -> Option<&'static str> {
    settings()
        .event_descriptions
        .get(&event.to_lowercase())
        .map(String::as_str)
}

pub fn is_important(option: &str) -> bool {
    settings().important.contains(&option.to_lowercase())
}

fn join_lines(lines: &[String]) -> String {
    let mut result: Vec<String> = Vec::new();
    for line in lines {
        match line.is_empty() {
            true => {
                if result.last().is_some_and(|last| last != "\n") {
                    result.push("\n".to_string());
                }
            }
            false => result.push(format!("{line}\n")),
        }
    }
    result.concat().trim().to_string()
}

fn base_indentation(content: &[String]) -> usize {
    content
        .iter()
        .filter(|line| line.starts_with(' '))
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start_matches(' ').len())
        .min()
        .map_or(7, |minimum| minimum.min(7))
}

fn get_categories(content: &[String]) -> IndexMap<String, Vec<String>> {
    let mut content = content;
    if content.first().is_some_and(|line| line.contains("TOR(1)")) {
        content = &content[1..];
    }
    if content.last().is_some_and(|line| line.starts_with("Tor")) {
        content = &content[..content.len() - 1];
    }
    let indentation = " ".repeat(base_indentation(content));
    let mut categories = IndexMap::new();
    let mut category: Option<String> = None;
    let mut lines: Vec<String> = Vec::new();
    for raw in content {
        let line = raw
            .replace('\u{2019}', "'")
            .replace('\u{2014}', "-")
            .replace('\u{b7}', "*");
        if !line.is_empty() && !line.starts_with(' ') {
            if let Some(name) = category.take() {
                if lines.last().is_some_and(String::is_empty) {
                    lines.pop();
                }
                categories.insert(name, std::mem::take(&mut lines));
            }
            category = Some(line.trim().to_string());
            lines = Vec::new();
        } else {
            lines.push(
                line.strip_prefix(indentation.as_str())
                    .unwrap_or(&line)
                    .to_string(),
            );
        }
    }
    if let Some(name) = category {
        categories.insert(name, lines);
    }
    categories
}

fn indented_descriptions(lines: &[String]) -> IndexMap<String, String> {
    let mut options: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut last_argument: Option<String> = None;
    for line in lines {
        if line == "    Note" {
            last_argument = None;
        } else if !line.is_empty() && !line.starts_with(' ') {
            options.insert(line.clone(), Vec::new());
            last_argument = Some(line.clone());
        } else if let (Some(argument), Some(rest)) =
            (&last_argument, line.strip_prefix("    "))
        {
            options
                .entry(argument.clone())
                .or_default()
                .push(rest.to_string());
        }
    }
    options
        .into_iter()
        .filter(|(_, description)| !description.is_empty())
        .map(|(argument, description)| (argument, description.join(" ")))
        .collect()
}

fn add_config_options(
    options: &mut IndexMap<String, ConfigOption>,
    category: &Category,
    lines: &[String],
) {
    fn add_option(
        options: &mut IndexMap<String, ConfigOption>,
        category: &Category,
        title: &str,
        description: &[String],
    ) {
        let is_sentence =
            title.ends_with(':') || (title.ends_with('.') && !title.ends_with("..."));
        if title.contains("PER INSTANCE OPTIONS") || is_sentence {
            return;
        }
        if title.contains(", ") {
            for subtitle in title.split(", ") {
                add_option(options, category, subtitle, description);
            }
            return;
        }
        let (name, usage) = title.split_once(' ').unwrap_or((title, ""));
        let summary = settings()
            .summaries
            .get(&format!("manual.summary.{}", name.to_lowercase()))
            .cloned()
            .unwrap_or_default();
        options.insert(
            name.to_string(),
            ConfigOption {
                name: name.to_string(),
                category: category.to_string(),
                usage: usage.to_string(),
                summary,
                description: join_lines(description).trim().to_string(),
            },
        );
    }
    let mut lines = lines;
    let end_index = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            line.contains("The following options") || line.contains("PER SERVICE OPTIONS")
        })
        .map(|(index, _)| index)
        .max();
    if let Some(index) = end_index {
        lines = &lines[index..];
        if let Some(blank) = lines.iter().position(String::is_empty) {
            lines = &lines[blank..];
        }
    }
    let mut last_title: Option<String> = None;
    let mut description: Vec<String> = Vec::new();
    for line in lines {
        if !line.is_empty() && !line.starts_with(' ') {
            if let Some(title) = last_title.take() {
                add_option(options, category, &title, &description);
            }
            last_title = Some(line.clone());
            description = Vec::new();
        } else {
            description.push(line.strip_prefix("    ").unwrap_or(line).to_string());
        }
    }
    if let Some(title) = last_title {
        add_option(options, category, &title, &description);
    }
}

pub async fn download_man_page(path: &Path, url: &str, timeout: Duration) -> Result<()> {
    if !is_available("pandoc") {
        return Err(Error::Io(std::io::Error::other(
            "We require pandoc to convert tor's manual into a man page",
        )));
    }
    let directory = tempfile_directory()?;
    let markdown_path = directory.join("tor.1.md");
    let manual_path = directory.join("tor.1");
    let outcome = async {
        let content = download(url, Some(timeout), 0).await.map_err(|error| {
            Error::DownloadFailed {
                url: url.to_string(),
                message: format!(
                    "Unable to download tor's manual from {url} to {}: {error}",
                    markdown_path.display()
                ),
            }
        })?;
        std::fs::write(&markdown_path, content)?;
        let source = markdown_path.to_string_lossy().into_owned();
        let target = manual_path.to_string_lossy().into_owned();
        let command = [
            "pandoc", "-s", "-f", "markdown", "-t", "man", &source, "-o", &target,
        ];
        call_with_environment(&command, false, None, &[]).map_err(|error| {
            Error::Io(std::io::Error::other(format!(
                "Unable to run '{}': {error}",
                command.join(" ")
            )))
        })?;
        if !manual_path.exists() {
            return Err(Error::Io(std::io::Error::other(
                "no man page was generated",
            )));
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&manual_path, path)?;
        Ok(())
    }
    .await;
    let _ = std::fs::remove_dir_all(&directory);
    outcome
}

fn tempfile_directory() -> Result<std::path::PathBuf> {
    let suffix: u64 = rand::random();
    let path = std::env::temp_dir().join(format!("stem-manual-{suffix:016x}"));
    std::fs::create_dir(&path)?;
    Ok(path)
}

impl Manual {
    pub fn from_cache(path: Option<&Path>) -> Result<Self> {
        match path {
            None => {
                let mut config = Config::new();
                config.load_str(EMBEDDED_MANUAL, false);
                Ok(Self::from_config(&config))
            }
            Some(path)
                if path
                    .extension()
                    .is_some_and(|extension| extension == "sqlite") =>
            {
                Self::from_sqlite_cache(path)
            }
            Some(path) => {
                let mut config = Config::new();
                config.load_with_options(path, false)?;
                Ok(Self::from_config(&config))
            }
        }
    }

    fn from_config(config: &Config) -> Self {
        let mut config_options: IndexMap<String, ConfigOption> = IndexMap::new();
        for key in config.keys() {
            let Some(rest) = key.strip_prefix("config_options.") else {
                continue;
            };
            let name = rest.split('.').next().unwrap_or_default().to_string();
            if config_options.contains_key(&name) {
                continue;
            }
            let field = |attribute: &str| {
                config
                    .get_value(&format!("config_options.{name}.{attribute}"))
                    .unwrap_or_default()
                    .to_string()
            };
            config_options.insert(
                name.clone(),
                ConfigOption {
                    name: field("name"),
                    category: field("category"),
                    usage: field("usage"),
                    summary: field("summary"),
                    description: field("description"),
                },
            );
        }
        Self {
            name: config.get_value("name").unwrap_or_default().to_string(),
            synopsis: config.get_value("synopsis").unwrap_or_default().to_string(),
            description: config
                .get_value("description")
                .unwrap_or_default()
                .to_string(),
            commandline_options: config.get_mapping("commandline_options"),
            signals: config.get_mapping("signals"),
            files: config.get_mapping("files"),
            config_options,
            man_commit: config.get_value("man_commit").map(str::to_string),
            stem_commit: config.get_value("stem_commit").map(str::to_string),
            schema: None,
        }
    }

    fn from_sqlite_cache(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::Io(std::io::Error::other(format!(
                "{} doesn't exist",
                path.display()
            ))));
        }
        let failure = |error: rusqlite::Error| {
            Error::Io(std::io::Error::other(format!(
                "Failed to read database metadata from {}: {error}",
                path.display()
            )))
        };
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(failure)?;
        let schema: i64 = connection
            .query_row("SELECT version FROM schema", [], |row| row.get(0))
            .map_err(failure)?;
        if schema != SCHEMA_VERSION {
            return Err(SchemaMismatch {
                message: format!(
                    "Stem's current manual schema version is {SCHEMA_VERSION}, but {} \
                    was version {schema}",
                    path.display()
                ),
                database_schema: schema,
                library_schema: SCHEMA_VERSION,
            }
            .into());
        }
        let (name, synopsis, description, man_commit, stem_commit) = connection
            .query_row(
                "SELECT name, synopsis, description, man_commit, stem_commit FROM \
                metadata",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .map_err(failure)?;
        let pairs = |table: &str| -> Result<IndexMap<String, String>> {
            let mut statement = connection
                .prepare(&format!("SELECT name, description FROM {table}"))
                .map_err(failure)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(failure)?;
            rows.collect::<std::result::Result<IndexMap<_, _>, _>>()
                .map_err(failure)
        };
        let mut config_options = IndexMap::new();
        let mut statement = connection
            .prepare(
                "SELECT name, category, usage, summary, description FROM torrc \
                ORDER BY position",
            )
            .map_err(failure)?;
        let rows = statement
            .query_map([], |row| {
                Ok(ConfigOption {
                    name: row.get(0)?,
                    category: row.get(1)?,
                    usage: row.get(2)?,
                    summary: row.get(3)?,
                    description: row.get(4)?,
                })
            })
            .map_err(failure)?;
        for option in rows {
            let option = option.map_err(failure)?;
            config_options.insert(option.name.clone(), option);
        }
        Ok(Self {
            name,
            synopsis,
            description,
            commandline_options: pairs("commandline")?,
            signals: pairs("signals")?,
            files: pairs("files")?,
            config_options,
            man_commit,
            stem_commit,
            schema: Some(schema),
        })
    }

    pub fn from_man(man_path: &str) -> Result<Self> {
        let has_encoding_argument = !is_mac() && !is_bsd() && !is_slackware();
        let mut command = vec!["man"];
        if has_encoding_argument {
            command.push("--encoding=ascii");
        }
        command.extend(["-P", "cat", man_path]);
        let output =
            call_with_environment(&command, false, None, &[("MANWIDTH", "10000000")])
                .map_err(|error| {
                    Error::Io(std::io::Error::other(format!(
                        "Unable to run '{}': {error}",
                        command.join(" ")
                    )))
                })?;
        let categories = get_categories(&output);
        let mut config_options = IndexMap::new();
        for (header, category) in &CATEGORY_SECTIONS {
            add_config_options(
                &mut config_options,
                category,
                categories.get(*header).map_or(&[], Vec::as_slice),
            );
        }
        for (category, lines) in &categories {
            let is_extra = category.ends_with(" OPTIONS")
                && !CATEGORY_SECTIONS
                    .iter()
                    .any(|(header, _)| header == category)
                && !matches!(
                    category.as_str(),
                    "COMMAND-LINE OPTIONS" | "NON-PERSISTENT OPTIONS"
                );
            if is_extra {
                add_config_options(&mut config_options, &Category::Unknown, lines);
            }
        }
        let section = |name: &str| categories.get(name).map_or(&[][..], Vec::as_slice);
        Ok(Self {
            name: join_lines(section("NAME")),
            synopsis: join_lines(section("SYNOPSIS")),
            description: join_lines(section("DESCRIPTION")),
            commandline_options: indented_descriptions(section("COMMAND-LINE OPTIONS")),
            signals: indented_descriptions(section("SIGNALS")),
            files: indented_descriptions(section("FILES")),
            config_options,
            ..Default::default()
        })
    }

    pub async fn from_remote(timeout: Duration) -> Result<Self> {
        Self::from_url(MANUAL_URL, timeout).await
    }

    pub async fn from_url(url: &str, timeout: Duration) -> Result<Self> {
        let directory = tempfile_directory()?;
        let path = directory.join("tor.1");
        let outcome = async {
            download_man_page(&path, url, timeout).await?;
            Self::from_man(&path.to_string_lossy())
        }
        .await;
        let _ = std::fs::remove_dir_all(&directory);
        outcome
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        match path
            .extension()
            .is_some_and(|extension| extension == "sqlite")
        {
            true => self.save_as_sqlite(path),
            false => self.save_as_config(path),
        }
    }

    fn save_as_sqlite(&self, path: &Path) -> Result<()> {
        let failure =
            |error: rusqlite::Error| Error::Io(std::io::Error::other(error.to_string()));
        let temporary = path.with_extension("sqlite.new");
        let _ = std::fs::remove_file(&temporary);
        {
            let connection = Connection::open(&temporary).map_err(failure)?;
            connection
                .execute("CREATE TABLE schema(version INTEGER)", [])
                .map_err(failure)?;
            connection
                .execute(
                    "INSERT INTO schema(version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )
                .map_err(failure)?;
            for statement in SCHEMA {
                connection.execute(statement, []).map_err(failure)?;
            }
            connection
                .execute(
                    "INSERT INTO metadata(name, synopsis, description, man_commit, \
                    stem_commit) VALUES (?1,?2,?3,?4,?5)",
                    params![
                        self.name,
                        self.synopsis,
                        self.description,
                        self.man_commit,
                        self.stem_commit
                    ],
                )
                .map_err(failure)?;
            for (table, entries) in [
                ("commandline", &self.commandline_options),
                ("signals", &self.signals),
                ("files", &self.files),
            ] {
                for (name, description) in entries {
                    connection
                        .execute(
                            &format!(
                                "INSERT INTO {table}(name, description) VALUES (?1,?2)"
                            ),
                            params![name, description],
                        )
                        .map_err(failure)?;
                }
            }
            for (position, option) in self.config_options.values().enumerate() {
                connection
                    .execute(
                        "INSERT INTO torrc(key, name, category, usage, summary, \
                        description, position) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                        params![
                            option.name.to_uppercase(),
                            option.name,
                            option.category,
                            option.usage,
                            option.summary,
                            option.description,
                            position as i64
                        ],
                    )
                    .map_err(failure)?;
            }
        }
        let _ = std::fs::remove_file(path);
        std::fs::rename(&temporary, path)?;
        Ok(())
    }

    fn save_as_config(&self, path: &Path) -> Result<()> {
        let mut config = Config::new();
        config.set("name", &self.name, true);
        config.set("synopsis", &self.synopsis, true);
        config.set("description", &self.description, true);
        if let Some(commit) = &self.man_commit {
            config.set("man_commit", commit, true);
        }
        if let Some(commit) = &self.stem_commit {
            config.set("stem_commit", commit, true);
        }
        for (key, entries) in [
            ("commandline_options", &self.commandline_options),
            ("signals", &self.signals),
            ("files", &self.files),
        ] {
            for (name, description) in entries {
                config.set(key, &format!("{name} => {description}"), false);
            }
        }
        for (key, option) in &self.config_options {
            config.set(
                &format!("config_options.{key}.category"),
                &option.category,
                true,
            );
            config.set(&format!("config_options.{key}.name"), &option.name, true);
            config.set(&format!("config_options.{key}.usage"), &option.usage, true);
            config.set(
                &format!("config_options.{key}.summary"),
                &option.summary,
                true,
            );
            config.set(
                &format!("config_options.{key}.description"),
                &option.description,
                true,
            );
        }
        config.save(path)
    }
}

pub fn manual_differences(previous: &Manual, current: &Manual) -> String {
    let mut lines: Vec<String> = Vec::new();
    let text_attributes = [
        ("name", &previous.name, &current.name),
        ("synopsis", &previous.synopsis, &current.synopsis),
        ("description", &previous.description, &current.description),
    ];
    for (attribute, old, new) in text_attributes {
        if old != new {
            lines.push(format!("* Manual's {attribute} attribute changed\n"));
            lines.push(format!("  Previously...\n\n{old}\n"));
            lines.push(format!("  Updating to...\n\n{new}"));
            lines.push("\n".to_string());
        }
    }
    for (attribute, old, new) in [
        (
            "commandline_options",
            &previous.commandline_options,
            &current.commandline_options,
        ),
        ("signals", &previous.signals, &current.signals),
        ("files", &previous.files, &current.files),
    ] {
        if old == new {
            continue;
        }
        lines.push(format!("* Manual's {attribute} attribute changed\n"));
        for (key, value) in new
            .iter()
            .filter(|(key, value)| old.get(*key) != Some(*value))
        {
            lines.push(format!("  adding {key} => {value}"));
        }
        for (key, value) in old
            .iter()
            .filter(|(key, value)| new.get(*key) != Some(*value))
        {
            lines.push(format!("  removing {key} => {value}"));
        }
        lines.push("\n".to_string());
    }
    if previous.config_options != current.config_options {
        lines.push("* Manual's config_options attribute changed\n".to_string());
        for (name, option) in &current.config_options {
            match previous.config_options.get(name) {
                None => lines.push(format!("  adding new config option => {name}")),
                Some(old) if old != option => {
                    for (attribute, new_value, old_value) in [
                        ("name", &option.name, &old.name),
                        ("category", &option.category, &old.category),
                        ("usage", &option.usage, &old.usage),
                        ("summary", &option.summary, &old.summary),
                        ("description", &option.description, &old.description),
                    ] {
                        if new_value != old_value {
                            lines.push(format!(
                                "  modified {name} ({attribute}) => {new_value}"
                            ));
                        }
                    }
                }
                Some(_) => {}
            }
        }
        for name in previous
            .config_options
            .keys()
            .filter(|name| !current.config_options.contains_key(*name))
        {
            lines.push(format!("  removing config option => {name}"));
        }
        lines.push("\n".to_string());
    }
    lines.join("\n")
}
