use std::collections::{BTreeMap, HashSet};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::descriptor::parsing::{DocumentHandler, ParsedFile, parse_path};
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    AlreadyRead {
        last_modified: u64,
        last_modified_when_read: u64,
    },
    ParsingFailure(String),
    UnrecognizedType(String),
    ReadFailed(String),
    FileMissing,
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyRead {
                last_modified,
                last_modified_when_read,
            } => write!(
                formatter,
                "File has already been read since it was last modified. \
                modification time: {last_modified}, last read: {last_modified_when_read}"
            ),
            Self::ParsingFailure(message) | Self::ReadFailed(message) => {
                formatter.write_str(message)
            }
            Self::UnrecognizedType(message) => {
                write!(formatter, "Unrecognized descriptor type: {message}")
            }
            Self::FileMissing => formatter.write_str("File does not exist"),
        }
    }
}

pub type ProcessedFiles = BTreeMap<PathBuf, u64>;

pub fn load_processed_files(path: &Path) -> Result<ProcessedFiles> {
    let mut processed = ProcessedFiles::new();
    for line in std::fs::read_to_string(path)?.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((file, timestamp)) = line.rsplit_once(' ') else {
            return Err(Error::parse(format!("Malformed line: {line}")));
        };
        if !Path::new(file).is_absolute() {
            return Err(Error::parse(format!("'{file}' is not an absolute path")));
        }
        let timestamp = match timestamp.bytes().all(|byte| byte.is_ascii_digit()) {
            true => timestamp.parse::<u64>().ok(),
            false => None,
        };
        let Some(timestamp) = timestamp else {
            return Err(Error::parse(format!(
                "'{line}' doesn't end with an integer timestamp"
            )));
        };
        processed.insert(PathBuf::from(file), timestamp);
    }
    Ok(processed)
}

pub fn save_processed_files(path: &Path, processed: &ProcessedFiles) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut output = String::new();
    for (file, timestamp) in processed {
        if !file.is_absolute() || file.to_string_lossy().contains('\n') {
            return Err(Error::invalid_input(format!(
                "Only absolute paths are acceptable: {}",
                file.display()
            )));
        }
        output.push_str(&format!("{} {timestamp}\n", file.display()));
    }
    std::fs::write(path, output)?;
    Ok(())
}

type ReadListener = Box<dyn FnMut(&Path) + Send>;
type SkipListener = Box<dyn FnMut(&Path, &SkipReason) + Send>;

pub struct DescriptorReader {
    targets: Vec<PathBuf>,
    validate: bool,
    follow_links: bool,
    persistence_path: Option<PathBuf>,
    document_handler: DocumentHandler,
    descriptor_type: Option<String>,
    processed_files: ProcessedFiles,
    read_listeners: Vec<ReadListener>,
    skip_listeners: Vec<SkipListener>,
}

impl DescriptorReader {
    pub fn new(targets: &[impl AsRef<Path>]) -> Self {
        Self {
            targets: targets
                .iter()
                .map(|target| absolute(target.as_ref()))
                .collect(),
            validate: false,
            follow_links: false,
            persistence_path: None,
            document_handler: DocumentHandler::Entries,
            descriptor_type: None,
            processed_files: ProcessedFiles::new(),
            read_listeners: Vec::new(),
            skip_listeners: Vec::new(),
        }
    }

    pub fn with_validation(mut self, validate: bool) -> Self {
        self.validate = validate;
        self
    }

    pub fn following_links(mut self) -> Self {
        self.follow_links = true;
        self
    }

    pub fn with_document_handler(mut self, handler: DocumentHandler) -> Self {
        self.document_handler = handler;
        self
    }

    pub fn with_descriptor_type(mut self, descriptor_type: &str) -> Self {
        self.descriptor_type = Some(descriptor_type.to_string());
        self
    }

    pub fn with_persistence(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        if let Ok(processed) = load_processed_files(&path) {
            self.processed_files = processed;
        }
        self.persistence_path = Some(path);
        self
    }

    pub fn processed_files(&self) -> &ProcessedFiles {
        &self.processed_files
    }

    pub fn set_processed_files(&mut self, processed: ProcessedFiles) {
        self.processed_files = processed;
    }

    pub fn register_read_listener(
        &mut self,
        listener: impl FnMut(&Path) + Send + 'static,
    ) {
        self.read_listeners.push(Box::new(listener));
    }

    pub fn register_skip_listener(
        &mut self,
        listener: impl FnMut(&Path, &SkipReason) + Send + 'static,
    ) {
        self.skip_listeners.push(Box::new(listener));
    }

    pub fn read_all(&mut self) -> Result<Vec<ParsedFile>> {
        let mut found = Vec::new();
        self.read_each(|file| {
            found.push(file);
            ControlFlow::Continue(())
        })?;
        Ok(found)
    }

    pub fn read_each(
        &mut self,
        mut handler: impl FnMut(ParsedFile) -> ControlFlow<()>,
    ) -> Result<()> {
        let mut new_processed = ProcessedFiles::new();
        let mut visited = HashSet::new();
        let mut remaining: Vec<PathBuf> = self.targets.clone();
        remaining.reverse();
        let mut stopped = false;
        while let Some(target) = remaining.pop() {
            if stopped {
                break;
            }
            if !target.exists() {
                self.notify_skip(&target, &SkipReason::FileMissing);
                continue;
            }
            let files = match target.is_dir() {
                true => self.walk(&target, &mut visited),
                false => vec![target],
            };
            for file in files {
                if self
                    .handle_file(&file, &mut new_processed, &mut handler)
                    .is_break()
                {
                    stopped = true;
                    break;
                }
            }
        }
        if !stopped {
            self.processed_files = new_processed;
        }
        if let Some(path) = &self.persistence_path {
            let _ = save_processed_files(path, &self.processed_files);
        }
        Ok(())
    }

    fn walk(&self, directory: &Path, visited: &mut HashSet<PathBuf>) -> Vec<PathBuf> {
        let canonical =
            std::fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf());
        if !visited.insert(canonical) {
            return Vec::new();
        }
        let Ok(entries) = std::fs::read_dir(directory) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> =
            entries.flatten().map(|entry| entry.path()).collect();
        paths.sort();
        let mut files = Vec::new();
        for path in paths {
            let metadata = match self.follow_links {
                true => std::fs::metadata(&path),
                false => std::fs::symlink_metadata(&path),
            };
            match metadata {
                Ok(metadata) if metadata.is_dir() => {
                    files.extend(self.walk(&path, visited))
                }
                Ok(_) => files.push(path),
                Err(_) => files.push(path),
            }
        }
        files
    }

    fn handle_file(
        &mut self,
        target: &Path,
        new_processed: &mut ProcessedFiles,
        handler: &mut impl FnMut(ParsedFile) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        let modified =
            match std::fs::metadata(target).and_then(|metadata| metadata.modified()) {
                Ok(time) => time
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |span| span.as_secs()),
                Err(error) => {
                    self.notify_skip(target, &SkipReason::ReadFailed(error.to_string()));
                    return ControlFlow::Continue(());
                }
            };
        new_processed.insert(target.to_path_buf(), modified);
        let last_used = self.processed_files.get(target).copied();
        if let Some(last_used) = last_used.filter(|last_used| *last_used >= modified) {
            self.notify_skip(
                target,
                &SkipReason::AlreadyRead {
                    last_modified: modified,
                    last_modified_when_read: last_used,
                },
            );
            return ControlFlow::Continue(());
        }
        if !target.is_file() {
            return ControlFlow::Continue(());
        }
        for listener in &mut self.read_listeners {
            listener(target);
        }
        let parsed = parse_path(
            target,
            self.descriptor_type.as_deref(),
            self.validate,
            self.document_handler,
        );
        match parsed {
            Ok(files) => {
                for file in files {
                    if handler(file).is_break() {
                        return ControlFlow::Break(());
                    }
                }
            }
            Err(error) => self.notify_skip(target, &skip_reason(&error)),
        }
        ControlFlow::Continue(())
    }

    fn notify_skip(&mut self, path: &Path, reason: &SkipReason) {
        for listener in &mut self.skip_listeners {
            listener(path, reason);
        }
    }
}

fn skip_reason(error: &Error) -> SkipReason {
    match error {
        Error::InvalidInput(message)
            if message.starts_with("Unable to determine the descriptor's type") =>
        {
            SkipReason::UnrecognizedType(message.clone())
        }
        Error::Io(error) => SkipReason::ReadFailed(error.to_string()),
        other => SkipReason::ParsingFailure(other.to_string()),
    }
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}
