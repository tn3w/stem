use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{Duration, NaiveDate, NaiveDateTime};

use crate::error::{Error, Result};

struct Unit {
    per_unit: f64,
    short: &'static str,
    long: &'static str,
}

const fn unit(per_unit: f64, short: &'static str, long: &'static str) -> Unit {
    Unit {
        per_unit,
        short,
        long,
    }
}

const SIZE_UNITS_BITS: [Unit; 6] = [
    unit(140737488355328.0, " Pb", " Petabit"),
    unit(137438953472.0, " Tb", " Terabit"),
    unit(134217728.0, " Gb", " Gigabit"),
    unit(131072.0, " Mb", " Megabit"),
    unit(128.0, " Kb", " Kilobit"),
    unit(0.125, " b", " Bit"),
];

const SIZE_UNITS_BYTES: [Unit; 6] = [
    unit(1125899906842624.0, " PB", " Petabyte"),
    unit(1099511627776.0, " TB", " Terabyte"),
    unit(1073741824.0, " GB", " Gigabyte"),
    unit(1048576.0, " MB", " Megabyte"),
    unit(1024.0, " KB", " Kilobyte"),
    unit(1.0, " B", " Byte"),
];

const TIME_UNITS: [Unit; 4] = [
    unit(86400.0, "d", " day"),
    unit(3600.0, "h", " hour"),
    unit(60.0, "m", " minute"),
    unit(1.0, "s", " second"),
];

fn unit_label(
    units: &[Unit],
    count: f64,
    decimal: usize,
    is_long: bool,
    round: bool,
) -> String {
    let sign = if count < 0.0 { "-" } else { "" };
    let mut count = count.abs();
    let smallest = &units[units.len() - 1];

    if count == 0.0 {
        let label = if is_long {
            format!("{}s", smallest.long)
        } else {
            smallest.short.to_string()
        };
        return format!("{sign}{count:.decimal$}{label}");
    }

    for unit in units {
        if count < unit.per_unit {
            continue;
        }
        if !round {
            count -= count % (unit.per_unit / 10f64.powi(decimal as i32));
        }
        let amount = format!("{sign}{:.decimal$}", count / unit.per_unit);
        if !is_long {
            return format!("{amount}{}", unit.short);
        }
        let is_plural = match decimal > 0 {
            true => count > unit.per_unit,
            false => count >= unit.per_unit * 2.0,
        };
        return format!("{amount}{}{}", unit.long, if is_plural { "s" } else { "" });
    }
    format!("{sign}{count:.decimal$}{}", smallest.short)
}

pub fn size_label(
    byte_count: f64,
    decimal: usize,
    is_long: bool,
    is_bytes: bool,
    round: bool,
) -> String {
    let units = if is_bytes {
        &SIZE_UNITS_BYTES
    } else {
        &SIZE_UNITS_BITS
    };
    unit_label(units, byte_count, decimal, is_long, round)
}

pub fn time_label(seconds: f64, decimal: usize, is_long: bool) -> String {
    unit_label(&TIME_UNITS, seconds, decimal, is_long, false)
}

pub fn time_labels(seconds: i64, is_long: bool) -> Vec<String> {
    let mut remaining = seconds;
    let mut labels = Vec::new();
    for unit in &TIME_UNITS {
        if remaining.abs() as f64 >= unit.per_unit {
            labels.push(unit_label(&TIME_UNITS, remaining as f64, 0, is_long, false));
            remaining %= unit.per_unit as i64;
        }
    }
    labels
}

pub fn short_time_label(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = seconds % 86400 / 3600;
    let minutes = seconds % 3600 / 60;
    let remaining = seconds % 60;
    match (days, hours) {
        (0, 0) => format!("{minutes:02}:{remaining:02}"),
        (0, _) => format!("{hours:02}:{minutes:02}:{remaining:02}"),
        _ => format!("{days}-{hours:02}:{minutes:02}:{remaining:02}"),
    }
}

pub fn parse_short_time_label(label: &str) -> Result<u64> {
    let (days, clock) = label.split_once('-').unwrap_or(("0", label));
    let parts: Vec<&str> = clock.split(':').collect();
    let (hours, minutes, seconds) = match parts.as_slice() {
        [hours, minutes, seconds] => (*hours, *minutes, *seconds),
        [minutes, seconds] => ("0", *minutes, *seconds),
        _ => {
            return Err(Error::parse(format!(
                "Invalid time format, we expected '[[dd-]hh:]mm:ss' or 'mm:ss.ss': \
                {label}"
            )));
        }
    };
    let non_numeric =
        || Error::parse(format!("Non-numeric value in time entry: {label}"));
    let whole_seconds = seconds.parse::<f64>().map_err(|_| non_numeric())?;
    if !whole_seconds.is_finite() || whole_seconds < 0.0 {
        return Err(non_numeric());
    }
    let parse = |part: &str| part.parse::<u64>().map_err(|_| non_numeric());
    Ok(whole_seconds as u64
        + parse(minutes)? * 60
        + parse(hours)? * 3600
        + parse(days)? * 86400)
}

fn digits(entry: &str, start: usize, length: usize) -> Option<u32> {
    let part = entry.get(start..start + length)?;
    match part.bytes().all(|byte| byte.is_ascii_digit()) {
        true => part.parse().ok(),
        false => None,
    }
}

pub fn parse_timestamp(entry: &str) -> Result<NaiveDateTime> {
    let invalid = || {
        Error::parse(format!(
            "Expected timestamp in format YYYY-MM-DD HH:MM:ss but got {entry}"
        ))
    };
    let bytes = entry.as_bytes();
    if bytes.len() != 19 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b' ' {
        return Err(invalid());
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return Err(invalid());
    }
    let field = |start, length| digits(entry, start, length).ok_or_else(invalid);
    let year = field(0, 4)? as i32;
    if year == 0 {
        return Err(invalid());
    }
    NaiveDate::from_ymd_opt(year, field(5, 2)?, field(8, 2)?)
        .and_then(|date| {
            date.and_hms_opt(field(11, 2).ok()?, field(14, 2).ok()?, field(17, 2).ok()?)
        })
        .ok_or_else(invalid)
}

pub fn parse_iso_timestamp(entry: &str) -> Result<NaiveDateTime> {
    let (timestamp, microseconds) = match entry.split_once('.') {
        Some((timestamp, microseconds)) => (timestamp, microseconds),
        None => (entry, "000000"),
    };
    if microseconds.len() != 6 || !microseconds.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::parse(
            "timestamp's microseconds should be six digits",
        ));
    }
    let Some((date, time)) = timestamp.split_once('T') else {
        return Err(Error::parse(
            "timestamp didn't contain delimeter 'T' between date and time",
        ));
    };
    let base = parse_timestamp(&format!("{date} {time}"))?;
    let microseconds: i64 = microseconds.parse().unwrap_or(0);
    Ok(base + Duration::microseconds(microseconds))
}

pub fn to_camel_case(label: &str, divider: char, joiner: &str) -> String {
    let words: Vec<String> = label
        .split(divider)
        .map(|entry| {
            let mut characters = entry.chars();
            match characters.next() {
                None => String::new(),
                Some(first) if entry.chars().count() == 1 => {
                    first.to_uppercase().collect()
                }
                Some(first) => {
                    let rest: String = characters.collect::<String>().to_lowercase();
                    format!("{}{rest}", first.to_uppercase())
                }
            }
        })
        .collect();
    words.join(joiner)
}

pub fn split_by_length(message: &str, size: usize) -> Vec<String> {
    let characters: Vec<char> = message.chars().collect();
    characters
        .chunks(size.max(1))
        .map(|chunk| chunk.iter().collect())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CropEnding {
    Ellipsis,
    Hyphen,
}

#[derive(Debug, Clone, Copy)]
pub struct CropOptions {
    pub min_word_length: Option<usize>,
    pub min_crop: usize,
    pub ending: CropEnding,
}

impl Default for CropOptions {
    fn default() -> Self {
        Self {
            min_word_length: Some(4),
            min_crop: 0,
            ending: CropEnding::Ellipsis,
        }
    }
}

fn find_char(characters: &[char], needle: char, start: usize) -> Option<usize> {
    characters
        .iter()
        .enumerate()
        .skip(start)
        .find(|(_, character)| **character == needle)
        .map(|(index, _)| index)
}

fn trimmed_length(characters: &[char]) -> usize {
    characters
        .iter()
        .rposition(|character| !character.is_whitespace())
        .map_or(0, |index| index + 1)
}

pub fn crop_with_remainder(
    message: &str,
    size: usize,
    options: CropOptions,
) -> (String, String) {
    crop_message(message, size, options, true)
}

pub fn crop(message: &str, size: usize, options: CropOptions) -> String {
    crop_message(message, size, options, false).0
}

fn crop_message(
    message: &str,
    size: usize,
    options: CropOptions,
    keep_punctuation: bool,
) -> (String, String) {
    let characters: Vec<char> = message.chars().collect();
    if characters.len() <= size {
        return (message.to_string(), String::new());
    }
    let mut size = size;
    let mut min_word_length = options.min_word_length;
    match options.ending {
        CropEnding::Ellipsis => {
            if size < 3 {
                return (String::new(), message.to_string());
            }
            size -= 3;
        }
        CropEnding::Hyphen => {
            min_word_length = min_word_length.map(|length| match length {
                0 => 0,
                length => length + 1,
            });
        }
    }
    let minimum = min_word_length.map_or(i128::MAX, |length| length as i128);
    let search_end = (size + 1).min(characters.len());
    let last_space = characters[..search_end].iter().rposition(|c| *c == ' ');
    let wordbreak = last_space.map(|index| trimmed_length(&characters[..index]));
    let mut include_crop = match wordbreak {
        None if (size as i128) < minimum => return (String::new(), message.to_string()),
        None => true,
        Some(wordbreak) => size as i128 - wordbreak as i128 > minimum,
    };
    if include_crop && options.min_crop > 0 {
        let next_break = find_char(&characters, ' ', size).unwrap_or(characters.len());
        include_crop =
            (next_break + 1) as i128 - size as i128 >= options.min_crop as i128;
    }
    let (mut cropped, mut remainder): (String, String);
    if include_crop {
        cropped = characters[..size].iter().collect();
        remainder = characters[size..].iter().collect();
        if options.ending == CropEnding::Hyphen {
            let last = cropped.pop().map(String::from).unwrap_or_default();
            remainder = format!("{last}{remainder}");
            cropped = format!("{}-", cropped.trim_end());
        }
    } else {
        let split = wordbreak.unwrap_or(0);
        cropped = characters[..split].iter().collect();
        remainder = characters[split..].iter().collect();
    }
    if !keep_punctuation && (cropped.ends_with(',') || cropped.ends_with('.')) {
        cropped.pop();
    }
    if options.ending == CropEnding::Ellipsis {
        cropped = format!("{}...", cropped.trim_end());
    }
    (cropped, remainder)
}

static COLOR_SUPPORT_DISABLED: AtomicBool = AtomicBool::new(false);

pub fn set_color_support_disabled(disabled: bool) {
    COLOR_SUPPORT_DISABLED.store(disabled, Ordering::Relaxed);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalColor {
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalStyle {
    Foreground(TerminalColor),
    Background(TerminalColor),
    Bold,
    Underline,
    Highlight,
    ReadlineEscape,
    Lines,
}

const RESET: &str = "\x1b[0m";

pub fn terminal_encoding(styles: &[TerminalStyle]) -> Option<String> {
    let codes: Vec<String> = styles
        .iter()
        .filter_map(|style| match style {
            TerminalStyle::Foreground(color) => Some(30 + *color as u8),
            TerminalStyle::Background(color) => Some(40 + *color as u8),
            TerminalStyle::Bold => Some(1),
            TerminalStyle::Underline => Some(4),
            TerminalStyle::Highlight => Some(7),
            _ => None,
        })
        .map(|code| code.to_string())
        .collect();
    match codes.is_empty() {
        true => None,
        false => Some(format!("\x1b[{}m", codes.join(";"))),
    }
}

pub fn format_terminal(message: &str, styles: &[TerminalStyle]) -> String {
    if COLOR_SUPPORT_DISABLED.load(Ordering::Relaxed) {
        return message.to_string();
    }
    if styles.contains(&TerminalStyle::Lines) {
        let remaining: Vec<TerminalStyle> = styles
            .iter()
            .copied()
            .filter(|style| *style != TerminalStyle::Lines)
            .collect();
        let lines: Vec<String> = message
            .split('\n')
            .map(|line| format_terminal(line, &remaining))
            .collect();
        return lines.join("\n");
    }
    if message.contains(RESET) {
        let parts: Vec<String> = message
            .split(RESET)
            .map(|part| format_terminal(part, styles))
            .collect();
        return parts.concat();
    }
    let Some(prefix) = terminal_encoding(styles) else {
        return message.to_string();
    };
    if styles.contains(&TerminalStyle::ReadlineEscape) {
        return format!("\x01{prefix}\x02{message}\x01{RESET}\x02");
    }
    format!("{prefix}{message}{RESET}")
}
