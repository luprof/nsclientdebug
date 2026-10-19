use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

use crate::models::{LogLevel, LogRecord};

static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_log_regex() -> &'static Regex {
    LOG_REGEX.get_or_init(|| {
        Regex::new(r"^(?P<year>\d{4})[/-](?P<month>\d{2})[/-](?P<day>\d{2})\s+(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})(?:\.(?P<ms>\d+))?\s+\[?(?P<level>[A-Za-z]+)\]?\s+(?:\[?(?P<pid>\d+):(?P<tid>\d+)\]?)?\s*(?:\[(?P<module>[^\]]+)\])?\s*(?P<msg>.*)$").unwrap()
    })
}

pub fn parse_log_line(file_name: &str, line_number: usize, line: &str) -> Option<LogRecord> {
    let trimmed = line.trim_end();
    if trimmed.is_empty() {
        return None;
    }

    let re = get_log_regex();

    if let Some(caps) = re.captures(trimmed) {
        let year: i32 = caps.name("year")?.as_str().parse().ok()?;
        let month: u32 = caps.name("month")?.as_str().parse().ok()?;
        let day: u32 = caps.name("day")?.as_str().parse().ok()?;
        let hour: u32 = caps.name("hour")?.as_str().parse().ok()?;
        let min: u32 = caps.name("min")?.as_str().parse().ok()?;
        let sec: u32 = caps.name("sec")?.as_str().parse().ok()?;

        let ms_str = caps.name("ms").map(|m| m.as_str()).unwrap_or("0");
        let milli: u32 = ms_str.parse().unwrap_or(0);

        let dt = chrono::NaiveDate::from_ymd_opt(year, month, day)?
            .and_hms_milli_opt(hour, min, sec, milli)?;

        let level_str = caps.name("level").map(|m| m.as_str()).unwrap_or("INFO");
        let level = match level_str.to_uppercase().as_str() {
            "TRACE" | "VERBOSE" => LogLevel::Trace,
            "DEBUG" | "DBG" => LogLevel::Debug,
            "INFO" | "INF" | "NOTICE" => LogLevel::Info,
            "WARN" | "WARNING" | "WRN" => LogLevel::Warning,
            "ERR" | "ERROR" => LogLevel::Error,
            "CRIT" | "CRITICAL" | "FATAL" => LogLevel::Critical,
            _ => LogLevel::Unknown,
        };

        let pid = caps.name("pid").and_then(|m| m.as_str().parse().ok());
        let tid = caps.name("tid").and_then(|m| m.as_str().parse().ok());
        let module = caps.name("module").map(|m| m.as_str().trim().to_string());
        let message = caps.name("msg").map(|m| m.as_str().trim().to_string()).unwrap_or_default();

        Some(LogRecord {
            file_name: file_name.to_string(),
            line_number,
            timestamp: dt,
            level,
            process_id: pid,
            thread_id: tid,
            module,
            message,
            raw_line: trimmed.to_string(),
        })
    } else {
        None
    }
}

pub fn parse_log_content(file_name: &str, content: &str) -> Vec<LogRecord> {
    let mut records = Vec::new();
    let mut current_record: Option<LogRecord> = None;

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;
        if let Some(rec) = parse_log_line(file_name, line_num, line) {
            if let Some(prev) = current_record.take() {
                records.push(prev);
            }
            current_record = Some(rec);
        } else if let Some(ref mut prev) = current_record {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                prev.message.push('\n');
                prev.message.push_str(trimmed);
                prev.raw_line.push('\n');
                prev.raw_line.push_str(line);
            }
        }
    }

    if let Some(last) = current_record {
        records.push(last);
    }

    records
}

pub fn parse_log_file<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<LogRecord>> {
    let path_ref = path.as_ref();
    let file_name = path_ref
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown.log");
    let content = std::fs::read_to_string(path_ref)?;
    Ok(parse_log_content(file_name, &content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_netskope_line() {
        let line = "2025/03/10 14:15:30.123 [INFO] [1234:5678] [tunnel] Tunnel connected to gateway 10.0.0.1";
        let rec = parse_log_line("test.log", 1, line).expect("Should parse standard log line");

        assert_eq!(rec.file_name, "test.log");
        assert_eq!(rec.line_number, 1);
        assert_eq!(rec.level, LogLevel::Info);
        assert_eq!(rec.process_id, Some(1234));
        assert_eq!(rec.thread_id, Some(5678));
        assert_eq!(rec.module.as_deref(), Some("tunnel"));
        assert_eq!(rec.message, "Tunnel connected to gateway 10.0.0.1");
    }

    #[test]
    fn test_parse_multiline_log() {
        let content = "2025/03/10 14:15:30.123 [ERROR] [1234:5678] [auth] Token validation failed\n Details: HTTP 401 Unauthorized";
        let records = parse_log_content("test.log", content);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].level, LogLevel::Error);
        assert!(records[0].message.contains("Token validation failed"));
        assert!(records[0].message.contains("HTTP 401 Unauthorized"));
    }
}
