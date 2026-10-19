use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
    Unknown,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Critical => "CRITICAL",
            LogLevel::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    pub file_name: String,
    pub line_number: usize,
    pub timestamp: NaiveDateTime,
    pub level: LogLevel,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub module: Option<String>,
    pub message: String,
    pub raw_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeSlot {
    pub start: NaiveDateTime,
    pub end: NaiveDateTime,
    pub label: String,
    pub record_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalySeverity {
    High,
    Medium,
    Low,
}

impl AnomalySeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalySeverity::High => "HIGH",
            AnomalySeverity::Medium => "MEDIUM",
            AnomalySeverity::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub severity: AnomalySeverity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub timestamp: Option<NaiveDateTime>,
    pub source_file: Option<String>,
    pub line_number: Option<usize>,
    pub matched_log: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActivitySummary {
    pub total_logs_in_slot: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub debug_count: usize,
    pub tunnel_status_changes: Vec<(NaiveDateTime, String)>,
    pub steering_events: Vec<(NaiveDateTime, String)>,
    pub gateway_transitions: Vec<(NaiveDateTime, String)>,
    pub auth_events: Vec<(NaiveDateTime, String)>,
    pub config_updates: Vec<(NaiveDateTime, String)>,
    pub active_gateways: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub total_logs: usize,
    pub total_files: usize,
    pub time_slots: Vec<TimeSlot>,
    pub selected_slot: Option<TimeSlot>,
    pub activity_summary: ActivitySummary,
    pub anomalies: Vec<Anomaly>,
}
