use chrono::{Duration, NaiveDateTime, Timelike};
use std::collections::HashSet;

use crate::models::{
    ActivitySummary, Anomaly, AnomalySeverity, LogLevel, LogRecord, TimeSlot,
};

pub fn generate_time_slots(records: &[LogRecord]) -> Vec<TimeSlot> {
    if records.is_empty() {
        return Vec::new();
    }

    let min_time = records.iter().map(|r| r.timestamp).min().unwrap();
    let max_time = records.iter().map(|r| r.timestamp).max().unwrap();

    let mut slot_start = min_time
        .with_minute(0)
        .unwrap()
        .with_second(0)
        .unwrap()
        .with_nanosecond(0)
        .unwrap();

    let mut slots = Vec::new();

    while slot_start <= max_time {
        let slot_end = slot_start + Duration::hours(1);

        let count = records
            .iter()
            .filter(|r| r.timestamp >= slot_start && r.timestamp < slot_end)
            .count();

        if count > 0 {
            let label = format!(
                "{} to {} ({} logs)",
                slot_start.format("%Y-%m-%d %H:%M"),
                slot_end.format("%H:%M"),
                count
            );

            slots.push(TimeSlot {
                start: slot_start,
                end: slot_end,
                label,
                record_count: count,
            });
        }

        slot_start = slot_end;
    }

    slots.reverse();
    slots
}

pub fn select_default_time_slot(slots: &[TimeSlot]) -> Option<TimeSlot> {
    slots.first().cloned()
}

pub fn filter_logs_by_slot<'a>(records: &'a [LogRecord], slot: &TimeSlot) -> Vec<&'a LogRecord> {
    records
        .iter()
        .filter(|r| r.timestamp >= slot.start && r.timestamp < slot.end)
        .collect()
}

pub fn summarize_activity(records: &[&LogRecord]) -> ActivitySummary {
    let mut summary = ActivitySummary::default();
    summary.total_logs_in_slot = records.len();

    let mut gateway_set = HashSet::new();

    for record in records {
        match record.level {
            LogLevel::Error | LogLevel::Critical => summary.error_count += 1,
            LogLevel::Warning => summary.warning_count += 1,
            LogLevel::Info => summary.info_count += 1,
            LogLevel::Debug | LogLevel::Trace => summary.debug_count += 1,
            LogLevel::Unknown => {}
        }

        let msg_lower = record.message.to_lowercase();

        if msg_lower.contains("tunnel")
            && (msg_lower.contains("connected")
                || msg_lower.contains("disconnected")
                || msg_lower.contains("connecting")
                || msg_lower.contains("reconnect")
                || msg_lower.contains("state changed"))
        {
            summary
                .tunnel_status_changes
                .push((record.timestamp, record.message.clone()));
        }

        if msg_lower.contains("steering")
            || msg_lower.contains("route")
            || msg_lower.contains("driver")
            || msg_lower.contains("pac file")
        {
            summary
                .steering_events
                .push((record.timestamp, record.message.clone()));
        }

        if msg_lower.contains("gateway")
            || msg_lower.contains("pop:")
            || msg_lower.contains("endpoint:")
        {
            summary
                .gateway_transitions
                .push((record.timestamp, record.message.clone()));

            if let Some(gw) = extract_gateway_ip_or_host(&record.message) {
                gateway_set.insert(gw);
            }
        }

        if msg_lower.contains("auth")
            || msg_lower.contains("token")
            || msg_lower.contains("login")
            || msg_lower.contains("sso")
            || msg_lower.contains("enrollment")
        {
            summary
                .auth_events
                .push((record.timestamp, record.message.clone()));
        }

        if msg_lower.contains("config")
            || msg_lower.contains("policy")
            || msg_lower.contains("nsuserconfig")
            || msg_lower.contains("downloaded new")
        {
            summary
                .config_updates
                .push((record.timestamp, record.message.clone()));
        }
    }

    summary.active_gateways = gateway_set.into_iter().collect();
    summary.active_gateways.sort();
    summary
}

pub fn detect_anomalies(records: &[&LogRecord]) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    let mut disconnect_count = 0;
    let mut last_disconnect_time: Option<NaiveDateTime> = None;
    let mut auth_failure_count = 0;

    for record in records {
        let msg_lower = record.message.to_lowercase();

        if record.level == LogLevel::Error || record.level == LogLevel::Critical {
            anomalies.push(Anomaly {
                severity: if record.level == LogLevel::Critical {
                    AnomalySeverity::High
                } else {
                    AnomalySeverity::Medium
                },
                category: "Log Error".to_string(),
                title: format!("Error logged in module {}", record.module.as_deref().unwrap_or("general")),
                description: record.message.clone(),
                timestamp: Some(record.timestamp),
                source_file: Some(record.file_name.clone()),
                line_number: Some(record.line_number),
                matched_log: Some(record.raw_line.clone()),
            });
        }

        if msg_lower.contains("tunnel") && (msg_lower.contains("disconnected") || msg_lower.contains("failed") || msg_lower.contains("down")) {
            disconnect_count += 1;
            if let Some(prev) = last_disconnect_time {
                let diff = record.timestamp.signed_duration_since(prev);
                if diff < Duration::minutes(5) {
                    anomalies.push(Anomaly {
                        severity: AnomalySeverity::High,
                        category: "Tunnel Instability".to_string(),
                        title: "Frequent Tunnel Disconnection Loop Detected".to_string(),
                        description: format!("Tunnel disconnected twice within {} seconds.", diff.num_seconds()),
                        timestamp: Some(record.timestamp),
                        source_file: Some(record.file_name.clone()),
                        line_number: Some(record.line_number),
                        matched_log: Some(record.raw_line.clone()),
                    });
                }
            }
            last_disconnect_time = Some(record.timestamp);
        }

        if (msg_lower.contains("auth") || msg_lower.contains("login") || msg_lower.contains("token"))
            && (msg_lower.contains("failed") || msg_lower.contains("denied") || msg_lower.contains("invalid") || msg_lower.contains("expired"))
        {
            auth_failure_count += 1;
            anomalies.push(Anomaly {
                severity: AnomalySeverity::High,
                category: "Authentication Failure".to_string(),
                title: "Authentication / Token Failure".to_string(),
                description: record.message.clone(),
                timestamp: Some(record.timestamp),
                source_file: Some(record.file_name.clone()),
                line_number: Some(record.line_number),
                matched_log: Some(record.raw_line.clone()),
            });
        }

        if msg_lower.contains("timeout") || msg_lower.contains("timed out") || msg_lower.contains("unreachable") || msg_lower.contains("connection refused") {
            anomalies.push(Anomaly {
                severity: AnomalySeverity::Medium,
                category: "Network / Timeout Issue".to_string(),
                title: "Gateway or Network Timeout Detected".to_string(),
                description: record.message.clone(),
                timestamp: Some(record.timestamp),
                source_file: Some(record.file_name.clone()),
                line_number: Some(record.line_number),
                matched_log: Some(record.raw_line.clone()),
            });
        }
    }

    if disconnect_count >= 3 {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::High,
            category: "High Disconnect Count".to_string(),
            title: format!("High Tunnel Disconnections ({} total in slot)", disconnect_count),
            description: "The Netskope client experienced multiple disconnections in this 1-hour window.".to_string(),
            timestamp: None,
            source_file: None,
            line_number: None,
            matched_log: None,
        });
    }

    if auth_failure_count >= 2 {
        anomalies.push(Anomaly {
            severity: AnomalySeverity::High,
            category: "Repeated Auth Failure".to_string(),
            title: format!("Multiple Authentication Failures ({} total in slot)", auth_failure_count),
            description: "Multiple authentication or token errors occurred during this timeframe.".to_string(),
            timestamp: None,
            source_file: None,
            line_number: None,
            matched_log: None,
        });
    }

    anomalies
}

fn extract_gateway_ip_or_host(msg: &str) -> Option<String> {
    let ip_re = regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").ok()?;
    if let Some(m) = ip_re.find(msg) {
        return Some(m.as_str().to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_parser::parse_log_content;

    #[test]
    fn test_time_slots_generation() {
        let content = "2025/03/10 14:10:00.000 [INFO] [1:1] [gen] log line 1\n2025/03/10 15:20:00.000 [INFO] [1:1] [gen] log line 2";
        let records = parse_log_content("test.log", content);
        let slots = generate_time_slots(&records);

        assert_eq!(slots.len(), 2);
        // Latest slot is first
        assert_eq!(slots[0].start, NaiveDateTime::parse_from_str("2025-03-10 15:00:00", "%Y-%m-%d %H:%M:%S").unwrap());
        assert_eq!(slots[1].start, NaiveDateTime::parse_from_str("2025-03-10 14:00:00", "%Y-%m-%d %H:%M:%S").unwrap());
    }

    #[test]
    fn test_summarize_activity_and_anomaly_detection() {
        let content = "2025/03/10 14:05:00.000 [INFO] [1:1] [tunnel] Tunnel connected to gateway 10.10.10.1\n2025/03/10 14:10:00.000 [ERROR] [1:1] [auth] Authentication token expired and auth failed\n2025/03/10 14:12:00.000 [ERROR] [1:1] [tunnel] Tunnel disconnected";
        let records = parse_log_content("test.log", content);
        let refs: Vec<&LogRecord> = records.iter().collect();

        let summary = summarize_activity(&refs);
        assert_eq!(summary.total_logs_in_slot, 3);
        assert_eq!(summary.error_count, 2);
        assert_eq!(summary.active_gateways, vec!["10.10.10.1"]);
        assert_eq!(summary.auth_events.len(), 1);

        let anomalies = detect_anomalies(&refs);
        assert!(!anomalies.is_empty());
        assert!(anomalies.iter().any(|a| a.category == "Authentication Failure"));
    }
}
