use egui::{Color32, RichText, ScrollArea, Ui};
use std::path::PathBuf;

use crate::analyzer::{
    detect_anomalies, filter_logs_by_slot, generate_time_slots,
    summarize_activity,
};
use crate::log_parser::parse_log_file;
use crate::models::{
    ActivitySummary, Anomaly, AnomalySeverity, LogLevel, LogRecord, TimeSlot,
};

#[derive(Debug, PartialEq, Eq)]
pub enum Tab {
    Summary,
    Anomalies,
    LogExplorer,
}

pub struct NetskopeLogAnalyzerApp {
    loaded_files: Vec<PathBuf>,
    all_records: Vec<LogRecord>,
    time_slots: Vec<TimeSlot>,
    selected_slot_index: usize,
    filtered_records: Vec<LogRecord>,
    activity_summary: ActivitySummary,
    anomalies: Vec<Anomaly>,
    active_tab: Tab,
    search_filter: String,
    level_filter: Option<LogLevel>,
    status_message: String,
}

impl NetskopeLogAnalyzerApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            loaded_files: Vec::new(),
            all_records: Vec::new(),
            time_slots: Vec::new(),
            selected_slot_index: 0,
            filtered_records: Vec::new(),
            activity_summary: ActivitySummary::default(),
            anomalies: Vec::new(),
            active_tab: Tab::Summary,
            search_filter: String::new(),
            level_filter: None,
            status_message: "Drag and drop Netskope debug log files anywhere or click 'Open Files'".to_string(),
        }
    }

    fn load_file_paths(&mut self, paths: Vec<PathBuf>) {
        let mut new_records = Vec::new();
        let mut loaded_count = 0;

        for path in paths {
            if self.loaded_files.contains(&path) {
                continue;
            }
            match parse_log_file(&path) {
                Ok(mut records) => {
                    loaded_count += 1;
                    self.loaded_files.push(path);
                    new_records.append(&mut records);
                }
                Err(err) => {
                    self.status_message = format!("Error opening file {}: {}", path.display(), err);
                }
            }
        }

        if !new_records.is_empty() {
            self.all_records.append(&mut new_records);
            self.all_records.sort_by_key(|r| r.timestamp);

            self.time_slots = generate_time_slots(&self.all_records);
            self.selected_slot_index = 0;

            self.reanalyze_selected_slot();
            self.status_message = format!(
                "Successfully loaded {} log records from {} files.",
                self.all_records.len(),
                self.loaded_files.len()
            );
        } else if loaded_count == 0 && self.status_message.is_empty() {
            self.status_message = "No valid log entries found in selected file(s)".to_string();
        }
    }

    fn reanalyze_selected_slot(&mut self) {
        if self.time_slots.is_empty() {
            self.filtered_records.clear();
            self.activity_summary = ActivitySummary::default();
            self.anomalies.clear();
            return;
        }

        if self.selected_slot_index >= self.time_slots.len() {
            self.selected_slot_index = 0;
        }

        let slot = &self.time_slots[self.selected_slot_index];
        let refs = filter_logs_by_slot(&self.all_records, slot);

        self.filtered_records = refs.iter().map(|r| (*r).clone()).collect();
        self.activity_summary = summarize_activity(&refs);
        self.anomalies = detect_anomalies(&refs);
    }

    fn render_header(&mut self, ui: &mut Ui) {
        ui.vertical(|ui| {
            ui.heading("Netskope Client Log Analyzer");
            ui.label(RichText::new(&self.status_message).italics().color(Color32::GRAY));

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("📁 Open Log Files").clicked() {
                    if let Some(files) = rfd::FileDialog::new()
                        .add_filter("Log Files", &["log", "txt"])
                        .pick_files()
                    {
                        self.load_file_paths(files);
                    }
                }

                if !self.loaded_files.is_empty() {
                    if ui.button("🗑 Clear All").clicked() {
                        self.loaded_files.clear();
                        self.all_records.clear();
                        self.time_slots.clear();
                        self.filtered_records.clear();
                        self.activity_summary = ActivitySummary::default();
                        self.anomalies.clear();
                        self.status_message = "Drag and drop Netskope debug log files anywhere".to_string();
                    }
                }

                ui.separator();
                ui.label(format!(
                    "Files loaded: {} | Total Log Entries: {}",
                    self.loaded_files.len(),
                    self.all_records.len()
                ));
            });

            if !self.time_slots.is_empty() {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Analysis Time Window (1-Hour Slot):").strong());
                    let current_label = self
                        .time_slots
                        .get(self.selected_slot_index)
                        .map(|s| s.label.as_str())
                        .unwrap_or("Select a slot");

                    let mut changed = false;
                    egui::ComboBox::from_id_salt("time_slot_combo")
                        .selected_text(current_label)
                        .show_ui(ui, |ui| {
                            for (idx, slot) in self.time_slots.iter().enumerate() {
                                if ui
                                    .selectable_value(&mut self.selected_slot_index, idx, &slot.label)
                                    .changed()
                                {
                                    changed = true;
                                }
                            }
                        });

                    if changed {
                        self.reanalyze_selected_slot();
                    }
                });
            }
        });
    }

    fn render_tabs(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            let summary_btn = ui.selectable_label(self.active_tab == Tab::Summary, "📊 Activity Summary");
            if summary_btn.clicked() {
                self.active_tab = Tab::Summary;
            }

            let anomaly_label = format!("⚠️ Highlighted Anomalies ({})", self.anomalies.len());
            let anomaly_btn = ui.selectable_label(self.active_tab == Tab::Anomalies, anomaly_label);
            if anomaly_btn.clicked() {
                self.active_tab = Tab::Anomalies;
            }

            let log_btn = ui.selectable_label(
                self.active_tab == Tab::LogExplorer,
                format!("🔍 Log Explorer ({})", self.filtered_records.len()),
            );
            if log_btn.clicked() {
                self.active_tab = Tab::LogExplorer;
            }
        });
        ui.separator();
    }

    fn render_summary_tab(&self, ui: &mut Ui) {
        ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(8.0);
            ui.heading("Client Activity Overview");
            ui.label("Summary of Netskope client operations during the selected 1-hour window:");

            ui.add_space(10.0);
            ui.columns(4, |cols| {
                cols[0].group(|ui| {
                    ui.label(RichText::new("Total Logs").strong());
                    ui.heading(self.activity_summary.total_logs_in_slot.to_string());
                });
                cols[1].group(|ui| {
                    ui.label(RichText::new("Errors / Crits").strong().color(Color32::RED));
                    ui.heading(
                        RichText::new(self.activity_summary.error_count.to_string())
                            .color(Color32::RED),
                    );
                });
                cols[2].group(|ui| {
                    ui.label(RichText::new("Warnings").strong().color(Color32::YELLOW));
                    ui.heading(
                        RichText::new(self.activity_summary.warning_count.to_string())
                            .color(Color32::YELLOW),
                    );
                });
                cols[3].group(|ui| {
                    ui.label(RichText::new("Detected Anomalies").strong().color(Color32::KHAKI));
                    ui.heading(self.anomalies.len().to_string());
                });
            });

            ui.add_space(15.0);
            ui.collapsing("🌐 Active Gateways / PoPs", |ui| {
                if self.activity_summary.active_gateways.is_empty() {
                    ui.label("No active gateways explicitly detected in this window.");
                } else {
                    for gw in &self.activity_summary.active_gateways {
                        ui.label(format!("• {}", gw));
                    }
                }
            });

            ui.add_space(10.0);
            ui.collapsing("🔒 Tunnel Status Events", |ui| {
                if self.activity_summary.tunnel_status_changes.is_empty() {
                    ui.label("No tunnel state changes detected.");
                } else {
                    for (ts, msg) in &self.activity_summary.tunnel_status_changes {
                        ui.label(format!("[{}] {}", ts.format("%H:%M:%S"), msg));
                    }
                }
            });

            ui.add_space(10.0);
            ui.collapsing("🛣 Steering & Routing Events", |ui| {
                if self.activity_summary.steering_events.is_empty() {
                    ui.label("No steering events detected.");
                } else {
                    for (ts, msg) in &self.activity_summary.steering_events {
                        ui.label(format!("[{}] {}", ts.format("%H:%M:%S"), msg));
                    }
                }
            });

            ui.add_space(10.0);
            ui.collapsing("🔑 Authentication & SSO Events", |ui| {
                if self.activity_summary.auth_events.is_empty() {
                    ui.label("No auth events detected.");
                } else {
                    for (ts, msg) in &self.activity_summary.auth_events {
                        ui.label(format!("[{}] {}", ts.format("%H:%M:%S"), msg));
                    }
                }
            });

            ui.add_space(10.0);
            ui.collapsing("⚙ Config & Policy Updates", |ui| {
                if self.activity_summary.config_updates.is_empty() {
                    ui.label("No config updates detected.");
                } else {
                    for (ts, msg) in &self.activity_summary.config_updates {
                        ui.label(format!("[{}] {}", ts.format("%H:%M:%S"), msg));
                    }
                }
            });
        });
    }

    fn render_anomalies_tab(&self, ui: &mut Ui) {
        ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(8.0);
            ui.heading("Highlighted Anomalies & Issues");

            if self.anomalies.is_empty() {
                ui.add_space(20.0);
                ui.label(
                    RichText::new("✅ No anomalies or critical issues detected in this 1-hour window!")
                        .color(Color32::GREEN)
                        .size(16.0),
                );
                return;
            }

            for anomaly in &self.anomalies {
                ui.add_space(8.0);
                let (badge_color, badge_text) = match anomaly.severity {
                    AnomalySeverity::High => (Color32::RED, "HIGH"),
                    AnomalySeverity::Medium => (Color32::YELLOW, "MEDIUM"),
                    AnomalySeverity::Low => (Color32::LIGHT_BLUE, "LOW"),
                };

                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("[{}]", badge_text))
                                .strong()
                                .color(badge_color),
                        );
                        ui.heading(&anomaly.title);
                        ui.label(RichText::new(&anomaly.category).italics().color(Color32::LIGHT_GRAY));
                    });

                    if let Some(ts) = anomaly.timestamp {
                        ui.label(format!("Time: {}", ts.format("%Y-%m-%d %H:%M:%S")));
                    }
                    if let (Some(f), Some(l)) = (&anomaly.source_file, anomaly.line_number) {
                        ui.label(format!("Source: {} (line {})", f, l));
                    }

                    ui.label(&anomaly.description);

                    if let Some(raw) = &anomaly.matched_log {
                        ui.add_space(4.0);
                        ui.code(raw);
                    }
                });
            }
        });
    }

    fn render_log_explorer_tab(&mut self, ui: &mut Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Search:");
            ui.text_edit_singleline(&mut self.search_filter);

            ui.separator();
            ui.label("Level:");
            if ui
                .selectable_label(self.level_filter.is_none(), "ALL")
                .clicked()
            {
                self.level_filter = None;
            }
            if ui
                .selectable_label(self.level_filter == Some(LogLevel::Error), "ERROR")
                .clicked()
            {
                self.level_filter = Some(LogLevel::Error);
            }
            if ui
                .selectable_label(self.level_filter == Some(LogLevel::Warning), "WARN")
                .clicked()
            {
                self.level_filter = Some(LogLevel::Warning);
            }
            if ui
                .selectable_label(self.level_filter == Some(LogLevel::Info), "INFO")
                .clicked()
            {
                self.level_filter = Some(LogLevel::Info);
            }
            if ui
                .selectable_label(self.level_filter == Some(LogLevel::Debug), "DEBUG")
                .clicked()
            {
                self.level_filter = Some(LogLevel::Debug);
            }
        });

        ui.add_space(8.0);

        let search_lower = self.search_filter.to_lowercase();
        let records_to_show: Vec<&LogRecord> = self
            .filtered_records
            .iter()
            .filter(|r| {
                if let Some(lvl) = self.level_filter {
                    if r.level != lvl {
                        return false;
                    }
                }
                if !search_lower.is_empty() {
                    return r.message.to_lowercase().contains(&search_lower)
                        || r.file_name.to_lowercase().contains(&search_lower)
                        || r.module
                            .as_ref()
                            .map(|m| m.to_lowercase().contains(&search_lower))
                            .unwrap_or(false);
                }
                true
            })
            .collect();

        ui.label(format!("Showing {} log lines", records_to_show.len()));

        ScrollArea::both().show(ui, |ui| {
            for record in records_to_show {
                let color = match record.level {
                    LogLevel::Error | LogLevel::Critical => Color32::RED,
                    LogLevel::Warning => Color32::YELLOW,
                    LogLevel::Info => Color32::LIGHT_BLUE,
                    LogLevel::Debug | LogLevel::Trace => Color32::GRAY,
                    LogLevel::Unknown => Color32::WHITE,
                };

                ui.horizontal(|ui| {
                    ui.label(RichText::new(record.timestamp.format("%H:%M:%S%.3f").to_string()).monospace());
                    ui.label(
                        RichText::new(format!("[{:7}]", record.level.as_str()))
                            .monospace()
                            .strong()
                            .color(color),
                    );
                    if let Some(mod_str) = &record.module {
                        ui.label(RichText::new(format!("[{}]", mod_str)).monospace().color(Color32::KHAKI));
                    }
                    ui.label(RichText::new(&record.message).monospace());
                });
            }
        });
    }
}

impl eframe::App for NetskopeLogAnalyzerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle drag and drop files
        let dropped_files = ctx.input(|i| i.raw.dropped_files.clone());
        if !dropped_files.is_empty() {
            let paths: Vec<PathBuf> = dropped_files
                .into_iter()
                .filter_map(|f| f.path)
                .collect();
            if !paths.is_empty() {
                self.load_file_paths(paths);
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_header(ui);
            ui.add_space(10.0);

            if self.all_records.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.group(|ui| {
                        ui.heading("📂 Drag & Drop Netskope Log Files Here");
                        ui.label("Supported log formats include Netskope client debug logs (e.g. nsdebuglog.log).");
                        ui.label("You can also click 'Open Log Files' above.");
                    });
                });
            } else {
                self.render_tabs(ui);
                match self.active_tab {
                    Tab::Summary => self.render_summary_tab(ui),
                    Tab::Anomalies => self.render_anomalies_tab(ui),
                    Tab::LogExplorer => self.render_log_explorer_tab(ui),
                }
            }
        });
    }
}
