pub mod app;
pub mod analyzer;
pub mod log_parser;
pub mod models;

use app::NetskopeLogAnalyzerApp;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 750.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title("Netskope Client Log Analyzer"),
        ..Default::default()
    };

    eframe::run_native(
        "Netskope Client Log Analyzer",
        native_options,
        Box::new(|cc| Ok(Box::new(NetskopeLogAnalyzerApp::new(cc)))),
    )
}
