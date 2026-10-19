# Netskope Client Log Analyzer

A cross-platform desktop GUI application built in **Rust** using **egui / eframe** to assist IT, Security, and Network administrators in troubleshooting Netskope Client issues by analyzing debug log files (`nsdebuglog.log`, etc.).

---

## Key Features

- **Drag-and-Drop Ingestion**: Easily drag and drop Netskope debug log files directly onto the application window or use the file picker.
- **1-Hour Time Window Selection**: Automatically detects the time range across loaded logs, groups activity into 1-hour time slots, and defaults to analyzing the latest available hour while letting users seamlessly switch slots.
- **Client Activity Summarization**: High-level visual dashboard summarizing client operations within the selected hour:
  - Tunnel connection and status state changes
  - Steering and routing events
  - Active gateway IP/PoP transitions
  - Authentication, SSO, and enrollment events
  - Configuration and policy updates
- **Anomaly & Issue Detection**: Automatically flags and highlights client anomalies categorized by severity (**HIGH**, **MEDIUM**, **LOW**):
  - High log errors and critical failures
  - Disconnect/reconnect flapping loops
  - Authentication and token expiration failures
  - Gateway and network timeout events
- **Interactive Log Explorer**: Filter log entries by log level (ERROR, WARN, INFO, DEBUG) or search by keyword/module with monospace formatting and line context.
- **Cross-Platform**: Native executable support for **macOS** and **Windows**.

---

## Project Structure

```text
netskope-log-analyzer/
├── Cargo.toml            # Dependencies and Rust package definitions
├── src/
│   ├── main.rs           # Application entry point and native window launcher
│   ├── lib.rs            # Library module definitions
│   ├── app.rs            # egui/eframe GUI implementation, tabs, drag & drop, and filters
│   ├── log_parser.rs     # Parser engine for Netskope log timestamps and multiline records
│   ├── analyzer.rs       # Time slot grouping, activity summarizer, and anomaly detection rules
│   └── models.rs         # Data structures (LogRecord, TimeSlot, ActivitySummary, Anomaly)
└── README.md             # Project documentation and guide
```

---

## Getting Started & Build Instructions

### Prerequisites

- **Rust toolchain** (Rust 1.75+ recommended): Install via [rustup.rs](https://rustup.rs/).

### Building & Running

1. **Clone or navigate to the repository directory**:
   ```bash
   cd netskope-log-analyzer
   ```

2. **Run the application locally**:
   ```bash
   cargo run --release
   ```

3. **Build target executable**:
   - **macOS**:
     ```bash
     cargo build --release
     ```
     The binary will be located at `target/release/netskope-log-analyzer`.
   - **Windows**:
     ```cmd
     cargo build --release
     ```
     The binary will be located at `target/release/netskope-log-analyzer.exe`.

---

## How to Use

1. **Launch the Application**.
2. **Load Log Files**:
   - Drag and drop one or more Netskope debug log files into the application window.
   - Alternatively, click the **📁 Open Log Files** button to choose files via the system file dialog.
3. **Select 1-Hour Time Window**:
   - By default, the application selects the latest available 1-hour slot.
   - Use the **Analysis Time Window** dropdown at the top to analyze a different 1-hour period.
4. **Explore Analysis Tabs**:
   - **📊 Activity Summary**: Review high-level metrics, active gateways, tunnel events, steering, auth events, and config updates.
   - **⚠️ Highlighted Anomalies**: Examine flagged issues, disconnections, error logs, and auth failures with line references and raw log context.
   - **🔍 Log Explorer**: Search through all parsed log lines in the selected window or filter by log level.

---

## Log Format & Detection Rules

The parser supports standard Netskope Client debug log formats:

```text
YYYY/MM/DD HH:MM:SS.mmm [LEVEL] [PID:TID] [MODULE] Message text...
```

### Anomaly Rules
- **Error/Critical Logs**: Flagged automatically with line numbers and file sources.
- **Tunnel Instability**: Triggered when tunnel disconnects occur multiple times or within 5 minutes of each other.
- **Authentication Failures**: Triggered on token expiration, auth denial, or repeated login failures.
- **Timeouts & Connection Refused**: Highlighted network unreachable or gateway timeout events.

---

## Testing

Run unit tests covering parsing logic, time slot generation, activity summarization, and anomaly detection:

```bash
cargo test
```
